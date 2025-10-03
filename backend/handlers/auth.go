package handlers

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"

	"leaflock/config"
	"leaflock/crypto"
	"leaflock/database"
	"leaflock/utils"
)

// AuthHandler handles authentication-related requests
type AuthHandler struct {
	db     database.Database
	redis  *redis.Client
	crypto *crypto.CryptoService
	config *config.Config
}

// NewAuthHandler creates a new authentication handler
func NewAuthHandler(db database.Database, redis *redis.Client, cryptoService *crypto.CryptoService, cfg *config.Config) *AuthHandler {
	return &AuthHandler{
		db:     db,
		redis:  redis,
		crypto: cryptoService,
		config: cfg,
	}
}

// SessionData structure for Redis storage
type SessionData struct {
	UserID    string    `json:"user_id"`
	IPAddress string    `json:"ip_address"`
	UserAgent string    `json:"user_agent"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// RegisterRequest represents a user registration request
type RegisterRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=12"`
}

// LoginRequest represents a user login request
type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
	MFACode  string `json:"mfa_code,omitempty"`
}

// AdminRecoveryRequest represents an admin recovery request
type AdminRecoveryRequest struct {
	Email           string `json:"email" validate:"required,email"`
	Password        string `json:"password" validate:"required,min=12"`
	RecoveryToken   string `json:"recovery_token" validate:"required"`
	ConfirmDeletion bool   `json:"confirm_deletion"`
}

type mfaCodeRequest struct {
	Code string `json:"code"`
}

// Store session in Redis with encrypted metadata
func (h *AuthHandler) storeSessionInRedis(ctx context.Context, tokenHash []byte, userID uuid.UUID, ipAddr, userAgent string, expiresAt time.Time) error {
	sessionData := SessionData{
		UserID:    userID.String(),
		IPAddress: ipAddr,
		UserAgent: userAgent,
		CreatedAt: time.Now(),
		ExpiresAt: expiresAt,
	}

	// Serialize session data
	data, err := json.Marshal(sessionData)
	if err != nil {
		return fmt.Errorf("failed to marshal session data: %w", err)
	}

	// Encrypt session data
	encryptedData, err := h.crypto.Encrypt(data)
	if err != nil {
		return fmt.Errorf("failed to encrypt session data: %w", err)
	}

	// Store in Redis with expiration
	sessionKey := fmt.Sprintf("session:%x", tokenHash)
	duration := time.Until(expiresAt)

	return h.redis.Set(ctx, sessionKey, encryptedData, duration).Err()
}

// Register godoc
// @Summary Register a new user
// @Description Register a new user with email and password
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body RegisterRequest true "Registration data"
// @Success 201 {object} map[string]interface{} "User registered successfully"
// @Failure 400 {object} map[string]interface{} "Invalid request"
// @Failure 409 {object} map[string]interface{} "Email already exists"
// @Failure 503 {object} map[string]interface{} "Registration disabled"
// @Router /auth/register [post]
func (h *AuthHandler) Register(c *fiber.Ctx) error {
	// Check if registration is enabled (runtime toggle)
	if config.RegEnabled.Load() != 1 {
		return c.Status(403).JSON(fiber.Map{"error": "Registration is currently disabled"})
	}

	var req RegisterRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
	}

	// Validate password requirements
	if len(req.Password) < 12 {
		return c.Status(400).JSON(fiber.Map{"error": "Password must be at least 12 characters long"})
	}

	// Generate salt and hash password
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to generate credentials"})
	}
	passwordHash := crypto.HashPassword(req.Password, salt)

	// Generate user's master encryption key
	masterKey := make([]byte, 32)
	if _, err := rand.Read(masterKey); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to generate credentials"})
	}

	// Derive key from password to encrypt master key
	userKey := argon2.IDKey([]byte(req.Password), salt, 1, 64*1024, 4, 32)

	// Encrypt master key with user's derived key
	aead, err := chacha20poly1305.NewX(userKey)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to initialize encryption"})
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to initialize encryption"})
	}
	encryptedMasterKey := aead.Seal(nonce, nonce, masterKey, nil)

	// Generate GDPR deletion key for email encryption
	deletionKey := make([]byte, 32)
	if _, err := rand.Read(deletionKey); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to generate credentials"})
	}

	// Create email hash for uniqueness and GDPR lookups
	emailHash := h.crypto.HashEmail(req.Email)

	// Encrypt email with GDPR key (allows recovery for deletion requests)
	encryptedEmail, err := h.crypto.EncryptWithGDPRKey([]byte(req.Email), deletionKey)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to protect account data"})
	}

	// Create deterministic email hash for secure login lookups
	emailSearchHash, err := h.crypto.EncryptDeterministic([]byte(strings.ToLower(req.Email)), "email_search")
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to protect account data"})
	}

	// Start transaction
	ctx := context.Background()
	tx, err := h.db.Begin(ctx)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Database error"})
	}
	defer func() {
		_ = tx.Rollback(ctx) // Rollback is safe to call even if tx was committed
	}()

	// Store GDPR deletion key
	_, err = tx.Exec(ctx, `
        INSERT INTO gdpr_keys (email_hash, deletion_key)
        VALUES ($1, $2)`,
		emailHash, deletionKey,
	)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to setup account security"})
	}

	// Create user
	var userID uuid.UUID
	err = tx.QueryRow(ctx, `
        INSERT INTO users (email_hash, email_encrypted, email_search_hash, password_hash, salt, master_key_encrypted)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING id`,
		emailHash, encryptedEmail, emailSearchHash, passwordHash, salt, encryptedMasterKey,
	).Scan(&userID)

	if err != nil {
		if strings.Contains(err.Error(), "duplicate") {
			return c.Status(409).JSON(fiber.Map{"error": "Email already registered"})
		}
		return c.Status(500).JSON(fiber.Map{"error": "Registration failed"})
	}

	// Create default workspace
	workspaceName, err := h.crypto.Encrypt([]byte("My Workspace"))
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to set up workspace"})
	}
	workspaceKey := make([]byte, 32)
	if _, err := rand.Read(workspaceKey); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to set up workspace"})
	}

	// Encrypt workspace key with user's master key
	encryptedWorkspaceKey, err := h.crypto.Encrypt(workspaceKey)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to set up workspace"})
	}

	var workspaceID uuid.UUID
	err = tx.QueryRow(ctx, `
        INSERT INTO workspaces (name_encrypted, owner_id, encryption_key_encrypted)
        VALUES ($1, $2, $3)
        RETURNING id`,
		workspaceName, userID, encryptedWorkspaceKey,
	).Scan(&workspaceID)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to create workspace"})
	}

	// Commit transaction
	if err = tx.Commit(ctx); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Registration failed"})
	}

	// Log audit event
	h.logAudit(ctx, userID, "user.registered", "user", userID, c)

	// Generate session token
	token, err := h.generateToken(userID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Token generation failed"})
	}

	return c.Status(201).JSON(fiber.Map{
		"message":      "Registration successful",
		"token":        token,
		"user_id":      userID,
		"workspace_id": workspaceID,
	})
}

// Login godoc
// @Summary User login
// @Description Authenticate user with email and password
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body LoginRequest true "Login credentials"
// @Success 200 {object} map[string]interface{} "Login successful"
// @Failure 400 {object} map[string]interface{} "Invalid request"
// @Failure 401 {object} map[string]interface{} "Invalid credentials"
// @Failure 423 {object} map[string]interface{} "MFA required"
// @Router /auth/login [post]
func (h *AuthHandler) Login(c *fiber.Ctx) error {
	// Enhanced debug logging for troubleshooting CORS/request issues
	log.Printf("🔍 Login Request Debug Info:")
	log.Printf("   - Method: %s", c.Method())
	log.Printf("   - Origin: %s", c.Get("Origin"))
	log.Printf("   - Content-Type: %s", c.Get("Content-Type"))
	log.Printf("   - User-Agent: %s", c.Get("User-Agent"))
	log.Printf("   - Content-Length: %s", c.Get("Content-Length"))

	var req LoginRequest
	if err := c.BodyParser(&req); err != nil {
		log.Printf("❌ Body parsing failed: %v", err)
		log.Printf("   - Raw body: %s", c.Body())
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
	}

	// Log parsed request details (without logging full password for security)
	log.Printf("✅ Request parsed successfully:")
	log.Printf("   - Email: %s", req.Email)
	log.Printf("   - Password length: %d", len(req.Password))
	if len(req.Password) > 0 {
		log.Printf("   - Password first char: %c", req.Password[0])
		log.Printf("   - Password last char: %c", req.Password[len(req.Password)-1])
	}
	log.Printf("   - MFA Code present: %t", req.MFACode != "")

	ctx := context.Background()

	// Create deterministic hash for secure email lookup
	emailSearchHash, err := h.crypto.EncryptDeterministic([]byte(strings.ToLower(req.Email)), "email_search")
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Authentication failed"})
	}

	// Get user using deterministic hash
	var userID uuid.UUID
	var passwordHash string
	var failedAttempts int
	var lockedUntil *time.Time
	var mfaEnabled bool
	var mfaSecret []byte

	err = h.db.QueryRow(ctx, `
        SELECT id, password_hash, failed_attempts, locked_until, mfa_enabled, mfa_secret_encrypted
        FROM users WHERE email_search_hash = $1`,
		emailSearchHash,
	).Scan(&userID, &passwordHash, &failedAttempts, &lockedUntil, &mfaEnabled, &mfaSecret)

	if err != nil {
		return c.Status(401).JSON(fiber.Map{"error": "Invalid credentials"})
	}

	// Check if account is locked with detailed time remaining
	if lockedUntil != nil && lockedUntil.After(time.Now()) {
		timeRemaining := time.Until(*lockedUntil)
		minutes := int(timeRemaining.Minutes())
		seconds := int(timeRemaining.Seconds()) % 60

		var timeMessage string
		if minutes > 0 {
			timeMessage = fmt.Sprintf("%d minutes and %d seconds", minutes, seconds)
		} else {
			timeMessage = fmt.Sprintf("%d seconds", seconds)
		}

		return c.Status(423).JSON(fiber.Map{
			"error":               fmt.Sprintf("Account locked due to too many failed login attempts. Please try again in %s.", timeMessage),
			"locked_until":        lockedUntil.Format(time.RFC3339),
			"retry_after_seconds": int(timeRemaining.Seconds()),
		})
	}

	// Debug logging for password verification
	log.Printf("🔍 Login attempt for email: %s", req.Email)
	log.Printf("🔍 Received password length: %d characters", len(req.Password))
	if len(req.Password) > 0 {
		log.Printf("🔍 Password starts with: %c", req.Password[0])
	}

	// Verify password
	if !crypto.VerifyPassword(req.Password, passwordHash) {

		// Increment failed attempts
		failedAttempts++

		var lockDuration time.Duration
		if failedAttempts >= 7 {
			lockDuration = 15 * time.Minute
		} else if failedAttempts >= 6 {
			lockDuration = 5 * time.Minute
		} else if failedAttempts >= h.config.MaxLoginAttempts {
			lockDuration = 1 * time.Minute
		}

		if lockDuration > 0 {
			lockUntil := time.Now().Add(lockDuration)
			if _, err := h.db.Exec(ctx, `
                UPDATE users SET failed_attempts = $1, locked_until = $2
                WHERE id = $3`,
				failedAttempts, lockUntil, userID,
			); err != nil {
				log.Printf("Warning: Failed to lock user account: %v", err)
			}
			h.logAudit(ctx, userID, "login.locked", "user", userID, c)

			// Calculate time remaining for the lockout message
			timeRemaining := time.Until(lockUntil)
			minutes := int(timeRemaining.Minutes())
			seconds := int(timeRemaining.Seconds()) % 60

			var timeMessage string
			if minutes > 0 {
				timeMessage = fmt.Sprintf("%d minutes and %d seconds", minutes, seconds)
			} else {
				timeMessage = fmt.Sprintf("%d seconds", seconds)
			}

			return c.Status(423).JSON(fiber.Map{
				"error":               fmt.Sprintf("Account locked due to too many failed login attempts. Please try again in %s.", timeMessage),
				"locked_until":        lockUntil.Format(time.RFC3339),
				"retry_after_seconds": int(timeRemaining.Seconds()),
			})
		}

		if _, err := h.db.Exec(ctx, `UPDATE users SET failed_attempts = $1 WHERE id = $2`, failedAttempts, userID); err != nil {
			log.Printf("Warning: Failed to update failed login attempts: %v", err)
		}
		h.logAudit(ctx, userID, "login.failed", "user", userID, c)

		return c.Status(401).JSON(fiber.Map{"error": "Invalid credentials"})
	}

	// Check if MFA is enabled - if yes, create temporary session token
	if mfaEnabled {
		// Generate temporary MFA session token
		mfaService := &MFAService{}
		sessionToken, err := mfaService.GenerateMFASessionToken(userID.String())
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "Failed to create MFA session"})
		}

		// Store session token in Redis with 5-minute expiration
		sessionKey := fmt.Sprintf("mfa_session:%s", sessionToken)
		err = h.redis.Set(ctx, sessionKey, userID.String(), 5*time.Minute).Err()
		if err != nil {
			log.Printf("Failed to store MFA session in Redis: %v", err)
			return c.Status(500).JSON(fiber.Map{"error": "Failed to create MFA session"})
		}

		h.logAudit(ctx, userID, "login.mfa_required", "user", userID, c)

		return c.Status(200).JSON(fiber.Map{
			"mfa_required":  true,
			"session_token": sessionToken,
		})
	}

	// Reset failed attempts and update last login
	if _, err := h.db.Exec(ctx, `
        UPDATE users SET failed_attempts = 0, locked_until = NULL, last_login = NOW()
        WHERE id = $1`,
		userID,
	); err != nil {
		log.Printf("Warning: Failed to reset failed login attempts: %v", err)
	}

	// Generate session
	sessionToken := make([]byte, 32)
	if _, err := rand.Read(sessionToken); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Session creation failed"})
	}
	sessionTokenStr := hex.EncodeToString(sessionToken)

	// Hash token for storage
	tokenHash := argon2.IDKey(sessionToken, []byte("session"), 1, 64*1024, 4, 32)

	// Store session in Redis
	expiresAt := time.Now().Add(h.config.SessionDuration)
	err = h.storeSessionInRedis(ctx, tokenHash, userID, utils.ClientIP(c), c.Get("User-Agent"), expiresAt)
	if err != nil {
		log.Printf("Failed to store session in Redis: %v", err)
		return c.Status(500).JSON(fiber.Map{"error": "Session creation failed"})
	}

	// Log successful login
	h.logAudit(ctx, userID, "login.success", "user", userID, c)

	// Generate JWT token
	token, err := h.generateToken(userID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Token generation failed"})
	}

	// Get workspace
	var workspaceID uuid.UUID
	_ = h.db.QueryRow(ctx, `SELECT id FROM workspaces WHERE owner_id = $1 LIMIT 1`, userID).Scan(&workspaceID) // Best effort, workspaceID will be nil UUID if not found

	return c.JSON(fiber.Map{
		"token":        token,
		"session":      sessionTokenStr,
		"user_id":      userID,
		"workspace_id": workspaceID,
	})
}

func (h *AuthHandler) AdminRecovery(c *fiber.Ctx) error {
	log.Println("🚨 Admin Recovery Request - Starting emergency admin recovery process")

	var req AdminRecoveryRequest
	if err := c.BodyParser(&req); err != nil {
		log.Printf("❌ Admin recovery body parsing failed: %v", err)
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
	}

	// Validate request
	if req.Email == "" {
		return c.Status(400).JSON(fiber.Map{"error": "Email is required"})
	}
	if len(req.Password) < 12 {
		return c.Status(400).JSON(fiber.Map{"error": "Password must be at least 12 characters long"})
	}
	if req.RecoveryToken == "" {
		return c.Status(400).JSON(fiber.Map{"error": "Recovery token is required"})
	}

	log.Printf("📧 Admin recovery for email: %s", req.Email)

	// Generate and validate recovery token
	expectedToken := h.generateRecoveryToken(req.Email)
	if req.RecoveryToken != expectedToken {
		log.Printf("❌ Invalid recovery token provided")
		return c.Status(401).JSON(fiber.Map{"error": "Invalid recovery token"})
	}

	// Only allow recovery for admin email
	if req.Email != h.config.DefaultAdminEmail {
		log.Printf("❌ Recovery attempted for non-admin email: %s", req.Email)
		return c.Status(403).JSON(fiber.Map{"error": "Recovery only allowed for default admin account"})
	}

	ctx := context.Background()

	// Check if this is a key mismatch situation
	oldEmailSearchHash, err := h.findExistingUserWithDifferentKey(ctx, req.Email)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		log.Printf("❌ Error checking for existing user: %v", err)
		return c.Status(500).JSON(fiber.Map{"error": "Recovery check failed"})
	}

	var userFound bool
	var existingUserID uuid.UUID

	if oldEmailSearchHash != "" {
		userFound = true
		log.Printf("🔍 Found existing admin user with old encryption key")

		// Get the user ID
		err = h.db.QueryRow(ctx, `SELECT id FROM users WHERE email_search_hash = $1`, oldEmailSearchHash).Scan(&existingUserID)
		if err != nil {
			log.Printf("❌ Error getting user ID: %v", err)
			return c.Status(500).JSON(fiber.Map{"error": "Recovery failed"})
		}
	}

	if userFound && !req.ConfirmDeletion {
		return c.JSON(fiber.Map{
			"status":          "confirmation_required",
			"message":         "An admin user exists but is unreachable due to encryption key mismatch. Continuing will delete the old user and create a new one.",
			"user_id":         existingUserID,
			"action_required": "Set confirm_deletion to true to proceed",
		})
	}

	// Begin transaction
	tx, err := h.db.Begin(ctx)
	if err != nil {
		log.Printf("❌ Failed to start recovery transaction: %v", err)
		return c.Status(500).JSON(fiber.Map{"error": "Recovery failed"})
	}
	defer func() {
		_ = tx.Rollback(ctx) // Rollback is safe to call even if tx was committed
	}()

	// If user exists, delete them and all related data
	if userFound {
		log.Printf("🗑️ Deleting existing admin user and related data...")

		// Delete related data first (to avoid foreign key constraints)
		tables := []string{
			"notes", "tags", "folders", "templates", "note_tags", "attachments",
			"shared_notes", "user_sessions", "audit_logs", "password_reset_tokens",
			"gdpr_keys",
		}

		for _, table := range tables {
			_, err = tx.Exec(ctx, fmt.Sprintf("DELETE FROM %s WHERE user_id = $1", table), existingUserID)
			if err != nil {
				log.Printf("⚠️ Error deleting from %s: %v", table, err)
				// Continue with other tables
			}
		}

		// Delete the user
		_, err = tx.Exec(ctx, "DELETE FROM users WHERE id = $1", existingUserID)
		if err != nil {
			log.Printf("❌ Error deleting user: %v", err)
			return c.Status(500).JSON(fiber.Map{"error": "Failed to delete existing user"})
		}

		log.Printf("✅ Deleted existing admin user and all related data")
	}

	// Create new admin user with current encryption key
	log.Printf("👤 Creating new admin user with current encryption key...")

	// Generate salt for password hashing
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		log.Printf("❌ Failed to generate salt: %v", err)
		return c.Status(500).JSON(fiber.Map{"error": "Recovery failed"})
	}

	// Hash password with Argon2id
	passwordHash := crypto.HashPassword(req.Password, salt)

	// Generate user's master encryption key
	masterKey := make([]byte, 32)
	if _, err := rand.Read(masterKey); err != nil {
		log.Printf("❌ Failed to generate master key: %v", err)
		return c.Status(500).JSON(fiber.Map{"error": "Recovery failed"})
	}

	// Derive key from password to encrypt master key
	userKey := argon2.IDKey([]byte(req.Password), salt, 1, 64*1024, 4, 32)

	// Encrypt master key with user's derived key
	aead, err := chacha20poly1305.NewX(userKey)
	if err != nil {
		log.Printf("❌ Failed to initialize encryption: %v", err)
		return c.Status(500).JSON(fiber.Map{"error": "Recovery failed"})
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		log.Printf("❌ Failed to generate nonce: %v", err)
		return c.Status(500).JSON(fiber.Map{"error": "Recovery failed"})
	}

	masterKeyEncrypted := aead.Seal(nonce, nonce, masterKey, nil)

	// Generate GDPR deletion key for email encryption
	deletionKey := make([]byte, 32)
	if _, err := rand.Read(deletionKey); err != nil {
		log.Printf("❌ Failed to generate GDPR deletion key: %v", err)
		return c.Status(500).JSON(fiber.Map{"error": "Recovery failed"})
	}

	// Create email hash for uniqueness and GDPR lookups
	emailHash := h.crypto.HashEmail(req.Email)

	// Encrypt email with GDPR key
	emailEncrypted, err := h.crypto.EncryptWithGDPRKey([]byte(req.Email), deletionKey)
	if err != nil {
		log.Printf("❌ Failed to encrypt email: %v", err)
		return c.Status(500).JSON(fiber.Map{"error": "Recovery failed"})
	}

	// Create deterministic email hash for secure login lookups (with CURRENT key)
	emailSearchHash, err := h.crypto.EncryptDeterministic([]byte(strings.ToLower(req.Email)), "email_search")
	if err != nil {
		log.Printf("❌ Failed to create email search hash: %v", err)
		return c.Status(500).JSON(fiber.Map{"error": "Recovery failed"})
	}

	// Store GDPR deletion key
	_, err = tx.Exec(ctx, `
		INSERT INTO gdpr_keys (email_hash, deletion_key)
		VALUES ($1, $2)`,
		emailHash, deletionKey,
	)
	if err != nil {
		log.Printf("❌ Failed to store GDPR key: %v", err)
		return c.Status(500).JSON(fiber.Map{"error": "Recovery failed"})
	}

	// Create new user
	newUserID := uuid.New()
	workspaceID := uuid.New()

	_, err = tx.Exec(ctx, `
		INSERT INTO users (
			id, email_encrypted, email_search_hash, password_hash,
			master_key_encrypted, workspace_id, created_at, updated_at,
			failed_attempts, locked_until, mfa_enabled
		) VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW(), 0, NULL, false)`,
		newUserID, emailEncrypted, emailSearchHash, passwordHash,
		masterKeyEncrypted, workspaceID,
	)
	if err != nil {
		log.Printf("❌ Failed to create new admin user: %v", err)
		return c.Status(500).JSON(fiber.Map{"error": "Recovery failed"})
	}

	// Commit transaction
	if err = tx.Commit(ctx); err != nil {
		log.Printf("❌ Failed to commit recovery transaction: %v", err)
		return c.Status(500).JSON(fiber.Map{"error": "Recovery failed"})
	}

	log.Printf("✅ Admin recovery completed successfully")
	log.Printf("   - New User ID: %s", newUserID)
	log.Printf("   - Workspace ID: %s", workspaceID)
	log.Printf("   - Email: %s", req.Email)

	return c.JSON(fiber.Map{
		"status":       "success",
		"message":      "Admin user recovered successfully",
		"user_id":      newUserID,
		"workspace_id": workspaceID,
		"instructions": "You can now login with the provided credentials",
	})
}

func (h *AuthHandler) generateRecoveryToken(email string) string {
	// Generate recovery token based on current server encryption key and email
	// This ensures only someone with access to the server config can generate valid tokens
	data := fmt.Sprintf("%s:%s:%s", email, h.config.EncryptionKey, "admin_recovery")
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("recovery_%x", hash[:16]) // First 16 bytes as hex
}

func (h *AuthHandler) findExistingUserWithDifferentKey(ctx context.Context, email string) (string, error) {
	// Try to find users with the same email but different email_search_hash
	// This indicates they were created with a different encryption key

	log.Printf("🔍 Searching for existing admin users that may have key mismatch...")

	var foundHashes [][]byte
	rows, err := h.db.Query(ctx, `
		SELECT DISTINCT email_search_hash
		FROM users
		WHERE LENGTH(email_search_hash) > 0
	`)
	if err != nil {
		return "", err
	}
	defer rows.Close()

	for rows.Next() {
		var hash []byte
		if err := rows.Scan(&hash); err != nil {
			continue
		}
		foundHashes = append(foundHashes, hash)
	}

	log.Printf("🔍 Found %d existing users in database", len(foundHashes))

	// Since we can't decrypt the stored emails to check if they match,
	// we'll assume any existing user might be the admin if there's exactly one user
	// and the current email search hash doesn't match
	currentEmailSearchHash, err := h.crypto.EncryptDeterministic([]byte(strings.ToLower(email)), "email_search")
	if err != nil {
		return "", err
	}

	// Check if current hash exists
	for _, hash := range foundHashes {
		if bytes.Equal(hash, currentEmailSearchHash) {
			log.Printf("🔍 Current email search hash found - no key mismatch")
			return "", sql.ErrNoRows // No mismatch
		}
	}

	// If we have exactly one user and it's not matching current hash, likely key mismatch
	if len(foundHashes) == 1 {
		log.Printf("🔍 Found potential key mismatch - one user exists with different hash")
		return string(foundHashes[0]), nil
	}

	log.Printf("🔍 No clear key mismatch detected")
	return "", sql.ErrNoRows
}

// GetMFAStatus godoc
// @Summary Get MFA status
// @Description Get the current MFA status for the authenticated user
// @Tags MFA
// @Security BearerAuth
// @Produce json
// @Success 200 {object} map[string]interface{} "MFA status"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 500 {object} map[string]interface{} "Server error"
// @Router /auth/mfa/status [get]
func (h *AuthHandler) GetMFAStatus(c *fiber.Ctx) error {
	v := c.Locals("user_id")
	uid, ok := v.(uuid.UUID)
	if !ok {
		return c.Status(401).JSON(fiber.Map{"error": "Unauthorized"})
	}
	var enabled bool
	var hasSecret sql.NullBool
	if err := h.db.QueryRow(c.Context(), `SELECT mfa_enabled, mfa_secret_encrypted IS NOT NULL FROM users WHERE id = $1`, uid).
		Scan(&enabled, &hasSecret); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to load MFA status"})
	}
	return c.JSON(fiber.Map{
		"enabled":    enabled,
		"has_secret": hasSecret.Valid && hasSecret.Bool,
	})
}

// BeginMFASetup godoc
// @Summary Begin MFA setup
// @Description Start MFA setup process and get QR code
// @Tags MFA
// @Security BearerAuth
// @Produce json
// @Success 200 {object} map[string]interface{} "Setup data with QR code"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 500 {object} map[string]interface{} "Server error"
// @Router /auth/mfa/begin [post]
func (h *AuthHandler) BeginMFASetup(c *fiber.Ctx) error {
	v := c.Locals("user_id")
	uid, ok := v.(uuid.UUID)
	if !ok {
		return c.Status(401).JSON(fiber.Map{"error": "Unauthorized"})
	}
	ctx := c.Context()
	var emailEnc []byte
	var emailHash []byte
	if err := h.db.QueryRow(ctx, `SELECT email_encrypted, email_hash FROM users WHERE id=$1`, uid).Scan(&emailEnc, &emailHash); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Unable to start MFA setup"})
	}

	// Get GDPR key to decrypt email for MFA setup
	var deletionKey []byte
	if err := h.db.QueryRow(ctx, `SELECT deletion_key FROM gdpr_keys WHERE email_hash = $1`, emailHash).Scan(&deletionKey); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Unable to start MFA setup"})
	}

	// Decrypt email for MFA setup
	emailBytes, err := h.crypto.DecryptWithGDPRKey(emailEnc, deletionKey)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Unable to start MFA setup"})
	}
	email := string(emailBytes)
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "LeafLock",
		AccountName: email,
		Period:      30,
		Digits:      otp.DigitsSix,
	})
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to generate MFA secret"})
	}
	secret := key.Secret()
	encryptedSecret, err := h.crypto.Encrypt([]byte(secret))
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to secure MFA secret"})
	}
	if _, err := h.db.Exec(ctx, `UPDATE users SET mfa_secret_encrypted = $1, mfa_enabled = FALSE WHERE id = $2`, encryptedSecret, uid); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to persist MFA secret"})
	}
	h.logAudit(ctx, uid, "mfa.setup_started", "user", uid, c)
	return c.JSON(fiber.Map{
		"secret":      secret,
		"otpauth_url": key.URL(),
		"issuer":      key.Issuer(),
		"account":     key.AccountName(),
	})
}

// EnableMFA godoc
// @Summary Enable MFA
// @Description Enable MFA after verifying TOTP code
// @Tags MFA
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body mfaCodeRequest true "TOTP code"
// @Success 200 {object} map[string]interface{} "MFA enabled with backup codes"
// @Failure 400 {object} map[string]interface{} "Invalid request"
// @Failure 401 {object} map[string]interface{} "Invalid code"
// @Failure 500 {object} map[string]interface{} "Server error"
// @Router /auth/mfa/enable [post]
func (h *AuthHandler) EnableMFA(c *fiber.Ctx) error {
	v := c.Locals("user_id")
	uid, ok := v.(uuid.UUID)
	if !ok {
		return c.Status(401).JSON(fiber.Map{"error": "Unauthorized"})
	}
	var req mfaCodeRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
	}
	code := strings.TrimSpace(req.Code)
	if code == "" {
		return c.Status(400).JSON(fiber.Map{"error": "MFA code required"})
	}
	ctx := c.Context()
	var secretEnc []byte
	if err := h.db.QueryRow(ctx, `SELECT mfa_secret_encrypted FROM users WHERE id = $1`, uid).Scan(&secretEnc); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "MFA secret not initialized"})
	}
	if len(secretEnc) == 0 {
		return c.Status(400).JSON(fiber.Map{"error": "MFA secret not initialized"})
	}
	secretBytes, err := h.crypto.Decrypt(secretEnc)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to access MFA secret"})
	}
	secret := strings.TrimSpace(string(secretBytes))
	if secret == "" {
		return c.Status(500).JSON(fiber.Map{"error": "MFA secret invalid"})
	}
	if !totp.Validate(code, secret) {
		h.logAudit(ctx, uid, "mfa.enable_failed", "user", uid, c)
		return c.Status(401).JSON(fiber.Map{"error": "Invalid MFA code"})
	}

	// Generate backup codes
	mfaService := &MFAService{}
	backupCodes, err := mfaService.GenerateBackupCodes(10)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to generate backup codes"})
	}

	// Hash backup codes before storage
	hashedCodes := make([][]byte, len(backupCodes))
	for i, code := range backupCodes {
		hashedCodes[i] = mfaService.HashBackupCode(code)
	}

	// Enable MFA and store backup codes
	if _, err := h.db.Exec(ctx, `
		UPDATE users
		SET mfa_enabled = TRUE, mfa_backup_codes = $1, mfa_backup_codes_used = NULL
		WHERE id = $2
	`, hashedCodes, uid); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to enable MFA"})
	}

	h.logAudit(ctx, uid, "mfa.enabled", "user", uid, c)

	return c.JSON(fiber.Map{
		"enabled":      true,
		"backup_codes": backupCodes,
		"message":      "MFA enabled successfully. Save these backup codes securely - they won't be shown again.",
	})
}

// DisableMFA godoc
// @Summary Disable MFA
// @Description Disable MFA after verifying TOTP code
// @Tags MFA
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body mfaCodeRequest true "TOTP code"
// @Success 200 {object} map[string]interface{} "MFA disabled"
// @Failure 400 {object} map[string]interface{} "Invalid request"
// @Failure 401 {object} map[string]interface{} "Invalid code"
// @Failure 500 {object} map[string]interface{} "Server error"
// @Router /auth/mfa/disable [post]
func (h *AuthHandler) DisableMFA(c *fiber.Ctx) error {
	v := c.Locals("user_id")
	uid, ok := v.(uuid.UUID)
	if !ok {
		return c.Status(401).JSON(fiber.Map{"error": "Unauthorized"})
	}
	var req mfaCodeRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
	}
	code := strings.TrimSpace(req.Code)
	if code == "" {
		return c.Status(400).JSON(fiber.Map{"error": "MFA code required"})
	}
	ctx := c.Context()
	var secretEnc []byte
	if err := h.db.QueryRow(ctx, `SELECT mfa_secret_encrypted FROM users WHERE id = $1`, uid).Scan(&secretEnc); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "MFA not enabled"})
	}
	if len(secretEnc) == 0 {
		return c.Status(400).JSON(fiber.Map{"error": "MFA not enabled"})
	}
	secretBytes, err := h.crypto.Decrypt(secretEnc)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to access MFA secret"})
	}
	secret := strings.TrimSpace(string(secretBytes))
	if secret == "" {
		return c.Status(500).JSON(fiber.Map{"error": "MFA secret invalid"})
	}
	if !totp.Validate(code, secret) {
		h.logAudit(ctx, uid, "mfa.disable_failed", "user", uid, c)
		return c.Status(401).JSON(fiber.Map{"error": "Invalid MFA code"})
	}
	if _, err := h.db.Exec(ctx, `UPDATE users SET mfa_enabled = FALSE, mfa_secret_encrypted = NULL, mfa_backup_codes = NULL, mfa_backup_codes_used = NULL WHERE id = $1`, uid); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to disable MFA"})
	}
	h.logAudit(ctx, uid, "mfa.disabled", "user", uid, c)
	return c.JSON(fiber.Map{"enabled": false})
}

// GetBackupCodes godoc
// @Summary Get backup codes status
// @Description Get backup codes count and remaining codes
// @Tags MFA
// @Security BearerAuth
// @Produce json
// @Success 200 {object} map[string]interface{} "Backup codes info"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 404 {object} map[string]interface{} "MFA not enabled"
// @Failure 500 {object} map[string]interface{} "Server error"
// @Router /auth/mfa/backup-codes [get]
func (h *AuthHandler) GetBackupCodes(c *fiber.Ctx) error {
	v := c.Locals("user_id")
	uid, ok := v.(uuid.UUID)
	if !ok {
		return c.Status(401).JSON(fiber.Map{"error": "Unauthorized"})
	}

	ctx := c.Context()
	var backupCodes [][]byte
	var backupCodesUsed [][]byte

	err := h.db.QueryRow(ctx, `
		SELECT mfa_backup_codes, mfa_backup_codes_used
		FROM users
		WHERE id = $1 AND mfa_enabled = true
	`, uid).Scan(&backupCodes, &backupCodesUsed)

	if err != nil {
		if err == sql.ErrNoRows {
			return c.Status(404).JSON(fiber.Map{"error": "MFA not enabled or no backup codes found"})
		}
		return c.Status(500).JSON(fiber.Map{"error": "Failed to retrieve backup codes"})
	}

	// Calculate remaining codes
	remaining := len(backupCodes)
	if backupCodesUsed != nil {
		remaining -= len(backupCodesUsed)
	}

	h.logAudit(ctx, uid, "mfa.backup_codes_viewed", "user", uid, c)

	return c.JSON(fiber.Map{
		"total":     len(backupCodes),
		"remaining": remaining,
		"note":      "Backup codes are stored securely and cannot be retrieved in plaintext",
	})
}

// RegenerateBackupCodes godoc
// @Summary Regenerate backup codes
// @Description Generate new backup codes after password verification
// @Tags MFA
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body object{password=string} true "User password"
// @Success 200 {object} map[string]interface{} "New backup codes"
// @Failure 400 {object} map[string]interface{} "Invalid request or MFA not enabled"
// @Failure 401 {object} map[string]interface{} "Invalid password"
// @Failure 500 {object} map[string]interface{} "Server error"
// @Router /auth/mfa/backup-codes/regenerate [post]
func (h *AuthHandler) RegenerateBackupCodes(c *fiber.Ctx) error {
	v := c.Locals("user_id")
	uid, ok := v.(uuid.UUID)
	if !ok {
		return c.Status(401).JSON(fiber.Map{"error": "Unauthorized"})
	}

	var req struct {
		Password string `json:"password" validate:"required"`
	}

	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
	}

	ctx := c.Context()

	// Verify password before regenerating codes
	var passwordHash string
	var mfaEnabled bool
	err := h.db.QueryRow(ctx, `
		SELECT password_hash, mfa_enabled
		FROM users
		WHERE id = $1
	`, uid).Scan(&passwordHash, &mfaEnabled)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to verify user"})
	}

	if !mfaEnabled {
		return c.Status(400).JSON(fiber.Map{"error": "MFA is not enabled"})
	}

	if !crypto.VerifyPassword(req.Password, passwordHash) {
		h.logAudit(ctx, uid, "mfa.backup_codes_regen_failed", "user", uid, c)
		return c.Status(401).JSON(fiber.Map{"error": "Invalid password"})
	}

	// Generate new backup codes using MFA service
	mfaService := &MFAService{}
	codes, err := mfaService.GenerateBackupCodes(10)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to generate backup codes"})
	}

	// Hash the backup codes before storage
	hashedCodes := make([][]byte, len(codes))
	for i, code := range codes {
		hashedCodes[i] = mfaService.HashBackupCode(code)
	}

	// Update database with new backup codes and clear used codes
	_, err = h.db.Exec(ctx, `
		UPDATE users
		SET mfa_backup_codes = $1, mfa_backup_codes_used = NULL
		WHERE id = $2
	`, hashedCodes, uid)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to save backup codes"})
	}

	h.logAudit(ctx, uid, "mfa.backup_codes_regenerated", "user", uid, c)

	return c.JSON(fiber.Map{
		"codes":   codes,
		"message": "New backup codes generated. Save these securely - they won't be shown again.",
	})
}

// VerifyMFACode godoc
// @Summary Verify MFA code
// @Description Verify TOTP or backup code during login
// @Tags MFA
// @Accept json
// @Produce json
// @Param request body object{session_token=string,code=string,is_backup_code=bool} true "Verification data"
// @Success 200 {object} map[string]interface{} "Login successful with JWT token"
// @Failure 400 {object} map[string]interface{} "Invalid request"
// @Failure 401 {object} map[string]interface{} "Invalid code or session"
// @Failure 500 {object} map[string]interface{} "Server error"
// @Router /auth/mfa/verify [post]
func (h *AuthHandler) VerifyMFACode(c *fiber.Ctx) error {
	var req struct {
		SessionToken string `json:"session_token" validate:"required"`
		Code         string `json:"code" validate:"required"`
		IsBackupCode bool   `json:"is_backup_code"`
	}

	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
	}

	ctx := c.Context()

	// Retrieve session token data from Redis
	sessionKey := fmt.Sprintf("mfa_session:%s", req.SessionToken)
	sessionData, err := h.redis.Get(ctx, sessionKey).Result()
	if err != nil {
		return c.Status(401).JSON(fiber.Map{"error": "Invalid or expired session token"})
	}

	// Parse session data to get user ID
	var userID uuid.UUID
	if err := userID.UnmarshalText([]byte(sessionData)); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Invalid session data"})
	}

	code := strings.TrimSpace(req.Code)
	if code == "" {
		return c.Status(400).JSON(fiber.Map{"error": "Code required"})
	}

	// Verify the code (TOTP or backup code)
	var verified bool
	var isBackupCodeUsed bool

	if req.IsBackupCode {
		// Verify backup code
		var backupCodes [][]byte
		var backupCodesUsed [][]byte

		err := h.db.QueryRow(ctx, `
			SELECT mfa_backup_codes, mfa_backup_codes_used
			FROM users
			WHERE id = $1
		`, userID).Scan(&backupCodes, &backupCodesUsed)

		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "Failed to verify backup code"})
		}

		mfaService := &MFAService{}
		isValid, codeIndex := mfaService.VerifyBackupCode(code, backupCodes)

		if !isValid {
			h.logAudit(ctx, userID, "mfa.backup_code_failed", "user", userID, c)
			return c.Status(401).JSON(fiber.Map{"error": "Invalid backup code"})
		}

		// Check if backup code was already used
		for _, usedHash := range backupCodesUsed {
			if bytes.Equal(usedHash, backupCodes[codeIndex]) {
				h.logAudit(ctx, userID, "mfa.backup_code_reuse_attempt", "user", userID, c)
				return c.Status(401).JSON(fiber.Map{"error": "This backup code has already been used"})
			}
		}

		// Mark backup code as used
		backupCodesUsed = append(backupCodesUsed, backupCodes[codeIndex])
		_, err = h.db.Exec(ctx, `
			UPDATE users
			SET mfa_backup_codes_used = $1
			WHERE id = $2
		`, backupCodesUsed, userID)

		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "Failed to mark backup code as used"})
		}

		verified = true
		isBackupCodeUsed = true
		h.logAudit(ctx, userID, "mfa.backup_code_used", "user", userID, c)

	} else {
		// Verify TOTP code
		var secretEnc []byte
		err := h.db.QueryRow(ctx, `SELECT mfa_secret_encrypted FROM users WHERE id = $1`, userID).Scan(&secretEnc)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "Failed to verify MFA code"})
		}

		secretBytes, err := h.crypto.Decrypt(secretEnc)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "Failed to access MFA secret"})
		}

		secret := strings.TrimSpace(string(secretBytes))
		if !totp.Validate(code, secret) {
			h.logAudit(ctx, userID, "mfa.verification_failed", "user", userID, c)
			return c.Status(401).JSON(fiber.Map{"error": "Invalid MFA code"})
		}

		verified = true
		h.logAudit(ctx, userID, "mfa.verification_success", "user", userID, c)
	}

	if !verified {
		return c.Status(401).JSON(fiber.Map{"error": "Verification failed"})
	}

	// Delete the temporary MFA session from Redis
	h.redis.Del(ctx, sessionKey)

	// Generate final JWT token
	token, err := h.generateToken(userID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Token generation failed"})
	}

	// Get workspace
	var workspaceID uuid.UUID
	_ = h.db.QueryRow(ctx, `SELECT id FROM workspaces WHERE owner_id = $1 LIMIT 1`, userID).Scan(&workspaceID)

	return c.JSON(fiber.Map{
		"token":        token,
		"user_id":      userID,
		"workspace_id": workspaceID,
		"backup_code_used": isBackupCodeUsed,
	})
}

// MFAService embedded for backup code operations
type MFAService struct{}

func (s *MFAService) GenerateBackupCodes(count int) ([]string, error) {
	if count <= 0 || count > 20 {
		return nil, fmt.Errorf("invalid backup code count: %d", count)
	}

	codes := make([]string, count)
	for i := 0; i < count; i++ {
		randomBytes := make([]byte, 10)
		if _, err := rand.Read(randomBytes); err != nil {
			return nil, err
		}

		encoded := hex.EncodeToString(randomBytes)
		code := strings.ToUpper(encoded[:16])
		codes[i] = fmt.Sprintf("%s-%s-%s-%s", code[0:4], code[4:8], code[8:12], code[12:16])
	}

	return codes, nil
}

func (s *MFAService) HashBackupCode(code string) []byte {
	normalized := strings.ToUpper(strings.ReplaceAll(code, "-", ""))
	salt := sha256.Sum256([]byte("leaflock_backup_code_salt_v1"))
	return argon2.IDKey([]byte(normalized), salt[:], 3, 64*1024, 4, 32)
}

func (s *MFAService) VerifyBackupCode(code string, hashedCodes [][]byte) (bool, int) {
	if len(hashedCodes) == 0 {
		return false, -1
	}

	inputHash := s.HashBackupCode(code)

	for i, storedHash := range hashedCodes {
		if len(storedHash) != len(inputHash) {
			continue
		}

		match := true
		for j := range storedHash {
			if storedHash[j] != inputHash[j] {
				match = false
			}
		}

		if match {
			return true, i
		}
	}

	return false, -1
}

func (h *AuthHandler) generateToken(userID uuid.UUID) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID.String(),
		"exp":     time.Now().Add(24 * time.Hour).Unix(),
		"iat":     time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	return token.SignedString(h.config.JWTSecret)
}

func (h *AuthHandler) logAudit(ctx context.Context, userID uuid.UUID, action, resourceType string, resourceID uuid.UUID, c *fiber.Ctx) {
	encryptedIP, err := h.crypto.Encrypt([]byte(utils.ClientIP(c)))
	if err != nil {
		log.Printf("failed to encrypt audit log IP: %v", err)
		encryptedIP = nil
	}
	encryptedUA, err := h.crypto.Encrypt([]byte(c.Get("User-Agent")))
	if err != nil {
		log.Printf("failed to encrypt audit log user agent: %v", err)
		encryptedUA = nil
	}

	if _, err := h.db.Exec(ctx, `
        INSERT INTO audit_log (user_id, action, resource_type, resource_id, ip_address_encrypted, user_agent_encrypted)
        VALUES ($1, $2, $3, $4, $5, $6)`,
		userID, action, resourceType, resourceID, encryptedIP, encryptedUA,
	); err != nil {
		log.Printf("failed to write audit log entry: %v", err)
	}
}
