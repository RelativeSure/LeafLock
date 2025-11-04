package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	appcrypto "leaflock/crypto"
	"leaflock/database"
	"leaflock/utils"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

var ErrEmailAlreadyExists = errors.New("email already exists")

type registerOptionKey string

const skipAutoLoginKey registerOptionKey = "skip_auto_login"

func WithSkipAutoLogin(ctx context.Context) context.Context {
	return context.WithValue(ctx, skipAutoLoginKey, true)
}

func shouldSkipAutoLogin(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	value, _ := ctx.Value(skipAutoLoginKey).(bool)
	return value
}

// Service coordinates all auth operations
type Service struct {
	db        database.Database
	// crypto removed - zero-knowledge architecture (no server-wide encryption key)
	session   sessionManager
	password  *PasswordManager
	mfa       *MFAManager
	jwtSecret string
}

type sessionManager interface {
	CreateSession(ctx context.Context, userID uuid.UUID, ipAddress, userAgent string, mfaVerified bool) (*Session, string, error)
	CreateMFASession(ctx context.Context, userID uuid.UUID, email, ipAddress, userAgent string, mfaEnabled bool) (string, error)
	GetMFASession(ctx context.Context, token string) (*MFASession, error)
	DeleteMFASession(ctx context.Context, token string) error
	DeleteSession(ctx context.Context, token string) error
	BlacklistJWT(ctx context.Context, token string, expiresAt time.Time) error
	IsJWTBlacklisted(ctx context.Context, token string) (bool, error)
}

const defaultEncryptionVersion = 1

// NewService creates a new auth service
// Zero-knowledge: MFA & session encryption derived from JWT secret (system-level)
func NewService(db database.Database, rdb *redis.Client, jwtSecret string) *Service {
	// Derive MFA encryption key from JWT secret (deterministic, per-deployment)
	mfaKey := sha256.Sum256(append([]byte(jwtSecret), []byte("-mfa-encryption")...))
	mfaCrypto := appcrypto.NewCryptoService(mfaKey[:])

	// Derive session encryption key from JWT secret (deterministic, per-deployment)
	sessionKey := sha256.Sum256(append([]byte(jwtSecret), []byte("-session-encryption")...))
	sessionCrypto := appcrypto.NewCryptoService(sessionKey[:])

	return &Service{
		db:        db,
		session:   NewSessionManager(rdb, sessionCrypto),
		password:  NewPasswordManager(db),
		mfa:       NewMFAManager(db, mfaCrypto),
		jwtSecret: jwtSecret,
	}
}

// Register registers a new user
func (s *Service) Register(ctx context.Context, email, password string) (*AuthResponse, error) {
	// Validate password strength
	if err := s.password.ValidatePasswordStrength(password); err != nil {
		return nil, err
	}

	// Generate salt
	salt, err := s.password.GenerateSalt()
	if err != nil {
		return nil, err
	}

	// Hash password
	passwordHash := s.password.HashPassword(password, salt)

	// Generate master key (32 bytes)
	masterKey := make([]byte, 32)
	if _, err := rand.Read(masterKey); err != nil {
		return nil, fmt.Errorf("failed to generate master key: %w", err)
	}

	// Derive key from password for encrypting master key
	derivedKey := s.password.DeriveKeyBytes(password, salt) // Get raw key bytes
	tempCrypto := appcrypto.NewCryptoService(derivedKey)
	masterKeyEncrypted, err := tempCrypto.EncryptBytes(masterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt master key: %w", err)
	}

	// Create email hashes
	emailBytes := []byte(strings.ToLower(strings.TrimSpace(email)))
	emailHash := sha256.Sum256(emailBytes)

	// Zero-knowledge: Store email in plaintext (needed for password reset, notifications)
	// Sensitive user content (notes) remains encrypted with password-derived keys

	// Create deterministic search hash for login
	searchHash := sha256.Sum256(append(emailBytes, []byte("search-salt")...))

	// Begin transaction
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	// Insert user
	userID := uuid.New()
	insertUserQuery := `
		INSERT INTO users (
			id, email_hash, email_plaintext, email_search_hash,
			password_hash, salt, master_key_encrypted,
			created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW())
		RETURNING id
	`

	err = tx.QueryRow(ctx, insertUserQuery,
		userID, emailHash[:], email, searchHash[:],
		passwordHash, salt, masterKeyEncrypted,
	).Scan(&userID)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate") || strings.Contains(err.Error(), "unique") {
			return nil, ErrEmailAlreadyExists
		}
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Create GDPR deletion key
	deletionKey := make([]byte, 32)
	if _, err := rand.Read(deletionKey); err != nil {
		return nil, fmt.Errorf("failed to generate deletion key: %w", err)
	}

	insertGDPRQuery := `
		INSERT INTO gdpr_keys (email_hash, deletion_key)
		VALUES ($1, $2)
	`
	_, err = tx.Exec(ctx, insertGDPRQuery, emailHash[:], deletionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create GDPR key: %w", err)
	}

	// Create default workspace
	workspaceID := uuid.New()
	workspaceKey := make([]byte, 32)
	if _, err := rand.Read(workspaceKey); err != nil {
		return nil, fmt.Errorf("failed to generate workspace key: %w", err)
	}

	// Encrypt workspace key with master key
	workspaceCrypto := appcrypto.NewCryptoService(masterKey)
	workspaceKeyEncrypted, err := workspaceCrypto.EncryptBytes(workspaceKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt workspace key: %w", err)
	}

	// Encrypt workspace name
	workspaceName := []byte("My Workspace")
	workspaceNameEncrypted, err := workspaceCrypto.EncryptBytes(workspaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt workspace name: %w", err)
	}

	insertWorkspaceQuery := `
		INSERT INTO workspaces (id, name_encrypted, owner_id, encryption_key_encrypted)
		VALUES ($1, $2, $3, $4)
	`
	_, err = tx.Exec(ctx, insertWorkspaceQuery, workspaceID, workspaceNameEncrypted, userID, workspaceKeyEncrypted)
	if err != nil {
		return nil, fmt.Errorf("failed to create workspace: %w", err)
	}

	// Assign user role
	assignRoleQuery := `
		INSERT INTO user_roles (user_id, role_id)
		SELECT $1, id FROM roles WHERE name = 'user'
	`
	_, err = tx.Exec(ctx, assignRoleQuery, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to assign role: %w", err)
	}

	// Commit transaction
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	// Log successful registration
	s.auditLog(ctx, userID, "user_registered", map[string]interface{}{
		"email":        email,
		"workspace_id": workspaceID.String(),
	})

	if shouldSkipAutoLogin(ctx) {
		return &AuthResponse{
			UserID:            userID.String(),
			WorkspaceID:       workspaceID.String(),
			IsAdmin:           false,
			EncryptionSalt:    base64.StdEncoding.EncodeToString(salt),
			EncryptionVersion: defaultEncryptionVersion,
		}, nil
	}

	// Create session and generate JWT
	ipAddress := utils.GetClientIPFromContext(ctx)
	userAgent := utils.GetUserAgentFromContext(ctx)

	session, _, err := s.session.CreateSession(ctx, userID, ipAddress, userAgent, false)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	jwtToken, err := s.GenerateJWT(userID, false)
	if err != nil {
		return nil, fmt.Errorf("failed to generate JWT: %w", err)
	}

	return &AuthResponse{
		Token:       jwtToken,
		UserID:      userID.String(),
		WorkspaceID: workspaceID.String(),
		IsAdmin:     false,
		ExpiresAt:   session.ExpiresAt,
		EncryptionSalt: func() string {
			if len(salt) == 0 {
				return ""
			}
			return base64.StdEncoding.EncodeToString(salt)
		}(),
		EncryptionVersion: defaultEncryptionVersion,
	}, nil
}

// Login authenticates a user
func (s *Service) Login(ctx context.Context, email, password, mfaCode string) (*AuthResponse, error) {
	// Create deterministic search hash
	emailBytes := []byte(strings.ToLower(strings.TrimSpace(email)))
	searchHash := sha256.Sum256(append(emailBytes, []byte("search-salt")...))

	// Look up user
	query := `
		SELECT id, password_hash, salt, mfa_enabled, mfa_secret_encrypted,
		       failed_attempts, locked_until, is_admin
		FROM users
		WHERE email_search_hash = $1 AND deleted_at IS NULL
	`

	var userID uuid.UUID
	var passwordHash string
	var salt []byte
	var mfaEnabled bool
	var mfaSecretEncrypted []byte
	var failedAttempts int
	var lockedUntil *time.Time
	var isAdmin bool

	err := s.db.QueryRow(ctx, query, searchHash[:]).Scan(
		&userID, &passwordHash, &salt, &mfaEnabled, &mfaSecretEncrypted,
		&failedAttempts, &lockedUntil, &isAdmin,
	)
	if err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	// Check account lock
	if lockedUntil != nil && time.Now().UTC().Before(*lockedUntil) {
		return nil, fmt.Errorf("account locked until %s", lockedUntil.Format(time.RFC3339))
	}

	// Verify password
	if !s.password.VerifyPassword(password, passwordHash, salt) {
		// Increment failed attempts
		s.incrementFailedAttempts(ctx, userID, failedAttempts)

		// Log failed login attempt
		s.auditLog(ctx, userID, "login_failed", map[string]interface{}{
			"reason":   "invalid_password",
			"attempts": failedAttempts + 1,
		})

		return nil, fmt.Errorf("invalid credentials")
	}

	// Reset failed attempts on successful password verification
	s.resetFailedAttempts(ctx, userID)

	// Check if MFA is enabled
	if mfaEnabled {
		// If MFA code provided, verify it
		if mfaCode != "" {
			// Decrypt MFA secret
			secretBytes, err := s.crypto.DecryptBytes(mfaSecretEncrypted)
			if err != nil {
				return nil, fmt.Errorf("failed to decrypt MFA secret: %w", err)
			}

			// Verify TOTP code
			valid := s.mfa.VerifyTOTP(string(secretBytes), mfaCode)
			if !valid {
				// Try as backup code
				valid, err := s.mfa.VerifyBackupCode(ctx, userID, mfaCode)
				if err != nil || !valid {
					return nil, fmt.Errorf("invalid MFA code")
				}
			}

			// MFA verified, create full session
			return s.createAuthResponse(ctx, userID, isAdmin, true)
		}

		// MFA required but code not provided, create MFA session
		ipAddress := utils.GetClientIPFromContext(ctx)
		userAgent := utils.GetUserAgentFromContext(ctx)

		sessionToken, err := s.session.CreateMFASession(ctx, userID, email, ipAddress, userAgent, true)
		if err != nil {
			return nil, fmt.Errorf("failed to create MFA session: %w", err)
		}

		saltEncoded := base64.StdEncoding.EncodeToString(salt)
		return &AuthResponse{
			MFARequired:       true,
			SessionToken:      sessionToken,
			UserID:            userID.String(),
			EncryptionSalt:    saltEncoded,
			EncryptionVersion: defaultEncryptionVersion,
		}, nil
	}

	// No MFA, create full session
	response, err := s.createAuthResponse(ctx, userID, isAdmin, false)
	if err != nil {
		return nil, err
	}

	// Log successful login
	s.auditLog(ctx, userID, "login_success", map[string]interface{}{
		"mfa_required": false,
		"is_admin":     isAdmin,
	})

	return response, nil
}

// VerifyMFA verifies an MFA code during login
func (s *Service) VerifyMFA(ctx context.Context, sessionToken, code string) (*AuthResponse, error) {
	// Get MFA session
	mfaSession, err := s.session.GetMFASession(ctx, sessionToken)
	if err != nil {
		return nil, fmt.Errorf("invalid or expired MFA session")
	}

	// Get user's MFA secret
	var mfaSecretEncrypted []byte
	var isAdmin bool
	query := `
		SELECT mfa_secret_encrypted, is_admin
		FROM users
		WHERE id = $1 AND mfa_enabled = true
	`

	err = s.db.QueryRow(ctx, query, mfaSession.UserID).Scan(&mfaSecretEncrypted, &isAdmin)
	if err != nil {
		return nil, fmt.Errorf("MFA not enabled")
	}

	// Decrypt secret
	secretBytes, err := s.crypto.DecryptBytes(mfaSecretEncrypted)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt MFA secret: %w", err)
	}

	// Verify code
	valid := s.mfa.VerifyTOTP(string(secretBytes), code)
	if !valid {
		// Try as backup code
		valid, err := s.mfa.VerifyBackupCode(ctx, mfaSession.UserID, code)
		if err != nil || !valid {
			return nil, fmt.Errorf("invalid MFA code")
		}
	}

	// Delete MFA session
	_ = s.session.DeleteMFASession(ctx, sessionToken)

	// Create full session
	response, err := s.createAuthResponse(ctx, mfaSession.UserID, isAdmin, true)
	if err != nil {
		return nil, err
	}

	// Log successful MFA verification
	s.auditLog(ctx, mfaSession.UserID, "mfa_verified", map[string]interface{}{
		"is_admin": isAdmin,
	})

	return response, nil
}

// Logout logs out a user
func (s *Service) Logout(ctx context.Context, token string) error {
	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.jwtSecret), nil
	})

	var expiresAt time.Time

	if err == nil && parsedToken.Valid {
		if claims, ok := parsedToken.Claims.(jwt.MapClaims); ok {
			if expValue, ok := claims["exp"]; ok {
				switch v := expValue.(type) {
				case float64:
					expiresAt = time.Unix(int64(v), 0)
				case json.Number:
					if parsed, parseErr := v.Int64(); parseErr == nil {
						expiresAt = time.Unix(parsed, 0)
					}
				case int64:
					expiresAt = time.Unix(v, 0)
				case int:
					expiresAt = time.Unix(int64(v), 0)
				}
			}
		}
	}

	if !expiresAt.IsZero() {
		if err := s.session.BlacklistJWT(ctx, token, expiresAt); err != nil {
			return fmt.Errorf("failed to revoke token: %w", err)
		}
	}

	if err := s.session.DeleteSession(ctx, token); err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}

	return nil
}

// GenerateJWT generates a JWT token
func (s *Service) GenerateJWT(userID uuid.UUID, isAdmin bool) (string, error) {
	claims := jwt.MapClaims{
		"user_id":  userID.String(),
		"is_admin": isAdmin,
		"exp":      time.Now().UTC().Add(SessionDuration).Unix(),
		"iat":      time.Now().UTC().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(s.jwtSecret))
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT: %w", err)
	}

	return signedToken, nil
}

// ValidateJWT validates a JWT token and returns the user ID
func (s *Service) ValidateJWT(tokenString string) (uuid.UUID, bool, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.jwtSecret), nil
	})

	if err != nil {
		return uuid.Nil, false, fmt.Errorf("invalid token: %w", err)
	}

	if !token.Valid {
		return uuid.Nil, false, fmt.Errorf("token is not valid")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return uuid.Nil, false, fmt.Errorf("invalid token claims")
	}

	userIDStr, ok := claims["user_id"].(string)
	if !ok {
		return uuid.Nil, false, fmt.Errorf("user_id not found in token")
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return uuid.Nil, false, fmt.Errorf("invalid user_id format")
	}

	isAdmin, _ := claims["is_admin"].(bool)

	return userID, isAdmin, nil
}

// Helper functions

func (s *Service) createAuthResponse(ctx context.Context, userID uuid.UUID, isAdmin, mfaVerified bool) (*AuthResponse, error) {
	// Get workspace ID
	var workspaceID uuid.UUID
	workspaceQuery := `
		SELECT id FROM workspaces WHERE owner_id = $1 LIMIT 1
	`
	err := s.db.QueryRow(ctx, workspaceQuery, userID).Scan(&workspaceID)
	if err != nil {
		workspaceID = uuid.Nil // No workspace found
	}

	// Update last login
	updateQuery := `
		UPDATE users SET last_login = NOW() WHERE id = $1
	`
	_, _ = s.db.Exec(ctx, updateQuery, userID)

	// Create session
	ipAddress := utils.GetClientIPFromContext(ctx)
	userAgent := utils.GetUserAgentFromContext(ctx)

	session, sessionToken, err := s.session.CreateSession(ctx, userID, ipAddress, userAgent, mfaVerified)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	// Generate JWT
	jwtToken, err := s.GenerateJWT(userID, isAdmin)
	if err != nil {
		return nil, fmt.Errorf("failed to generate JWT: %w", err)
	}

	response := &AuthResponse{
		Token:     jwtToken,
		UserID:    userID.String(),
		IsAdmin:   isAdmin,
		ExpiresAt: session.ExpiresAt,
	}

	if workspaceID != uuid.Nil {
		response.WorkspaceID = workspaceID.String()
	}

	// Store token in session for logout
	_ = sessionToken // Session token is managed internally

	var saltBytes []byte
	if err := s.db.QueryRow(ctx, `SELECT salt FROM users WHERE id = $1`, userID).Scan(&saltBytes); err == nil {
		response.EncryptionSalt = base64.StdEncoding.EncodeToString(saltBytes)
		response.EncryptionVersion = defaultEncryptionVersion
	}

	return response, nil
}

func (s *Service) incrementFailedAttempts(ctx context.Context, userID uuid.UUID, currentAttempts int) {
	newAttempts := currentAttempts + 1
	var lockedUntil *time.Time

	// Lock account after 5 failed attempts (15 minutes)
	if newAttempts >= 5 {
		lockTime := time.Now().UTC().Add(15 * time.Minute)
		lockedUntil = &lockTime
	}

	query := `
		UPDATE users
		SET failed_attempts = $1, locked_until = $2
		WHERE id = $3
	`
	_, _ = s.db.Exec(ctx, query, newAttempts, lockedUntil, userID)
}

func (s *Service) resetFailedAttempts(ctx context.Context, userID uuid.UUID) {
	query := `
		UPDATE users
		SET failed_attempts = 0, locked_until = NULL
		WHERE id = $1
	`
	_, _ = s.db.Exec(ctx, query, userID)
}

// EnsureDefaultAdmin creates a default admin user if no users exist and admin creation is enabled
func (s *Service) EnsureDefaultAdmin(ctx context.Context, enabled bool, email, password string) error {
	if !enabled {
		return nil // Admin creation disabled
	}

	// Check if default admin already exists (by email search hash)
	// IMPORTANT: Check for THIS specific admin email, not just if any users exist
	emailBytes := []byte(strings.ToLower(strings.TrimSpace(email)))
	searchHash := sha256.Sum256(append(emailBytes, []byte("search-salt")...))

	var adminExists bool
	query := `SELECT EXISTS(SELECT 1 FROM users WHERE email_search_hash = $1 AND deleted_at IS NULL)`
	err := s.db.QueryRow(ctx, query, searchHash[:]).Scan(&adminExists)
	if err != nil {
		return fmt.Errorf("failed to check admin existence: %w", err)
	}

	if adminExists {
		log.Printf("✓ Default admin user already exists: %s", email)
		return nil
	}

	log.Printf("Creating default admin user: %s", email)

	// Validate password strength
	if err := s.password.ValidatePasswordStrength(password); err != nil {
		return fmt.Errorf("admin password validation failed: %w", err)
	}

	// Generate salt
	salt, err := s.password.GenerateSalt()
	if err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	// Hash password
	passwordHash := s.password.HashPassword(password, salt)

	// Generate master key (32 bytes)
	masterKey := make([]byte, 32)
	if _, err := rand.Read(masterKey); err != nil {
		return fmt.Errorf("failed to generate master key: %w", err)
	}

	// Derive key from password for encrypting master key
	derivedKey := s.password.DeriveKeyBytes(password, salt)
	tempCrypto := appcrypto.NewCryptoService(derivedKey)
	masterKeyEncrypted, err := tempCrypto.EncryptBytes(masterKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt master key: %w", err)
	}

	// Create email hash (emailBytes and searchHash already declared above for admin existence check)
	emailHash := sha256.Sum256(emailBytes)

	// Zero-knowledge: Store email in plaintext (needed for operational use)
	// searchHash already computed above for admin existence check

	// Begin transaction
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	// Insert admin user
	userID := uuid.New()
	insertUserQuery := `
		INSERT INTO users (
			id, email_hash, email_plaintext, email_search_hash,
			password_hash, salt, master_key_encrypted,
			is_admin, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())
		RETURNING id
	`

	err = tx.QueryRow(ctx, insertUserQuery,
		userID, emailHash[:], email, searchHash[:],
		passwordHash, salt, masterKeyEncrypted, true,
	).Scan(&userID)
	if err != nil {
		return fmt.Errorf("failed to create admin user: %w", err)
	}

	// Create GDPR deletion key
	deletionKey := make([]byte, 32)
	if _, err := rand.Read(deletionKey); err != nil {
		return fmt.Errorf("failed to generate deletion key: %w", err)
	}

	insertGDPRQuery := `
		INSERT INTO gdpr_keys (email_hash, deletion_key)
		VALUES ($1, $2)
	`
	_, err = tx.Exec(ctx, insertGDPRQuery, emailHash[:], deletionKey)
	if err != nil {
		return fmt.Errorf("failed to create GDPR key: %w", err)
	}

	// Create default workspace
	workspaceID := uuid.New()
	workspaceKey := make([]byte, 32)
	if _, err := rand.Read(workspaceKey); err != nil {
		return fmt.Errorf("failed to generate workspace key: %w", err)
	}

	// Encrypt workspace key with master key
	workspaceCrypto := appcrypto.NewCryptoService(masterKey)
	workspaceKeyEncrypted, err := workspaceCrypto.EncryptBytes(workspaceKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt workspace key: %w", err)
	}

	// Encrypt workspace name
	workspaceName := []byte("Admin Workspace")
	workspaceNameEncrypted, err := workspaceCrypto.EncryptBytes(workspaceName)
	if err != nil {
		return fmt.Errorf("failed to encrypt workspace name: %w", err)
	}

	insertWorkspaceQuery := `
		INSERT INTO workspaces (id, name_encrypted, owner_id, encryption_key_encrypted)
		VALUES ($1, $2, $3, $4)
	`
	_, err = tx.Exec(ctx, insertWorkspaceQuery, workspaceID, workspaceNameEncrypted, userID, workspaceKeyEncrypted)
	if err != nil {
		return fmt.Errorf("failed to create workspace: %w", err)
	}

	// Assign both user and admin roles
	assignRolesQuery := `
		INSERT INTO user_roles (user_id, role_id)
		SELECT $1, id FROM roles WHERE name IN ('user', 'admin')
	`
	_, err = tx.Exec(ctx, assignRolesQuery, userID)
	if err != nil {
		return fmt.Errorf("failed to assign roles: %w", err)
	}

	// Commit transaction
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// auditLog logs an audit event for security tracking
func (s *Service) auditLog(ctx context.Context, userID uuid.UUID, action string, metadata map[string]interface{}) {
	// Get client info from context
	ipAddress := utils.GetClientIPFromContext(ctx)
	userAgent := utils.GetUserAgentFromContext(ctx)

	// Zero-knowledge: Hash IP and User-Agent for privacy
	var ipHash, uaHash []byte
	if ipAddress != "" {
		hash := sha256.Sum256([]byte(ipAddress))
		ipHash = hash[:]
	}
	if userAgent != "" {
		hash := sha256.Sum256([]byte(userAgent))
		uaHash = hash[:]
	}

	// Insert audit log (metadata as plaintext JSONB)
	query := `
		INSERT INTO audit_log (user_id, action, resource_type, ip_address_hash, user_agent_hash, metadata)
		VALUES ($1, $2, $3, $4, $5, $6)
	`
	_, _ = s.db.Exec(ctx, query, userID, action, "auth", ipHash, uaHash, metadata)
}
