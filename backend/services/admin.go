package services

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/argon2"
)

// AdminUserStatus represents the state of an admin user
type AdminUserStatus int

const (
	AdminUserNotExists AdminUserStatus = iota // Admin user doesn't exist
	AdminUserIncomplete                       // Admin user exists but missing workspace/role
	AdminUserComplete                         // Admin user exists with all requirements
)

// AdminUserInfo holds information about an existing admin user
type AdminUserInfo struct {
	Status      AdminUserStatus
	UserID      uuid.UUID
	MasterKey   []byte
	HasWorkspace bool
	HasRole     bool
}

// AdminConfig holds configuration for default admin user creation
type AdminConfig struct {
	Enabled  bool
	Email    string
	Password string
}

// CryptoService interface for encryption operations
type CryptoService interface {
	EncryptDeterministic(data []byte, context string) (string, error)
	HashEmail(email string) string
	EncryptWithGDPRKey(data []byte, gdprKey []byte) (string, error)
}

// Database interface for database operations
type Database interface {
	QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row
	Exec(ctx context.Context, sql string, arguments ...interface{}) (pgconn.CommandTag, error)
	Begin(ctx context.Context) (pgx.Tx, error)
}

// AdminService handles admin user operations
type AdminService struct {
	db     Database
	crypto CryptoService
	config AdminConfig
}

// NewAdminService creates a new admin service
func NewAdminService(db Database, crypto CryptoService) *AdminService {
	config := AdminConfig{
		Enabled:  getEnvBool("ENABLE_DEFAULT_ADMIN", true),
		Email:    getEnvString("DEFAULT_ADMIN_EMAIL", "admin@leaflock.app"),
		Password: getEnvString("DEFAULT_ADMIN_PASSWORD", "AdminPass123!"),
	}

	return &AdminService{
		db:     db,
		crypto: crypto,
		config: config,
	}
}

// ValidateAdminConfig validates the admin configuration
func (a *AdminService) ValidateAdminConfig() error {
	if !a.config.Enabled {
		return nil
	}

	if a.config.Email == "" {
		return errors.New("admin email cannot be empty")
	}

	if !isValidEmail(a.config.Email) {
		return fmt.Errorf("invalid admin email format: %s", a.config.Email)
	}

	if err := a.validatePassword(a.config.Password); err != nil {
		return fmt.Errorf("admin password validation failed: %w", err)
	}

	return nil
}

// validatePassword ensures the password meets security requirements
func (a *AdminService) validatePassword(password string) error {
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters long")
	}

	if len(password) > 128 {
		return errors.New("password must be less than 128 characters long")
	}

	// Check for at least one uppercase, one lowercase, one digit, and one special char
	hasUpper := regexp.MustCompile(`[A-Z]`).MatchString(password)
	hasLower := regexp.MustCompile(`[a-z]`).MatchString(password)
	hasDigit := regexp.MustCompile(`[0-9]`).MatchString(password)
	hasSpecial := regexp.MustCompile(`[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\?]`).MatchString(password)

	if !hasUpper {
		return errors.New("password must contain at least one uppercase letter")
	}
	if !hasLower {
		return errors.New("password must contain at least one lowercase letter")
	}
	if !hasDigit {
		return errors.New("password must contain at least one digit")
	}
	if !hasSpecial {
		return errors.New("password must contain at least one special character")
	}

	return nil
}

// CreateDefaultAdminUser creates the default admin user if enabled
func (a *AdminService) CreateDefaultAdminUser() error {
	if !a.config.Enabled {
		log.Println("⏭️ Default admin user creation is disabled")
		return nil
	}

	log.Printf("🔧 Starting default admin user creation process...")
	log.Printf("   - Email: %s", a.config.Email)
	log.Printf("   - Password length: %d characters", len(a.config.Password))
	log.Printf("   - Password starts with: %c", a.config.Password[0])
	log.Printf("   - Password ends with: %c", a.config.Password[len(a.config.Password)-1])

	// Validate configuration
	if err := a.ValidateAdminConfig(); err != nil {
		log.Printf("❌ Admin configuration validation failed: %v", err)
		return fmt.Errorf("admin configuration invalid: %w", err)
	}

	// Check admin user status
	adminInfo, err := a.checkAdminUserStatus()
	if err != nil {
		log.Printf("❌ Failed to check admin user status: %v", err)
		return fmt.Errorf("failed to check admin user status: %w", err)
	}

	switch adminInfo.Status {
	case AdminUserComplete:
		log.Printf("✅ Admin user already exists and is complete: %s", a.config.Email)
		return nil

	case AdminUserIncomplete:
		log.Printf("🔧 Admin user exists but is incomplete, repairing...")
		if err := a.repairIncompleteAdminUser(adminInfo); err != nil {
			log.Printf("❌ Failed to repair admin user: %v", err)
			return fmt.Errorf("failed to repair admin user: %w", err)
		}
		log.Printf("✅ Admin user repaired successfully: %s", a.config.Email)
		return nil

	case AdminUserNotExists:
		log.Printf("🔧 Admin user does not exist, creating new one...")
		if err := a.createAdminUserInDatabase(); err != nil {
			log.Printf("❌ Failed to create admin user: %v", err)
			return fmt.Errorf("failed to create admin user: %w", err)
		}
		log.Printf("✅ Successfully created default admin user: %s", a.config.Email)
		log.Printf("🔐 Admin can now login with the configured credentials")
		return nil

	default:
		return fmt.Errorf("unknown admin user status: %d", adminInfo.Status)
	}
}

// checkAdminUserStatus checks the status of the admin user (exists, incomplete, complete)
func (a *AdminService) checkAdminUserStatus() (*AdminUserInfo, error) {
	ctx := context.Background()
	
	// Generate the email search hash using the crypto service
	emailSearchHash, err := a.crypto.EncryptDeterministic([]byte(strings.ToLower(a.config.Email)), "email_search")
	if err != nil {
		return nil, fmt.Errorf("failed to generate email search hash: %w", err)
	}

	// Check if admin user exists with current encryption key
	var userID uuid.UUID
	var masterKeyEncrypted []byte
	var salt []byte
	err = a.db.QueryRow(ctx, `SELECT id, master_key_encrypted, salt FROM users WHERE email_search_hash = $1`, emailSearchHash).Scan(&userID, &masterKeyEncrypted, &salt)
	
	if err != nil {
		if err.Error() == "no rows in result set" {
			log.Printf("🔍 Admin user not found with email: %s", a.config.Email)
			return &AdminUserInfo{Status: AdminUserNotExists}, nil
		}
		log.Printf("❌ Database query failed when checking admin user: %v", err)
		return nil, fmt.Errorf("database query failed: %w", err)
	}

	log.Printf("🔍 Found admin user (ID: %s)", userID)

	// User exists, now check if they have workspace and role
	var workspaceCount int
	err = a.db.QueryRow(ctx, `SELECT COUNT(*) FROM workspaces WHERE user_id = $1`, userID).Scan(&workspaceCount)
	if err != nil {
		log.Printf("❌ Failed to check workspace for admin user: %v", err)
		return nil, fmt.Errorf("failed to check workspace: %w", err)
	}

	var roleCount int
	err = a.db.QueryRow(ctx, `SELECT COUNT(*) FROM user_roles ur JOIN roles r ON ur.role_id = r.id WHERE ur.user_id = $1 AND r.name = 'admin'`, userID).Scan(&roleCount)
	if err != nil {
		log.Printf("❌ Failed to check admin role for user: %v", err)
		return nil, fmt.Errorf("failed to check admin role: %w", err)
	}

	hasWorkspace := workspaceCount > 0
	hasRole := roleCount > 0

	log.Printf("🔍 Admin user status check:")
	log.Printf("   - Has workspace: %t (%d workspaces)", hasWorkspace, workspaceCount)
	log.Printf("   - Has admin role: %t", hasRole)

	// Decrypt master key for potential repair operations
	userKey := argon2.IDKey([]byte(a.config.Password), salt, 1, 64*1024, 4, 32)
	var masterKey []byte
	if len(masterKeyEncrypted) > 24 { // Minimum size for nonce + encrypted data
		aead, err := chacha20poly1305.NewX(userKey)
		if err == nil {
			nonce := masterKeyEncrypted[:aead.NonceSize()]
			ciphertext := masterKeyEncrypted[aead.NonceSize():]
			masterKey, err = aead.Open(nil, nonce, ciphertext, nil)
			if err != nil {
				log.Printf("⚠️ Warning: Cannot decrypt master key for admin user: %v", err)
			}
		}
	}

	status := AdminUserComplete
	if !hasWorkspace || !hasRole {
		status = AdminUserIncomplete
	}

	var statusText string
	switch status {
	case AdminUserComplete:
		statusText = "COMPLETE"
	case AdminUserIncomplete:
		statusText = "INCOMPLETE"
	case AdminUserNotExists:
		statusText = "NOT_EXISTS"
	}

	log.Printf("🔍 Admin user final status: %s", statusText)
	if len(masterKey) > 0 {
		log.Printf("   - Master key decrypted successfully")
	} else {
		log.Printf("   - Master key decryption failed or unavailable")
	}

	return &AdminUserInfo{
		Status:       status,
		UserID:       userID,
		MasterKey:    masterKey,
		HasWorkspace: hasWorkspace,
		HasRole:      hasRole,
	}, nil
}

// repairIncompleteAdminUser repairs an admin user that's missing workspace or role
func (a *AdminService) repairIncompleteAdminUser(info *AdminUserInfo) error {
	ctx := context.Background()

	// Begin transaction
	tx, err := a.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	log.Printf("🔧 Repairing incomplete admin user (ID: %s)", info.UserID)
	log.Printf("   - Has workspace: %t", info.HasWorkspace)
	log.Printf("   - Has admin role: %t", info.HasRole)

	// Create workspace if missing
	if !info.HasWorkspace {
		log.Printf("   - Creating missing workspace...")
		if len(info.MasterKey) == 0 {
			return fmt.Errorf("cannot create workspace: master key not available")
		}
		if err := a.createAdminWorkspace(ctx, tx, info.UserID, info.MasterKey); err != nil {
			return fmt.Errorf("failed to create admin workspace: %w", err)
		}
		log.Printf("   ✅ Created admin workspace")
	}

	// Assign admin role if missing
	if !info.HasRole {
		log.Printf("   - Assigning missing admin role...")
		if err := a.assignAdminRole(ctx, tx, info.UserID); err != nil {
			return fmt.Errorf("failed to assign admin role: %w", err)
		}
		log.Printf("   ✅ Assigned admin role")
	}

	// Commit transaction
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit admin user repair: %w", err)
	}

	log.Printf("✅ Successfully repaired admin user: %s", a.config.Email)
	return nil
}

// createAdminUserInDatabase creates the admin user in the database
func (a *AdminService) createAdminUserInDatabase() error {
	ctx := context.Background()

	// Check for any encryption key mismatches first
	var totalUserCount int
	err := a.db.QueryRow(ctx, `SELECT COUNT(*) FROM users`).Scan(&totalUserCount)
	if err != nil {
		return fmt.Errorf("failed to check existing users: %w", err)
	}

	if totalUserCount > 0 {
		log.Printf("⚠️  Admin user not accessible with current encryption key, but %d other users exist", totalUserCount)
		log.Printf("   This indicates a SERVER_ENCRYPTION_KEY mismatch.")
		log.Printf("   Creating new admin user with current key...")
		log.Printf("   Use /api/v1/auth/admin-recovery to clean up old unreachable users if needed.")
	} else {
		log.Println("🔐 No users found - creating default admin user...")
	}

	log.Println("⚠️  WARNING: Default admin credentials are insecure. Please change them immediately after first login!")

	// Generate salt for password hashing (same as main.go)
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	// Hash password with Argon2id (same as main.go)
	passwordHash := a.hashPassword(a.config.Password, salt)

	// Generate user's master encryption key (same as main.go)
	masterKey := make([]byte, 32)
	if _, err := rand.Read(masterKey); err != nil {
		return fmt.Errorf("failed to generate master key: %w", err)
	}

	// Derive key from password to encrypt master key (same as main.go)
	userKey := argon2.IDKey([]byte(a.config.Password), salt, 1, 64*1024, 4, 32)

	// Encrypt master key with user's derived key (same as main.go)
	aead, err := chacha20poly1305.NewX(userKey)
	if err != nil {
		return fmt.Errorf("failed to initialize encryption: %w", err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	masterKeyEncrypted := aead.Seal(nonce, nonce, masterKey, nil)

	// Generate GDPR deletion key for email encryption (same as main.go)
	deletionKey := make([]byte, 32)
	if _, err := rand.Read(deletionKey); err != nil {
		return fmt.Errorf("failed to generate GDPR deletion key: %w", err)
	}

	// Create email hash for uniqueness and GDPR lookups (same as main.go)
	emailHash := a.crypto.HashEmail(a.config.Email)

	// Encrypt email with GDPR key (same as main.go)
	emailEncrypted, err := a.crypto.EncryptWithGDPRKey([]byte(a.config.Email), deletionKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt email: %w", err)
	}

	// Generate email search hash (same as main.go)
	emailSearchHash, err := a.crypto.EncryptDeterministic([]byte(strings.ToLower(a.config.Email)), "email_search")
	if err != nil {
		return fmt.Errorf("failed to generate email search hash: %w", err)
	}

	// Start transaction (same as main.go)
	tx, err := a.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to start transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	// Store GDPR deletion key (same as main.go)
	_, err = tx.Exec(ctx, `
		INSERT INTO gdpr_keys (email_hash, deletion_key)
		VALUES ($1, $2)`,
		emailHash, deletionKey,
	)
	if err != nil {
		return fmt.Errorf("failed to store GDPR deletion key: %w", err)
	}

	// Insert default admin user (same as main.go)
	_, err = tx.Exec(ctx, `
		INSERT INTO users (
			email_hash, email_encrypted, email_search_hash,
			password_hash, salt, master_key_encrypted,
			is_admin, mfa_enabled, failed_attempts
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`, emailHash, emailEncrypted, emailSearchHash, passwordHash, salt, masterKeyEncrypted, true, false, 0)

	if err != nil {
		return fmt.Errorf("failed to create default admin user: %w", err)
	}

	// Get the created user ID
	var userID uuid.UUID
	err = tx.QueryRow(ctx, `SELECT id FROM users WHERE email_search_hash = $1`, emailSearchHash).Scan(&userID)
	if err != nil {
		return fmt.Errorf("failed to retrieve created admin user ID: %w", err)
	}

	// Create workspace for admin user
	if err := a.createAdminWorkspace(ctx, tx, userID, masterKey); err != nil {
		return fmt.Errorf("failed to create admin workspace: %w", err)
	}

	// Assign admin role
	if err := a.assignAdminRole(ctx, tx, userID); err != nil {
		return fmt.Errorf("failed to assign admin role: %w", err)
	}

	// Commit transaction
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit admin user creation: %w", err)
	}

	return nil
}

// Helper functions

func getEnvString(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return strings.ToLower(value) == "true" || value == "1"
}

func isValidEmail(email string) bool {
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	return emailRegex.MatchString(email)
}

// generateSecureID generates a cryptographically secure random ID
func generateSecureID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", bytes), nil
}

// hashPassword implements the same Argon2id hashing as main.go HashPassword function
func (a *AdminService) hashPassword(password string, salt []byte) string {
	// Use same parameters as main.go: 3 iterations, 64MB memory, 4 parallelism, 32 byte key
	hash := argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, 32)
	
	// Format same as main.go
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, 64*1024, 3, 4, 
		encodeB64(salt), 
		encodeB64(hash))
}

// encodeB64 encodes bytes to base64 without padding (same as main.go)
func encodeB64(data []byte) string {
	return base64.RawStdEncoding.EncodeToString(data)
}

// createAdminWorkspace creates a default workspace for the admin user
func (a *AdminService) createAdminWorkspace(ctx context.Context, tx pgx.Tx, userID uuid.UUID, masterKey []byte) error {
	workspaceName := "Admin Workspace"
	
	// Generate workspace encryption key
	workspaceKey := make([]byte, 32)
	if _, err := rand.Read(workspaceKey); err != nil {
		return fmt.Errorf("failed to generate workspace key: %w", err)
	}

	// Encrypt workspace name with master key
	aead, err := chacha20poly1305.NewX(masterKey)
	if err != nil {
		return fmt.Errorf("failed to initialize encryption: %w", err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	nameEncrypted := aead.Seal(nonce, nonce, []byte(workspaceName), nil)

	// Hash workspace name for search
	nameHash := a.crypto.HashEmail(workspaceName) // Reuse email hashing function

	// Create workspace in database
	_, err = tx.Exec(ctx, `
		INSERT INTO workspaces (user_id, name_encrypted, name_hash, workspace_key_encrypted, created_at, updated_at)
		VALUES ($1, $2, $3, $4, NOW(), NOW())
	`, userID, nameEncrypted, nameHash, workspaceKey)

	if err != nil {
		return fmt.Errorf("failed to create workspace: %w", err)
	}

	return nil
}

// assignAdminRole assigns the admin role to the user
func (a *AdminService) assignAdminRole(ctx context.Context, tx pgx.Tx, userID uuid.UUID) error {
	// Get the admin role ID
	var roleID uuid.UUID
	err := tx.QueryRow(ctx, `SELECT id FROM roles WHERE name = 'admin'`).Scan(&roleID)
	if err != nil {
		log.Printf("❌ Failed to find 'admin' role in database: %v", err)
		return fmt.Errorf("failed to find admin role: %w", err)
	}

	log.Printf("🔍 Found admin role (ID: %s)", roleID)

	// Assign role to user
	_, err = tx.Exec(ctx, `
		INSERT INTO user_roles (user_id, role_id, assigned_at)
		VALUES ($1, $2, NOW())
	`, userID, roleID)

	if err != nil {
		log.Printf("❌ Failed to assign admin role to user %s: %v", userID, err)
		return fmt.Errorf("failed to assign admin role: %w", err)
	}

	log.Printf("✅ Assigned admin role to user %s", userID)

	return nil
}