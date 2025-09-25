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

	// Check if admin user already exists
	exists, err := a.adminUserExists()
	if err != nil {
		log.Printf("❌ Failed to check if admin user exists: %v", err)
		return fmt.Errorf("failed to check admin user existence: %w", err)
	}

	if exists {
		log.Printf("ℹ️ Admin user already exists with email: %s", a.config.Email)
		return nil
	}

	// Create the admin user
	if err := a.createAdminUserInDatabase(); err != nil {
		log.Printf("❌ Failed to create admin user: %v", err)
		return fmt.Errorf("failed to create admin user: %w", err)
	}

	log.Printf("✅ Successfully created default admin user: %s", a.config.Email)
	log.Printf("🔐 Admin can now login with the configured credentials")

	return nil
}

// adminUserExists checks if an admin user already exists with the configured email
func (a *AdminService) adminUserExists() (bool, error) {
	ctx := context.Background()
	
	// Generate the email search hash using the crypto service (same as main.go)
	emailSearchHash, err := a.crypto.EncryptDeterministic([]byte(strings.ToLower(a.config.Email)), "email_search")
	if err != nil {
		return false, fmt.Errorf("failed to generate email search hash: %w", err)
	}

	// Check if admin user exists with current encryption key (same logic as main.go)
	var existingAdminID uuid.UUID
	err = a.db.QueryRow(ctx, `SELECT id FROM users WHERE email_search_hash = $1`, emailSearchHash).Scan(&existingAdminID)
	if err == nil {
		log.Printf("✅ Default admin user already exists and is accessible (ID: %s)", existingAdminID)
		return true, nil
	}

	// Check if this is a "no rows" error (user doesn't exist)
	if err.Error() == "no rows in result set" {
		return false, nil
	}

	// Some other database error occurred
	return false, fmt.Errorf("database query failed: %w", err)
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