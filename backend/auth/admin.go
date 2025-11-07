package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"log"
	"os"
	"strings"

	appcrypto "leaflock/crypto"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// AdminConfig holds default admin user configuration from environment
type AdminConfig struct {
	Enabled  bool
	Email    string
	Password string
}

// LoadAdminConfig loads admin configuration from environment variables
func LoadAdminConfig() AdminConfig {
	enabled := strings.ToLower(os.Getenv("ENABLE_DEFAULT_ADMIN")) == "true"
	email := os.Getenv("DEFAULT_ADMIN_EMAIL")
	password := os.Getenv("DEFAULT_ADMIN_PASSWORD")

	// Set defaults if not specified
	if email == "" {
		email = "admin@leaflock.local"
	}

	// Validate password if enabled
	if enabled && password == "" {
		log.Fatal("ENABLE_DEFAULT_ADMIN is true but DEFAULT_ADMIN_PASSWORD is not set")
	}

	return AdminConfig{
		Enabled:  enabled,
		Email:    email,
		Password: password,
	}
}

// EnsureDefaultAdminFromEnv ensures the default admin user exists and is properly configured
// This function loads configuration from environment variables and is idempotent
// Unlike EnsureDefaultAdmin, this can UPDATE existing users (promote to admin, change password)
func (s *Service) EnsureDefaultAdminFromEnv(ctx context.Context) error {
	config := LoadAdminConfig()

	// Skip if disabled
	if !config.Enabled {
		log.Println("[Admin] Default admin user is disabled (ENABLE_DEFAULT_ADMIN=false)")
		return nil
	}

	// Validate configuration
	if config.Email == "" {
		return fmt.Errorf("default admin email is empty")
	}
	if config.Password == "" {
		return fmt.Errorf("default admin password is empty")
	}

	// Check password strength
	if err := s.password.ValidatePasswordStrength(config.Password); err != nil {
		return fmt.Errorf("default admin password is too weak: %w", err)
	}

	// Hash email for lookup
	emailHash := sha256.Sum256([]byte(strings.ToLower(config.Email)))

	// Check if admin user exists
	var userID uuid.UUID
	var isAdmin bool
	var currentPasswordHash string
	var currentSalt []byte

	err := s.db.QueryRow(ctx, `
		SELECT id, is_admin, password_hash, salt
		FROM users
		WHERE email_hash = $1`,
		emailHash[:],
	).Scan(&userID, &isAdmin, &currentPasswordHash, &currentSalt)

	if err == pgx.ErrNoRows {
		// Admin user doesn't exist - create it
		return s.createDefaultAdmin(ctx, config)
	} else if err != nil {
		return fmt.Errorf("failed to check for admin user: %w", err)
	}

	// Admin user exists - ensure it's properly configured
	return s.updateDefaultAdmin(ctx, userID, config, isAdmin, currentPasswordHash, currentSalt)
}

// createDefaultAdmin creates a new default admin user
func (s *Service) createDefaultAdmin(ctx context.Context, config AdminConfig) error {
	log.Printf("[Admin] Creating default admin user: %s", config.Email)

	// Generate salt
	salt, err := s.password.GenerateSalt()
	if err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	// Hash password
	passwordHash := s.password.HashPassword(config.Password, salt)

	// Generate master key (32 bytes)
	masterKey := make([]byte, 32)
	if _, err := rand.Read(masterKey); err != nil {
		return fmt.Errorf("failed to generate master key: %w", err)
	}

	// Derive key from password for encrypting master key
	derivedKey := s.password.DeriveKeyBytes(config.Password, salt)
	tempCrypto := appcrypto.NewCryptoService(derivedKey)

	// Encrypt master key
	masterKeyEncrypted, err := tempCrypto.EncryptBytes(masterKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt master key: %w", err)
	}

	// Create email hashes
	emailBytes := []byte(strings.ToLower(strings.TrimSpace(config.Email)))
	emailHash := sha256.Sum256(emailBytes)

	// Zero-knowledge: Store email in plaintext (needed for password reset, notifications)
	// Create deterministic search hash for login
	searchHash := sha256.Sum256(append(emailBytes, []byte("search-salt")...))

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
		userID, emailHash[:], config.Email, searchHash[:],
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

	log.Printf("[Admin] ✅ Default admin user created successfully: %s", config.Email)
	return nil
}

// updateDefaultAdmin updates an existing admin user if needed
func (s *Service) updateDefaultAdmin(ctx context.Context, userID uuid.UUID, config AdminConfig, isAdmin bool, currentPasswordHash string, currentSalt []byte) error {
	needsUpdate := false

	// Check if admin flag needs to be set
	if !isAdmin {
		log.Printf("[Admin] User %s exists but is not admin - promoting to admin", config.Email)
		needsUpdate = true
	}

	// Check if password needs to be updated
	// We verify the current password to see if it matches the env password
	newPasswordHash := s.password.HashPassword(config.Password, currentSalt)
	if newPasswordHash != currentPasswordHash {
		log.Printf("[Admin] Admin password has changed in environment - updating password")
		log.Printf("[Admin] ⚠️  WARNING: Changing password will generate new master key - old notes will be inaccessible!")

		// Generate new salt
		salt, err := s.password.GenerateSalt()
		if err != nil {
			return fmt.Errorf("failed to generate new salt: %w", err)
		}

		// Hash new password
		passwordHash := s.password.HashPassword(config.Password, salt)

		// Generate new master key
		masterKey := make([]byte, 32)
		if _, err := rand.Read(masterKey); err != nil {
			return fmt.Errorf("failed to generate master key: %w", err)
		}

		// Derive key from new password
		derivedKey := s.password.DeriveKeyBytes(config.Password, salt)
		tempCrypto := appcrypto.NewCryptoService(derivedKey)

		// Encrypt master key
		masterKeyEncrypted, err := tempCrypto.EncryptBytes(masterKey)
		if err != nil {
			return fmt.Errorf("failed to encrypt master key: %w", err)
		}

		// Update password and master key
		_, err = s.db.Exec(ctx, `
			UPDATE users
			SET password_hash = $1,
				salt = $2,
				master_key_encrypted = $3,
				updated_at = NOW()
			WHERE id = $4`,
			passwordHash,
			salt,
			masterKeyEncrypted,
			userID,
		)

		if err != nil {
			return fmt.Errorf("failed to update admin password: %w", err)
		}

		log.Printf("[Admin] ✅ Admin password updated successfully")
		needsUpdate = false // Already updated in above query
	}

	// Apply admin flag update if needed (promote to admin)
	if needsUpdate && !isAdmin {
		_, err := s.db.Exec(ctx, `UPDATE users SET is_admin = true, updated_at = NOW() WHERE id = $1`, userID)
		if err != nil {
			return fmt.Errorf("failed to promote user to admin: %w", err)
		}

		// Ensure admin role is assigned
		_, err = s.db.Exec(ctx, `
			INSERT INTO user_roles (user_id, role_id)
			SELECT $1, id FROM roles WHERE name = 'admin'
			ON CONFLICT DO NOTHING
		`, userID)
		if err != nil {
			return fmt.Errorf("failed to assign admin role: %w", err)
		}

		log.Printf("[Admin] ✅ User promoted to admin: %s", config.Email)
	}

	if !needsUpdate && newPasswordHash == currentPasswordHash {
		log.Printf("[Admin] ✅ Default admin user is properly configured: %s", config.Email)
	}

	return nil
}

// GetAdminInfo returns information about the default admin configuration (for debugging)
func GetAdminInfo() map[string]interface{} {
	config := LoadAdminConfig()

	// Don't expose the actual password!
	passwordHint := ""
	if config.Password != "" {
		// Show only first 2 and last 2 characters
		if len(config.Password) > 4 {
			passwordHint = config.Password[:2] + "..." + config.Password[len(config.Password)-2:]
		} else {
			passwordHint = "***"
		}
	}

	return map[string]interface{}{
		"enabled":       config.Enabled,
		"email":         config.Email,
		"password_hint": passwordHint,
		"configured":    config.Enabled && config.Email != "" && config.Password != "",
	}
}
