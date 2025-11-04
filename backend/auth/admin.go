package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

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
	masterKeyEncrypted, err := tempCrypto.Encrypt(masterKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt master key: %w", err)
	}

	// Hash email for storage
	emailHash := sha256.Sum256([]byte(strings.ToLower(config.Email)))

	// Create deterministic search hash (for login lookups)
	emailSearchHash := sha256.Sum256(append([]byte("email_search:"), []byte(strings.ToLower(config.Email))...))

	// Encrypt email for privacy
	emailEncrypted, err := s.crypto.Encrypt([]byte(config.Email))
	if err != nil {
		return fmt.Errorf("failed to encrypt email: %w", err)
	}

	// Generate keypair for sharing encrypted notes
	publicKey, privateKey, err := s.crypto.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate keypair: %w", err)
	}

	// Encrypt private key with user's derived key
	privateKeyEncrypted, err := tempCrypto.Encrypt(privateKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt private key: %w", err)
	}

	// Create user with admin flag
	var userID uuid.UUID
	err = s.db.QueryRow(ctx, `
		INSERT INTO users (
			email_hash,
			email_encrypted,
			email_search_hash,
			password_hash,
			salt,
			master_key_encrypted,
			public_key,
			private_key_encrypted,
			is_admin,
			created_at,
			updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), NOW())
		RETURNING id`,
		emailHash[:],
		emailEncrypted,
		emailSearchHash[:],
		passwordHash,
		salt,
		masterKeyEncrypted,
		publicKey,
		privateKeyEncrypted,
		true, // is_admin = true
	).Scan(&userID)

	if err != nil {
		return fmt.Errorf("failed to create admin user: %w", err)
	}

	// Create default workspace for admin
	_, err = s.db.Exec(ctx, `
		INSERT INTO workspaces (owner_id, name_encrypted, encryption_key_encrypted)
		VALUES ($1, $2, $3)`,
		userID,
		emailEncrypted, // Use encrypted email as workspace name
		masterKeyEncrypted,
	)

	if err != nil {
		return fmt.Errorf("failed to create admin workspace: %w", err)
	}

	log.Printf("[Admin] ✅ Default admin user created successfully: %s", config.Email)
	return nil
}

// updateDefaultAdmin updates an existing admin user if needed
func (s *Service) updateDefaultAdmin(ctx context.Context, userID uuid.UUID, config AdminConfig, isAdmin bool, currentPasswordHash string, currentSalt []byte) error {
	needsUpdate := false
	updates := []string{}

	// Check if admin flag needs to be set
	if !isAdmin {
		log.Printf("[Admin] User %s exists but is not admin - promoting to admin", config.Email)
		updates = append(updates, "SET is_admin = true")
		needsUpdate = true
	}

	// Check if password needs to be updated
	// We verify the current password to see if it matches the env password
	newPasswordHash := s.password.HashPassword(config.Password, currentSalt)
	if newPasswordHash != currentPasswordHash {
		log.Printf("[Admin] Admin password has changed in environment - updating password")

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
		masterKeyEncrypted, err := tempCrypto.Encrypt(masterKey)
		if err != nil {
			return fmt.Errorf("failed to encrypt master key: %w", err)
		}

		// Generate new keypair
		publicKey, privateKey, err := s.crypto.GenerateKeyPair()
		if err != nil {
			return fmt.Errorf("failed to generate keypair: %w", err)
		}

		// Encrypt private key
		privateKeyEncrypted, err := tempCrypto.Encrypt(privateKey)
		if err != nil {
			return fmt.Errorf("failed to encrypt private key: %w", err)
		}

		// Update password and keys
		_, err = s.db.Exec(ctx, `
			UPDATE users
			SET password_hash = $1,
				salt = $2,
				master_key_encrypted = $3,
				public_key = $4,
				private_key_encrypted = $5,
				updated_at = NOW()
			WHERE id = $6`,
			passwordHash,
			salt,
			masterKeyEncrypted,
			publicKey,
			privateKeyEncrypted,
			userID,
		)

		if err != nil {
			return fmt.Errorf("failed to update admin password: %w", err)
		}

		log.Printf("[Admin] ⚠️  Admin password updated - old notes may be inaccessible!")
		needsUpdate = false // Already updated in above query
	}

	// Apply admin flag update if needed
	if needsUpdate && len(updates) > 0 {
		query := fmt.Sprintf("UPDATE users %s, updated_at = NOW() WHERE id = $1", strings.Join(updates, ", "))
		_, err := s.db.Exec(ctx, query, userID)
		if err != nil {
			return fmt.Errorf("failed to update admin user: %w", err)
		}
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
