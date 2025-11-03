package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"time"

	appcrypto "leaflock/crypto"
	"leaflock/database"
	"leaflock/utils"

	"github.com/google/uuid"
	"golang.org/x/crypto/argon2"
)

const (
	// Argon2id parameters (same as legacy for compatibility)
	Argon2Time      = 3
	Argon2Memory    = 64 * 1024 // 64MB
	Argon2Threads   = 4
	Argon2KeyLength = 32

	// Password requirements
	MinPasswordLength = 12

	// Reset token expiration
	ResetTokenExpiry = 15 * time.Minute

	// Reset token verification controls
	resetTokenVerifyMaxAttempts = 10
	resetTokenVerifyWindow      = 15 * time.Minute
)

// PasswordManager handles password operations
type PasswordManager struct {
	db     database.Database
	crypto *appcrypto.CryptoService
}

// NewPasswordManager creates a new password manager
func NewPasswordManager(db database.Database, crypto *appcrypto.CryptoService) *PasswordManager {
	return &PasswordManager{
		db:     db,
		crypto: crypto,
	}
}

// HashPassword hashes a password using Argon2id
func (pm *PasswordManager) HashPassword(password string, salt []byte) string {
	hash := argon2.IDKey(
		[]byte(password),
		salt,
		Argon2Time,
		Argon2Memory,
		Argon2Threads,
		Argon2KeyLength,
	)

	// Format: $argon2id$v=19$m=65536,t=3,p=4$<base64_salt>$<base64_hash>
	return fmt.Sprintf(
		"$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		Argon2Memory,
		Argon2Time,
		Argon2Threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	)
}

// DeriveKeyBytes derives a raw key from password and salt using Argon2id.
// Returns the raw key bytes for use in encryption (32 bytes).
func (pm *PasswordManager) DeriveKeyBytes(password string, salt []byte) []byte {
	return argon2.IDKey(
		[]byte(password),
		salt,
		Argon2Time,
		Argon2Memory,
		Argon2Threads,
		Argon2KeyLength,
	)
}

// VerifyPassword verifies a password against a hash
func (pm *PasswordManager) VerifyPassword(password, passwordHash string, salt []byte) bool {
	computed := pm.HashPassword(password, salt)
	return computed == passwordHash
}

// ValidatePasswordStrength validates password strength
func (pm *PasswordManager) ValidatePasswordStrength(password string) error {
	if len(password) < MinPasswordLength {
		return fmt.Errorf("password must be at least %d characters long", MinPasswordLength)
	}

	// Check for at least one uppercase
	if matched, _ := regexp.MatchString(`[A-Z]`, password); !matched {
		return fmt.Errorf("password must contain at least one uppercase letter")
	}

	// Check for at least one lowercase
	if matched, _ := regexp.MatchString(`[a-z]`, password); !matched {
		return fmt.Errorf("password must contain at least one lowercase letter")
	}

	// Check for at least one digit
	if matched, _ := regexp.MatchString(`[0-9]`, password); !matched {
		return fmt.Errorf("password must contain at least one digit")
	}

	// Check for at least one special character
	if matched, _ := regexp.MatchString(`[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>/?]`, password); !matched {
		return fmt.Errorf("password must contain at least one special character")
	}

	return nil
}

// GenerateSalt generates a cryptographically secure random salt
func (pm *PasswordManager) GenerateSalt() ([]byte, error) {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}
	return salt, nil
}

// CreateResetToken creates a password reset token
func (pm *PasswordManager) CreateResetToken(ctx context.Context, userID uuid.UUID, ipAddress, userAgent string) (string, error) {
	// Generate secure token (32 bytes = 256 bits)
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", fmt.Errorf("failed to generate reset token: %w", err)
	}
	token := base64.URLEncoding.EncodeToString(tokenBytes)

	// Hash token for storage (SHA-256)
	hash := sha256.Sum256([]byte(token))

	// Encrypt IP and User-Agent
	ipEncrypted, err := pm.crypto.EncryptBytes([]byte(ipAddress))
	if err != nil {
		return "", fmt.Errorf("failed to encrypt IP address: %w", err)
	}

	uaEncrypted, err := pm.crypto.EncryptBytes([]byte(userAgent))
	if err != nil {
		return "", fmt.Errorf("failed to encrypt user agent: %w", err)
	}

	// Store in database
	query := `
		INSERT INTO password_reset_tokens
		(user_id, token_hash, expires_at, ip_address_encrypted, user_agent_encrypted)
		VALUES ($1, $2, $3, $4, $5)
	`

	expiresAt := time.Now().UTC().Add(ResetTokenExpiry)
	_, err = pm.db.Exec(ctx, query, userID, hash[:], expiresAt, ipEncrypted, uaEncrypted)
	if err != nil {
		return "", fmt.Errorf("failed to store reset token: %w", err)
	}

	return token, nil
}

// VerifyResetToken verifies a password reset token
func (pm *PasswordManager) VerifyResetToken(ctx context.Context, token string) (uuid.UUID, error) {
	// Hash token
	hash := sha256.Sum256([]byte(token))

	// Look up token in database
	query := `
		SELECT user_id, expires_at, used, verify_attempts, verify_window_start
		FROM password_reset_tokens
		WHERE token_hash = $1
	`

	var userID uuid.UUID
	var expiresAt time.Time
	var used bool
	var attempts int
	var windowStart sql.NullTime

	err := pm.db.QueryRow(ctx, query, hash[:]).Scan(&userID, &expiresAt, &used, &attempts, &windowStart)
	if err != nil {
		return uuid.Nil, fmt.Errorf("invalid or expired reset token")
	}

	now := time.Now().UTC()
	if !windowStart.Valid || now.Sub(windowStart.Time) > resetTokenVerifyWindow {
		attempts = 0
		windowStart = sql.NullTime{Time: now, Valid: true}
	}

	if attempts >= resetTokenVerifyMaxAttempts {
		return uuid.Nil, fmt.Errorf("too many verification attempts. Please request a new reset link")
	}

	attempts++
	if _, err := pm.db.Exec(ctx, `
		UPDATE password_reset_tokens
		SET verify_attempts = $1, verify_window_start = $2
		WHERE token_hash = $3
	`, attempts, windowStart.Time, hash[:]); err != nil {
		return uuid.Nil, fmt.Errorf("failed to track verification attempt: %w", err)
	}

	// Check if already used
	if used {
		return uuid.Nil, fmt.Errorf("reset token already used")
	}

	// Check if expired
	if now.After(expiresAt) {
		return uuid.Nil, fmt.Errorf("reset token expired")
	}

	return userID, nil
}

// CompletePasswordReset completes the password reset process
func (pm *PasswordManager) CompletePasswordReset(ctx context.Context, token, newPassword string) error {
	// Verify token and get user ID
	userID, err := pm.VerifyResetToken(ctx, token)
	if err != nil {
		return err
	}

	// Validate new password strength
	if err := pm.ValidatePasswordStrength(newPassword); err != nil {
		return err
	}

	// Generate new salt
	salt, err := pm.GenerateSalt()
	if err != nil {
		return err
	}

	// Hash new password
	passwordHash := pm.HashPassword(newPassword, salt)

	// Generate new master key (user will need to re-encrypt their data)
	masterKey := make([]byte, 32)
	if _, err := rand.Read(masterKey); err != nil {
		return fmt.Errorf("failed to generate master key: %w", err)
	}

	// Derive key from new password
	derivedKey := argon2.IDKey(
		[]byte(newPassword),
		salt,
		Argon2Time,
		Argon2Memory,
		Argon2Threads,
		Argon2KeyLength,
	)

	// Encrypt master key with derived key
	tempCrypto := appcrypto.NewCryptoService(derivedKey)
	masterKeyEncrypted, err := tempCrypto.EncryptBytes(masterKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt master key: %w", err)
	}

	// Begin transaction
	tx, err := pm.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	// Update user password
	updateQuery := `
		UPDATE users
		SET password_hash = $1, salt = $2, master_key_encrypted = $3, updated_at = NOW()
		WHERE id = $4
	`
	_, err = tx.Exec(ctx, updateQuery, passwordHash, salt, masterKeyEncrypted, userID)
	if err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	// Mark ALL reset tokens for this user as used
	markUsedQuery := `
		UPDATE password_reset_tokens
		SET used = true
		WHERE user_id = $1
	`
	_, err = tx.Exec(ctx, markUsedQuery, userID)
	if err != nil {
		return fmt.Errorf("failed to mark token as used: %w", err)
	}

	// Commit transaction
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	// Log password reset completion
	pm.auditLog(ctx, userID, "password_reset_completed", map[string]interface{}{
		"user_id": userID.String(),
	})

	return nil
}

// InvalidateAllResetTokens invalidates all reset tokens for a user
func (pm *PasswordManager) InvalidateAllResetTokens(ctx context.Context, userID uuid.UUID) error {
	query := `
		UPDATE password_reset_tokens
		SET used = true
		WHERE user_id = $1 AND used = false
	`
	_, err := pm.db.Exec(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("failed to invalidate reset tokens: %w", err)
	}
	return nil
}

// CleanupExpiredTokens removes expired reset tokens (should be run periodically)
func (pm *PasswordManager) CleanupExpiredTokens(ctx context.Context) error {
	query := `
		DELETE FROM password_reset_tokens
		WHERE expires_at < NOW() OR used = true
	`
	_, err := pm.db.Exec(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to cleanup expired tokens: %w", err)
	}
	return nil
}

// auditLog logs an audit event for security tracking
func (pm *PasswordManager) auditLog(ctx context.Context, userID uuid.UUID, action string, metadata map[string]interface{}) {
	// Get client info from context
	ipAddress := utils.GetClientIPFromContext(ctx)
	userAgent := utils.GetUserAgentFromContext(ctx)

	// Encrypt IP and User-Agent
	ipEncrypted, err := pm.crypto.EncryptBytes([]byte(ipAddress))
	if err != nil {
		return // Fail silently for audit logging
	}

	uaEncrypted, err := pm.crypto.EncryptBytes([]byte(userAgent))
	if err != nil {
		return // Fail silently for audit logging
	}

	// Encrypt metadata if provided
	var metadataEncrypted []byte
	if metadata != nil {
		metadataBytes, err := json.Marshal(metadata)
		if err == nil {
			metadataEncrypted, _ = pm.crypto.EncryptBytes(metadataBytes)
		}
	}

	// Insert audit log
	query := `
		INSERT INTO audit_log (user_id, action, resource_type, ip_address_encrypted, user_agent_encrypted, metadata_encrypted)
		VALUES ($1, $2, $3, $4, $5, $6)
	`
	_, _ = pm.db.Exec(ctx, query, userID, action, "auth", ipEncrypted, uaEncrypted, metadataEncrypted)
}
