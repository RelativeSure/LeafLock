package auth

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"strings"

	appcrypto "leaflock/crypto"
	"leaflock/database"

	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/argon2"
)

const (
	// MFA constants
	BackupCodeCount  = 10
	BackupCodeLength = 12 // XXXX-XXXX-XXXX format
	TOTPIssuer       = "LeafLock"
	TOTPPeriod       = 30
	TOTPDigits       = 6
)

// MFAManager handles MFA operations
type MFAManager struct {
	db     database.Database
	crypto *appcrypto.CryptoService
}

// NewMFAManager creates a new MFA manager
func NewMFAManager(db database.Database, crypto *appcrypto.CryptoService) *MFAManager {
	return &MFAManager{
		db:     db,
		crypto: crypto,
	}
}

// GenerateTOTPSecret generates a new TOTP secret for a user
func (mm *MFAManager) GenerateTOTPSecret(email string) (*otp.Key, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      TOTPIssuer,
		AccountName: email,
		Period:      TOTPPeriod,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to generate TOTP secret: %w", err)
	}

	return key, nil
}

// VerifyTOTP verifies a TOTP code
func (mm *MFAManager) VerifyTOTP(secret, code string) bool {
	return totp.Validate(code, secret)
}

// GenerateBackupCodes generates backup codes with a per-user salt
func (mm *MFAManager) GenerateBackupCodes(userSalt []byte) ([]string, [][]byte, error) {
	codes := make([]string, BackupCodeCount)
	hashes := make([][]byte, BackupCodeCount)

	for i := 0; i < BackupCodeCount; i++ {
		// Generate 80 bits of randomness (10 bytes)
		randomBytes := make([]byte, 10)
		if _, err := rand.Read(randomBytes); err != nil {
			return nil, nil, fmt.Errorf("failed to generate random bytes: %w", err)
		}

		// Encode as base32 and format
		encoded := base32.StdEncoding.EncodeToString(randomBytes)
		encoded = strings.TrimRight(encoded, "=") // Remove padding
		code := mm.formatBackupCode(encoded[:12])
		codes[i] = code

		// Hash the code for storage (Argon2id) with per-user salt
		hash := mm.hashBackupCode(code, userSalt)
		hashes[i] = hash
	}

	return codes, hashes, nil
}

// VerifyBackupCode verifies a backup code and marks it as used
func (mm *MFAManager) VerifyBackupCode(ctx context.Context, userID uuid.UUID, code string) (bool, error) {
	// Normalize code
	normalized := mm.normalizeBackupCode(code)

	// Get user's backup codes and salt
	query := `
		SELECT mfa_backup_codes, mfa_backup_codes_used, mfa_backup_code_salt
		FROM users
		WHERE id = $1
	`

	var backupCodes [][]byte
	var usedCodes [][]byte
	var userSalt []byte

	err := mm.db.QueryRow(ctx, query, userID).Scan(&backupCodes, &usedCodes, &userSalt)
	if err != nil {
		return false, fmt.Errorf("failed to get backup codes: %w", err)
	}

	// If user has no salt (legacy user), regenerate backup codes on first use
	if len(userSalt) == 0 {
		return false, fmt.Errorf("backup codes need to be regenerated for security update")
	}

	// Check each backup code
	codeHash := mm.hashBackupCode(normalized, userSalt)
	matchedIndex := -1

	for i, storedHash := range backupCodes {
		if mm.compareHashes(codeHash, storedHash) {
			matchedIndex = i
			break
		}
	}

	if matchedIndex == -1 {
		return false, nil // Code doesn't match any
	}

	// Check if already used
	for _, usedHash := range usedCodes {
		if mm.compareHashes(codeHash, usedHash) {
			return false, fmt.Errorf("backup code already used")
		}
	}

	// Mark as used atomically to prevent race conditions
	updateQuery := `
		UPDATE users
		SET mfa_backup_codes_used = array_append(mfa_backup_codes_used, $1)
		WHERE id = $2 AND NOT ($1 = ANY(mfa_backup_codes_used))
	`

	result, err := mm.db.Exec(ctx, updateQuery, codeHash, userID)
	if err != nil {
		return false, fmt.Errorf("failed to mark backup code as used: %w", err)
	}

	// Check if the update actually affected a row
	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		return false, fmt.Errorf("backup code already used")
	}

	return true, nil
}

// EnableMFA enables MFA for a user
func (mm *MFAManager) EnableMFA(ctx context.Context, userID uuid.UUID, secret string, code string) ([]string, error) {
	// Verify the TOTP code first
	if !mm.VerifyTOTP(secret, code) {
		return nil, fmt.Errorf("invalid verification code")
	}

	// Encrypt TOTP secret
	encryptedSecret, err := mm.crypto.EncryptBytes([]byte(secret))
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt TOTP secret: %w", err)
	}

	// Generate per-user salt for backup codes (32 bytes for security)
	userSalt := make([]byte, 32)
	if _, err := rand.Read(userSalt); err != nil {
		return nil, fmt.Errorf("failed to generate backup code salt: %w", err)
	}

	// Generate backup codes with per-user salt
	plainCodes, hashedCodes, err := mm.GenerateBackupCodes(userSalt)
	if err != nil {
		return nil, fmt.Errorf("failed to generate backup codes: %w", err)
	}

	// Update user in database including the salt
	query := `
		UPDATE users
		SET mfa_enabled = true,
		    mfa_secret_encrypted = $1,
		    mfa_backup_codes = $2,
		    mfa_backup_codes_used = ARRAY[]::bytea[],
		    mfa_backup_code_salt = $3,
		    updated_at = NOW()
		WHERE id = $4
	`

	_, err = mm.db.Exec(ctx, query, encryptedSecret, hashedCodes, userSalt, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to enable MFA: %w", err)
	}

	return plainCodes, nil
}

// DisableMFA disables MFA for a user
func (mm *MFAManager) DisableMFA(ctx context.Context, userID uuid.UUID, code string) error {
	// Get user's MFA secret
	var encryptedSecret []byte
	query := `
		SELECT mfa_secret_encrypted
		FROM users
		WHERE id = $1 AND mfa_enabled = true
	`

	err := mm.db.QueryRow(ctx, query, userID).Scan(&encryptedSecret)
	if err != nil {
		return fmt.Errorf("MFA not enabled for user")
	}

	// Decrypt secret
	secretBytes, err := mm.crypto.DecryptBytes(encryptedSecret)
	if err != nil {
		return fmt.Errorf("failed to decrypt MFA secret: %w", err)
	}

	// Verify code
	if !mm.VerifyTOTP(string(secretBytes), code) {
		// Try as backup code
		valid, err := mm.VerifyBackupCode(ctx, userID, code)
		if err != nil || !valid {
			return fmt.Errorf("invalid verification code")
		}
	}

	// Disable MFA
	updateQuery := `
		UPDATE users
		SET mfa_enabled = false,
		    mfa_secret_encrypted = NULL,
		    mfa_backup_codes = NULL,
		    mfa_backup_codes_used = NULL,
		    updated_at = NOW()
		WHERE id = $1
	`

	_, err = mm.db.Exec(ctx, updateQuery, userID)
	if err != nil {
		return fmt.Errorf("failed to disable MFA: %w", err)
	}

	return nil
}

// RegenerateBackupCodes generates new backup codes for a user
func (mm *MFAManager) RegenerateBackupCodes(ctx context.Context, userID uuid.UUID, password string) ([]string, error) {
	// Verify user's password first
	var passwordHash string
	var salt []byte
	query := `
		SELECT password_hash, salt
		FROM users
		WHERE id = $1 AND mfa_enabled = true
	`

	err := mm.db.QueryRow(ctx, query, userID).Scan(&passwordHash, &salt)
	if err != nil {
		return nil, fmt.Errorf("MFA not enabled for user")
	}

	// Verify password
	pm := NewPasswordManager(mm.db)
	if !pm.VerifyPassword(password, passwordHash, salt) {
		return nil, fmt.Errorf("invalid password")
	}

	// Generate new per-user salt for backup codes (32 bytes for security)
	userSalt := make([]byte, 32)
	if _, err := rand.Read(userSalt); err != nil {
		return nil, fmt.Errorf("failed to generate backup code salt: %w", err)
	}

	// Generate new backup codes with per-user salt
	plainCodes, hashedCodes, err := mm.GenerateBackupCodes(userSalt)
	if err != nil {
		return nil, fmt.Errorf("failed to generate backup codes: %w", err)
	}

	// Update in database including the new salt
	updateQuery := `
		UPDATE users
		SET mfa_backup_codes = $1,
		    mfa_backup_codes_used = ARRAY[]::bytea[],
		    mfa_backup_code_salt = $2,
		    updated_at = NOW()
		WHERE id = $3
	`

	_, err = mm.db.Exec(ctx, updateQuery, hashedCodes, userSalt, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to update backup codes: %w", err)
	}

	return plainCodes, nil
}

// GetMFAStatus returns MFA status for a user
func (mm *MFAManager) GetMFAStatus(ctx context.Context, userID uuid.UUID) (bool, int, error) {
	query := `
		SELECT mfa_enabled,
		       COALESCE(array_length(mfa_backup_codes, 1), 0) - COALESCE(array_length(mfa_backup_codes_used, 1), 0) as remaining_codes
		FROM users
		WHERE id = $1
	`

	var enabled bool
	var remainingCodes int

	err := mm.db.QueryRow(ctx, query, userID).Scan(&enabled, &remainingCodes)
	if err != nil {
		return false, 0, fmt.Errorf("failed to get MFA status: %w", err)
	}

	return enabled, remainingCodes, nil
}

// GetDecryptedTOTPSecret gets and decrypts a user's TOTP secret
func (mm *MFAManager) GetDecryptedTOTPSecret(ctx context.Context, userID uuid.UUID) (string, error) {
	var encryptedSecret []byte
	query := `
		SELECT mfa_secret_encrypted
		FROM users
		WHERE id = $1 AND mfa_enabled = true
	`

	err := mm.db.QueryRow(ctx, query, userID).Scan(&encryptedSecret)
	if err != nil {
		return "", fmt.Errorf("MFA not enabled for user")
	}

	secretBytes, err := mm.crypto.DecryptBytes(encryptedSecret)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt MFA secret: %w", err)
	}

	return string(secretBytes), nil
}

// Helper functions

func (mm *MFAManager) hashBackupCode(code string, userSalt []byte) []byte {
	// Use Argon2id for consistent hashing with per-user random salt
	// This prevents rainbow table attacks even if the database is compromised
	hash := argon2.IDKey([]byte(code), userSalt, 3, 64*1024, 4, 32)
	return hash
}

func (mm *MFAManager) compareHashes(hash1, hash2 []byte) bool {
	if len(hash1) != len(hash2) {
		return false
	}

	// Constant-time comparison
	var diff byte
	for i := 0; i < len(hash1); i++ {
		diff |= hash1[i] ^ hash2[i]
	}

	return diff == 0
}

func (mm *MFAManager) formatBackupCode(code string) string {
	// Format as XXXX-XXXX-XXXX
	if len(code) < 12 {
		code = code + strings.Repeat("0", 12-len(code))
	}
	return fmt.Sprintf("%s-%s-%s", code[0:4], code[4:8], code[8:12])
}

func (mm *MFAManager) normalizeBackupCode(code string) string {
	// Remove dashes and spaces, convert to uppercase
	normalized := strings.ReplaceAll(code, "-", "")
	normalized = strings.ReplaceAll(normalized, " ", "")
	return strings.ToUpper(normalized)
}
