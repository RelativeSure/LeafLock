package services

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// MFAService handles MFA-related operations
type MFAService struct{}

// NewMFAService creates a new MFA service
func NewMFAService() *MFAService {
	return &MFAService{}
}

// GenerateBackupCodes generates cryptographically secure backup codes
// Returns an array of formatted backup codes (e.g., "XXXX-XXXX-XXXX-XXXX")
func (s *MFAService) GenerateBackupCodes(count int) ([]string, error) {
	if count <= 0 || count > 20 {
		return nil, fmt.Errorf("invalid backup code count: %d (must be 1-20)", count)
	}

	codes := make([]string, count)
	for i := 0; i < count; i++ {
		code, err := s.generateSingleBackupCode()
		if err != nil {
			return nil, fmt.Errorf("failed to generate backup code %d: %w", i, err)
		}
		codes[i] = code
	}

	return codes, nil
}

// generateSingleBackupCode generates one backup code with format XXXX-XXXX-XXXX-XXXX
func (s *MFAService) generateSingleBackupCode() (string, error) {
	// Generate 10 random bytes (80 bits of entropy)
	randomBytes := make([]byte, 10)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Encode to base32 for readability (no ambiguous characters)
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(randomBytes)

	// Take first 16 characters and format as XXXX-XXXX-XXXX-XXXX
	code := strings.ToUpper(encoded[:16])
	formatted := fmt.Sprintf("%s-%s-%s-%s",
		code[0:4],
		code[4:8],
		code[8:12],
		code[12:16],
	)

	return formatted, nil
}

// HashBackupCode hashes a backup code using Argon2id for secure storage
func (s *MFAService) HashBackupCode(code string) []byte {
	// Normalize code (remove dashes, uppercase)
	normalized := strings.ToUpper(strings.ReplaceAll(code, "-", ""))

	// Use deterministic salt based on code content for backup code hashing
	// This allows verification without storing the salt separately
	salt := sha256.Sum256([]byte("leaflock_backup_code_salt_v1"))

	// Argon2id parameters: 3 iterations, 64MB memory, 4 parallelism, 32 byte hash
	hash := argon2.IDKey([]byte(normalized), salt[:], 3, 64*1024, 4, 32)

	return hash
}

// VerifyBackupCode verifies a backup code against an array of hashed codes
// Returns (isValid, indexOfCode) - index is -1 if not found
func (s *MFAService) VerifyBackupCode(code string, hashedCodes [][]byte) (bool, int) {
	if len(hashedCodes) == 0 {
		return false, -1
	}

	inputHash := s.HashBackupCode(code)

	for i, storedHash := range hashedCodes {
		if len(storedHash) != len(inputHash) {
			continue
		}

		// Constant-time comparison to prevent timing attacks
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

// GenerateMFASessionToken generates a temporary session token for MFA verification
// This token is used between password verification and MFA verification
func (s *MFAService) GenerateMFASessionToken(userID string) (string, error) {
	// Generate 32 random bytes
	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("failed to generate session token: %w", err)
	}

	// Combine user ID with random bytes for uniqueness
	data := fmt.Sprintf("%s:%s", userID, hex.EncodeToString(randomBytes))

	// Hash to create final token
	hash := sha256.Sum256([]byte(data))
	token := fmt.Sprintf("mfa_session_%s", hex.EncodeToString(hash[:]))

	return token, nil
}

// NormalizeBackupCode normalizes a backup code for comparison
// Removes dashes and converts to uppercase
func (s *MFAService) NormalizeBackupCode(code string) string {
	return strings.ToUpper(strings.ReplaceAll(code, "-", ""))
}

// FormatBackupCode formats a plain code string into XXXX-XXXX-XXXX-XXXX format
func (s *MFAService) FormatBackupCode(code string) string {
	// Remove any existing dashes and spaces
	clean := strings.ReplaceAll(strings.ReplaceAll(code, "-", ""), " ", "")
	clean = strings.ToUpper(clean)

	if len(clean) != 16 {
		return code // Return as-is if not 16 characters
	}

	return fmt.Sprintf("%s-%s-%s-%s",
		clean[0:4],
		clean[4:8],
		clean[8:12],
		clean[12:16],
	)
}
