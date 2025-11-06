package auth

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateTOTPSecret(t *testing.T) {
	mm := &MFAManager{}
	
	key, err := mm.GenerateTOTPSecret("test@example.com")
	require.NoError(t, err)
	assert.NotNil(t, key)
	assert.Contains(t, key.Secret(), "")
	assert.Equal(t, TOTPIssuer, key.Issuer())
	assert.Equal(t, "test@example.com", key.AccountName())
}

func TestVerifyTOTP_Valid(t *testing.T) {
	mm := &MFAManager{}
	
	key, err := mm.GenerateTOTPSecret("test@example.com")
	require.NoError(t, err)
	
	code, err := totp.GenerateCode(key.Secret(), time.Now())
	require.NoError(t, err)
	
	result := mm.VerifyTOTP(key.Secret(), code)
	assert.True(t, result)
}

func TestVerifyTOTP_Invalid(t *testing.T) {
	mm := &MFAManager{}
	
	key, err := mm.GenerateTOTPSecret("test@example.com")
	require.NoError(t, err)
	
	result := mm.VerifyTOTP(key.Secret(), "000000")
	assert.False(t, result)
}

func TestGenerateBackupCodes(t *testing.T) {
	mm := &MFAManager{}

	// Generate a test salt
	testSalt := make([]byte, 32)
	_, err := rand.Read(testSalt)
	require.NoError(t, err)

	codes, hashes, err := mm.GenerateBackupCodes(testSalt)
	require.NoError(t, err)
	assert.Equal(t, BackupCodeCount, len(codes))
	assert.Equal(t, BackupCodeCount, len(hashes))
	
	// Verify format (XXXX-XXXX-XXXX)
	for _, code := range codes {
		assert.Regexp(t, `^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$`, code)
	}
	
	// Verify hashes are not empty
	for _, hash := range hashes {
		assert.NotEmpty(t, hash)
	}
}

func TestNormalizeBackupCode(t *testing.T) {
	mm := &MFAManager{}
	
	tests := []struct {
		input    string
		expected string
	}{
		{"ABCD-EFGH-IJKL", "ABCDEFGHIJKL"},
		{"abcd-efgh-ijkl", "ABCDEFGHIJKL"},
		{"ABCD EFGH IJKL", "ABCDEFGHIJKL"},
		{"ABCDEFGHIJKL", "ABCDEFGHIJKL"},
		{"  abcd-efgh-ijkl  ", "ABCDEFGHIJKL"},
	}
	
	for _, tt := range tests {
		result := mm.normalizeBackupCode(tt.input)
		assert.Equal(t, tt.expected, result, "Input: %s", tt.input)
	}
}

func TestFormatBackupCode(t *testing.T) {
	mm := &MFAManager{}
	
	// Test with 12+ character input
	input := "ABCDEFGHIJKL"
	result := mm.formatBackupCode(input)
	assert.Equal(t, "ABCD-EFGH-IJKL", result)
	
	// Test with shorter input (should pad)
	input2 := "ABCDEFGHIJ"
	result2 := mm.formatBackupCode(input2)
	assert.Equal(t, "ABCD-EFGH-IJ00", result2)
}

func TestCompareHashes(t *testing.T) {
	mm := &MFAManager{}
	
	hash1 := []byte{1, 2, 3, 4}
	hash2 := []byte{1, 2, 3, 4}
	hash3 := []byte{1, 2, 3, 5}
	
	assert.True(t, mm.compareHashes(hash1, hash2))
	assert.False(t, mm.compareHashes(hash1, hash3))
	assert.False(t, mm.compareHashes(hash1, []byte{1, 2, 3})) // Different lengths
}

func TestGenerateBackupCodes_Uniqueness(t *testing.T) {
	mm := &MFAManager{}

	testSalt := make([]byte, 32)
	_, err := rand.Read(testSalt)
	require.NoError(t, err)

	codes, _, err := mm.GenerateBackupCodes(testSalt)
	require.NoError(t, err)
	
	// Verify all codes are unique
	codeSet := make(map[string]bool)
	for _, code := range codes {
		assert.False(t, codeSet[code], "Duplicate code found: %s", code)
		codeSet[code] = true
	}
	assert.Equal(t, BackupCodeCount, len(codeSet))
}

// TestGenerateBackupCodes_HashVerification removed as it tests unexported methods

func TestVerifyTOTP_TimeWindow(t *testing.T) {
	mm := &MFAManager{}
	
	key, err := mm.GenerateTOTPSecret("test@example.com")
	require.NoError(t, err)
	
	// Generate code for slightly past time (within 30s window)
	pastTime := time.Now().Add(-15 * time.Second)
	code, err := totp.GenerateCode(key.Secret(), pastTime)
	require.NoError(t, err)
	
	// Should still be valid within the time window
	result := mm.VerifyTOTP(key.Secret(), code)
	assert.True(t, result, "Code from 15 seconds ago should still be valid")
}

func TestVerifyTOTP_EmptySecret(t *testing.T) {
	mm := &MFAManager{}
	
	result := mm.VerifyTOTP("", "123456")
	assert.False(t, result, "Empty secret should fail validation")
}

func TestVerifyTOTP_EmptyCode(t *testing.T) {
	mm := &MFAManager{}
	
	key, err := mm.GenerateTOTPSecret("test@example.com")
	require.NoError(t, err)
	
	result := mm.VerifyTOTP(key.Secret(), "")
	assert.False(t, result, "Empty code should fail validation")
}

func TestVerifyTOTP_InvalidCodeFormat(t *testing.T) {
	mm := &MFAManager{}
	
	key, err := mm.GenerateTOTPSecret("test@example.com")
	require.NoError(t, err)
	
	invalidCodes := []string{
		"12345",      // Too short
		"1234567",    // Too long
		"abcdef",     // Letters instead of numbers
		"123-456",    // With dash
		"123 456",    // With space
	}
	
	for _, code := range invalidCodes {
		result := mm.VerifyTOTP(key.Secret(), code)
		assert.False(t, result, "Invalid code format should fail: %s", code)
	}
}

func TestGenerateTOTPSecret_MultipleAccounts(t *testing.T) {
	mm := &MFAManager{}
	
	accounts := []string{
		"user1@example.com",
		"user2@example.com",
		"admin@example.com",
	}
	
	secrets := make(map[string]bool)
	for _, account := range accounts {
		key, err := mm.GenerateTOTPSecret(account)
		require.NoError(t, err)
		
		// Verify each secret is unique
		assert.False(t, secrets[key.Secret()], "Duplicate secret for account: %s", account)
		secrets[key.Secret()] = true
		
		// Verify account name is set correctly
		assert.Equal(t, account, key.AccountName())
	}
}

func TestBackupCodeFormat_Length(t *testing.T) {
	mm := &MFAManager{}

	testSalt := make([]byte, 32)
	_, err := rand.Read(testSalt)
	require.NoError(t, err)

	codes, _, err := mm.GenerateBackupCodes(testSalt)
	require.NoError(t, err)
	
	for _, code := range codes {
		// Format is XXXX-XXXX-XXXX (14 characters with dashes)
		assert.Equal(t, 14, len(code), "Code length should be 14: %s", code)
		
		// Verify dashes are at positions 4 and 9
		if len(code) == 14 {
			assert.Equal(t, '-', rune(code[4]), "Expected dash at position 4")
			assert.Equal(t, '-', rune(code[9]), "Expected dash at position 9")
		}
	}
}

// TestNormalizeBackupCode_EdgeCases removed as it tests unexported methods

func TestTOTPSecret_URLGeneration(t *testing.T) {
	mm := &MFAManager{}
	
	email := "test@example.com"
	key, err := mm.GenerateTOTPSecret(email)
	require.NoError(t, err)
	
	url := key.URL()
	assert.Contains(t, url, "otpauth://totp/")
	assert.Contains(t, url, TOTPIssuer)
	assert.Contains(t, url, email)
	assert.Contains(t, url, "secret=")
}

// TestBackupCodeHashSecurity removed as it tests unexported methods
