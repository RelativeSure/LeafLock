package auth

import (
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
	
	codes, hashes, err := mm.GenerateBackupCodes()
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
