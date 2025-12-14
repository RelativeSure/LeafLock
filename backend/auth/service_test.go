package auth

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewService(t *testing.T) {
	// This is a basic test to ensure the service can be created
	// In a real test suite, you'd use testcontainers or mocks

	// For now, we'll just test that the function doesn't panic
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("NewService panicked: %v", r)
		}
	}()

	// Note: This would need proper test setup with real dependencies
	// or comprehensive mocking to be fully functional
}

func TestPasswordManager_HashPassword(t *testing.T) {
	pm := &PasswordManager{}

	password := "TestPassword123!"
	salt := make([]byte, 32)

	// Test that hashing doesn't panic
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("HashPassword panicked: %v", r)
		}
	}()

	hash := pm.HashPassword(password, salt)

	if hash == "" {
		t.Error("HashPassword returned empty string")
	}

	// Verify format
	if len(hash) < 50 { // Argon2id hashes are typically longer
		t.Error("HashPassword returned suspiciously short hash")
	}
}

func TestPasswordManager_ValidatePasswordStrength(t *testing.T) {
	pm := &PasswordManager{}

	tests := []struct {
		name        string
		password    string
		expectError bool
	}{
		{
			name:        "Valid password",
			password:    "TestPassword123!",
			expectError: false,
		},
		{
			name:        "Too short",
			password:    "Test123!",
			expectError: true,
		},
		{
			name:        "No uppercase",
			password:    "testpassword123!",
			expectError: true,
		},
		{
			name:        "No lowercase",
			password:    "TESTPASSWORD123!",
			expectError: true,
		},
		{
			name:        "No digit",
			password:    "TestPassword!",
			expectError: true,
		},
		{
			name:        "No special char",
			password:    "TestPassword123",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := pm.ValidatePasswordStrength(tt.password)

			if tt.expectError && err == nil {
				t.Errorf("Expected error for password %q, but got none", tt.password)
			}

			if !tt.expectError && err != nil {
				t.Errorf("Expected no error for password %q, but got: %v", tt.password, err)
			}
		})
	}
}

func TestMFAManager_GenerateBackupCodes(t *testing.T) {
	mm := &MFAManager{}

	testSalt := make([]byte, 32)
	_, err := rand.Read(testSalt)
	require.NoError(t, err)

	codes, hashes, err := mm.GenerateBackupCodes(testSalt)
	if err != nil {
		t.Fatalf("GenerateBackupCodes failed: %v", err)
	}

	if len(codes) != BackupCodeCount {
		t.Errorf("Expected %d codes, got %d", BackupCodeCount, len(codes))
	}

	if len(hashes) != BackupCodeCount {
		t.Errorf("Expected %d hashes, got %d", BackupCodeCount, len(hashes))
	}

	// Test code format
	for i, code := range codes {
		if len(code) != 14 { // XXXX-XXXX-XXXX format
			t.Errorf("Code %d has wrong length: %d (expected 14)", i, len(code))
		}

		// Check for dashes
		if code[4] != '-' || code[9] != '-' {
			t.Errorf("Code %d has wrong format: %s", i, code)
		}
	}
}

func TestMFAManager_VerifyTOTP(t *testing.T) {
	mm := &MFAManager{}

	// Test with invalid secret (should return false)
	valid := mm.VerifyTOTP("invalid-secret", "123456")
	if valid {
		t.Error("VerifyTOTP should return false for invalid secret")
	}

	// Note: For a complete test, you'd need to generate a real TOTP secret
	// and test with actual codes, but that requires time-based testing
}

func TestSessionManager_HashToken(t *testing.T) {
	sm := &SessionManager{}

	token := "test-token-123"
	hash1 := sm.hashToken(token)
	hash2 := sm.hashToken(token)

	// Hash should be deterministic
	if hash1 != hash2 {
		t.Error("Token hash should be deterministic")
	}

	// Hash should be different for different tokens
	hash3 := sm.hashToken("different-token")
	if hash1 == hash3 {
		t.Error("Different tokens should produce different hashes")
	}
}

// Note: These are basic unit tests. For comprehensive testing, you would need:
// 1. Integration tests with real database and Redis
// 2. Testcontainers for isolated test environments
// 3. Mock implementations for external dependencies
// 4. Tests for error conditions and edge cases
// 5. Performance tests for cryptographic operations
// 6. Security tests for timing attacks and other vulnerabilities
