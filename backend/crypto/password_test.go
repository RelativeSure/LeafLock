package crypto

import (
	"crypto/rand"
	"strings"
	"testing"
)

// TestHashPassword tests password hashing functionality
func TestHashPassword(t *testing.T) {
	password := "SecurePassword123!"
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	hash := HashPassword(password, salt)

	// Verify hash format
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Error("Hash should start with $argon2id$")
	}

	// Verify hash has correct number of parts
	parts := strings.Split(hash, "$")
	if len(parts) != 6 {
		t.Errorf("Hash should have 6 parts, got %d", len(parts))
	}

	// Verify algorithm identifier
	if parts[1] != "argon2id" {
		t.Errorf("Expected algorithm argon2id, got %s", parts[1])
	}
}

// TestHashPasswordDeterministic tests that same password and salt produce same hash
func TestHashPasswordDeterministic(t *testing.T) {
	password := "TestPassword123"
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	hash1 := HashPassword(password, salt)
	hash2 := HashPassword(password, salt)

	if hash1 != hash2 {
		t.Error("Same password and salt should produce same hash")
	}
}

// TestHashPasswordDifferentSalts tests that different salts produce different hashes
func TestHashPasswordDifferentSalts(t *testing.T) {
	password := "SamePassword123"

	salt1 := make([]byte, 16)
	_, err := rand.Read(salt1)
	if err != nil {
		t.Fatalf("Failed to generate salt1: %v", err)
	}

	salt2 := make([]byte, 16)
	_, err = rand.Read(salt2)
	if err != nil {
		t.Fatalf("Failed to generate salt2: %v", err)
	}

	hash1 := HashPassword(password, salt1)
	hash2 := HashPassword(password, salt2)

	if hash1 == hash2 {
		t.Error("Different salts should produce different hashes")
	}
}

// TestVerifyPassword tests password verification with correct password
func TestVerifyPassword(t *testing.T) {
	password := "CorrectPassword123!"
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	hash := HashPassword(password, salt)

	if !VerifyPassword(password, hash) {
		t.Error("VerifyPassword should return true for correct password")
	}
}

// TestVerifyPasswordIncorrect tests password verification with incorrect password
func TestVerifyPasswordIncorrect(t *testing.T) {
	password := "CorrectPassword123!"
	wrongPassword := "WrongPassword123!"
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	hash := HashPassword(password, salt)

	if VerifyPassword(wrongPassword, hash) {
		t.Error("VerifyPassword should return false for incorrect password")
	}
}

// TestVerifyPasswordCaseSensitive tests that password verification is case-sensitive
func TestVerifyPasswordCaseSensitive(t *testing.T) {
	password := "CaseSensitive123"
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	hash := HashPassword(password, salt)

	// Try with different case
	if VerifyPassword("casesensitive123", hash) {
		t.Error("Password verification should be case-sensitive")
	}

	if VerifyPassword("CASESENSITIVE123", hash) {
		t.Error("Password verification should be case-sensitive")
	}
}

// TestVerifyPasswordInvalidFormat tests verification with malformed hash
func TestVerifyPasswordInvalidFormat(t *testing.T) {
	password := "SomePassword123"

	testCases := []struct {
		name string
		hash string
	}{
		{"empty hash", ""},
		{"invalid format", "not-a-valid-hash"},
		{"too few parts", "$argon2id$v=19$m=65536"},
		{"wrong algorithm", "$bcrypt$v=19$m=65536,t=3,p=4$salt$hash"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if VerifyPassword(password, tc.hash) {
				t.Errorf("VerifyPassword should return false for %s", tc.name)
			}
		})
	}
}

// TestHashPasswordEmptyPassword tests hashing of empty password
func TestHashPasswordEmptyPassword(t *testing.T) {
	password := ""
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	hash := HashPassword(password, salt)

	// Verify it creates a valid hash
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Error("Empty password should still produce valid hash")
	}

	// Verify it can be verified
	if !VerifyPassword(password, hash) {
		t.Error("Empty password should verify correctly")
	}
}

// TestHashPasswordSpecialCharacters tests password with special characters
func TestHashPasswordSpecialCharacters(t *testing.T) {
	passwords := []string{
		"P@ssw0rd!",
		"Test#123$%^",
		"Unicode密码测试",
		"Emoji😀🔒🔑",
		"Newline\nPassword",
		"Tab\tPassword",
	}

	for _, password := range passwords {
		t.Run(password, func(t *testing.T) {
			salt := make([]byte, 16)
			_, err := rand.Read(salt)
			if err != nil {
				t.Fatalf("Failed to generate salt: %v", err)
			}

			hash := HashPassword(password, salt)

			if !VerifyPassword(password, hash) {
				t.Errorf("Password with special characters should verify: %s", password)
			}
		})
	}
}

// TestHashPasswordLongPassword tests very long passwords
func TestHashPasswordLongPassword(t *testing.T) {
	// Create a 1000 character password
	password := strings.Repeat("LongPassword123!", 62) + "Long" // 1000 chars

	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	hash := HashPassword(password, salt)

	if !VerifyPassword(password, hash) {
		t.Error("Long password should verify correctly")
	}
}

// TestHashPasswordDifferentPasswords tests that different passwords produce different hashes
func TestHashPasswordDifferentPasswords(t *testing.T) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	hash1 := HashPassword("Password1", salt)
	hash2 := HashPassword("Password2", salt)

	if hash1 == hash2 {
		t.Error("Different passwords should produce different hashes (with same salt)")
	}
}

// TestVerifyPasswordTimingAttackResistance tests that verification uses constant-time comparison
// Note: This is a basic test; true timing attack testing requires statistical analysis
func TestVerifyPasswordTimingAttackResistance(t *testing.T) {
	password := "SecurePassword123"
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	hash := HashPassword(password, salt)

	// These should all fail in constant time
	testPasswords := []string{
		"S",                         // Very short
		"SecurePassword12",          // Almost correct
		"SecurePassword123!",        // One char extra
		"WrongPasswordXXX",          // Completely wrong
		"",                          // Empty
		strings.Repeat("X", 100),    // Very long wrong password
	}

	for _, testPwd := range testPasswords {
		if VerifyPassword(testPwd, hash) {
			t.Errorf("VerifyPassword should return false for: %s", testPwd)
		}
	}
}

// TestHashPasswordParameters tests that hash contains expected Argon2 parameters
func TestHashPasswordParameters(t *testing.T) {
	password := "TestPassword123"
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	hash := HashPassword(password, salt)
	parts := strings.Split(hash, "$")

	if len(parts) != 6 {
		t.Fatalf("Expected 6 parts in hash, got %d", len(parts))
	}

	// Check parameters part (format: m=65536,t=3,p=4)
	params := parts[3]
	expectedParams := "m=65536,t=3,p=4"
	if params != expectedParams {
		t.Errorf("Expected parameters %s, got %s", expectedParams, params)
	}

	// Check version part
	expectedVersion := "v=19" // Argon2 version 19
	if parts[2] != expectedVersion {
		t.Errorf("Expected version %s, got %s", expectedVersion, parts[2])
	}
}

// BenchmarkHashPassword benchmarks password hashing performance
func BenchmarkHashPassword(b *testing.B) {
	password := "BenchmarkPassword123!"
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		b.Fatalf("Failed to generate random data: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = HashPassword(password, salt)
	}
}

// BenchmarkVerifyPassword benchmarks password verification performance
func BenchmarkVerifyPassword(b *testing.B) {
	password := "BenchmarkPassword123!"
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		b.Fatalf("Failed to generate random data: %v", err)
	}
	hash := HashPassword(password, salt)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = VerifyPassword(password, hash)
	}
}

// BenchmarkHashPasswordParallel benchmarks parallel password hashing
func BenchmarkHashPasswordParallel(b *testing.B) {
	password := "ParallelPassword123!"

	b.RunParallel(func(pb *testing.PB) {
		salt := make([]byte, 16)
		if _, err := rand.Read(salt); err != nil {
			b.Fatalf("Failed to generate random data: %v", err)
		}

		for pb.Next() {
			_ = HashPassword(password, salt)
		}
	})
}

// BenchmarkVerifyPasswordParallel benchmarks parallel password verification
func BenchmarkVerifyPasswordParallel(b *testing.B) {
	password := "ParallelPassword123!"
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		b.Fatalf("Failed to generate random data: %v", err)
	}
	hash := HashPassword(password, salt)

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = VerifyPassword(password, hash)
		}
	})
}