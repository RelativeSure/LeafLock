package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"testing"
	"golang.org/x/crypto/argon2"
	"crypto/subtle"
	"strings"
)

func TestDebugPasswordFlow(t *testing.T) {
	// Test the exact password from logs
	passwords := []string{
		"#wmR8xWxZ&#JHZPd8HTYmafctWSe0N*jgPG%bYS@", // Complex test password
		"AdminPass123!",                              // Default from .env
	}

	for _, password := range passwords {
		t.Logf("\n========== Testing password: %s ==========", password)
		t.Logf("Password length: %d", len(password))
		t.Logf("Password bytes: %v", []byte(password))

		// Generate salt like in seedDefaultAdminUser
		salt := make([]byte, 32)
		if _, err := rand.Read(salt); err != nil {
			t.Fatalf("Failed to generate salt: %v", err)
		}

		// Hash password using the HashPassword function
		hash := HashPasswordDebug(password, salt, t)
		t.Logf("Generated hash: %s", hash)

		// Verify the password
		isValid := VerifyPasswordDebug(password, hash, t)
		if !isValid {
			t.Errorf("Password verification failed for: %s", password)
		} else {
			t.Logf("✅ Password verification succeeded")
		}

		// Test with wrong password
		wrongPassword := password + "wrong"
		isInvalid := VerifyPasswordDebug(wrongPassword, hash, t)
		if isInvalid {
			t.Errorf("Wrong password should not verify: %s", wrongPassword)
		} else {
			t.Logf("✅ Wrong password correctly rejected")
		}
	}
}

// Copy of HashPassword with debug logging
func HashPasswordDebug(password string, salt []byte, t *testing.T) string {
	t.Logf("Hashing password:")
	t.Logf("  - Input password: %s", password)
	t.Logf("  - Input password bytes: %v", []byte(password))
	t.Logf("  - Salt length: %d", len(salt))

	hash := argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, 32)
	t.Logf("  - Generated hash length: %d", len(hash))

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	result := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, 64*1024, 3, 4, b64Salt, b64Hash)

	t.Logf("  - Final hash format: %s", result)
	return result
}

// Copy of VerifyPassword with debug logging
func VerifyPasswordDebug(password, encodedHash string, t *testing.T) bool {
	t.Logf("Verifying password:")
	t.Logf("  - Input password: %s", password)
	t.Logf("  - Input password bytes: %v", []byte(password))

	parts := strings.Split(encodedHash, "$")
	t.Logf("  - Hash parts count: %d", len(parts))

	if len(parts) != 6 {
		t.Logf("  - ERROR: Invalid hash format (expected 6 parts)")
		return false
	}

	salt, err1 := base64.RawStdEncoding.DecodeString(parts[4])
	hash, err2 := base64.RawStdEncoding.DecodeString(parts[5])

	if err1 != nil {
		t.Logf("  - ERROR decoding salt: %v", err1)
		return false
	}
	if err2 != nil {
		t.Logf("  - ERROR decoding hash: %v", err2)
		return false
	}

	t.Logf("  - Decoded salt length: %d", len(salt))
	t.Logf("  - Decoded hash length: %d", len(hash))

	comparisonHash := argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, 32)
	t.Logf("  - Generated comparison hash length: %d", len(comparisonHash))

	result := subtle.ConstantTimeCompare(hash, comparisonHash) == 1
	t.Logf("  - Comparison result: %v", result)

	return result
}

func TestPasswordEnvironmentHandling(t *testing.T) {
	// Simulate what happens when password comes from environment variable
	envPassword := "#wmR8xWxZ&#JHZPd8HTYmafctWSe0N*jgPG%bYS@"

	t.Logf("Original password: %s", envPassword)
	t.Logf("Password length: %d", len(envPassword))
	t.Logf("Password bytes: %v", []byte(envPassword))

	// Test if any characters might be escaped or modified
	for i, char := range envPassword {
		t.Logf("  Char %d: '%c' (byte: %d)", i, char, byte(char))
	}
}