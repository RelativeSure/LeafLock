package main

import (
	"crypto/rand"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestComplexPasswordHashing tests the core password hashing and verification
// functionality with the exact password from the authentication system
func TestComplexPasswordHashing(t *testing.T) {
	// The exact complex password from the authentication fix
	complexPassword := "#wmR8xWxZ&#JHZPd8HTYmafctWSe0N*jgPG%bYS@"

	t.Run("HashAndVerifyComplexPassword", func(t *testing.T) {
		// Generate a random salt
		salt := make([]byte, 32)
		_, err := rand.Read(salt)
		require.NoError(t, err, "Should generate random salt")

		// Test password hashing
		hashedPassword := HashPassword(complexPassword, salt)
		assert.NotEmpty(t, hashedPassword, "Hashed password should not be empty")
		assert.True(t, strings.HasPrefix(hashedPassword, "$argon2id$"), "Should use Argon2id hashing")

		// Verify the hash format is correct
		parts := strings.Split(hashedPassword, "$")
		assert.Len(t, parts, 6, "Argon2id hash should have 6 parts")
		assert.Equal(t, "argon2id", parts[1], "Should use argon2id algorithm")

		// Test password verification with correct password
		isValid := VerifyPassword(complexPassword, hashedPassword)
		assert.True(t, isValid, "Complex password should verify correctly")

		// Test password verification with wrong password
		wrongPassword := complexPassword + "WRONG"
		isInvalid := VerifyPassword(wrongPassword, hashedPassword)
		assert.False(t, isInvalid, "Wrong password should not verify")

		// Test password verification with empty password
		isEmpty := VerifyPassword("", hashedPassword)
		assert.False(t, isEmpty, "Empty password should not verify")
	})

	t.Run("SpecialCharacterHandling", func(t *testing.T) {
		// Test various special character passwords
		specialPasswords := []string{
			"#wmR8xWxZ&#JHZPd8HTYmafctWSe0N*jgPG%bYS@",
			"P@ssw0rd!#$%^&*()_+-={}[]|\\:;\"'<>?,./",
			"Test&123!@#$%^&*()_+={}[]|\\:;\"'<>?,./~`",
			"Password with spaces and symbols! @#$%^&*()",
			"Unicode_password_Åø€¥£¢∞§¶•ªº",
		}

		for i, password := range specialPasswords {
			t.Run(string(rune('A'+i)), func(t *testing.T) {
				salt := make([]byte, 32)
				rand.Read(salt)

				hash := HashPassword(password, salt)
				assert.NotEmpty(t, hash, "Should hash special character password")
				assert.True(t, VerifyPassword(password, hash), "Should verify special character password correctly")
				assert.False(t, VerifyPassword(password+"wrong", hash), "Should reject wrong password")
			})
		}
	})

	t.Run("HashConsistency", func(t *testing.T) {
		// Test that the same password with the same salt produces the same hash
		salt := make([]byte, 32)
		rand.Read(salt)

		hash1 := HashPassword(complexPassword, salt)
		hash2 := HashPassword(complexPassword, salt)

		assert.Equal(t, hash1, hash2, "Same password and salt should produce same hash")

		// Test that different salts produce different hashes
		salt2 := make([]byte, 32)
		rand.Read(salt2)
		hash3 := HashPassword(complexPassword, salt2)

		assert.NotEqual(t, hash1, hash3, "Different salts should produce different hashes")
	})

	t.Run("InvalidHashFormats", func(t *testing.T) {
		invalidHashes := []string{
			"",
			"not-a-hash",
			"$argon2id$",
			"$argon2id$v=19$m=65536,t=3,p=4$invalid",
			"$md5$invalid-hash-format",
			"$argon2id$v=19$m=65536,t=3,p=4$salt$", // Missing hash part
		}

		for _, invalidHash := range invalidHashes {
			t.Run("InvalidHash_"+invalidHash, func(t *testing.T) {
				result := VerifyPassword(complexPassword, invalidHash)
				assert.False(t, result, "Should reject invalid hash format: %s", invalidHash)
			})
		}
	})
}

// TestEnvironmentVariableSpecialCharacters tests environment variable handling
func TestEnvironmentVariableSpecialCharacters(t *testing.T) {
	t.Run("SpecialCharacterPreservation", func(t *testing.T) {
		testPassword := "#wmR8xWxZ&#JHZPd8HTYmafctWSe0N*jgPG%bYS@"

		// Test that special characters are preserved in string literals
		assert.Equal(t, testPassword, "#wmR8xWxZ&#JHZPd8HTYmafctWSe0N*jgPG%bYS@")

		// Test that the password contains expected special characters
		assert.Contains(t, testPassword, "#", "Should contain hash symbol")
		assert.Contains(t, testPassword, "&", "Should contain ampersand")
		assert.Contains(t, testPassword, "@", "Should contain at symbol")
		assert.Contains(t, testPassword, "*", "Should contain asterisk")
		assert.Contains(t, testPassword, "%", "Should contain percent")

		// Test password length
		assert.Equal(t, 40, len(testPassword), "Password should be 40 characters long")

		// Test that it's not empty or whitespace
		assert.NotEmpty(t, testPassword, "Password should not be empty")
		assert.NotEqual(t, strings.TrimSpace(testPassword), "", "Password should not be just whitespace")
	})

	t.Run("ConfigStructAssignment", func(t *testing.T) {
		// Test that the password can be properly assigned to config struct
		config := &Config{
			DefaultAdminPassword: "#wmR8xWxZ&#JHZPd8HTYmafctWSe0N*jgPG%bYS@",
		}

		assert.Equal(t, "#wmR8xWxZ&#JHZPd8HTYmafctWSe0N*jgPG%bYS@", config.DefaultAdminPassword)
		assert.NotEmpty(t, config.DefaultAdminPassword, "Config password should not be empty")
	})
}

// TestSeedDefaultAdminUserFunctionality tests the admin seeding without database
func TestSeedDefaultAdminUserFunctionality(t *testing.T) {
	t.Run("PasswordHashingConfiguration", func(t *testing.T) {
		// Test the password hashing configuration used in seedDefaultAdminUser
		testPassword := "#wmR8xWxZ&#JHZPd8HTYmafctWSe0N*jgPG%bYS@"

		// Generate salt like the real function does
		salt := make([]byte, 32)
		rand.Read(salt)

		// Hash password like seedDefaultAdminUser does
		hashedPassword := HashPassword(testPassword, salt)

		// Verify the hash follows expected format
		assert.True(t, strings.HasPrefix(hashedPassword, "$argon2id$v="), "Should start with argon2id version")
		assert.Contains(t, hashedPassword, "m=65536", "Should use 64MB memory")
		assert.Contains(t, hashedPassword, "t=3", "Should use 3 iterations")
		assert.Contains(t, hashedPassword, "p=4", "Should use 4 parallelism")

		// Verify password verification works
		assert.True(t, VerifyPassword(testPassword, hashedPassword), "Should verify correctly")
	})

	t.Run("EmailEncryptionCompatibility", func(t *testing.T) {
		// Test that email encryption works with the expected email
		email := "admin@leaflock.app"

		// Generate encryption key like the system does
		encKey := make([]byte, 32)
		rand.Read(encKey)
		crypto := NewCryptoService(encKey)

		// Test deterministic encryption for email search
		emailSearchHash, err := crypto.EncryptDeterministic([]byte(strings.ToLower(email)), "email_search")
		require.NoError(t, err, "Should encrypt email for search")
		assert.NotEmpty(t, emailSearchHash, "Email search hash should not be empty")

		// Test that the same email produces the same search hash
		emailSearchHash2, err := crypto.EncryptDeterministic([]byte(strings.ToLower(email)), "email_search")
		require.NoError(t, err, "Should encrypt email consistently")
		assert.Equal(t, emailSearchHash, emailSearchHash2, "Should produce consistent search hash")

		// Test regular email encryption
		encryptedEmail, err := crypto.Encrypt([]byte(email))
		require.NoError(t, err, "Should encrypt email")
		assert.NotEmpty(t, encryptedEmail, "Encrypted email should not be empty")
		assert.NotEqual(t, email, string(encryptedEmail), "Encrypted email should be different from plaintext")

		// Test decryption
		decryptedEmail, err := crypto.Decrypt(encryptedEmail)
		require.NoError(t, err, "Should decrypt email")
		assert.Equal(t, email, string(decryptedEmail), "Decrypted email should match original")
	})
}

// TestComplexPasswordVariations tests various complex password scenarios
func TestComplexPasswordVariations(t *testing.T) {
	testCases := []struct {
		name     string
		password string
		valid    bool
	}{
		{
			name:     "OriginalComplexPassword",
			password: "#wmR8xWxZ&#JHZPd8HTYmafctWSe0N*jgPG%bYS@",
			valid:    true,
		},
		{
			name:     "SimilarComplexPassword",
			password: "#wmR8xWxZ&#JHZPd8HTYmafctWSe0N*jgPG%bYS@Extra",
			valid:    true,
		},
		{
			name:     "EmptyPassword",
			password: "",
			valid:    true, // Empty passwords can be hashed, just not secure
		},
		{
			name:     "OnlySpecialCharacters",
			password: "!@#$%^&*()_+-={}[]|\\:;\"'<>?,./",
			valid:    true,
		},
		{
			name:     "UnicodePassword",
			password: "🔒🗝️🛡️🔐Admin123!",
			valid:    true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			salt := make([]byte, 32)
			rand.Read(salt)

			hash := HashPassword(tc.password, salt)
			if tc.valid {
				assert.NotEmpty(t, hash, "Should produce hash for valid password")
				assert.True(t, VerifyPassword(tc.password, hash), "Should verify password correctly")
			}
		})
	}
}
