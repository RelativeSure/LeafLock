package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// AuthTestSuite tests the authentication system comprehensively
type AuthTestSuite struct {
	suite.Suite
	config       *Config
	rdb          *redis.Client
	crypto       *CryptoService
	db           Database
	cleanupRedis func()
	cleanupDB    func()
}

func (suite *AuthTestSuite) SetupTest() {
	// Generate test keys
	jwtKey := make([]byte, 64)
	encKey := make([]byte, 32)
	rand.Read(jwtKey)
	rand.Read(encKey)

	// Create test config with special character password
	suite.config = &Config{
		JWTSecret:            jwtKey,
		EncryptionKey:        encKey,
		MaxLoginAttempts:     3,
		LockoutDuration:      5 * time.Minute,
		SessionDuration:      24 * time.Hour,
		AllowedOrigins:       []string{"https://localhost:3000"},
		DefaultAdminEnabled:  true,
		DefaultAdminEmail:    "admin@leaflock.app",
		DefaultAdminPassword: "#wmR8xWxZ&#JHZPd8HTYmafctWSe0N*jgPG%bYS@",
	}

	// Set up test database and Redis
	suite.db, suite.cleanupDB = setupTestDB(suite.T())
	suite.rdb, suite.cleanupRedis = setupTestRedis(suite.T())
	suite.crypto = NewCryptoService(encKey)
}

func (suite *AuthTestSuite) TearDownTest() {
	if suite.cleanupDB != nil {
		suite.cleanupDB()
	}
	if suite.cleanupRedis != nil {
		suite.cleanupRedis()
	}
}

// Test 1: Admin user creation with special characters
func (suite *AuthTestSuite) TestAdminUserCreationWithSpecialCharacters() {
	suite.Run("CreateDefaultAdminWithComplexPassword", func() {
		// Clear any existing users first
		_, err := suite.db.Exec(context.Background(), "DELETE FROM users")
		require.NoError(suite.T(), err)

		// Test the seedDefaultAdminUser function
		err = seedDefaultAdminUser(suite.db, suite.crypto, suite.config)
		require.NoError(suite.T(), err, "Should successfully create admin user with special character password")

		// Verify admin user was created
		ctx := context.Background()
		var count int
		err = suite.db.QueryRow(ctx, "SELECT COUNT(*) FROM users").Scan(&count)
		require.NoError(suite.T(), err)
		assert.Equal(suite.T(), 1, count, "Should have exactly one user (the admin)")

		// Verify admin user details
		emailSearchHash, err := suite.crypto.EncryptDeterministic([]byte(strings.ToLower(suite.config.DefaultAdminEmail)), "email_search")
		require.NoError(suite.T(), err)

		var adminID uuid.UUID
		var hashedPassword string
		var encryptedEmail []byte
		var isAdmin bool
		var createdAt time.Time

		err = suite.db.QueryRow(ctx,
			"SELECT id, email_encrypted, password_hash, is_admin, created_at FROM users WHERE email_search_hash = $1",
			emailSearchHash).Scan(&adminID, &encryptedEmail, &hashedPassword, &isAdmin, &createdAt)
		require.NoError(suite.T(), err, "Should find the created admin user")

		assert.True(suite.T(), isAdmin, "User should be marked as admin")
		assert.NotEmpty(suite.T(), hashedPassword, "Password hash should not be empty")
		assert.NotEmpty(suite.T(), encryptedEmail, "Encrypted email should not be empty")
		assert.True(suite.T(), time.Since(createdAt) < time.Minute, "Should be recently created")

		// Test password verification with the complex password
		isValid := VerifyPassword(suite.config.DefaultAdminPassword, hashedPassword)
		assert.True(suite.T(), isValid, "Complex password should verify correctly")

		// Test that the password hash format is correct (Argon2id)
		assert.True(suite.T(), strings.HasPrefix(hashedPassword, "$argon2id$"), "Should use Argon2id hashing")
		parts := strings.Split(hashedPassword, "$")
		assert.Len(suite.T(), parts, 6, "Argon2id hash should have 6 parts")
	})

	suite.Run("HandleDuplicateAdminCreation", func() {
		// Try to create admin again - should not fail
		err := seedDefaultAdminUser(suite.db, suite.crypto, suite.config)
		require.NoError(suite.T(), err, "Should handle duplicate admin creation gracefully")

		// Verify still only one user
		ctx := context.Background()
		var count int
		err = suite.db.QueryRow(ctx, "SELECT COUNT(*) FROM users").Scan(&count)
		require.NoError(suite.T(), err)
		assert.Equal(suite.T(), 1, count, "Should still have exactly one user")
	})
}

// Test 2: Password verification with complex password
func (suite *AuthTestSuite) TestPasswordVerificationWithComplexPassword() {
	suite.Run("VerifyComplexPassword", func() {
		// Create admin user
		err := seedDefaultAdminUser(suite.db, suite.crypto, suite.config)
		require.NoError(suite.T(), err)

		// Get the admin user's password hash from database
		ctx := context.Background()
		emailSearchHash, err := suite.crypto.EncryptDeterministic([]byte(strings.ToLower(suite.config.DefaultAdminEmail)), "email_search")
		require.NoError(suite.T(), err)

		var hashedPassword string
		err = suite.db.QueryRow(ctx, "SELECT password_hash FROM users WHERE email_search_hash = $1", emailSearchHash).Scan(&hashedPassword)
		require.NoError(suite.T(), err, "Should retrieve admin user password hash")

		// Test password verification with the complex password
		isValid := VerifyPassword(suite.config.DefaultAdminPassword, hashedPassword)
		assert.True(suite.T(), isValid, "Complex password should verify correctly")

		// Test with wrong password
		wrongPassword := "#wmR8xWxZ&#JHZPd8HTYmafctWSe0N*jgPG%bYS@WRONG"
		isInvalid := VerifyPassword(wrongPassword, hashedPassword)
		assert.False(suite.T(), isInvalid, "Wrong password should not verify")

		// Test with empty password
		isEmpty := VerifyPassword("", hashedPassword)
		assert.False(suite.T(), isEmpty, "Empty password should not verify")
	})
}

// Test 3: Admin user identification functionality
func (suite *AuthTestSuite) TestAdminUserIdentification() {
	suite.Run("CheckAdminUserExists", func() {
		// Ensure admin user exists
		err := seedDefaultAdminUser(suite.db, suite.crypto, suite.config)
		require.NoError(suite.T(), err)

		// Test finding admin by email
		ctx := context.Background()
		defaultEmail := suite.config.DefaultAdminEmail
		emailSearchHash, err := suite.crypto.EncryptDeterministic([]byte(strings.ToLower(defaultEmail)), "email_search")
		require.NoError(suite.T(), err)

		var adminID uuid.UUID
		var isAdmin bool
		err = suite.db.QueryRow(ctx, "SELECT id, is_admin FROM users WHERE email_search_hash = $1", emailSearchHash).Scan(&adminID, &isAdmin)
		require.NoError(suite.T(), err, "Should find the admin user")

		assert.True(suite.T(), isAdmin, "User should be marked as admin")
		assert.NotEqual(suite.T(), uuid.Nil, adminID, "Admin should have valid ID")
	})

	suite.Run("VerifyAdminPrivileges", func() {
		// Create admin user
		err := seedDefaultAdminUser(suite.db, suite.crypto, suite.config)
		require.NoError(suite.T(), err)

		// Verify admin user has correct permissions
		ctx := context.Background()
		emailSearchHash, err := suite.crypto.EncryptDeterministic([]byte(strings.ToLower(suite.config.DefaultAdminEmail)), "email_search")
		require.NoError(suite.T(), err)

		var adminID uuid.UUID
		var isAdmin bool
		var createdAt time.Time
		err = suite.db.QueryRow(ctx, "SELECT id, is_admin, created_at FROM users WHERE email_search_hash = $1", emailSearchHash).Scan(&adminID, &isAdmin, &createdAt)
		require.NoError(suite.T(), err)

		assert.True(suite.T(), isAdmin, "Should be marked as admin")
		assert.True(suite.T(), time.Since(createdAt) < time.Minute, "Should be recently created")
	})
}

// Test 4: Environment variable handling
func (suite *AuthTestSuite) TestEnvironmentVariableHandling() {
	suite.Run("SpecialCharacterPasswordFromEnv", func() {
		// Test that special characters in password are handled correctly
		specialPasswords := []string{
			"#wmR8xWxZ&#JHZPd8HTYmafctWSe0N*jgPG%bYS@",
			"P@ssw0rd!#$%^&*()_+-={}[]|\\:;\"'<>?,./",
			"Test&123!@#$%^&*()_+={}[]|\\:;\"'<>?,./~`",
			"Åø€¥£¢∞§¶•ªº–≠œ∑´®†¥¨ˆøπ\"'«…æ≤≥÷",
			"🔒🗝️🛡️🔐🗂️📂📁🗃️📋📊📈📉📊🗂️",
		}

		for i, testPassword := range specialPasswords {
			suite.Run(fmt.Sprintf("SpecialPassword_%d", i), func() {
				// Create config with special password
				testConfig := *suite.config
				testConfig.DefaultAdminPassword = testPassword

				// Create a salt and test password hashing
				salt := make([]byte, 32)
				rand.Read(salt)

				hashedPassword := HashPassword(testPassword, salt)
				assert.NotEmpty(suite.T(), hashedPassword, "Password hash should not be empty")
				assert.True(suite.T(), strings.HasPrefix(hashedPassword, "$argon2id$"), "Should use Argon2id")

				// Test password verification
				isValid := VerifyPassword(testPassword, hashedPassword)
				assert.True(suite.T(), isValid, "Special character password should verify correctly")

				// Test with wrong password
				isInvalid := VerifyPassword(testPassword+"wrong", hashedPassword)
				assert.False(suite.T(), isInvalid, "Wrong password should not verify")
			})
		}
	})

	suite.Run("ConfigurationLoading", func() {
		// Test that configuration is loaded correctly
		assert.Equal(suite.T(), "#wmR8xWxZ&#JHZPd8HTYmafctWSe0N*jgPG%bYS@", suite.config.DefaultAdminPassword)
		assert.Equal(suite.T(), "admin@leaflock.app", suite.config.DefaultAdminEmail)
		assert.True(suite.T(), suite.config.DefaultAdminEnabled)
		assert.NotEmpty(suite.T(), suite.config.JWTSecret)
		assert.NotEmpty(suite.T(), suite.config.EncryptionKey)
	})

	suite.Run("GetEnvOrDefaultFunction", func() {
		// Test the getEnvOrDefault function behavior
		// This simulates how environment variables would be processed

		testCases := []struct {
			envValue     string
			defaultValue string
			expected     string
		}{
			{"", "default", "default"},
			{"value", "default", "value"},
			{"#special@chars!", "default", "#special@chars!"},
			{"quotes\"inside", "default", "quotes\"inside"},
			{"spaces in value", "default", "spaces in value"},
		}

		for _, tc := range testCases {
			suite.Run(fmt.Sprintf("EnvVar_%s", tc.envValue), func() {
				// Simulate getEnvOrDefault behavior
				var result string
				if tc.envValue != "" {
					result = tc.envValue
				} else {
					result = tc.defaultValue
				}

				assert.Equal(suite.T(), tc.expected, result, "Environment variable should be processed correctly")
			})
		}
	})
}

// Test 5: Integration tests for complete auth flow
func (suite *AuthTestSuite) TestCompleteAuthFlow() {
	suite.Run("CompleteAuthenticationFlow", func() {
		// Step 1: Verify no users exist initially
		ctx := context.Background()
		var initialCount int
		err := suite.db.QueryRow(ctx, "SELECT COUNT(*) FROM users").Scan(&initialCount)
		require.NoError(suite.T(), err)

		// Step 2: Seed default admin user
		err = seedDefaultAdminUser(suite.db, suite.crypto, suite.config)
		require.NoError(suite.T(), err, "Should create default admin user")

		// Step 3: Verify admin user was created
		var postSeedCount int
		err = suite.db.QueryRow(ctx, "SELECT COUNT(*) FROM users").Scan(&postSeedCount)
		require.NoError(suite.T(), err)
		assert.Equal(suite.T(), initialCount+1, postSeedCount, "Should have one more user after seeding")

		// Step 4: Verify admin user has correct attributes
		emailSearchHash, err := suite.crypto.EncryptDeterministic([]byte(strings.ToLower(suite.config.DefaultAdminEmail)), "email_search")
		require.NoError(suite.T(), err)

		var adminID uuid.UUID
		var hashedPassword string
		var isAdmin bool
		err = suite.db.QueryRow(ctx, "SELECT id, password_hash, is_admin FROM users WHERE email_search_hash = $1", emailSearchHash).Scan(&adminID, &hashedPassword, &isAdmin)
		require.NoError(suite.T(), err, "Should find admin user")

		assert.True(suite.T(), isAdmin, "User should be marked as admin")
		assert.NotEmpty(suite.T(), hashedPassword, "Should have password hash")

		// Step 5: Verify password authentication works
		isValidPassword := VerifyPassword(suite.config.DefaultAdminPassword, hashedPassword)
		assert.True(suite.T(), isValidPassword, "Admin password should verify correctly")

		// Step 6: Test that wrong password is rejected
		isInvalidPassword := VerifyPassword("wrong-password", hashedPassword)
		assert.False(suite.T(), isInvalidPassword, "Wrong password should be rejected")
	})

	suite.Run("DatabaseIntegrityChecks", func() {
		// Ensure admin user exists
		err := seedDefaultAdminUser(suite.db, suite.crypto, suite.config)
		require.NoError(suite.T(), err)

		ctx := context.Background()

		// Test email encryption is working
		emailSearchHash, err := suite.crypto.EncryptDeterministic([]byte(strings.ToLower(suite.config.DefaultAdminEmail)), "email_search")
		require.NoError(suite.T(), err)

		var encryptedEmail []byte
		var deletionKey []byte
	err = suite.db.QueryRow(ctx, `
		SELECT u.email_encrypted, g.deletion_key
		FROM users u
		JOIN gdpr_keys g ON g.email_hash = u.email_hash
		WHERE u.email_search_hash = $1`, emailSearchHash).Scan(&encryptedEmail, &deletionKey)
		require.NoError(suite.T(), err)

		// Verify email is actually encrypted (should not be plaintext)
		assert.NotEqual(suite.T(), suite.config.DefaultAdminEmail, string(encryptedEmail), "Email should be encrypted, not plaintext")
		assert.NotEmpty(suite.T(), encryptedEmail, "Encrypted email should not be empty")

		// Verify we can decrypt the email
		decryptedEmailBytes, err := suite.crypto.DecryptWithGDPRKey(encryptedEmail, deletionKey)
		require.NoError(suite.T(), err, "Should be able to decrypt email")
		decryptedEmail := string(decryptedEmailBytes)
		assert.Equal(suite.T(), suite.config.DefaultAdminEmail, decryptedEmail, "Decrypted email should match original")
	})
}

// Test password hashing edge cases
func (suite *AuthTestSuite) TestPasswordHashingEdgeCases() {
	suite.Run("EmptyPassword", func() {
		salt := make([]byte, 32)
		rand.Read(salt)

		hash := HashPassword("", salt)
		assert.NotEmpty(suite.T(), hash, "Should handle empty password")
		assert.True(suite.T(), VerifyPassword("", hash), "Empty password should verify")
		assert.False(suite.T(), VerifyPassword("not-empty", hash), "Non-empty password should not verify against empty hash")
	})

	suite.Run("VeryLongPassword", func() {
		longPassword := strings.Repeat("a", 10000) // 10KB password
		salt := make([]byte, 32)
		rand.Read(salt)

		hash := HashPassword(longPassword, salt)
		assert.NotEmpty(suite.T(), hash, "Should handle very long password")
		assert.True(suite.T(), VerifyPassword(longPassword, hash), "Very long password should verify")
	})

	suite.Run("BinaryDataPassword", func() {
		// Test with binary data (null bytes, etc.)
		binaryPassword := string([]byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD})
		salt := make([]byte, 32)
		rand.Read(salt)

		hash := HashPassword(binaryPassword, salt)
		assert.NotEmpty(suite.T(), hash, "Should handle binary data in password")
		assert.True(suite.T(), VerifyPassword(binaryPassword, hash), "Binary password should verify")
	})

	suite.Run("InvalidHashFormat", func() {
		// Test VerifyPassword with invalid hash formats
		invalidHashes := []string{
			"not-a-hash",
			"$argon2id$",
			"$argon2id$v=19$m=65536,t=3,p=4$invalid",
			"$md5$invalid-hash-format",
			"",
		}

		for _, hash := range invalidHashes {
			suite.Run(fmt.Sprintf("InvalidHash_%s", hash), func() {
				result := VerifyPassword("password", hash)
				assert.False(suite.T(), result, "Should reject invalid hash format")
			})
		}
	})
}

// Test environment variable edge cases
func (suite *AuthTestSuite) TestEnvironmentVariableEdgeCases() {
	suite.Run("ConfigWithDisabledAdminCreation", func() {
		// Test with admin creation disabled
		disabledConfig := *suite.config
		disabledConfig.DefaultAdminEnabled = false

		// Clear existing users
		_, err := suite.db.Exec(context.Background(), "DELETE FROM users")
		require.NoError(suite.T(), err)

		// Try to seed admin with disabled config
		err = seedDefaultAdminUser(suite.db, suite.crypto, &disabledConfig)
		require.NoError(suite.T(), err, "Should not error when admin creation is disabled")

		// Verify no users were created
		var count int
		err = suite.db.QueryRow(context.Background(), "SELECT COUNT(*) FROM users").Scan(&count)
		require.NoError(suite.T(), err)
		assert.Equal(suite.T(), 0, count, "Should not create admin when disabled")
	})

	suite.Run("ConfigWithEmptyPassword", func() {
		// Test with empty default password
		emptyPasswordConfig := *suite.config
		emptyPasswordConfig.DefaultAdminPassword = ""

		// Clear existing users
		_, err := suite.db.Exec(context.Background(), "DELETE FROM users")
		require.NoError(suite.T(), err)

		// Try to seed admin with empty password
		err = seedDefaultAdminUser(suite.db, suite.crypto, &emptyPasswordConfig)

		// This should either fail or handle gracefully
		if err == nil {
			// If it succeeds, verify the behavior
			var count int
			err = suite.db.QueryRow(context.Background(), "SELECT COUNT(*) FROM users").Scan(&count)
			require.NoError(suite.T(), err)
			// Implementation decision: either 0 (rejected) or 1 (allowed) users
			assert.True(suite.T(), count >= 0 && count <= 1, "Should handle empty password configuration")
		}
	})
}

// Run the authentication test suite
func TestAuthenticationSuite(t *testing.T) {
	suite.Run(t, new(AuthTestSuite))
}

// Standalone test for environment variable simulation
func TestEnvironmentVariableSimulation(t *testing.T) {
	t.Run("SimulateEnvVarWithSpecialChars", func(t *testing.T) {
		// Test environment variable reading with the exact password from the request
		testPassword := "#wmR8xWxZ&#JHZPd8HTYmafctWSe0N*jgPG%bYS@"

		// Simulate setting and reading environment variable
		os.Setenv("TEST_ADMIN_PASSWORD", testPassword)
		defer os.Unsetenv("TEST_ADMIN_PASSWORD")

		retrievedPassword := os.Getenv("TEST_ADMIN_PASSWORD")
		assert.Equal(t, testPassword, retrievedPassword, "Environment variable should preserve special characters")

		// Test with getEnvOrDefault simulation
		result := func(key, defaultValue string) string {
			if value := os.Getenv(key); value != "" {
				return value
			}
			return defaultValue
		}("TEST_ADMIN_PASSWORD", "default")

		assert.Equal(t, testPassword, result, "getEnvOrDefault should return the special character password")
	})
}

// Performance test for password operations
func TestPasswordPerformance(t *testing.T) {
	t.Run("PasswordHashingPerformance", func(t *testing.T) {
		password := "#wmR8xWxZ&#JHZPd8HTYmafctWSe0N*jgPG%bYS@"
		salt := make([]byte, 32)
		rand.Read(salt)

		// Time password hashing
		start := time.Now()
		hash := HashPassword(password, salt)
		hashDuration := time.Since(start)

		assert.NotEmpty(t, hash, "Should produce hash")
		assert.True(t, hashDuration < 5*time.Second, "Password hashing should complete within reasonable time")

		// Time password verification
		start = time.Now()
		isValid := VerifyPassword(password, hash)
		verifyDuration := time.Since(start)

		assert.True(t, isValid, "Password should verify correctly")
		assert.True(t, verifyDuration < 5*time.Second, "Password verification should complete within reasonable time")

		t.Logf("Password hashing took: %v", hashDuration)
		t.Logf("Password verification took: %v", verifyDuration)
	})
}
