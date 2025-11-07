package auth

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// PasswordManagerTestSuite tests PasswordManager
type PasswordManagerTestSuite struct {
	suite.Suite
	pm     *PasswordManager
	mockDB *MockDB
}

func (suite *PasswordManagerTestSuite) SetupTest() {
	suite.mockDB = &MockDB{}

	suite.pm = NewPasswordManager(suite.mockDB)
}

func TestPasswordManagerTestSuite(t *testing.T) {
	suite.Run(t, new(PasswordManagerTestSuite))
}

// =====================================
// Test HashPassword and VerifyPassword
// =====================================

func (suite *PasswordManagerTestSuite) TestHashPassword_ValidPassword() {
	password := "MySecureP@ssw0rd123!"
	salt := make([]byte, 32)
	_, err := rand.Read(salt)
	require.NoError(suite.T(), err)

	hash := suite.pm.HashPassword(password, salt)

	// Verify format: $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
	assert.Contains(suite.T(), hash, "$argon2id$v=19$")
	assert.Contains(suite.T(), hash, fmt.Sprintf("m=%d", Argon2Memory))
	assert.Contains(suite.T(), hash, fmt.Sprintf("t=%d", Argon2Time))
	assert.Contains(suite.T(), hash, fmt.Sprintf("p=%d", Argon2Threads))

	// Verify salt is base64 encoded in hash
	saltB64 := base64.RawStdEncoding.EncodeToString(salt)
	assert.Contains(suite.T(), hash, saltB64)
}

func (suite *PasswordManagerTestSuite) TestHashPassword_Deterministic() {
	password := "TestPassword123!"
	salt := make([]byte, 32)
	_, err := rand.Read(salt)
	require.NoError(suite.T(), err)

	hash1 := suite.pm.HashPassword(password, salt)
	hash2 := suite.pm.HashPassword(password, salt)

	// Same password and salt should produce identical hash
	assert.Equal(suite.T(), hash1, hash2)
}

func (suite *PasswordManagerTestSuite) TestHashPassword_DifferentPasswords() {
	salt := make([]byte, 32)
	_, err := rand.Read(salt)
	require.NoError(suite.T(), err)

	hash1 := suite.pm.HashPassword("Password1", salt)
	hash2 := suite.pm.HashPassword("Password2", salt)

	// Different passwords should produce different hashes
	assert.NotEqual(suite.T(), hash1, hash2)
}

func (suite *PasswordManagerTestSuite) TestHashPassword_DifferentSalts() {
	password := "SamePassword123!"

	salt1 := make([]byte, 32)
	_, err := rand.Read(salt1)
	require.NoError(suite.T(), err)

	salt2 := make([]byte, 32)
	_, err = rand.Read(salt2)
	require.NoError(suite.T(), err)

	hash1 := suite.pm.HashPassword(password, salt1)
	hash2 := suite.pm.HashPassword(password, salt2)

	// Same password with different salts should produce different hashes
	assert.NotEqual(suite.T(), hash1, hash2)
}

func (suite *PasswordManagerTestSuite) TestVerifyPassword_ValidPassword() {
	password := "MySecureP@ssw0rd123!"
	salt := make([]byte, 32)
	_, err := rand.Read(salt)
	require.NoError(suite.T(), err)

	hash := suite.pm.HashPassword(password, salt)

	// Verification should succeed
	assert.True(suite.T(), suite.pm.VerifyPassword(password, hash, salt))
}

func (suite *PasswordManagerTestSuite) TestVerifyPassword_InvalidPassword() {
	password := "CorrectPassword123!"
	wrongPassword := "WrongPassword123!"
	salt := make([]byte, 32)
	_, err := rand.Read(salt)
	require.NoError(suite.T(), err)

	hash := suite.pm.HashPassword(password, salt)

	// Verification should fail with wrong password
	assert.False(suite.T(), suite.pm.VerifyPassword(wrongPassword, hash, salt))
}

func (suite *PasswordManagerTestSuite) TestVerifyPassword_WrongSalt() {
	password := "MySecureP@ssw0rd123!"
	correctSalt := make([]byte, 32)
	_, err := rand.Read(correctSalt)
	require.NoError(suite.T(), err)

	wrongSalt := make([]byte, 32)
	_, err = rand.Read(wrongSalt)
	require.NoError(suite.T(), err)

	hash := suite.pm.HashPassword(password, correctSalt)

	// Verification should fail with wrong salt
	assert.False(suite.T(), suite.pm.VerifyPassword(password, hash, wrongSalt))
}

// =====================================
// Test DeriveKeyBytes
// =====================================

func (suite *PasswordManagerTestSuite) TestDeriveKeyBytes_Returns32Bytes() {
	password := "TestPassword123!"
	salt := make([]byte, 32)
	_, err := rand.Read(salt)
	require.NoError(suite.T(), err)

	key := suite.pm.DeriveKeyBytes(password, salt)

	// Should return exactly 32 bytes (256 bits)
	assert.Len(suite.T(), key, 32)
}

func (suite *PasswordManagerTestSuite) TestDeriveKeyBytes_Deterministic() {
	password := "TestPassword123!"
	salt := make([]byte, 32)
	_, err := rand.Read(salt)
	require.NoError(suite.T(), err)

	key1 := suite.pm.DeriveKeyBytes(password, salt)
	key2 := suite.pm.DeriveKeyBytes(password, salt)

	// Same inputs should produce same key
	assert.Equal(suite.T(), key1, key2)
}

func (suite *PasswordManagerTestSuite) TestDeriveKeyBytes_DifferentPasswords() {
	salt := make([]byte, 32)
	_, err := rand.Read(salt)
	require.NoError(suite.T(), err)

	key1 := suite.pm.DeriveKeyBytes("Password1", salt)
	key2 := suite.pm.DeriveKeyBytes("Password2", salt)

	// Different passwords should produce different keys
	assert.NotEqual(suite.T(), key1, key2)
}

// =====================================
// Test ValidatePasswordStrength
// =====================================

func (suite *PasswordManagerTestSuite) TestValidatePasswordStrength_ValidPassword() {
	validPasswords := []string{
		"MyP@ssw0rd123!",         // 14 chars, all requirements
		"Testing123!@#$%^",       // Special chars
		"LongP@ssw0rd123!Secure", // Long password
	}

	for _, password := range validPasswords {
		err := suite.pm.ValidatePasswordStrength(password)
		assert.NoError(suite.T(), err, "Password should be valid: %s", password)
	}
}

func (suite *PasswordManagerTestSuite) TestValidatePasswordStrength_TooShort() {
	shortPasswords := []string{
		"Short1!",   // 7 chars
		"Pass1!",    // 6 chars
		"P@ssw0rd1", // 9 chars (< 12)
	}

	for _, password := range shortPasswords {
		err := suite.pm.ValidatePasswordStrength(password)
		assert.Error(suite.T(), err, "Password should be rejected (too short): %s", password)
		assert.Contains(suite.T(), err.Error(), "at least 12 characters")
	}
}

func (suite *PasswordManagerTestSuite) TestValidatePasswordStrength_NoUppercase() {
	err := suite.pm.ValidatePasswordStrength("mypassword123!")
	assert.Error(suite.T(), err)
	assert.Contains(suite.T(), err.Error(), "uppercase letter")
}

func (suite *PasswordManagerTestSuite) TestValidatePasswordStrength_NoLowercase() {
	err := suite.pm.ValidatePasswordStrength("MYPASSWORD123!")
	assert.Error(suite.T(), err)
	assert.Contains(suite.T(), err.Error(), "lowercase letter")
}

func (suite *PasswordManagerTestSuite) TestValidatePasswordStrength_NoDigit() {
	err := suite.pm.ValidatePasswordStrength("MyPassword!!!")
	assert.Error(suite.T(), err)
	assert.Contains(suite.T(), err.Error(), "digit")
}

func (suite *PasswordManagerTestSuite) TestValidatePasswordStrength_NoSpecialChar() {
	err := suite.pm.ValidatePasswordStrength("MyPassword123")
	assert.Error(suite.T(), err)
	assert.Contains(suite.T(), err.Error(), "special character")
}

// =====================================
// Test GenerateSalt
// =====================================

func (suite *PasswordManagerTestSuite) TestGenerateSalt_Returns32Bytes() {
	salt, err := suite.pm.GenerateSalt()

	assert.NoError(suite.T(), err)
	assert.Len(suite.T(), salt, 32)
}

func (suite *PasswordManagerTestSuite) TestGenerateSalt_UniqueValues() {
	salt1, err1 := suite.pm.GenerateSalt()
	salt2, err2 := suite.pm.GenerateSalt()

	assert.NoError(suite.T(), err1)
	assert.NoError(suite.T(), err2)

	// Salts should be different (cryptographically random)
	assert.NotEqual(suite.T(), salt1, salt2)
}

// =====================================
// Test CreateResetToken
// =====================================

func (suite *PasswordManagerTestSuite) TestCreateResetToken_Success() {
	ctx := context.Background()
	userID := uuid.New()
	ipAddress := "192.168.1.1"
	userAgent := "Mozilla/5.0 Test Browser"
	start := time.Now()

	// Mock database Exec
	suite.mockDB.On("Exec", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "INSERT INTO password_reset_tokens")
	}), userID, mock.Anything, mock.MatchedBy(func(arg interface{}) bool {
		expiresAt, ok := arg.(time.Time)
		if !ok {
			return false
		}
		ttl := time.Until(expiresAt)
		return ttl <= ResetTokenExpiry && ttl >= ResetTokenExpiry-time.Minute && expiresAt.After(start)
	}), mock.Anything, mock.Anything).Return(int64(1), nil)

	token, err := suite.pm.CreateResetToken(ctx, userID, ipAddress, userAgent)

	assert.NoError(suite.T(), err)
	assert.NotEmpty(suite.T(), token)

	// Token should be base64-URL encoded (32 bytes = 44 chars base64)
	assert.Greater(suite.T(), len(token), 40)

	suite.mockDB.AssertExpectations(suite.T())
}

func (suite *PasswordManagerTestSuite) TestCreateResetToken_DatabaseError() {
	ctx := context.Background()
	userID := uuid.New()
	ipAddress := "192.168.1.1"
	userAgent := "Test Browser"

	// Mock database Exec failure
	suite.mockDB.On("Exec", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(int64(0), fmt.Errorf("database error"))

	token, err := suite.pm.CreateResetToken(ctx, userID, ipAddress, userAgent)

	assert.Error(suite.T(), err)
	assert.Empty(suite.T(), token)
	assert.Contains(suite.T(), err.Error(), "failed to store reset token")
}

// =====================================
// Test VerifyResetToken
// =====================================

func (suite *PasswordManagerTestSuite) TestVerifyResetToken_ValidToken() {
	ctx := context.Background()
	userID := uuid.New()

	// Create a valid token (not expired, not used)
	tokenBytes := make([]byte, 32)
	_, err := rand.Read(tokenBytes)
	require.NoError(suite.T(), err)
	token := base64.URLEncoding.EncodeToString(tokenBytes)

	expiresAt := time.Now().UTC().Add(30 * time.Minute)
	used := false

	mockRow := &MockRow{}
	suite.mockDB.On("QueryRow", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "verify_attempts")
	}), mock.Anything).Return(mockRow)
	suite.mockDB.On("Exec",
		mock.Anything,
		mock.MatchedBy(func(sql string) bool {
			return contains(sql, "UPDATE password_reset_tokens")
		}),
		mock.Anything,
		mock.Anything,
		mock.Anything,
	).Return(int64(1), nil)

	mockRow.On("Scan", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		if uid, ok := args[0].(*uuid.UUID); ok {
			*uid = userID
		}
		if exp, ok := args[1].(*time.Time); ok {
			*exp = expiresAt
		}
		if u, ok := args[2].(*bool); ok {
			*u = used
		}
		if attemptsPtr, ok := args[3].(*int); ok {
			*attemptsPtr = 0
		}
		if windowPtr, ok := args[4].(*sql.NullTime); ok {
			*windowPtr = sql.NullTime{Valid: false}
		}
	}).Return(nil)

	resultUserID, err := suite.pm.VerifyResetToken(ctx, token)

	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), userID, resultUserID)
}

func (suite *PasswordManagerTestSuite) TestVerifyResetToken_TokenNotFound() {
	ctx := context.Background()
	token := base64.URLEncoding.EncodeToString([]byte("invalid-token"))

	mockRow := &MockRow{}
	suite.mockDB.On("QueryRow", mock.Anything, mock.Anything, mock.Anything).Return(mockRow)
	mockRow.On("Scan", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(sql.ErrNoRows)

	resultUserID, err := suite.pm.VerifyResetToken(ctx, token)

	assert.Error(suite.T(), err)
	assert.Equal(suite.T(), uuid.Nil, resultUserID)
	assert.Contains(suite.T(), err.Error(), "invalid or expired")
}

func (suite *PasswordManagerTestSuite) TestVerifyResetToken_AlreadyUsed() {
	ctx := context.Background()
	userID := uuid.New()

	tokenBytes := make([]byte, 32)
	_, err := rand.Read(tokenBytes)
	require.NoError(suite.T(), err)
	token := base64.URLEncoding.EncodeToString(tokenBytes)

	expiresAt := time.Now().UTC().Add(30 * time.Minute)
	used := true // Already used

	mockRow := &MockRow{}
	suite.mockDB.On("QueryRow", mock.Anything, mock.Anything, mock.Anything).Return(mockRow)
	suite.mockDB.On("Exec",
		mock.Anything,
		mock.MatchedBy(func(sql string) bool {
			return contains(sql, "UPDATE password_reset_tokens")
		}),
		mock.Anything,
		mock.Anything,
		mock.Anything,
	).Return(int64(1), nil)

	mockRow.On("Scan", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		if uid, ok := args[0].(*uuid.UUID); ok {
			*uid = userID
		}
		if exp, ok := args[1].(*time.Time); ok {
			*exp = expiresAt
		}
		if u, ok := args[2].(*bool); ok {
			*u = used
		}
		if attemptsPtr, ok := args[3].(*int); ok {
			*attemptsPtr = 0
		}
		if windowPtr, ok := args[4].(*sql.NullTime); ok {
			*windowPtr = sql.NullTime{Valid: true, Time: time.Now().Add(-time.Minute)}
		}
	}).Return(nil)

	resultUserID, err := suite.pm.VerifyResetToken(ctx, token)

	assert.Error(suite.T(), err)
	assert.Equal(suite.T(), uuid.Nil, resultUserID)
	assert.Contains(suite.T(), err.Error(), "already used")
}

func (suite *PasswordManagerTestSuite) TestVerifyResetToken_Expired() {
	ctx := context.Background()
	userID := uuid.New()

	tokenBytes := make([]byte, 32)
	_, err := rand.Read(tokenBytes)
	require.NoError(suite.T(), err)
	token := base64.URLEncoding.EncodeToString(tokenBytes)

	expiresAt := time.Now().UTC().Add(-30 * time.Minute) // Expired 30 minutes ago
	used := false

	mockRow := &MockRow{}
	suite.mockDB.On("QueryRow", mock.Anything, mock.Anything, mock.Anything).Return(mockRow)
	suite.mockDB.On("Exec",
		mock.Anything,
		mock.MatchedBy(func(sql string) bool {
			return contains(sql, "UPDATE password_reset_tokens")
		}),
		mock.Anything,
		mock.Anything,
		mock.Anything,
	).Return(int64(1), nil)

	mockRow.On("Scan", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		if uid, ok := args[0].(*uuid.UUID); ok {
			*uid = userID
		}
		if exp, ok := args[1].(*time.Time); ok {
			*exp = expiresAt
		}
		if u, ok := args[2].(*bool); ok {
			*u = used
		}
		if attemptsPtr, ok := args[3].(*int); ok {
			*attemptsPtr = 0
		}
		if windowPtr, ok := args[4].(*sql.NullTime); ok {
			*windowPtr = sql.NullTime{Valid: true, Time: time.Now().Add(-time.Minute)}
		}
	}).Return(nil)

	resultUserID, err := suite.pm.VerifyResetToken(ctx, token)

	assert.Error(suite.T(), err)
	assert.Equal(suite.T(), uuid.Nil, resultUserID)
	assert.Contains(suite.T(), err.Error(), "expired")
}

func (suite *PasswordManagerTestSuite) TestVerifyResetToken_TooManyAttempts() {
	ctx := context.Background()
	tokenBytes := make([]byte, 32)
	_, err := rand.Read(tokenBytes)
	require.NoError(suite.T(), err)
	token := base64.URLEncoding.EncodeToString(tokenBytes)

	mockRow := &MockRow{}
	suite.mockDB.On("QueryRow", mock.Anything, mock.Anything, mock.Anything).Return(mockRow)

	mockRow.On("Scan", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			if attemptsPtr, ok := args[3].(*int); ok {
				*attemptsPtr = resetTokenVerifyMaxAttempts
			}
			if windowPtr, ok := args[4].(*sql.NullTime); ok {
				*windowPtr = sql.NullTime{Valid: true, Time: time.Now()}
			}
		}).Return(nil)

	resultUserID, err := suite.pm.VerifyResetToken(ctx, token)

	assert.Error(suite.T(), err)
	assert.Equal(suite.T(), uuid.Nil, resultUserID)
	assert.Contains(suite.T(), err.Error(), "too many verification attempts")
	suite.mockDB.AssertNotCalled(suite.T(), "Exec", mock.Anything, mock.Anything, mock.Anything)
}

func (suite *PasswordManagerTestSuite) TestVerifyResetToken_AttemptWindowResets() {
	ctx := context.Background()
	userID := uuid.New()

	tokenBytes := make([]byte, 32)
	_, err := rand.Read(tokenBytes)
	require.NoError(suite.T(), err)
	token := base64.URLEncoding.EncodeToString(tokenBytes)

	mockRow := &MockRow{}
	suite.mockDB.On("QueryRow", mock.Anything, mock.Anything, mock.Anything).Return(mockRow)
	suite.mockDB.On("Exec",
		mock.Anything,
		mock.MatchedBy(func(sql string) bool {
			return contains(sql, "UPDATE password_reset_tokens")
		}),
		mock.Anything,
		mock.Anything,
		mock.Anything,
	).Return(int64(1), nil)

	mockRow.On("Scan", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			if uid, ok := args[0].(*uuid.UUID); ok {
				*uid = userID
			}
			if exp, ok := args[1].(*time.Time); ok {
				*exp = time.Now().Add(30 * time.Minute)
			}
			if u, ok := args[2].(*bool); ok {
				*u = false
			}
			if attemptsPtr, ok := args[3].(*int); ok {
				*attemptsPtr = resetTokenVerifyMaxAttempts
			}
			if windowPtr, ok := args[4].(*sql.NullTime); ok {
				*windowPtr = sql.NullTime{Valid: true, Time: time.Now().Add(-resetTokenVerifyWindow - time.Minute)}
			}
		}).Return(nil)

	resultUserID, err := suite.pm.VerifyResetToken(ctx, token)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), userID, resultUserID)
}

// =====================================
// Test CompletePasswordReset
// =====================================

func (suite *PasswordManagerTestSuite) TestCompletePasswordReset_Success() {
	ctx := context.Background()
	userID := uuid.New()

	// Create valid token
	tokenBytes := make([]byte, 32)
	_, err := rand.Read(tokenBytes)
	require.NoError(suite.T(), err)
	token := base64.URLEncoding.EncodeToString(tokenBytes)

	newPassword := "NewSecureP@ssw0rd123!"
	expiresAt := time.Now().UTC().Add(30 * time.Minute)

	// Mock VerifyResetToken
	mockRow := &MockRow{}
	suite.mockDB.On("QueryRow", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "verify_attempts")
	}), mock.Anything).Return(mockRow)
	suite.mockDB.On("Exec",
		mock.Anything,
		mock.MatchedBy(func(sql string) bool {
			return contains(sql, "UPDATE password_reset_tokens")
		}),
		mock.Anything,
		mock.Anything,
		mock.Anything,
	).Return(int64(1), nil)

	mockRow.On("Scan", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		if uid, ok := args[0].(*uuid.UUID); ok {
			*uid = userID
		}
		if exp, ok := args[1].(*time.Time); ok {
			*exp = expiresAt
		}
		if u, ok := args[2].(*bool); ok {
			*u = false
		}
		if attemptsPtr, ok := args[3].(*int); ok {
			*attemptsPtr = 0
		}
		if windowPtr, ok := args[4].(*sql.NullTime); ok {
			*windowPtr = sql.NullTime{Valid: false}
		}
	}).Return(nil)

	// Mock transaction
	mockTx := &MockTx{}
	suite.mockDB.On("Begin", mock.Anything).Return(mockTx, nil)
	mockTx.On("Exec", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "UPDATE users")
	}), mock.Anything, mock.Anything, mock.Anything, userID).Return(int64(1), nil)
	mockTx.On("Exec", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "UPDATE password_reset_tokens")
	}), userID).Return(int64(1), nil)
	mockTx.On("Commit", mock.Anything).Return(nil)
	mockTx.On("Rollback", mock.Anything).Return(nil)

	// Mock audit log
	suite.mockDB.On("Exec", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "INSERT INTO audit_log")
	}), mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(int64(1), nil)

	err = suite.pm.CompletePasswordReset(ctx, token, newPassword)

	assert.NoError(suite.T(), err)
}

func (suite *PasswordManagerTestSuite) TestCompletePasswordReset_InvalidToken() {
	ctx := context.Background()
	token := "invalid-token"
	newPassword := "NewSecureP@ssw0rd123!"

	mockRow := &MockRow{}
	suite.mockDB.On("QueryRow", mock.Anything, mock.Anything, mock.Anything).Return(mockRow)
	mockRow.On("Scan", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(sql.ErrNoRows)

	err := suite.pm.CompletePasswordReset(ctx, token, newPassword)

	assert.Error(suite.T(), err)
	assert.Contains(suite.T(), err.Error(), "invalid or expired")
}

func (suite *PasswordManagerTestSuite) TestCompletePasswordReset_WeakPassword() {
	ctx := context.Background()
	userID := uuid.New()

	tokenBytes := make([]byte, 32)
	_, err := rand.Read(tokenBytes)
	require.NoError(suite.T(), err)
	token := base64.URLEncoding.EncodeToString(tokenBytes)

	weakPassword := "weak" // Too short, no uppercase, no special char
	expiresAt := time.Now().UTC().Add(30 * time.Minute)

	mockRow := &MockRow{}
	suite.mockDB.On("QueryRow", mock.Anything, mock.Anything, mock.Anything).Return(mockRow)
	suite.mockDB.On("Exec",
		mock.Anything,
		mock.MatchedBy(func(sql string) bool {
			return contains(sql, "UPDATE password_reset_tokens")
		}),
		mock.Anything,
		mock.Anything,
		mock.Anything,
	).Return(int64(1), nil)

	mockRow.On("Scan", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		if uid, ok := args[0].(*uuid.UUID); ok {
			*uid = userID
		}
		if exp, ok := args[1].(*time.Time); ok {
			*exp = expiresAt
		}
		if u, ok := args[2].(*bool); ok {
			*u = false
		}
		if attemptsPtr, ok := args[3].(*int); ok {
			*attemptsPtr = 0
		}
		if windowPtr, ok := args[4].(*sql.NullTime); ok {
			*windowPtr = sql.NullTime{Valid: false}
		}
	}).Return(nil)

	err = suite.pm.CompletePasswordReset(ctx, token, weakPassword)

	assert.Error(suite.T(), err)
	assert.Contains(suite.T(), err.Error(), "at least 12 characters")
}

func (suite *PasswordManagerTestSuite) TestCompletePasswordReset_TransactionFailure() {
	ctx := context.Background()
	userID := uuid.New()

	tokenBytes := make([]byte, 32)
	_, err := rand.Read(tokenBytes)
	require.NoError(suite.T(), err)
	token := base64.URLEncoding.EncodeToString(tokenBytes)

	newPassword := "NewSecureP@ssw0rd123!"
	expiresAt := time.Now().UTC().Add(30 * time.Minute)

	mockRow := &MockRow{}
	suite.mockDB.On("QueryRow", mock.Anything, mock.Anything, mock.Anything).Return(mockRow)
	suite.mockDB.On("Exec",
		mock.Anything,
		mock.MatchedBy(func(sql string) bool {
			return contains(sql, "UPDATE password_reset_tokens")
		}),
		mock.Anything,
		mock.Anything,
		mock.Anything,
	).Return(int64(1), nil)

	mockRow.On("Scan", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		if uid, ok := args[0].(*uuid.UUID); ok {
			*uid = userID
		}
		if exp, ok := args[1].(*time.Time); ok {
			*exp = expiresAt
		}
		if u, ok := args[2].(*bool); ok {
			*u = false
		}
		if attemptsPtr, ok := args[3].(*int); ok {
			*attemptsPtr = 0
		}
		if windowPtr, ok := args[4].(*sql.NullTime); ok {
			*windowPtr = sql.NullTime{Valid: false}
		}
	}).Return(nil)

	mockTx := &MockTx{}
	suite.mockDB.On("Begin", mock.Anything).Return(mockTx, nil)
	mockTx.On("Exec", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(int64(0), fmt.Errorf("database error"))
	mockTx.On("Rollback", mock.Anything).Return(nil)

	err = suite.pm.CompletePasswordReset(ctx, token, newPassword)

	assert.Error(suite.T(), err)
	assert.Contains(suite.T(), err.Error(), "failed to update password")
}

// =====================================
// Test InvalidateAllResetTokens
// =====================================

func (suite *PasswordManagerTestSuite) TestInvalidateAllResetTokens_Success() {
	ctx := context.Background()
	userID := uuid.New()

	suite.mockDB.On("Exec", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "UPDATE password_reset_tokens") && contains(sql, "used = true")
	}), userID).Return(int64(3), nil) // 3 tokens invalidated

	err := suite.pm.InvalidateAllResetTokens(ctx, userID)

	assert.NoError(suite.T(), err)
	suite.mockDB.AssertExpectations(suite.T())
}

func (suite *PasswordManagerTestSuite) TestInvalidateAllResetTokens_DatabaseError() {
	ctx := context.Background()
	userID := uuid.New()

	suite.mockDB.On("Exec", mock.Anything, mock.Anything, mock.Anything).Return(int64(0), fmt.Errorf("database error"))

	err := suite.pm.InvalidateAllResetTokens(ctx, userID)

	assert.Error(suite.T(), err)
	assert.Contains(suite.T(), err.Error(), "failed to invalidate reset tokens")
}

// =====================================
// Test CleanupExpiredTokens
// =====================================

func (suite *PasswordManagerTestSuite) TestCleanupExpiredTokens_Success() {
	ctx := context.Background()

	suite.mockDB.On("Exec", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "DELETE FROM password_reset_tokens")
	})).Return(int64(5), nil) // 5 tokens cleaned up

	err := suite.pm.CleanupExpiredTokens(ctx)

	assert.NoError(suite.T(), err)
	suite.mockDB.AssertExpectations(suite.T())
}

func (suite *PasswordManagerTestSuite) TestCleanupExpiredTokens_DatabaseError() {
	ctx := context.Background()

	suite.mockDB.On("Exec", mock.Anything, mock.Anything).Return(int64(0), fmt.Errorf("database error"))

	err := suite.pm.CleanupExpiredTokens(ctx)

	assert.Error(suite.T(), err)
	assert.Contains(suite.T(), err.Error(), "failed to cleanup expired tokens")
}

// =====================================
// Helper Functions for Tests
// =====================================

// contains checks if a string contains a substring (case-insensitive helper)
func contains(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}

// Mock implementations (reuse from handlers_test.go)
type MockDB struct {
	mock.Mock
}

func (m *MockDB) QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row {
	callArgs := append([]interface{}{ctx, sql}, args...)
	mockArgs := m.Called(callArgs...)
	return mockArgs.Get(0).(pgx.Row)
}

func (m *MockDB) Exec(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
	callArgs := append([]interface{}{ctx, sql}, args...)
	mockArgs := m.Called(callArgs...)
	rowsAffected := mockArgs.Get(0).(int64)
	tag := pgconn.NewCommandTag(fmt.Sprintf("UPDATE %d", rowsAffected))
	return tag, mockArgs.Error(1)
}

func (m *MockDB) Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error) {
	callArgs := append([]interface{}{ctx, sql}, args...)
	mockArgs := m.Called(callArgs...)
	if mockArgs.Get(0) == nil {
		return nil, mockArgs.Error(1)
	}
	return mockArgs.Get(0).(pgx.Rows), mockArgs.Error(1)
}

func (m *MockDB) Begin(ctx context.Context) (pgx.Tx, error) {
	mockArgs := m.Called(ctx)
	if mockArgs.Get(0) == nil {
		return nil, mockArgs.Error(1)
	}
	return mockArgs.Get(0).(pgx.Tx), mockArgs.Error(1)
}

type MockRow struct {
	mock.Mock
}

func (m *MockRow) Scan(dest ...interface{}) error {
	mockArgs := m.Called(dest...)
	return mockArgs.Error(0)
}

type MockTx struct {
	mock.Mock
}

func (m *MockTx) QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row {
	callArgs := append([]interface{}{ctx, sql}, args...)
	mockArgs := m.Called(callArgs...)
	return mockArgs.Get(0).(pgx.Row)
}

func (m *MockTx) Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error) {
	callArgs := append([]interface{}{ctx, sql}, args...)
	mockArgs := m.Called(callArgs...)
	return mockArgs.Get(0).(pgx.Rows), mockArgs.Error(1)
}

func (m *MockTx) Exec(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
	callArgs := append([]interface{}{ctx, sql}, args...)
	mockArgs := m.Called(callArgs...)
	rowsAffected := mockArgs.Get(0).(int64)
	tag := pgconn.NewCommandTag(fmt.Sprintf("UPDATE %d", rowsAffected))
	return tag, mockArgs.Error(1)
}

func (m *MockTx) Rollback(ctx context.Context) error {
	mockArgs := m.Called(ctx)
	return mockArgs.Error(0)
}

func (m *MockTx) Commit(ctx context.Context) error {
	mockArgs := m.Called(ctx)
	return mockArgs.Error(0)
}

func (m *MockTx) Begin(ctx context.Context) (pgx.Tx, error) {
	mockArgs := m.Called(ctx)
	return mockArgs.Get(0).(pgx.Tx), mockArgs.Error(1)
}

func (m *MockTx) CopyFrom(ctx context.Context, tableName pgx.Identifier, columnNames []string, rowSrc pgx.CopyFromSource) (int64, error) {
	return 0, nil
}

func (m *MockTx) SendBatch(ctx context.Context, b *pgx.Batch) pgx.BatchResults {
	return nil
}

func (m *MockTx) LargeObjects() pgx.LargeObjects {
	return pgx.LargeObjects{}
}

func (m *MockTx) Prepare(ctx context.Context, name, sql string) (*pgconn.StatementDescription, error) {
	return nil, nil
}

func (m *MockTx) Deallocate(ctx context.Context, name string) error {
	return nil
}

func (m *MockTx) Conn() *pgx.Conn {
	return nil
}
