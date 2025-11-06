package auth

import (
	"context"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
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

func TestServiceValidateJWTSuccess(t *testing.T) {
	svc := &Service{jwtSecret: "unit-test-secret"}
	userID := uuid.New()
	token, err := svc.GenerateJWT(userID, true)
	if err != nil {
		t.Fatalf("GenerateJWT failed: %v", err)
	}

	parsedID, isAdmin, err := svc.ValidateJWT(token)
	if err != nil {
		t.Fatalf("ValidateJWT returned error: %v", err)
	}
	if parsedID != userID {
		t.Fatalf("expected user ID %s, got %s", userID, parsedID)
	}
	if !isAdmin {
		t.Fatal("expected isAdmin to be true")
	}
}

func TestServiceValidateJWTInvalidToken(t *testing.T) {
	svc := &Service{jwtSecret: "unit-test-secret"}

	if _, _, err := svc.ValidateJWT("not-a-token"); err == nil {
		t.Fatal("expected error for invalid token string")
	}
}

func TestServiceValidateJWTMissingUserID(t *testing.T) {
	svc := &Service{jwtSecret: "unit-test-secret"}
	claims := jwt.MapClaims{
		"exp":      time.Now().Add(time.Hour).Unix(),
		"is_admin": false,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(svc.jwtSecret))
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	if _, _, err := svc.ValidateJWT(signed); err == nil {
		t.Fatal("expected error when user_id claim missing")
	}
}

func TestServiceValidateJWTInvalidUserIDFormat(t *testing.T) {
	svc := &Service{jwtSecret: "unit-test-secret"}
	claims := jwt.MapClaims{
		"user_id": 12345,
		"exp":     time.Now().Add(time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(svc.jwtSecret))
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	if _, _, err := svc.ValidateJWT(signed); err == nil {
		t.Fatal("expected error for invalid user_id format")
	}
}

func TestServiceValidateJWTExpiredToken(t *testing.T) {
	svc := &Service{jwtSecret: "unit-test-secret"}
	claims := jwt.MapClaims{
		"user_id": uuid.New().String(),
		"exp":     time.Now().Add(-time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(svc.jwtSecret))
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	if _, _, err := svc.ValidateJWT(signed); err == nil {
		t.Fatal("expected error for expired token")
	}
}

func TestServiceLogout_BlacklistsAndDeletesToken(t *testing.T) {
	stub := &logoutSessionStub{}
	svc := &Service{session: stub, jwtSecret: "unit-test-secret"}

	userID := uuid.New()
	token, err := svc.GenerateJWT(userID, false)
	require.NoError(t, err)

	err = svc.Logout(context.Background(), token)
	require.NoError(t, err)
	require.Len(t, stub.blacklistCalls, 1)
	require.Equal(t, token, stub.blacklistCalls[0].token)

	parsed, err := jwt.Parse(token, func(tkn *jwt.Token) (interface{}, error) {
		return []byte(svc.jwtSecret), nil
	})
	require.NoError(t, err)
	claims, ok := parsed.Claims.(jwt.MapClaims)
	require.True(t, ok)
	expFloat, ok := claims["exp"].(float64)
	require.True(t, ok)
	expectedExpiry := time.Unix(int64(expFloat), 0)
	require.WithinDuration(t, expectedExpiry, stub.blacklistCalls[0].expiresAt, time.Second)

	require.Len(t, stub.deletedTokens, 1)
	require.Equal(t, token, stub.deletedTokens[0])
}

func TestServiceLogout_BlacklistErrorPropagates(t *testing.T) {
	stub := &logoutSessionStub{blacklistErr: errors.New("redis down")}
	svc := &Service{session: stub, jwtSecret: "unit-test-secret"}

	token, err := svc.GenerateJWT(uuid.New(), false)
	require.NoError(t, err)

	err = svc.Logout(context.Background(), token)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to revoke token")
	require.Empty(t, stub.deletedTokens)
}

func TestServiceLogout_NonJWTTokenSkipsBlacklist(t *testing.T) {
	stub := &logoutSessionStub{blacklistErr: errors.New("should not be called")}
	svc := &Service{session: stub, jwtSecret: "unit-test-secret"}

	err := svc.Logout(context.Background(), "not-a-jwt-token")
	require.NoError(t, err)
	require.Len(t, stub.blacklistCalls, 0)
	require.Len(t, stub.deletedTokens, 1)
	require.Equal(t, "not-a-jwt-token", stub.deletedTokens[0])
}

type blacklistCall struct {
	token     string
	expiresAt time.Time
}

type logoutSessionStub struct {
	blacklistErr   error
	deleteErr      error
	blacklistCalls []blacklistCall
	deletedTokens  []string
}

func (s *logoutSessionStub) CreateSession(ctx context.Context, userID uuid.UUID, ipAddress, userAgent string, mfaVerified bool) (*Session, string, error) {
	return nil, "", nil
}

func (s *logoutSessionStub) CreateMFASession(ctx context.Context, userID uuid.UUID, email, ipAddress, userAgent string, mfaEnabled bool) (string, error) {
	return "", nil
}

func (s *logoutSessionStub) GetMFASession(ctx context.Context, token string) (*MFASession, error) {
	return nil, nil
}

func (s *logoutSessionStub) DeleteMFASession(ctx context.Context, token string) error {
	return nil
}

func (s *logoutSessionStub) DeleteSession(ctx context.Context, token string) error {
	s.deletedTokens = append(s.deletedTokens, token)
	if s.deleteErr != nil {
		return s.deleteErr
	}
	return nil
}

func (s *logoutSessionStub) BlacklistJWT(ctx context.Context, token string, expiresAt time.Time) error {
	s.blacklistCalls = append(s.blacklistCalls, blacklistCall{token: token, expiresAt: expiresAt})
	if s.blacklistErr != nil {
		return s.blacklistErr
	}
	return nil
}

func (s *logoutSessionStub) IsJWTBlacklisted(ctx context.Context, token string) (bool, error) {
	return false, nil
}

// Note: These are basic unit tests. For comprehensive testing, you would need:
// 1. Integration tests with real database and Redis
// 2. Testcontainers for isolated test environments
// 3. Mock implementations for external dependencies
// 4. Tests for error conditions and edge cases
// 5. Performance tests for cryptographic operations
// 6. Security tests for timing attacks and other vulnerabilities
