package auth

import (
	"context"
	"crypto/sha256"
	"strings"
	"testing"
	"time"

	appcrypto "leaflock/crypto"

	miniredis "github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/redis/go-redis/v9"
)

func newTestRedis(t *testing.T) (*redis.Client, func()) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	cleanup := func() {
		_ = rdb.Close()
		mr.Close()
	}
	return rdb, cleanup
}

// TestLogin_InvalidCredentials tests login with non-existent user
func TestLogin_InvalidCredentials(t *testing.T) {
	mockDB := &mockServiceDB{
		queryRowFuncs: []func(dest ...interface{}) error{
			func(dest ...interface{}) error {
				return pgx.ErrNoRows
			},
		},
	}

	rdb, cleanup := newTestRedis(t)
	defer cleanup()
	service := NewService(mockDB, rdb, "test-secret-key-must-be-at-least-64-chars-long-for-HS512-padding")

	_, err := service.Login(context.Background(), "nonexistent@example.com", "password", "")
	if err == nil {
		t.Fatal("Expected error for invalid credentials, got nil")
	}
	if err.Error() != "invalid credentials" {
		t.Errorf("Expected 'invalid credentials' error, got: %v", err)
	}
}

// TestLogin_WrongPassword tests login with correct email but wrong password
func TestLogin_WrongPassword(t *testing.T) {
	userID := uuid.New()
	pm := NewPasswordManager(nil)
	salt, _ := pm.GenerateSalt()
	correctPasswordHash := pm.HashPassword("CorrectPassword123!", salt)

	mockDB := &mockServiceDB{
		queryRowFuncs: []func(dest ...interface{}) error{
			func(dest ...interface{}) error {
				// Scan user data
				if uid, ok := dest[0].(*uuid.UUID); ok {
					*uid = userID
				}
				if pwHash, ok := dest[1].(*string); ok {
					*pwHash = correctPasswordHash
				}
				if saltBytes, ok := dest[2].(*[]byte); ok {
					*saltBytes = salt
				}
				if mfaEnabled, ok := dest[3].(*bool); ok {
					*mfaEnabled = false
				}
				if mfaSecret, ok := dest[4].(*[]byte); ok {
					*mfaSecret = nil
				}
				if failedAttempts, ok := dest[5].(*int); ok {
					*failedAttempts = 0
				}
				if lockedUntil, ok := dest[6].(**time.Time); ok {
					*lockedUntil = nil
				}
				if isAdmin, ok := dest[7].(*bool); ok {
					*isAdmin = false
				}
				return nil
			},
		},
		execFuncs: []func(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error){
			func(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
				// Increment failed attempts
				return pgconn.NewCommandTag("UPDATE 1"), nil
			},
		},
	}

	rdb, cleanup := newTestRedis(t)
	defer cleanup()
	service := NewService(mockDB, rdb, "test-secret-key-must-be-at-least-64-chars-long-for-HS512-padding")

	_, err := service.Login(context.Background(), "user@example.com", "WrongPassword123!", "")
	if err == nil {
		t.Fatal("Expected error for wrong password, got nil")
	}
	if err.Error() != "invalid credentials" {
		t.Errorf("Expected 'invalid credentials' error, got: %v", err)
	}
}

// TestLogin_AccountLocked tests login with locked account
func TestLogin_AccountLocked(t *testing.T) {
	userID := uuid.New()
	lockUntil := time.Now().UTC().Add(15 * time.Minute)

	mockDB := &mockServiceDB{
		queryRowFuncs: []func(dest ...interface{}) error{
			func(dest ...interface{}) error {
				if uid, ok := dest[0].(*uuid.UUID); ok {
					*uid = userID
				}
				if pwHash, ok := dest[1].(*string); ok {
					*pwHash = "hash"
				}
				if salt, ok := dest[2].(*[]byte); ok {
					*salt = make([]byte, 32)
				}
				if mfaEnabled, ok := dest[3].(*bool); ok {
					*mfaEnabled = false
				}
				if mfaSecret, ok := dest[4].(*[]byte); ok {
					*mfaSecret = nil
				}
				if failedAttempts, ok := dest[5].(*int); ok {
					*failedAttempts = 5
				}
				if lockedUntil, ok := dest[6].(**time.Time); ok {
					*lockedUntil = &lockUntil
				}
				if isAdmin, ok := dest[7].(*bool); ok {
					*isAdmin = false
				}
				return nil
			},
		},
	}

	rdb, cleanup := newTestRedis(t)
	defer cleanup()
	service := NewService(mockDB, rdb, "test-secret-key-must-be-at-least-64-chars-long-for-HS512-padding")

	_, err := service.Login(context.Background(), "locked@example.com", "password", "")
	if err == nil {
		t.Fatal("Expected error for locked account, got nil")
	}
	if err.Error()[:14] != "account locked" {
		t.Errorf("Expected 'account locked' error, got: %v", err)
	}
}

// TestLogin_MFAEnabledNoCode tests login with MFA enabled but no code provided
func TestLogin_MFAEnabledNoCode(t *testing.T) {
	userID := uuid.New()
	pm := NewPasswordManager(nil)
	salt, _ := pm.GenerateSalt()
	passwordHash := pm.HashPassword("Password123!", salt)

	mockDB := &mockServiceDB{
		queryRowFuncs: []func(dest ...interface{}) error{
			func(dest ...interface{}) error {
				if uid, ok := dest[0].(*uuid.UUID); ok {
					*uid = userID
				}
				if pwHash, ok := dest[1].(*string); ok {
					*pwHash = passwordHash
				}
				if saltBytes, ok := dest[2].(*[]byte); ok {
					*saltBytes = salt
				}
				if mfaEnabled, ok := dest[3].(*bool); ok {
					*mfaEnabled = true // MFA is enabled
				}
				if mfaSecret, ok := dest[4].(*[]byte); ok {
					*mfaSecret = []byte("encrypted-secret")
				}
				if failedAttempts, ok := dest[5].(*int); ok {
					*failedAttempts = 0
				}
				if lockedUntil, ok := dest[6].(**time.Time); ok {
					*lockedUntil = nil
				}
				if isAdmin, ok := dest[7].(*bool); ok {
					*isAdmin = false
				}
				return nil
			},
		},
		execFuncs: []func(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error){
			func(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
				// Reset failed attempts
				return pgconn.NewCommandTag("UPDATE 1"), nil
			},
		},
	}

	rdb, cleanup := newTestRedis(t)
	defer cleanup()
	service := NewService(mockDB, rdb, "test-secret-key-must-be-at-least-64-chars-long-for-HS512-padding")

	resp, err := service.Login(context.Background(), "mfa-user@example.com", "Password123!", "")
	if err != nil {
		t.Fatalf("Expected partial auth response, got error: %v", err)
	}
	if resp.MFARequired != true {
		t.Error("Expected MFARequired to be true")
	}
	if resp.Token != "" {
		t.Error("Expected empty token for MFA-required response")
	}
}

// TestLogin_MFAWithInvalidCode tests login with MFA enabled and invalid code
func TestLogin_MFAWithInvalidCode(t *testing.T) {
	userID := uuid.New()
	systemSecret := "test-secret-key-must-be-at-least-64-chars-long-for-encryption"
	// Derive MFA encryption key the same way NewService does
	mfaKey := sha256.Sum256(append([]byte(systemSecret), []byte("-mfa-encryption")...))
	cryptoSvc := appcrypto.NewCryptoService(mfaKey[:])
	pm := NewPasswordManager(nil)
	salt, _ := pm.GenerateSalt()
	passwordHash := pm.HashPassword("Password123!", salt)

	// Encrypt a TOTP secret
	mfaSecret, _ := cryptoSvc.EncryptBytes([]byte("JBSWY3DPEHPK3PXP"))

	mockDB := &mockServiceDB{
		queryRowFuncs: []func(dest ...interface{}) error{
			func(dest ...interface{}) error {
				if uid, ok := dest[0].(*uuid.UUID); ok {
					*uid = userID
				}
				if pwHash, ok := dest[1].(*string); ok {
					*pwHash = passwordHash
				}
				if saltBytes, ok := dest[2].(*[]byte); ok {
					*saltBytes = salt
				}
				if mfaEnabled, ok := dest[3].(*bool); ok {
					*mfaEnabled = true
				}
				if mfaSecretEnc, ok := dest[4].(*[]byte); ok {
					*mfaSecretEnc = mfaSecret
				}
				if failedAttempts, ok := dest[5].(*int); ok {
					*failedAttempts = 0
				}
				if lockedUntil, ok := dest[6].(**time.Time); ok {
					*lockedUntil = nil
				}
				if isAdmin, ok := dest[7].(*bool); ok {
					*isAdmin = false
				}
				return nil
			},
			// Query for backup code verification (will fail)
			func(dest ...interface{}) error {
				return pgx.ErrNoRows
			},
		},
		execFuncs: []func(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error){
			func(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
				// Reset failed attempts
				return pgconn.NewCommandTag("UPDATE 1"), nil
			},
		},
	}

	rdb, cleanup := newTestRedis(t)
	defer cleanup()
	service := NewService(mockDB, rdb, systemSecret)

	_, err := service.Login(context.Background(), "mfa-user@example.com", "Password123!", "000000")
	if err == nil {
		t.Fatal("Expected error for invalid MFA code, got nil")
	}
	if err.Error() != "invalid MFA code" {
		t.Errorf("Expected 'invalid MFA code' error, got: %v", err)
	}
}

// TestLogin_MFADecryptionError tests login when MFA secret decryption fails
func TestLogin_MFADecryptionError(t *testing.T) {
	userID := uuid.New()
	pm := NewPasswordManager(nil)
	salt, _ := pm.GenerateSalt()
	passwordHash := pm.HashPassword("Password123!", salt)

	mockDB := &mockServiceDB{
		queryRowFuncs: []func(dest ...interface{}) error{
			func(dest ...interface{}) error {
				if uid, ok := dest[0].(*uuid.UUID); ok {
					*uid = userID
				}
				if pwHash, ok := dest[1].(*string); ok {
					*pwHash = passwordHash
				}
				if saltBytes, ok := dest[2].(*[]byte); ok {
					*saltBytes = salt
				}
				if mfaEnabled, ok := dest[3].(*bool); ok {
					*mfaEnabled = true
				}
				if mfaSecret, ok := dest[4].(*[]byte); ok {
					// Invalid encrypted data that will fail to decrypt
					*mfaSecret = []byte("invalid-encrypted-data")
				}
				if failedAttempts, ok := dest[5].(*int); ok {
					*failedAttempts = 0
				}
				if lockedUntil, ok := dest[6].(**time.Time); ok {
					*lockedUntil = nil
				}
				if isAdmin, ok := dest[7].(*bool); ok {
					*isAdmin = false
				}
				return nil
			},
		},
		execFuncs: []func(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error){
			func(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
				return pgconn.NewCommandTag("UPDATE 1"), nil
			},
		},
	}

	rdb, cleanup := newTestRedis(t)
	defer cleanup()
	service := NewService(mockDB, rdb, "test-secret-key-must-be-at-least-64-chars-long-for-HS512-padding")

	_, err := service.Login(context.Background(), "mfa-user@example.com", "Password123!", "123456")
	if err == nil {
		t.Fatal("Expected error for MFA decryption failure, got nil")
	}
	// Just check that it contains the error message
	if !strings.Contains(err.Error(), "failed to decrypt MFA secret") {
		t.Errorf("Expected error containing 'failed to decrypt MFA secret', got: %v", err)
	}
}
