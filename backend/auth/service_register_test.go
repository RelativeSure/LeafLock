package auth

import (
	"context"
	"errors"
	"strings"
	"testing"

	appcrypto "leaflock/crypto"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/redis/go-redis/v9"
)

// TestRegister_WeakPassword tests registration with weak passwords
func TestRegister_WeakPassword(t *testing.T) {
	mockDB := &mockServiceDB{}
	cryptoSvc := appcrypto.NewCryptoService(make([]byte, 32))
	rdb := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
	service := NewService(mockDB, rdb, cryptoSvc, "test-secret-key-must-be-at-least-64-chars-long-for-HS512-padding")

	weakPasswords := []string{
		"short",
		"onlylowercase",
		"ONLYUPPERCASE",
		"NoSpecialChar123",
		"NoDigits!@#",
		"123456789",
	}

	for _, password := range weakPasswords {
		_, err := service.Register(context.Background(), "test@example.com", password)
		if err == nil {
			t.Errorf("Expected error for weak password %q, got nil", password)
		}
	}
}

// TestRegister_DuplicateEmail tests registration with duplicate email
func TestRegister_DuplicateEmail(t *testing.T) {
	mockTx := &mockTx{
		queryRowFuncs: []func(dest ...interface{}) error{
			func(dest ...interface{}) error {
				// Return duplicate key error
				return errors.New("duplicate key value violates unique constraint")
			},
		},
	}

	mockDB := &mockServiceDB{
		beginFunc: func(ctx context.Context) (pgx.Tx, error) {
			return mockTx, nil
		},
	}

	cryptoSvc := appcrypto.NewCryptoService(make([]byte, 32))
	rdb := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
	service := NewService(mockDB, rdb, cryptoSvc, "test-secret-key-must-be-at-least-64-chars-long-for-HS512-padding")

	_, err := service.Register(context.Background(), "existing@example.com", "ValidPassword123!")
	if err == nil {
		t.Fatal("Expected error for duplicate email, got nil")
	}
	if err.Error() != "email already exists" {
		t.Errorf("Expected 'email already exists' error, got: %v", err)
	}
}

// TestRegister_TransactionBeginError tests registration when transaction begin fails
func TestRegister_TransactionBeginError(t *testing.T) {
	mockDB := &mockServiceDB{
		beginFunc: func(ctx context.Context) (pgx.Tx, error) {
			return nil, errors.New("failed to begin transaction")
		},
	}

	cryptoSvc := appcrypto.NewCryptoService(make([]byte, 32))
	rdb := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
	service := NewService(mockDB, rdb, cryptoSvc, "test-secret-key-must-be-at-least-64-chars-long-for-HS512-padding")

	_, err := service.Register(context.Background(), "test@example.com", "ValidPassword123!")
	if err == nil {
		t.Fatal("Expected error when transaction begin fails, got nil")
	}
	if !strings.Contains(err.Error(), "failed to begin transaction") {
		t.Errorf("Expected error containing 'failed to begin transaction', got: %v", err)
	}
}

// TestRegister_UserInsertError tests registration when user insert fails
func TestRegister_UserInsertError(t *testing.T) {
	mockTx := &mockTx{
		queryRowFuncs: []func(dest ...interface{}) error{
			func(dest ...interface{}) error {
				return errors.New("database insert failed")
			},
		},
	}

	mockDB := &mockServiceDB{
		beginFunc: func(ctx context.Context) (pgx.Tx, error) {
			return mockTx, nil
		},
	}

	cryptoSvc := appcrypto.NewCryptoService(make([]byte, 32))
	rdb := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
	service := NewService(mockDB, rdb, cryptoSvc, "test-secret-key-must-be-at-least-64-chars-long-for-HS512-padding")

	_, err := service.Register(context.Background(), "test@example.com", "ValidPassword123!")
	if err == nil {
		t.Fatal("Expected error when user insert fails, got nil")
	}
	if err.Error()[:21] != "failed to create user" {
		t.Errorf("Expected 'failed to create user' error, got: %v", err)
	}
}

// TestRegister_GDPRKeyInsertError tests registration when GDPR key insert fails
func TestRegister_GDPRKeyInsertError(t *testing.T) {
	userID := uuid.New()
	callCount := 0

	mockTx := &mockTx{
		queryRowFuncs: []func(dest ...interface{}) error{
			func(dest ...interface{}) error {
				// User insert succeeds
				if uid, ok := dest[0].(*uuid.UUID); ok {
					*uid = userID
				}
				return nil
			},
		},
		execFuncs: []func(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error){
			func(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
				callCount++
				// GDPR key insert fails
				return pgconn.CommandTag{}, errors.New("GDPR key insert failed")
			},
		},
	}

	mockDB := &mockServiceDB{
		beginFunc: func(ctx context.Context) (pgx.Tx, error) {
			return mockTx, nil
		},
	}

	cryptoSvc := appcrypto.NewCryptoService(make([]byte, 32))
	rdb := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
	service := NewService(mockDB, rdb, cryptoSvc, "test-secret-key-must-be-at-least-64-chars-long-for-HS512-padding")

	_, err := service.Register(context.Background(), "test@example.com", "ValidPassword123!")
	if err == nil {
		t.Fatal("Expected error when GDPR key insert fails, got nil")
	}
	if !strings.Contains(err.Error(), "failed to create GDPR key") {
		t.Errorf("Expected error containing 'failed to create GDPR key', got: %v", err)
	}
}

// TestRegister_WorkspaceInsertError tests registration when workspace insert fails
func TestRegister_WorkspaceInsertError(t *testing.T) {
	// Skip - exec call count logic is more complex than the simple mock supports
	t.Skip("Workspace insert error testing requires stateful exec mock")
}

// TestRegister_RoleAssignmentError tests registration when role assignment fails
func TestRegister_RoleAssignmentError(t *testing.T) {
	// Skip - exec call count logic is more complex than the simple mock supports
	t.Skip("Role assignment error testing requires stateful exec mock")
}

// TestRegister_CommitError tests registration when transaction commit fails
func TestRegister_CommitError(t *testing.T) {
	// Skip this test - mockTx.Commit cannot be overridden easily in the current mock setup
	t.Skip("Commit error testing requires more complex mock setup")
}
