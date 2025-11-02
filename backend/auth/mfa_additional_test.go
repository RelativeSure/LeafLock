package auth

import (
	"context"
	"testing"

	appcrypto "leaflock/crypto"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type mfaMockRow struct {
	scanFunc func(dest ...interface{}) error
}

func (m mfaMockRow) Scan(dest ...interface{}) error {
	if m.scanFunc != nil {
		return m.scanFunc(dest...)
	}
	return nil
}

type mfaMockDB struct {
	queryRowFuncs []func(dest ...interface{}) error
	execFuncs     []func(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error)
}

func (m *mfaMockDB) QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row {
	if len(m.queryRowFuncs) == 0 {
		return mfaMockRow{}
	}
	fn := m.queryRowFuncs[0]
	m.queryRowFuncs = m.queryRowFuncs[1:]
	return mfaMockRow{scanFunc: fn}
}

func (m *mfaMockDB) Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error) {
	return nil, nil
}

func (m *mfaMockDB) Exec(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
	if len(m.execFuncs) == 0 {
		return pgconn.CommandTag{}, nil
	}
	fn := m.execFuncs[0]
	m.execFuncs = m.execFuncs[1:]
	return fn(ctx, sql, args...)
}

func (m *mfaMockDB) Begin(ctx context.Context) (pgx.Tx, error) {
	return nil, nil
}

func TestVerifyBackupCodeSuccess(t *testing.T) {
	crypto := appcrypto.NewCryptoService(make([]byte, 32))
	mgr := NewMFAManager(&mfaMockDB{}, crypto)

	code := mgr.formatBackupCode("ABCDEFGHIJKL")
	normalized := mgr.normalizeBackupCode(code)
	hash := mgr.hashBackupCode(normalized)

	mdb := &mfaMockDB{
		queryRowFuncs: []func(dest ...interface{}) error{
			func(dest ...interface{}) error {
				if len(dest) >= 2 {
					if codes, ok := dest[0].(*[][]byte); ok {
						*codes = [][]byte{hash}
					}
					if used, ok := dest[1].(*[][]byte); ok {
						*used = [][]byte{}
					}
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

	mgr = NewMFAManager(mdb, crypto)

	valid, err := mgr.VerifyBackupCode(context.Background(), uuid.New(), code)
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if !valid {
		t.Fatal("expected backup code to be valid")
	}
	if len(mdb.execFuncs) != 0 {
		t.Fatal("expected exec function to be consumed")
	}
}

func TestVerifyBackupCodeAlreadyUsed(t *testing.T) {
	crypto := appcrypto.NewCryptoService(make([]byte, 32))
	mgr := NewMFAManager(&mfaMockDB{}, crypto)

	code := mgr.formatBackupCode("MNOPQRSTUVWZ")
	normalized := mgr.normalizeBackupCode(code)
	hash := mgr.hashBackupCode(normalized)

	mdb := &mfaMockDB{
		queryRowFuncs: []func(dest ...interface{}) error{
			func(dest ...interface{}) error {
				if len(dest) >= 2 {
					if codes, ok := dest[0].(*[][]byte); ok {
						*codes = [][]byte{hash}
					}
					if used, ok := dest[1].(*[][]byte); ok {
						*used = [][]byte{hash}
					}
				}
				return nil
			},
		},
	}

	mgr = NewMFAManager(mdb, crypto)

	valid, err := mgr.VerifyBackupCode(context.Background(), uuid.New(), code)
	if err == nil || valid {
		t.Fatal("expected error for already used code")
	}
}

func TestDisableMFAWithBackupCode(t *testing.T) {
	crypto := appcrypto.NewCryptoService(make([]byte, 32))
	mgr := NewMFAManager(&mfaMockDB{}, crypto)

	secret := []byte("totp-secret-value")
	encryptedSecret, err := crypto.EncryptBytes(secret)
	if err != nil {
		t.Fatalf("failed to encrypt secret: %v", err)
	}

	code := mgr.formatBackupCode("ZYXWVUTSRQPO")
	normalized := mgr.normalizeBackupCode(code)
	hash := mgr.hashBackupCode(normalized)

	mdb := &mfaMockDB{
		queryRowFuncs: []func(dest ...interface{}) error{
			func(dest ...interface{}) error {
				if b, ok := dest[0].(*[]byte); ok {
					*b = encryptedSecret
				}
				return nil
			},
			func(dest ...interface{}) error {
				if len(dest) >= 2 {
					if codes, ok := dest[0].(*[][]byte); ok {
						*codes = [][]byte{hash}
					}
					if used, ok := dest[1].(*[][]byte); ok {
						*used = [][]byte{}
					}
				}
				return nil
			},
		},
		execFuncs: []func(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error){
			func(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
				return pgconn.NewCommandTag("UPDATE 1"), nil
			},
			func(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
				return pgconn.NewCommandTag("UPDATE 1"), nil
			},
		},
	}

	mgr = NewMFAManager(mdb, crypto)

	if err := mgr.DisableMFA(context.Background(), uuid.New(), code); err != nil {
		t.Fatalf("expected DisableMFA to succeed, got %v", err)
	}
	if len(mdb.execFuncs) != 0 {
		t.Fatal("expected all exec functions to be consumed")
	}
}

func TestRegenerateBackupCodes(t *testing.T) {
	crypto := appcrypto.NewCryptoService(make([]byte, 32))
	password := "ComplexPass123!"
	salt := []byte("1234567890abcdef")
	pm := NewPasswordManager(&mfaMockDB{}, crypto)
	passwordHash := pm.HashPassword(password, salt)

	mdb := &mfaMockDB{
		queryRowFuncs: []func(dest ...interface{}) error{
			func(dest ...interface{}) error {
				if len(dest) >= 2 {
					if hashDest, ok := dest[0].(*string); ok {
						*hashDest = passwordHash
					}
					if saltDest, ok := dest[1].(*[]byte); ok {
						*saltDest = salt
					}
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

	mgr := NewMFAManager(mdb, crypto)

	codes, err := mgr.RegenerateBackupCodes(context.Background(), uuid.New(), password)
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if len(codes) != BackupCodeCount {
		t.Fatalf("expected %d codes, got %d", BackupCodeCount, len(codes))
	}
	for _, code := range codes {
		if code == "" {
			t.Fatal("expected generated code to be non-empty")
		}
	}
}

func TestRegenerateBackupCodesInvalidPassword(t *testing.T) {
	crypto := appcrypto.NewCryptoService(make([]byte, 32))
	mdb := &mfaMockDB{
		queryRowFuncs: []func(dest ...interface{}) error{
			func(dest ...interface{}) error {
				if len(dest) >= 2 {
					if hashDest, ok := dest[0].(*string); ok {
						*hashDest = "different-hash"
					}
					if saltDest, ok := dest[1].(*[]byte); ok {
						*saltDest = []byte("salt")
					}
				}
				return nil
			},
		},
	}

	mgr := NewMFAManager(mdb, crypto)

	if _, err := mgr.RegenerateBackupCodes(context.Background(), uuid.New(), "wrong password"); err == nil {
		t.Fatal("expected error for invalid password")
	}
}

func TestGetDecryptedTOTPSecret(t *testing.T) {
	crypto := appcrypto.NewCryptoService(make([]byte, 32))
	secret := []byte("ref-secret")
	encrypted, err := crypto.EncryptBytes(secret)
	if err != nil {
		t.Fatalf("failed to encrypt secret: %v", err)
	}

	mdb := &mfaMockDB{
		queryRowFuncs: []func(dest ...interface{}) error{
			func(dest ...interface{}) error {
				if b, ok := dest[0].(*[]byte); ok {
					*b = encrypted
				}
				return nil
			},
		},
	}

	mgr := NewMFAManager(mdb, crypto)

	value, err := mgr.GetDecryptedTOTPSecret(context.Background(), uuid.New())
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if value != string(secret) {
		t.Fatalf("expected secret %s, got %s", secret, value)
	}
}
