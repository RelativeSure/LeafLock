package auth

import (
	"context"
	"encoding/base64"
	"sync"
	"testing"
	"time"

	appcrypto "leaflock/crypto"
	"leaflock/utils"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type mockServiceDB struct {
	queryRowFuncs []func(dest ...interface{}) error
	execFuncs     []func(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error)
	beginFunc     func(ctx context.Context) (pgx.Tx, error)
	beginCalls    int
}

func (m *mockServiceDB) QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row {
	if len(m.queryRowFuncs) == 0 {
		return mockRow{}
	}
	fn := m.queryRowFuncs[0]
	m.queryRowFuncs = m.queryRowFuncs[1:]
	return mockRow{scanFunc: fn}
}

func (m *mockServiceDB) Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error) {
	return nil, nil
}

func (m *mockServiceDB) Exec(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
	if len(m.execFuncs) == 0 {
		return pgconn.NewCommandTag("EXEC 0"), nil
	}
	fn := m.execFuncs[0]
	m.execFuncs = m.execFuncs[1:]
	return fn(ctx, sql, args...)
}

func (m *mockServiceDB) Begin(ctx context.Context) (pgx.Tx, error) {
	m.beginCalls++
	if m.beginFunc != nil {
		return m.beginFunc(ctx)
	}
	return &mockTx{}, nil
}

type mockRow struct {
	scanFunc func(dest ...interface{}) error
}

func (m mockRow) Scan(dest ...interface{}) error {
	if m.scanFunc != nil {
		return m.scanFunc(dest...)
	}
	return nil
}

type mockTx struct {
	execFuncs     []func(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error)
	queryRowFuncs []func(dest ...interface{}) error
	execCalls     []string
	committed     bool
	rolledBack    bool
}

func (m *mockTx) Begin(ctx context.Context) (pgx.Tx, error) {
	return nil, pgx.ErrTxClosed
}

func (m *mockTx) Commit(ctx context.Context) error {
	m.committed = true
	return nil
}

func (m *mockTx) Rollback(ctx context.Context) error {
	m.rolledBack = true
	return nil
}

func (m *mockTx) CopyFrom(ctx context.Context, tableName pgx.Identifier, columnNames []string, rowSrc pgx.CopyFromSource) (int64, error) {
	return 0, nil
}

func (m *mockTx) SendBatch(ctx context.Context, b *pgx.Batch) pgx.BatchResults {
	return nil
}

func (m *mockTx) LargeObjects() pgx.LargeObjects {
	return pgx.LargeObjects{}
}

func (m *mockTx) Prepare(ctx context.Context, name, sql string) (*pgconn.StatementDescription, error) {
	return nil, nil
}

func (m *mockTx) Exec(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
	m.execCalls = append(m.execCalls, sql)
	if len(m.execFuncs) == 0 {
		return pgconn.NewCommandTag("EXEC 1"), nil
	}
	fn := m.execFuncs[0]
	m.execFuncs = m.execFuncs[1:]
	return fn(ctx, sql, args...)
}

func (m *mockTx) Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error) {
	return nil, nil
}

func (m *mockTx) QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row {
	if len(m.queryRowFuncs) == 0 {
		return mockRow{}
	}
	fn := m.queryRowFuncs[0]
	m.queryRowFuncs = m.queryRowFuncs[1:]
	return mockRow{scanFunc: fn}
}

func (m *mockTx) Conn() *pgx.Conn {
	return nil
}

type mockSessionManager struct {
	createSession func(ctx context.Context, userID uuid.UUID, ipAddress, userAgent string, mfaVerified bool) (*Session, string, error)
	mu            sync.Mutex
	lastSession   *Session
}

func (m *mockSessionManager) CreateSession(ctx context.Context, userID uuid.UUID, ipAddress, userAgent string, mfaVerified bool) (*Session, string, error) {
	if m.createSession != nil {
		session, token, err := m.createSession(ctx, userID, ipAddress, userAgent, mfaVerified)
		if session != nil {
			m.mu.Lock()
			m.lastSession = session
			m.mu.Unlock()
		}
		return session, token, err
	}
	s := &Session{UserID: userID, Token: "token", ExpiresAt: time.Now().Add(time.Hour)}
	m.mu.Lock()
	m.lastSession = s
	m.mu.Unlock()
	return s, "token", nil
}

func (m *mockSessionManager) CreateMFASession(ctx context.Context, userID uuid.UUID, email, ipAddress, userAgent string, mfaEnabled bool) (string, error) {
	return "mfa-token", nil
}

func (m *mockSessionManager) GetMFASession(ctx context.Context, token string) (*MFASession, error) {
	return nil, nil
}

func (m *mockSessionManager) DeleteMFASession(ctx context.Context, token string) error {
	return nil
}

func (m *mockSessionManager) DeleteSession(ctx context.Context, token string) error {
	return nil
}

func (m *mockSessionManager) BlacklistJWT(ctx context.Context, token string, expiresAt time.Time) error {
	return nil
}

func (m *mockSessionManager) IsJWTBlacklisted(ctx context.Context, token string) (bool, error) {
	return false, nil
}

func TestCreateAuthResponsePopulatesFields(t *testing.T) {
	userID := uuid.New()
	workspaceID := uuid.New()
	salt := []byte("test-salt")
	db := &mockServiceDB{
		queryRowFuncs: []func(dest ...interface{}) error{
			func(dest ...interface{}) error {
				if idPtr, ok := dest[0].(*uuid.UUID); ok {
					*idPtr = workspaceID
				}
				return nil
			},
			func(dest ...interface{}) error {
				if saltPtr, ok := dest[0].(*[]byte); ok {
					*saltPtr = salt
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

	crypto := appcrypto.NewCryptoService(make([]byte, 32))
	sessionMgr := &mockSessionManager{}
	service := &Service{
		db:        db,
		crypto:    crypto,
		session:   sessionMgr,
		password:  NewPasswordManager(db),
		mfa:       NewMFAManager(db, crypto),
		jwtSecret: "unit-secret",
	}

	ctx := context.Background()
	ctx = context.WithValue(ctx, utils.ContextKeyClientIP, "127.0.0.1")
	ctx = context.WithValue(ctx, utils.ContextKeyUserAgent, "unit-test")

	resp, err := service.createAuthResponse(ctx, userID, true, true)
	if err != nil {
		t.Fatalf("createAuthResponse returned error: %v", err)
	}
	if resp.UserID != userID.String() {
		t.Fatalf("expected user ID %s, got %s", userID, resp.UserID)
	}
	if resp.WorkspaceID != workspaceID.String() {
		t.Fatalf("expected workspace ID %s, got %s", workspaceID, resp.WorkspaceID)
	}
	if resp.EncryptionSalt != base64.StdEncoding.EncodeToString(salt) {
		t.Fatalf("unexpected encryption salt: %s", resp.EncryptionSalt)
	}
	if resp.EncryptionVersion != defaultEncryptionVersion {
		t.Fatalf("expected encryption version %d, got %d", defaultEncryptionVersion, resp.EncryptionVersion)
	}
	if _, err := jwt.Parse(resp.Token, func(token *jwt.Token) (interface{}, error) {
		return []byte(service.jwtSecret), nil
	}); err != nil {
		t.Fatalf("returned JWT is invalid: %v", err)
	}
}

func TestIncrementFailedAttemptsLocksAccount(t *testing.T) {
	var capturedAttempts int
	var lockedUntil interface{}
	targetUser := uuid.New()
	db := &mockServiceDB{
		execFuncs: []func(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error){
			func(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
				capturedAttempts = args[0].(int)
				lockedUntil = args[1]
				if args[2].(uuid.UUID) != targetUser {
					t.Fatalf("expected user ID %s, got %v", targetUser, args[2])
				}
				return pgconn.NewCommandTag("UPDATE 1"), nil
			},
		},
	}

	service := &Service{db: db}
	service.incrementFailedAttempts(context.Background(), targetUser, 5)
	if capturedAttempts != 6 {
		t.Fatalf("expected attempts to increment to 6, got %d", capturedAttempts)
	}
	if lockedUntil == nil {
		t.Fatal("expected lockedUntil to be set")
	}
}

func TestResetFailedAttemptsClearsState(t *testing.T) {
	var called bool
	targetUser := uuid.New()
	db := &mockServiceDB{
		execFuncs: []func(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error){
			func(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
				called = true
				if args[0].(uuid.UUID) != targetUser {
					t.Fatalf("expected user ID %s, got %v", targetUser, args[0])
				}
				return pgconn.NewCommandTag("UPDATE 1"), nil
			},
		},
	}

	service := &Service{db: db}
	service.resetFailedAttempts(context.Background(), targetUser)
	if !called {
		t.Fatal("expected update query to be executed")
	}
}

func TestAuditLogExecutesInsert(t *testing.T) {
	called := false
	db := &mockServiceDB{
		execFuncs: []func(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error){
			func(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
				called = true
				if len(args) != 6 {
					t.Fatalf("expected 6 args, got %d", len(args))
				}
				return pgconn.NewCommandTag("INSERT 1"), nil
			},
		},
	}

	service := &Service{db: db}
	ctx := context.Background()
	ctx = context.WithValue(ctx, utils.ContextKeyClientIP, "203.0.113.5")
	ctx = context.WithValue(ctx, utils.ContextKeyUserAgent, "Mozilla/5.0")

	service.auditLog(ctx, uuid.New(), "login", map[string]interface{}{"status": "success"})
	if !called {
		t.Fatal("expected audit log to execute insert")
	}
}

func TestEnsureDefaultAdminCreatesRecords(t *testing.T) {
	userID := uuid.New()
	db := &mockServiceDB{}
	crypto := appcrypto.NewCryptoService(make([]byte, 32))
	tx := &mockTx{
		queryRowFuncs: []func(dest ...interface{}) error{
			func(dest ...interface{}) error {
				if idPtr, ok := dest[0].(*uuid.UUID); ok {
					*idPtr = userID
				}
				return nil
			},
		},
	}
	db.beginFunc = func(ctx context.Context) (pgx.Tx, error) {
		return tx, nil
	}
	db.queryRowFuncs = []func(dest ...interface{}) error{
		func(dest ...interface{}) error {
			if countPtr, ok := dest[0].(*int); ok {
				*countPtr = 0
			}
			return nil
		},
	}
	db.execFuncs = []func(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error){
		func(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
			return pgconn.NewCommandTag("UPDATE 1"), nil
		},
	}

	service := &Service{
		db:        db,
		crypto:    crypto,
		session:   &mockSessionManager{},
		password:  NewPasswordManager(db),
		mfa:       NewMFAManager(db, crypto),
		jwtSecret: "secret",
	}

	if err := service.EnsureDefaultAdmin(context.Background(), true, "admin@example.com", "ComplexPass123!"); err != nil {
		t.Fatalf("EnsureDefaultAdmin returned error: %v", err)
	}
	if !tx.committed {
		t.Fatal("expected transaction to be committed")
	}
	if len(tx.execCalls) < 3 {
		t.Fatalf("expected multiple exec calls, got %d", len(tx.execCalls))
	}
}

func TestEnsureDefaultAdminSkipsWhenAdminExists(t *testing.T) {
	db := &mockServiceDB{
		queryRowFuncs: []func(dest ...interface{}) error{
			func(dest ...interface{}) error {
				// Return true for EXISTS query (admin already exists)
				if existsPtr, ok := dest[0].(*bool); ok {
					*existsPtr = true
				}
				return nil
			},
		},
	}

	service := &Service{db: db, password: NewPasswordManager(db, appcrypto.NewCryptoService(make([]byte, 32)))}

	if err := service.EnsureDefaultAdmin(context.Background(), true, "admin@example.com", "ComplexPass123!"); err != nil {
		t.Fatalf("expected no error when admin exists, got %v", err)
	}
	if db.beginCalls != 0 {
		t.Fatalf("expected no transaction to begin when admin exists, got %d", db.beginCalls)
	}
}
