package database

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type mockRow struct {
	scanFunc func(dest ...interface{}) error
}

func (m mockRow) Scan(dest ...interface{}) error {
	if m.scanFunc != nil {
		return m.scanFunc(dest...)
	}
	return nil
}

type mockDatabase struct {
	execFunc      func(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error)
	queryRowFuncs []func(dest ...interface{}) error
	beginFunc     func(ctx context.Context) (pgx.Tx, error)
	beginCalls    int
}

func (m *mockDatabase) QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row {
	if len(m.queryRowFuncs) == 0 {
		return mockRow{}
	}
	fn := m.queryRowFuncs[0]
	m.queryRowFuncs = m.queryRowFuncs[1:]
	return mockRow{scanFunc: fn}
}

func (m *mockDatabase) Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error) {
	return nil, nil
}

func (m *mockDatabase) Exec(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
	if m.execFunc != nil {
		return m.execFunc(ctx, sql, args...)
	}
	return pgconn.CommandTag{}, nil
}

func (m *mockDatabase) Begin(ctx context.Context) (pgx.Tx, error) {
	m.beginCalls++
	if m.beginFunc != nil {
		return m.beginFunc(ctx)
	}
	return nil, nil
}

type mockTx struct {
	execCalls      []string
	commitCalled   bool
	rollbackCalled bool
}

func (m *mockTx) Begin(ctx context.Context) (pgx.Tx, error) {
	return nil, errors.New("not implemented")
}

func (m *mockTx) Commit(ctx context.Context) error {
	m.commitCalled = true
	return nil
}

func (m *mockTx) Rollback(ctx context.Context) error {
	m.rollbackCalled = true
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

func (m *mockTx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	m.execCalls = append(m.execCalls, sql)
	return pgconn.CommandTag{}, nil
}

func (m *mockTx) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	return nil, nil
}

func (m *mockTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	return mockRow{}
}

func (m *mockTx) Conn() *pgx.Conn {
	return nil
}

func TestCheckMigrationStatus_NoMigrations(t *testing.T) {
	db := &mockDatabase{
		execFunc: func(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
			return pgconn.CommandTag{}, nil
		},
		queryRowFuncs: []func(dest ...interface{}) error{
			func(dest ...interface{}) error {
				return pgx.ErrNoRows
			},
		},
	}

	version, needsMigration := checkMigrationStatus(context.Background(), db)
	if version != "" {
		t.Fatalf("expected empty version, got %q", version)
	}
	if !needsMigration {
		t.Fatal("expected migrations to be required")
	}
}

func TestCheckMigrationStatus_UpToDate(t *testing.T) {
	db := &mockDatabase{
		queryRowFuncs: []func(dest ...interface{}) error{
			func(dest ...interface{}) error {
				if len(dest) > 0 {
					if s, ok := dest[0].(*string); ok {
						*s = MigrationSchemaVersion
					}
				}
				return nil
			},
		},
		beginFunc: func(ctx context.Context) (pgx.Tx, error) {
			return &mockTx{}, nil
		},
	}

	version, needsMigration := checkMigrationStatus(context.Background(), db)
	if version != MigrationSchemaVersion {
		t.Fatalf("expected version %s, got %s", MigrationSchemaVersion, version)
	}
	if needsMigration {
		t.Fatal("expected no migrations required")
	}
}

func TestCheckMigrationStatus_TableCountCheck(t *testing.T) {
	db := &mockDatabase{
		queryRowFuncs: []func(dest ...interface{}) error{
			func(dest ...interface{}) error {
				if s, ok := dest[0].(*string); ok {
					*s = "2024.01.01.001"
				}
				return nil
			},
			func(dest ...interface{}) error {
				if i, ok := dest[0].(*int); ok {
					*i = 4
				}
				return nil
			},
		},
	}

	version, needsMigration := checkMigrationStatus(context.Background(), db)
	if version != "2024.01.01.001" {
		t.Fatalf("expected version to be preserved, got %s", version)
	}
	if !needsMigration {
		t.Fatal("expected migrations to be required when version mismatches")
	}
}

func TestCheckMigrationStatus_QueryError(t *testing.T) {
	db := &mockDatabase{
		queryRowFuncs: []func(dest ...interface{}) error{
			func(dest ...interface{}) error {
				return errors.New("scan error")
			},
		},
	}

	version, needsMigration := checkMigrationStatus(context.Background(), db)
	if version != "" {
		t.Fatalf("expected empty version on error, got %s", version)
	}
	if !needsMigration {
		t.Fatal("expected migrations to be required on scan error")
	}
}

func TestRunOptimizedMigrations_SkipsWhenUpToDate(t *testing.T) {
	db := &mockDatabase{
		queryRowFuncs: []func(dest ...interface{}) error{
			func(dest ...interface{}) error {
				if s, ok := dest[0].(*string); ok {
					*s = MigrationSchemaVersion
				}
				return nil
			},
		},
		beginFunc: func(ctx context.Context) (pgx.Tx, error) {
			return &mockTx{}, nil
		},
	}

	if err := runOptimizedMigrations(context.Background(), db); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if db.beginCalls != 0 {
		t.Fatalf("expected no transaction to begin, got %d", db.beginCalls)
	}
}

func TestRunOptimizedMigrations_ExecutesSchema(t *testing.T) {
	migrationTx := &mockTx{}
	db := &mockDatabase{
		queryRowFuncs: []func(dest ...interface{}) error{
			func(dest ...interface{}) error {
				return pgx.ErrNoRows
			},
		},
		beginFunc: func(ctx context.Context) (pgx.Tx, error) {
			return migrationTx, nil
		},
	}

	if err := runOptimizedMigrations(context.Background(), db); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(migrationTx.execCalls) != 2 {
		t.Fatalf("expected 2 exec calls, got %d", len(migrationTx.execCalls))
	}
	if !migrationTx.commitCalled {
		t.Fatal("expected transaction commit")
	}
	if !migrationTx.rollbackCalled {
		t.Fatal("expected deferred rollback to be invoked")
	}
}

func TestFastHealthCheck(t *testing.T) {
	db := &mockDatabase{
		queryRowFuncs: []func(dest ...interface{}) error{
			func(dest ...interface{}) error {
				if i, ok := dest[0].(*int); ok {
					*i = 1
				}
				return nil
			},
		},
	}

	if err := fastHealthCheck(context.Background(), db); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	dbFail := &mockDatabase{
		queryRowFuncs: []func(dest ...interface{}) error{
			func(dest ...interface{}) error {
				return errors.New("query failed")
			},
		},
	}

	if err := fastHealthCheck(context.Background(), dbFail); err == nil {
		t.Fatal("expected error when query fails")
	}
}

func TestValidateDatabaseConnectivity(t *testing.T) {
	successDB := &mockDatabase{
		queryRowFuncs: []func(dest ...interface{}) error{
			func(dest ...interface{}) error {
				if i, ok := dest[0].(*int); ok {
					*i = 1
				}
				return nil
			},
		},
	}

	if err := validateDatabaseConnectivity(successDB); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	failingDB := &mockDatabase{
		queryRowFuncs: []func(dest ...interface{}) error{
			func(dest ...interface{}) error {
				return errors.New("health check failed")
			},
		},
	}

	if err := validateDatabaseConnectivity(failingDB); err == nil {
		t.Fatal("expected connectivity validation to fail")
	}
}
