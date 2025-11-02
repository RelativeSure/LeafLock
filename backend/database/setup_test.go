package database

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
)

// MockDatabase implements Database interface for testing
type MockDatabase struct {
	QueryRowFunc func(ctx context.Context, sql string, args ...interface{}) pgx.Row
	QueryFunc    func(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error)
	ExecFunc     func(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error)
	BeginFunc    func(ctx context.Context) (pgx.Tx, error)
}

func (m *MockDatabase) QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row {
	if m.QueryRowFunc != nil {
		return m.QueryRowFunc(ctx, sql, args...)
	}
	return nil
}

func (m *MockDatabase) Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error) {
	if m.QueryFunc != nil {
		return m.QueryFunc(ctx, sql, args...)
	}
	return nil, nil
}

func (m *MockDatabase) Exec(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
	if m.ExecFunc != nil {
		return m.ExecFunc(ctx, sql, args...)
	}
	return pgconn.CommandTag{}, nil
}

func (m *MockDatabase) Begin(ctx context.Context) (pgx.Tx, error) {
	if m.BeginFunc != nil {
		return m.BeginFunc(ctx)
	}
	return nil, nil
}

// MockRow implements pgx.Row interface
type MockRow struct {
	ScanFunc func(dest ...interface{}) error
}

func (m *MockRow) Scan(dest ...interface{}) error {
	if m.ScanFunc != nil {
		return m.ScanFunc(dest...)
	}
	return nil
}

// MockTx implements pgx.Tx interface for testing
type MockTx struct {
	ExecFunc     func(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error)
	QueryRowFunc func(ctx context.Context, sql string, args ...interface{}) pgx.Row
	CommitFunc   func(ctx context.Context) error
	RollbackFunc func(ctx context.Context) error
}

func (m *MockTx) Begin(ctx context.Context) (pgx.Tx, error) {
	return nil, errors.New("nested transactions not supported")
}

func (m *MockTx) Commit(ctx context.Context) error {
	if m.CommitFunc != nil {
		return m.CommitFunc(ctx)
	}
	return nil
}

func (m *MockTx) Rollback(ctx context.Context) error {
	if m.RollbackFunc != nil {
		return m.RollbackFunc(ctx)
	}
	return nil
}

func (m *MockTx) CopyFrom(ctx context.Context, tableName pgx.Identifier, columnNames []string, rowSrc pgx.CopyFromSource) (int64, error) {
	return 0, errors.New("not implemented")
}

func (m *MockTx) SendBatch(ctx context.Context, b *pgx.Batch) pgx.BatchResults {
	return nil
}

func (m *MockTx) LargeObjects() pgx.LargeObjects {
	return pgx.LargeObjects{}
}

func (m *MockTx) Prepare(ctx context.Context, name, sql string) (*pgconn.StatementDescription, error) {
	return nil, errors.New("not implemented")
}

func (m *MockTx) Exec(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
	if m.ExecFunc != nil {
		return m.ExecFunc(ctx, sql, args...)
	}
	return pgconn.CommandTag{}, nil
}

func (m *MockTx) Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error) {
	return nil, errors.New("not implemented")
}

func (m *MockTx) QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row {
	if m.QueryRowFunc != nil {
		return m.QueryRowFunc(ctx, sql, args...)
	}
	return nil
}

func (m *MockTx) Conn() *pgx.Conn {
	return nil
}

func TestAdminURLAndDBName_InvalidURL(t *testing.T) {
	// Test with truly invalid URL format
	invalidURL := "://invalid"
	adminURL, dbName := adminURLAndDBName(invalidURL)
	// When URL parse fails, it returns the original URL and empty dbName
	assert.Equal(t, invalidURL, adminURL)
	assert.Equal(t, "", dbName)
}

func TestAdminURLAndDBName_EmptyPath(t *testing.T) {
	url := "postgresql://user:pass@localhost:5432/"
	adminURL, dbName := adminURLAndDBName(url)
	assert.Contains(t, adminURL, "/postgres")
	assert.Equal(t, "", dbName)
}

func TestSafePgIdent_InvalidCharacters(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"SQL injection attempt", "mydb; DROP TABLE users--"},
		{"Spaces", "my database"},
		{"Special chars", "db@name!"},
		{"Quotes", "db'name"},
		{"Double quotes", `db"name`},
		{"Dash", "my-db"},
		{"Dots", "my.db"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ok := safePgIdent(tt.input)
			assert.False(t, ok, "Expected safePgIdent to reject: %s", tt.input)
		})
	}
}

func TestSafePgIdent_ValidIdentifiers(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"Simple", "mydb"},
		{"With underscores", "my_database_name"},
		{"With numbers", "db123"},
		{"Mixed", "MyDatabase_2024"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, ok := safePgIdent(tt.input)
			assert.True(t, ok)
			assert.Equal(t, tt.input, result)
		})
	}
}

func TestCheckMigrationStatus_CreateTableError(t *testing.T) {
	mockDB := &MockDatabase{
		ExecFunc: func(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
			return pgconn.CommandTag{}, errors.New("permission denied")
		},
	}

	version, needsMigration := checkMigrationStatus(context.Background(), mockDB)
	assert.Equal(t, "", version)
	assert.True(t, needsMigration)
}

func TestCheckMigrationStatus_VersionMatch(t *testing.T) {
	mockDB := &MockDatabase{
		ExecFunc: func(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
			return pgconn.CommandTag{}, nil
		},
		QueryRowFunc: func(ctx context.Context, sql string, args ...interface{}) pgx.Row {
			return &MockRow{
				ScanFunc: func(dest ...interface{}) error {
					if version, ok := dest[0].(*string); ok {
						*version = MigrationSchemaVersion
					}
					return nil
				},
			}
		},
	}

	version, needsMigration := checkMigrationStatus(context.Background(), mockDB)
	assert.Equal(t, MigrationSchemaVersion, version)
	assert.False(t, needsMigration)
}

func TestCheckMigrationStatus_VersionMismatch(t *testing.T) {
	mockDB := &MockDatabase{
		ExecFunc: func(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
			return pgconn.CommandTag{}, nil
		},
		QueryRowFunc: func(ctx context.Context, sql string, args ...interface{}) pgx.Row {
			callCount := 0
			return &MockRow{
				ScanFunc: func(dest ...interface{}) error {
					callCount++
					if callCount == 1 {
						// First call: version check
						if version, ok := dest[0].(*string); ok {
							*version = "2024.01.01.001" // Old version
						}
					} else {
						// Second call: table count check
						if count, ok := dest[0].(*int); ok {
							*count = 4
						}
					}
					return nil
				},
			}
		},
	}

	version, needsMigration := checkMigrationStatus(context.Background(), mockDB)
	assert.Equal(t, "2024.01.01.001", version)
	assert.True(t, needsMigration)
}

func TestCheckMigrationStatus_NoRowsError(t *testing.T) {
	mockDB := &MockDatabase{
		ExecFunc: func(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
			return pgconn.CommandTag{}, nil
		},
		QueryRowFunc: func(ctx context.Context, sql string, args ...interface{}) pgx.Row {
			return &MockRow{
				ScanFunc: func(dest ...interface{}) error {
					return pgx.ErrNoRows
				},
			}
		},
	}

	version, needsMigration := checkMigrationStatus(context.Background(), mockDB)
	assert.Equal(t, "", version)
	assert.True(t, needsMigration)
}

func TestRunOptimizedMigrations_AlreadyUpToDate(t *testing.T) {
	mockDB := &MockDatabase{
		ExecFunc: func(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
			return pgconn.CommandTag{}, nil
		},
		QueryRowFunc: func(ctx context.Context, sql string, args ...interface{}) pgx.Row {
			return &MockRow{
				ScanFunc: func(dest ...interface{}) error {
					if version, ok := dest[0].(*string); ok {
						*version = MigrationSchemaVersion
					}
					return nil
				},
			}
		},
	}

	err := runOptimizedMigrations(context.Background(), mockDB)
	assert.NoError(t, err)
}

func TestRunOptimizedMigrations_BeginTransactionError(t *testing.T) {
	mockDB := &MockDatabase{
		ExecFunc: func(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
			return pgconn.CommandTag{}, nil
		},
		QueryRowFunc: func(ctx context.Context, sql string, args ...interface{}) pgx.Row {
			return &MockRow{
				ScanFunc: func(dest ...interface{}) error {
					if version, ok := dest[0].(*string); ok {
						*version = "2024.01.01.001"
					}
					return nil
				},
			}
		},
		BeginFunc: func(ctx context.Context) (pgx.Tx, error) {
			return nil, errors.New("failed to begin transaction")
		},
	}

	err := runOptimizedMigrations(context.Background(), mockDB)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to begin migration transaction")
}

func TestRunOptimizedMigrations_ExecSchemaError(t *testing.T) {
	mockTx := &MockTx{
		ExecFunc: func(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
			return pgconn.CommandTag{}, errors.New("syntax error in schema")
		},
		RollbackFunc: func(ctx context.Context) error {
			return nil
		},
	}

	mockDB := &MockDatabase{
		ExecFunc: func(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
			return pgconn.CommandTag{}, nil
		},
		QueryRowFunc: func(ctx context.Context, sql string, args ...interface{}) pgx.Row {
			return &MockRow{
				ScanFunc: func(dest ...interface{}) error {
					if version, ok := dest[0].(*string); ok {
						*version = "2024.01.01.001"
					}
					return nil
				},
			}
		},
		BeginFunc: func(ctx context.Context) (pgx.Tx, error) {
			return mockTx, nil
		},
	}

	err := runOptimizedMigrations(context.Background(), mockDB)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to execute migrations")
}

func TestRunOptimizedMigrations_UpdateVersionError(t *testing.T) {
	execCallCount := 0
	mockTx := &MockTx{
		ExecFunc: func(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
			execCallCount++
			if execCallCount == 1 {
				// First call: execute schema (success)
				return pgconn.CommandTag{}, nil
			}
			// Second call: update version (failure)
			return pgconn.CommandTag{}, errors.New("failed to insert version")
		},
		RollbackFunc: func(ctx context.Context) error {
			return nil
		},
	}

	mockDB := &MockDatabase{
		ExecFunc: func(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
			return pgconn.CommandTag{}, nil
		},
		QueryRowFunc: func(ctx context.Context, sql string, args ...interface{}) pgx.Row {
			return &MockRow{
				ScanFunc: func(dest ...interface{}) error {
					if version, ok := dest[0].(*string); ok {
						*version = "2024.01.01.001"
					}
					return nil
				},
			}
		},
		BeginFunc: func(ctx context.Context) (pgx.Tx, error) {
			return mockTx, nil
		},
	}

	err := runOptimizedMigrations(context.Background(), mockDB)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to update migration version")
}

func TestRunOptimizedMigrations_CommitError(t *testing.T) {
	mockTx := &MockTx{
		ExecFunc: func(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
			return pgconn.CommandTag{}, nil
		},
		CommitFunc: func(ctx context.Context) error {
			return errors.New("failed to commit transaction")
		},
		RollbackFunc: func(ctx context.Context) error {
			return nil
		},
	}

	mockDB := &MockDatabase{
		ExecFunc: func(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
			return pgconn.CommandTag{}, nil
		},
		QueryRowFunc: func(ctx context.Context, sql string, args ...interface{}) pgx.Row {
			return &MockRow{
				ScanFunc: func(dest ...interface{}) error {
					if version, ok := dest[0].(*string); ok {
						*version = "2024.01.01.001"
					}
					return nil
				},
			}
		},
		BeginFunc: func(ctx context.Context) (pgx.Tx, error) {
			return mockTx, nil
		},
	}

	err := runOptimizedMigrations(context.Background(), mockDB)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to commit migration transaction")
}

func TestUpdateMigrationVersion_Success(t *testing.T) {
	mockTx := &MockTx{
		ExecFunc: func(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
			assert.Contains(t, sql, "INSERT INTO _migrations")
			assert.Equal(t, "2025.01.01.001", args[0])
			return pgconn.CommandTag{}, nil
		},
	}

	err := updateMigrationVersion(context.Background(), mockTx, "2025.01.01.001")
	assert.NoError(t, err)
}

func TestFastHealthCheck_Success(t *testing.T) {
	mockDB := &MockDatabase{
		QueryRowFunc: func(ctx context.Context, sql string, args ...interface{}) pgx.Row {
			return &MockRow{
				ScanFunc: func(dest ...interface{}) error {
					if result, ok := dest[0].(*int); ok {
						*result = 1
					}
					return nil
				},
			}
		},
	}

	err := fastHealthCheck(context.Background(), mockDB)
	assert.NoError(t, err)
}

func TestFastHealthCheck_QueryError(t *testing.T) {
	mockDB := &MockDatabase{
		QueryRowFunc: func(ctx context.Context, sql string, args ...interface{}) pgx.Row {
			return &MockRow{
				ScanFunc: func(dest ...interface{}) error {
					return errors.New("connection lost")
				},
			}
		},
	}

	err := fastHealthCheck(context.Background(), mockDB)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "database health check failed")
}

func TestValidateDatabaseConnectivity_Success(t *testing.T) {
	mockDB := &MockDatabase{
		QueryRowFunc: func(ctx context.Context, sql string, args ...interface{}) pgx.Row {
			return &MockRow{
				ScanFunc: func(dest ...interface{}) error {
					if result, ok := dest[0].(*int); ok {
						*result = 1
					}
					return nil
				},
			}
		},
	}

	err := validateDatabaseConnectivity(mockDB)
	assert.NoError(t, err)
}

func TestValidateDatabaseConnectivity_Timeout(t *testing.T) {
	mockDB := &MockDatabase{
		QueryRowFunc: func(ctx context.Context, sql string, args ...interface{}) pgx.Row {
			return &MockRow{
				ScanFunc: func(dest ...interface{}) error {
					// Simulate slow query exceeding context timeout
					time.Sleep(4 * time.Second)
					return errors.New("context deadline exceeded")
				},
			}
		},
	}

	err := validateDatabaseConnectivity(mockDB)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "database connectivity check failed")
}

func TestSetupDatabase_InvalidURL(t *testing.T) {
	_, err := SetupDatabase("invalid://not-a-database-url")
	assert.Error(t, err)
}

func TestSetupDatabaseFast_InvalidURL(t *testing.T) {
	_, err := SetupDatabaseFast("invalid://not-a-database-url")
	assert.Error(t, err)
}

func TestCheckMigrationStatus_TableCountCheckLowCount(t *testing.T) {
	callCount := 0
	mockDB := &MockDatabase{
		ExecFunc: func(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
			return pgconn.CommandTag{}, nil
		},
		QueryRowFunc: func(ctx context.Context, sql string, args ...interface{}) pgx.Row {
			return &MockRow{
				ScanFunc: func(dest ...interface{}) error {
					callCount++
					if callCount == 1 {
						// Version query
						if version, ok := dest[0].(*string); ok {
							*version = "2024.01.01.001"
						}
					} else {
						// Table count query
						if count, ok := dest[0].(*int); ok {
							*count = 2 // Less than 4 tables
						}
					}
					return nil
				},
			}
		},
	}

	version, needsMigration := checkMigrationStatus(context.Background(), mockDB)
	assert.Equal(t, "2024.01.01.001", version)
	assert.True(t, needsMigration)
}

func TestCheckMigrationStatus_TableCountCheckError(t *testing.T) {
	callCount := 0
	mockDB := &MockDatabase{
		ExecFunc: func(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
			return pgconn.CommandTag{}, nil
		},
		QueryRowFunc: func(ctx context.Context, sql string, args ...interface{}) pgx.Row {
			return &MockRow{
				ScanFunc: func(dest ...interface{}) error {
					callCount++
					if callCount == 1 {
						// Version query success
						if version, ok := dest[0].(*string); ok {
							*version = "2024.01.01.001"
						}
						return nil
					}
					// Table count query fails
					return errors.New("table query failed")
				},
			}
		},
	}

	version, needsMigration := checkMigrationStatus(context.Background(), mockDB)
	assert.Equal(t, "2024.01.01.001", version)
	assert.True(t, needsMigration)
}
