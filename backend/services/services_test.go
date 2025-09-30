package services

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Mock Database implementation for testing
type mockDatabase struct {
	queryRowFunc func(ctx context.Context, sql string, args ...interface{}) pgx.Row
	execFunc     func(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error)
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

func (m *mockDatabase) QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row {
	if m.queryRowFunc != nil {
		return m.queryRowFunc(ctx, sql, args...)
	}
	return mockRow{}
}

func (m *mockDatabase) Exec(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
	if m.execFunc != nil {
		return m.execFunc(ctx, sql, args...)
	}
	return pgconn.CommandTag{}, nil
}

func (m *mockDatabase) Begin(ctx context.Context) (pgx.Tx, error) {
	return nil, nil
}

// Mock CryptoService implementation for testing
type mockCryptoService struct {
	encryptFunc              func(data []byte) ([]byte, error)
	encryptDeterministicFunc func(data []byte, context string) ([]byte, error)
	hashEmailFunc            func(email string) []byte
	encryptWithGDPRKeyFunc   func(data []byte, gdprKey []byte) ([]byte, error)
}

func (m *mockCryptoService) Encrypt(data []byte) ([]byte, error) {
	if m.encryptFunc != nil {
		return m.encryptFunc(data)
	}
	return []byte("encrypted"), nil
}

func (m *mockCryptoService) EncryptDeterministic(data []byte, context string) ([]byte, error) {
	if m.encryptDeterministicFunc != nil {
		return m.encryptDeterministicFunc(data, context)
	}
	return []byte("deterministic_hash"), nil
}

func (m *mockCryptoService) HashEmail(email string) []byte {
	if m.hashEmailFunc != nil {
		return m.hashEmailFunc(email)
	}
	return []byte("email_hash")
}

func (m *mockCryptoService) EncryptWithGDPRKey(data []byte, gdprKey []byte) ([]byte, error) {
	if m.encryptWithGDPRKeyFunc != nil {
		return m.encryptWithGDPRKeyFunc(data, gdprKey)
	}
	return []byte("gdpr_encrypted"), nil
}

// Test Cleanup Service
func TestRunCleanupTasks(t *testing.T) {
	t.Run("successful cleanup", func(t *testing.T) {
		resetAttemptsExecuted := false
		cleanupNotesExecuted := false

		mockDB := &mockDatabase{
			execFunc: func(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
				if strings.Contains(sql, "UPDATE users") {
					resetAttemptsExecuted = true
					return pgconn.CommandTag{}, nil
				}
				if strings.Contains(sql, "cleanup_old_deleted_notes") {
					cleanupNotesExecuted = true
					return pgconn.CommandTag{}, nil
				}
				return pgconn.CommandTag{}, nil
			},
			queryRowFunc: func(ctx context.Context, sql string, args ...interface{}) pgx.Row {
				return mockRow{
					scanFunc: func(dest ...interface{}) error {
						if count, ok := dest[0].(*int); ok {
							*count = 5
						}
						return nil
					},
				}
			},
		}

		RunCleanupTasks(context.Background(), mockDB)

		if !resetAttemptsExecuted {
			t.Error("Expected reset attempts to be executed")
		}
		if !cleanupNotesExecuted {
			t.Error("Expected cleanup notes to be executed")
		}
	})

	t.Run("handles database errors gracefully", func(t *testing.T) {
		mockDB := &mockDatabase{
			execFunc: func(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
				return pgconn.CommandTag{}, errors.New("database error")
			},
			queryRowFunc: func(ctx context.Context, sql string, args ...interface{}) pgx.Row {
				return mockRow{
					scanFunc: func(dest ...interface{}) error {
						return errors.New("scan error")
					},
				}
			},
		}

		// Should not panic
		RunCleanupTasks(context.Background(), mockDB)
	})
}

func TestStartCleanupService(t *testing.T) {
	t.Run("starts background goroutine", func(t *testing.T) {
		mockDB := &mockDatabase{
			execFunc: func(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
				return pgconn.CommandTag{}, nil
			},
			queryRowFunc: func(ctx context.Context, sql string, args ...interface{}) pgx.Row {
				return mockRow{
					scanFunc: func(dest ...interface{}) error {
						return nil
					},
				}
			},
		}

		// This should start a background goroutine without blocking
		StartCleanupService(mockDB)

		// Give it a moment to start
		time.Sleep(100 * time.Millisecond)
	})
}

// Test Templates Service
func TestSeedDefaultTemplates(t *testing.T) {
	t.Run("skips when templates already exist", func(t *testing.T) {
		mockDB := &mockDatabase{
			queryRowFunc: func(ctx context.Context, sql string, args ...interface{}) pgx.Row {
				return mockRow{
					scanFunc: func(dest ...interface{}) error {
						if count, ok := dest[0].(*int); ok {
							*count = 5 // Templates already exist
						}
						return nil
					},
				}
			},
		}

		mockCrypto := &mockCryptoService{}

		err := SeedDefaultTemplates(mockDB, mockCrypto)
		if err != nil {
			t.Errorf("Expected no error, got: %v", err)
		}
	})

	t.Run("seeds templates when none exist", func(t *testing.T) {
		insertCount := 0
		mockDB := &mockDatabase{
			queryRowFunc: func(ctx context.Context, sql string, args ...interface{}) pgx.Row {
				return mockRow{
					scanFunc: func(dest ...interface{}) error {
						if count, ok := dest[0].(*int); ok {
							*count = 0 // No templates exist
						}
						return nil
					},
				}
			},
			execFunc: func(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
				if strings.Contains(sql, "INSERT INTO templates") {
					insertCount++
				}
				return pgconn.CommandTag{}, nil
			},
		}

		mockCrypto := &mockCryptoService{}

		err := SeedDefaultTemplates(mockDB, mockCrypto)
		if err != nil {
			t.Errorf("Expected no error, got: %v", err)
		}

		expectedCount := len(defaultTemplates)
		if insertCount != expectedCount {
			t.Errorf("Expected %d templates to be inserted, got %d", expectedCount, insertCount)
		}
	})

	t.Run("handles encryption errors", func(t *testing.T) {
		mockDB := &mockDatabase{
			queryRowFunc: func(ctx context.Context, sql string, args ...interface{}) pgx.Row {
				return mockRow{
					scanFunc: func(dest ...interface{}) error {
						if count, ok := dest[0].(*int); ok {
							*count = 0
						}
						return nil
					},
				}
			},
		}

		mockCrypto := &mockCryptoService{
			encryptFunc: func(data []byte) ([]byte, error) {
				return nil, errors.New("encryption failed")
			},
		}

		err := SeedDefaultTemplates(mockDB, mockCrypto)
		if err == nil {
			t.Error("Expected error for encryption failure")
		}
	})

	t.Run("handles database insertion errors", func(t *testing.T) {
		mockDB := &mockDatabase{
			queryRowFunc: func(ctx context.Context, sql string, args ...interface{}) pgx.Row {
				return mockRow{
					scanFunc: func(dest ...interface{}) error {
						if count, ok := dest[0].(*int); ok {
							*count = 0
						}
						return nil
					},
				}
			},
			execFunc: func(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
				return pgconn.CommandTag{}, errors.New("insert failed")
			},
		}

		mockCrypto := &mockCryptoService{}

		err := SeedDefaultTemplates(mockDB, mockCrypto)
		if err == nil {
			t.Error("Expected error for database insertion failure")
		}
	})
}

func TestDefaultTemplatesStructure(t *testing.T) {
	t.Run("all templates have required fields", func(t *testing.T) {
		for _, template := range defaultTemplates {
			if template.Name == "" {
				t.Error("Template missing name")
			}
			if template.Description == "" {
				t.Errorf("Template %s missing description", template.Name)
			}
			if template.Content == "" {
				t.Errorf("Template %s missing content", template.Name)
			}
			if len(template.Tags) == 0 {
				t.Errorf("Template %s missing tags", template.Name)
			}
			if template.Icon == "" {
				t.Errorf("Template %s missing icon", template.Name)
			}
		}
	})

	t.Run("has expected number of templates", func(t *testing.T) {
		expectedCount := 5 // Meeting Notes, Project Planning, Daily Journal, Code Review, Bug Report
		if len(defaultTemplates) != expectedCount {
			t.Errorf("Expected %d default templates, got %d", expectedCount, len(defaultTemplates))
		}
	})
}

// Test Allowlist Service
func TestCurrentAllowlist(t *testing.T) {
	t.Run("returns empty map when not initialized", func(t *testing.T) {
		adminAllowlist.Store(make(map[string]struct{}))
		result := CurrentAllowlist()
		if len(result) != 0 {
			t.Errorf("Expected empty map, got %d entries", len(result))
		}
	})

	t.Run("returns stored allowlist", func(t *testing.T) {
		testMap := map[string]struct{}{
			"user1": {},
			"user2": {},
		}
		adminAllowlist.Store(testMap)
		result := CurrentAllowlist()
		if len(result) != 2 {
			t.Errorf("Expected 2 entries, got %d", len(result))
		}
	})
}

func TestIsUserInAdminAllowlist(t *testing.T) {
	t.Run("returns true for user in allowlist", func(t *testing.T) {
		testMap := map[string]struct{}{
			"user1": {},
		}
		adminAllowlist.Store(testMap)

		if !IsUserInAdminAllowlist("user1") {
			t.Error("Expected user1 to be in allowlist")
		}
	})

	t.Run("returns false for user not in allowlist", func(t *testing.T) {
		testMap := map[string]struct{}{
			"user1": {},
		}
		adminAllowlist.Store(testMap)

		if IsUserInAdminAllowlist("user2") {
			t.Error("Expected user2 to not be in allowlist")
		}
	})

	t.Run("checks environment variable as fallback", func(t *testing.T) {
		adminAllowlist.Store(make(map[string]struct{}))
		os.Setenv("ADMIN_USER_IDS", "user3,user4")
		defer os.Unsetenv("ADMIN_USER_IDS")

		if !IsUserInAdminAllowlist("user3") {
			t.Error("Expected user3 to be found in environment")
		}
	})

	t.Run("handles whitespace in user IDs", func(t *testing.T) {
		testMap := map[string]struct{}{
			"user1": {},
		}
		adminAllowlist.Store(testMap)

		if !IsUserInAdminAllowlist("  user1  ") {
			t.Error("Expected trimmed user1 to be in allowlist")
		}
	})
}

func TestLoadAllowlistFromSources(t *testing.T) {
	t.Run("loads from environment variable", func(t *testing.T) {
		envList := "user1,user2,user3"
		result, _ := LoadAllowlistFromSources(envList, "")

		if len(result) != 3 {
			t.Errorf("Expected 3 entries, got %d", len(result))
		}

		if _, ok := result["user1"]; !ok {
			t.Error("Expected user1 in result")
		}
	})

	t.Run("handles empty environment variable", func(t *testing.T) {
		result, _ := LoadAllowlistFromSources("", "")

		if len(result) != 0 {
			t.Errorf("Expected 0 entries, got %d", len(result))
		}
	})

	t.Run("loads from file", func(t *testing.T) {
		// Create a temporary file for testing
		tmpFile, err := os.CreateTemp("", "allowlist_test_*.txt")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(tmpFile.Name())

		content := "ADMIN_USER_IDS=file_user1,file_user2\n"
		if _, err := tmpFile.WriteString(content); err != nil {
			t.Fatal(err)
		}
		tmpFile.Close()

		result, _ := LoadAllowlistFromSources("", tmpFile.Name())

		if len(result) != 2 {
			t.Errorf("Expected 2 entries from file, got %d", len(result))
		}

		if _, ok := result["file_user1"]; !ok {
			t.Error("Expected file_user1 in result")
		}
	})

	t.Run("combines environment and file sources", func(t *testing.T) {
		tmpFile, err := os.CreateTemp("", "allowlist_test_*.txt")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(tmpFile.Name())

		content := "ADMIN_USER_IDS=file_user1\n"
		tmpFile.WriteString(content)
		tmpFile.Close()

		result, _ := LoadAllowlistFromSources("env_user1", tmpFile.Name())

		if len(result) != 2 {
			t.Errorf("Expected 2 entries, got %d", len(result))
		}
	})

	t.Run("ignores comments and empty lines in file", func(t *testing.T) {
		tmpFile, err := os.CreateTemp("", "allowlist_test_*.txt")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(tmpFile.Name())

		content := "# This is a comment\n\nADMIN_USER_IDS=user1\n# Another comment\n"
		tmpFile.WriteString(content)
		tmpFile.Close()

		result, _ := LoadAllowlistFromSources("", tmpFile.Name())

		if len(result) != 1 {
			t.Errorf("Expected 1 entry, got %d", len(result))
		}
	})

	t.Run("strips quotes from file values", func(t *testing.T) {
		tmpFile, err := os.CreateTemp("", "allowlist_test_*.txt")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(tmpFile.Name())

		content := `ADMIN_USER_IDS="user1,user2"`
		tmpFile.WriteString(content)
		tmpFile.Close()

		result, _ := LoadAllowlistFromSources("", tmpFile.Name())

		if len(result) != 2 {
			t.Errorf("Expected 2 entries, got %d", len(result))
		}
	})
}

// Test Admin Validation Service
func TestValidateEncryptionKeyAndAdminAccess(t *testing.T) {
	t.Run("succeeds with no users", func(t *testing.T) {
		mockDB := &mockDatabase{
			queryRowFunc: func(ctx context.Context, sql string, args ...interface{}) pgx.Row {
				return mockRow{
					scanFunc: func(dest ...interface{}) error {
						if userCount, ok := dest[0].(*int); ok {
							*userCount = 0
						}
						if adminExists, ok := dest[1].(*bool); ok {
							*adminExists = false
						}
						return nil
					},
				}
			},
		}

		mockCrypto := &mockCryptoService{}

		err := ValidateEncryptionKeyAndAdminAccess(mockDB, mockCrypto, "admin@example.com")
		if err != nil {
			t.Errorf("Expected no error with no users, got: %v", err)
		}
	})

	t.Run("succeeds when admin exists", func(t *testing.T) {
		mockDB := &mockDatabase{
			queryRowFunc: func(ctx context.Context, sql string, args ...interface{}) pgx.Row {
				return mockRow{
					scanFunc: func(dest ...interface{}) error {
						if userCount, ok := dest[0].(*int); ok {
							*userCount = 1
						}
						if adminExists, ok := dest[1].(*bool); ok {
							*adminExists = true
						}
						return nil
					},
				}
			},
		}

		mockCrypto := &mockCryptoService{}

		err := ValidateEncryptionKeyAndAdminAccess(mockDB, mockCrypto, "admin@example.com")
		if err != nil {
			t.Errorf("Expected no error when admin exists, got: %v", err)
		}
	})

	t.Run("returns error when admin not accessible", func(t *testing.T) {
		callCount := 0
		mockDB := &mockDatabase{
			queryRowFunc: func(ctx context.Context, sql string, args ...interface{}) pgx.Row {
				callCount++
				return mockRow{
					scanFunc: func(dest ...interface{}) error {
						if callCount == 1 {
							// First query: user count and admin existence
							if userCount, ok := dest[0].(*int); ok {
								*userCount = 5
							}
							if adminExists, ok := dest[1].(*bool); ok {
								*adminExists = false
							}
						} else {
							// Second query: users with hashes
							if usersWithHashes, ok := dest[0].(*int); ok {
								*usersWithHashes = 5
							}
						}
						return nil
					},
				}
			},
		}

		mockCrypto := &mockCryptoService{}

		err := ValidateEncryptionKeyAndAdminAccess(mockDB, mockCrypto, "admin@example.com")
		if err == nil {
			t.Error("Expected error when admin not accessible")
		}
	})

	t.Run("handles encryption error", func(t *testing.T) {
		mockDB := &mockDatabase{}

		mockCrypto := &mockCryptoService{
			encryptDeterministicFunc: func(data []byte, context string) ([]byte, error) {
				return nil, errors.New("encryption failed")
			},
		}

		err := ValidateEncryptionKeyAndAdminAccess(mockDB, mockCrypto, "admin@example.com")
		if err == nil {
			t.Error("Expected error when encryption fails")
		}
	})
}
