package services

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Mock Database implementation for testing
type mockDatabase struct {
	queryRowFunc func(ctx context.Context, sql string, args ...interface{}) pgx.Row
	queryFunc    func(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error)
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

func (m *mockDatabase) Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error) {
	if m.queryFunc != nil {
		return m.queryFunc(ctx, sql, args...)
	}
	return nil, nil
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
// Note: TestSeedDefaultTemplates was removed as seeding is now handled by templates handler
// The default templates are tested via TestDefaultTemplatesStructure below

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
