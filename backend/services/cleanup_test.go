package services

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockDatabase implements database.Database interface for cleanup tests
type MockDatabase struct {
	mock.Mock
}

func (m *MockDatabase) QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row {
	callArgs := append([]interface{}{ctx, sql}, args...)
	mockArgs := m.Called(callArgs...)
	return mockArgs.Get(0).(pgx.Row)
}

func (m *MockDatabase) Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error) {
	callArgs := append([]interface{}{ctx, sql}, args...)
	mockArgs := m.Called(callArgs...)
	return mockArgs.Get(0).(pgx.Rows), mockArgs.Error(1)
}

func (m *MockDatabase) Exec(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
	callArgs := append([]interface{}{ctx, sql}, args...)
	mockArgs := m.Called(callArgs...)
	rowsAffected := mockArgs.Get(0).(int64)
	tag := pgconn.NewCommandTag("UPDATE " + fmt.Sprintf("%d", rowsAffected))
	return tag, mockArgs.Error(1)
}

func (m *MockDatabase) Begin(ctx context.Context) (pgx.Tx, error) {
	mockArgs := m.Called(ctx)
	return mockArgs.Get(0).(pgx.Tx), mockArgs.Error(1)
}

// MockRow implements pgx.Row for cleanup tests
type MockRow struct {
	mock.Mock
}

func (m *MockRow) Scan(dest ...interface{}) error {
	mockArgs := m.Called(dest...)
	return mockArgs.Error(0)
}

func TestRunCleanupTasks_Success(t *testing.T) {
	mockDB := &MockDatabase{}

	// Mock failed login attempts reset
	mockDB.On("Exec", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return strings.Contains(sql, "UPDATE users") && strings.Contains(sql, "failed_attempts")
	}), mock.Anything).Return(int64(5), nil)

	// Mock cleanup function call
	mockDB.On("Exec", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return strings.Contains(sql, "cleanup_old_deleted_notes")
	}), mock.Anything).Return(int64(0), nil)

	// Mock count query
	mockRow := &MockRow{}
	mockDB.On("QueryRow", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return strings.Contains(sql, "SELECT COUNT(*)") && strings.Contains(sql, "deleted_at")
	}), mock.Anything).Return(mockRow)

	mockRow.On("Scan", mock.Anything).Run(func(args mock.Arguments) {
		if count, ok := args[0].(*int); ok {
			*count = 3
		}
	}).Return(nil)

	ctx := context.Background()
	RunCleanupTasks(ctx, mockDB)

	mockDB.AssertExpectations(t)
}

func TestRunCleanupTasks_ErrorHandling(t *testing.T) {
	mockDB := &MockDatabase{}

	// Mock failed login attempts reset error
	mockDB.On("Exec", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return strings.Contains(sql, "UPDATE users")
	}), mock.Anything).Return(int64(0), assert.AnError)

	// Mock cleanup function call error
	mockDB.On("Exec", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return strings.Contains(sql, "cleanup_old_deleted_notes")
	}), mock.Anything).Return(int64(0), assert.AnError)

	// Mock count query (should still run even with error)
	mockRow := &MockRow{}
	mockDB.On("QueryRow", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return strings.Contains(sql, "SELECT COUNT(*)")
	}), mock.Anything).Return(mockRow)

	mockRow.On("Scan", mock.Anything).Return(assert.AnError)

	ctx := context.Background()
	// Should not panic even with errors
	RunCleanupTasks(ctx, mockDB)

	mockDB.AssertExpectations(t)
}
