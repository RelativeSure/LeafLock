package handlers

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// stubRows implements pgx.Rows for deterministic test data.
type stubRows struct {
	scanFuncs []func(dest ...interface{}) error
	index     int
}

func newStubRows(funcs ...func(dest ...interface{}) error) *stubRows {
	return &stubRows{scanFuncs: funcs}
}

func (s *stubRows) Next() bool {
	if s.index < len(s.scanFuncs) {
		s.index++
		return true
	}
	return false
}

func (s *stubRows) Scan(dest ...interface{}) error {
	if s.index == 0 || s.index > len(s.scanFuncs) {
		return assert.AnError
	}
	return s.scanFuncs[s.index-1](dest...)
}

func (s *stubRows) Close()                        {}
func (s *stubRows) Err() error                    { return nil }
func (s *stubRows) CommandTag() pgconn.CommandTag { return pgconn.NewCommandTag("") }
func (s *stubRows) FieldDescriptions() []pgconn.FieldDescription {
	return nil
}
func (s *stubRows) Values() ([]interface{}, error) { return nil, nil }
func (s *stubRows) RawValues() [][]byte            { return nil }
func (s *stubRows) Conn() *pgx.Conn                { return nil }

func expectCountQuery(t *testing.T, db *MockDB, contains string, value int, withArg bool) {
	t.Helper()
	row := new(MockRow)
	row.On("Scan", mock.Anything).Run(func(args mock.Arguments) {
		*(args[0].(*int)) = value
	}).Return(nil).Once()

	callArgs := []interface{}{mock.Anything, mock.MatchedBy(func(query string) bool {
		return strings.Contains(query, contains)
	})}
	if withArg {
		callArgs = append(callArgs, mock.Anything)
	}
	db.On("QueryRow", callArgs...).Return(row).Once()
}

func expectQuery(t *testing.T, db *MockDB, contains string, rows pgx.Rows, withArg bool) {
	t.Helper()
	callArgs := []interface{}{mock.Anything, mock.MatchedBy(func(query string) bool {
		return strings.Contains(query, contains)
	})}
	if withArg {
		callArgs = append(callArgs, mock.Anything)
	}
	db.On("Query", callArgs...).Return(rows, nil).Once()
}

func TestAnalyticsHandler_GetUserAnalytics_AggregatesData(t *testing.T) {
	mockDB := new(MockDB)
	handler := NewAnalyticsHandler(mockDB)
	userID := uuid.New()

	expectCountQuery(t, mockDB, "FROM notes", 7, true)
	expectCountQuery(t, mockDB, "FROM folders", 3, true)
	expectCountQuery(t, mockDB, "FROM tags", 4, true)
	expectCountQuery(t, mockDB, "FROM collaborations", 2, true)
	expectCountQuery(t, mockDB, "CURRENT_DATE", 1, true)       // today
	expectCountQuery(t, mockDB, "INTERVAL '7 days'", 5, true)  // week
	expectCountQuery(t, mockDB, "INTERVAL '30 days'", 9, true) // month

	activityRows := newStubRows(func(dest ...interface{}) error {
		*(dest[0].(*time.Time)) = time.Date(2024, 10, 10, 0, 0, 0, 0, time.UTC)
		*(dest[1].(*int)) = 2
		return nil
	})
	expectQuery(t, mockDB, "GROUP BY DATE(n.created_at)", activityRows, true)

	folderRows := newStubRows(func(dest ...interface{}) error {
		name := "Work"
		*(dest[0].(*string)) = name
		*(dest[1].(*int)) = 4
		return nil
	})
	expectQuery(t, mockDB, "COALESCE(f.name_encrypted", folderRows, true)

	tagRows := newStubRows(func(dest ...interface{}) error {
		name := "Security"
		*(dest[0].(*string)) = name
		*(dest[1].(*int)) = 3
		return nil
	})
	expectQuery(t, mockDB, "FROM tags t", tagRows, true)

	auditRows := newStubRows(func(dest ...interface{}) error {
		action := "note_created"
		metadata := map[string]string{"note": "abc"}
		timestamp := time.Date(2024, 10, 11, 12, 0, 0, 0, time.UTC)
		*(dest[0].(*string)) = action
		*(dest[1].(*interface{})) = metadata
		*(dest[2].(*time.Time)) = timestamp
		return nil
	})
	expectQuery(t, mockDB, "FROM audit_log", auditRows, true)

	app := fiber.New()
	app.Get("/analytics", func(c *fiber.Ctx) error {
		c.Locals("user_id", userID)
		return handler.GetUserAnalytics(c)
	})

	req := httptest.NewRequest("GET", "/analytics", nil)
	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	var stats UserStats
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&stats))
	assert.Equal(t, 7, stats.TotalNotes)
	assert.Len(t, stats.ActivityByDay, 1)
	assert.Len(t, stats.NotesByFolder, 1)
	assert.Len(t, stats.RecentActivity, 1)

	mockDB.AssertExpectations(t)
}

func TestAnalyticsHandler_GetAdminAnalytics_ReturnsMetrics(t *testing.T) {
	mockDB := new(MockDB)
	handler := NewAnalyticsHandler(mockDB)

	expectCountQuery(t, mockDB, "FROM users WHERE deleted_at IS NULL", 25, false)
	expectCountQuery(t, mockDB, "FROM notes WHERE deleted_at IS NULL", 120, false)
	expectCountQuery(t, mockDB, "FROM workspaces", 10, false)
	expectCountQuery(t, mockDB, "last_login", 18, false)

	userGrowthRows := newStubRows(func(dest ...interface{}) error {
		date := time.Date(2024, 9, 30, 0, 0, 0, 0, time.UTC)
		*(dest[0].(*time.Time)) = date
		*(dest[1].(*int)) = 5
		return nil
	})
	expectQuery(t, mockDB, "FROM users", userGrowthRows, false)

	noteGrowthRows := newStubRows(func(dest ...interface{}) error {
		date := time.Date(2024, 9, 28, 0, 0, 0, 0, time.UTC)
		*(dest[0].(*time.Time)) = date
		*(dest[1].(*int)) = 8
		return nil
	})
	expectQuery(t, mockDB, "FROM notes", noteGrowthRows, false)

	app := fiber.New()
	app.Get("/admin/analytics", handler.GetAdminAnalytics)

	req := httptest.NewRequest("GET", "/admin/analytics", nil)
	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	var payload map[string]interface{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&payload))
	assert.EqualValues(t, 25, payload["total_users"])
	assert.NotEmpty(t, payload["user_growth"])

	mockDB.AssertExpectations(t)
}
