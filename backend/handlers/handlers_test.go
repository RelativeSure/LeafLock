package handlers

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"

	"leaflock/crypto"
)

// =====================
// Mock Implementations
// =====================

// MockDB represents a mock database connection for unit tests
type MockDB struct {
	mock.Mock
}

func (m *MockDB) QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row {
	callArgs := append([]interface{}{ctx, sql}, args...)
	mockArgs := m.Called(callArgs...)
	return mockArgs.Get(0).(pgx.Row)
}

func (m *MockDB) Exec(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
	callArgs := append([]interface{}{ctx, sql}, args...)
	mockArgs := m.Called(callArgs...)
	rowsAffected := mockArgs.Get(0).(int64)
	tag := pgconn.NewCommandTag("UPDATE " + fmt.Sprintf("%d", rowsAffected))
	return tag, mockArgs.Error(1)
}

func (m *MockDB) Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error) {
	callArgs := append([]interface{}{ctx, sql}, args...)
	mockArgs := m.Called(callArgs...)
	if mockArgs.Get(0) == nil {
		return nil, mockArgs.Error(1)
	}
	return mockArgs.Get(0).(pgx.Rows), mockArgs.Error(1)
}

func (m *MockDB) Begin(ctx context.Context) (pgx.Tx, error) {
	mockArgs := m.Called(ctx)
	if mockArgs.Get(0) == nil {
		return nil, mockArgs.Error(1)
	}
	return mockArgs.Get(0).(pgx.Tx), mockArgs.Error(1)
}

type MockRow struct {
	mock.Mock
}

func (m *MockRow) Scan(dest ...interface{}) error {
	mockArgs := m.Called(dest...)
	return mockArgs.Error(0)
}

type MockRows struct {
	mock.Mock
	closed bool
}

func (m *MockRows) Next() bool {
	mockArgs := m.Called()
	return mockArgs.Bool(0)
}

func (m *MockRows) Scan(dest ...interface{}) error {
	mockArgs := m.Called(dest...)
	return mockArgs.Error(0)
}

func (m *MockRows) Close() {
	m.closed = true
}

func (m *MockRows) Err() error {
	return nil
}

func (m *MockRows) CommandTag() pgconn.CommandTag {
	return pgconn.NewCommandTag("")
}

func (m *MockRows) FieldDescriptions() []pgconn.FieldDescription {
	return nil
}

func (m *MockRows) Values() ([]interface{}, error) {
	return nil, nil
}

func (m *MockRows) RawValues() [][]byte {
	return nil
}

func (m *MockRows) Conn() *pgx.Conn {
	return nil
}

type MockTx struct {
	mock.Mock
}

func (m *MockTx) QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row {
	callArgs := append([]interface{}{ctx, sql}, args...)
	mockArgs := m.Called(callArgs...)
	return mockArgs.Get(0).(pgx.Row)
}

func (m *MockTx) Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error) {
	callArgs := append([]interface{}{ctx, sql}, args...)
	mockArgs := m.Called(callArgs...)
	return mockArgs.Get(0).(pgx.Rows), mockArgs.Error(1)
}

func (m *MockTx) Exec(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
	callArgs := append([]interface{}{ctx, sql}, args...)
	mockArgs := m.Called(callArgs...)
	rowsAffected := mockArgs.Get(0).(int64)
	tag := pgconn.NewCommandTag("UPDATE " + fmt.Sprintf("%d", rowsAffected))
	return tag, mockArgs.Error(1)
}

func (m *MockTx) Rollback(ctx context.Context) error {
	mockArgs := m.Called(ctx)
	return mockArgs.Error(0)
}

func (m *MockTx) Commit(ctx context.Context) error {
	mockArgs := m.Called(ctx)
	return mockArgs.Error(0)
}

func (m *MockTx) Begin(ctx context.Context) (pgx.Tx, error) {
	mockArgs := m.Called(ctx)
	return mockArgs.Get(0).(pgx.Tx), mockArgs.Error(1)
}

func (m *MockTx) CopyFrom(ctx context.Context, tableName pgx.Identifier, columnNames []string, rowSrc pgx.CopyFromSource) (int64, error) {
	return 0, nil
}

func (m *MockTx) SendBatch(ctx context.Context, b *pgx.Batch) pgx.BatchResults {
	return nil
}

func (m *MockTx) LargeObjects() pgx.LargeObjects {
	return pgx.LargeObjects{}
}

func (m *MockTx) Prepare(ctx context.Context, name, sql string) (*pgconn.StatementDescription, error) {
	return nil, nil
}

func (m *MockTx) Deallocate(ctx context.Context, name string) error {
	return nil
}

func (m *MockTx) Conn() *pgx.Conn {
	return nil
}

type MockRedisClient struct {
	mock.Mock
}

func (m *MockRedisClient) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.StatusCmd {
	args := m.Called(ctx, key, value, expiration)
	cmd := redis.NewStatusCmd(ctx)
	if err := args.Error(0); err != nil {
		cmd.SetErr(err)
	}
	return cmd
}

func (m *MockRedisClient) Get(ctx context.Context, key string) *redis.StringCmd {
	args := m.Called(ctx, key)
	cmd := redis.NewStringCmd(ctx)
	if str, ok := args.Get(0).(string); ok {
		cmd.SetVal(str)
	}
	if err := args.Error(1); err != nil {
		cmd.SetErr(err)
	}
	return cmd
}

func (m *MockRedisClient) Del(ctx context.Context, keys ...string) *redis.IntCmd {
	args := m.Called(ctx, keys)
	cmd := redis.NewIntCmd(ctx)
	if err := args.Error(0); err != nil {
		cmd.SetErr(err)
	}
	return cmd
}

// =====================
// AuthHandler Tests - REMOVED (migrated to backend/auth package)
// =====================

// =====================
// NotesHandler Tests
// =====================

type NotesHandlerTestSuite struct {
	suite.Suite
	handler     *NotesHandler
	mockDB      *MockDB
	cryptoSvc   *crypto.CryptoService
	userID      uuid.UUID
	workspaceID uuid.UUID
}

func (suite *NotesHandlerTestSuite) SetupTest() {
	suite.mockDB = &MockDB{}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		suite.T().Fatalf("Failed to generate random data: %v", err)
	}
	suite.cryptoSvc = crypto.NewCryptoService(key)

	suite.handler = NewNotesHandler(suite.mockDB, suite.cryptoSvc)
	suite.userID = uuid.New()
	suite.workspaceID = uuid.New()
}

func (suite *NotesHandlerTestSuite) TestNewNotesHandler() {
	handler := NewNotesHandler(suite.mockDB, suite.cryptoSvc)
	suite.NotNil(handler)
	suite.Equal(suite.mockDB, handler.db)
	suite.Equal(suite.cryptoSvc, handler.crypto)
}

func (suite *NotesHandlerTestSuite) TestGetNotesSuccess() {
	app := fiber.New()

	// Mock workspace lookup
	mockRow := &MockRow{}
	suite.mockDB.On("QueryRow", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "workspaces")
	}), suite.userID).Return(mockRow)

	mockRow.On("Scan", mock.Anything).Run(func(args mock.Arguments) {
		if wid, ok := args[0].(*uuid.UUID); ok {
			*wid = suite.workspaceID
		}
	}).Return(nil)

	// Mock notes query
	mockRows := &MockRows{}
	suite.mockDB.On("Query", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "SELECT id, title_encrypted")
	}), suite.workspaceID).Return(mockRows, nil)

	// Return one note
	mockRows.On("Next").Return(true).Once()
	mockRows.On("Next").Return(false).Once()

	titleEnc, _ := suite.cryptoSvc.Encrypt([]byte("Test Note"))
	contentEnc, _ := suite.cryptoSvc.Encrypt([]byte("Test content"))
	noteID := uuid.New()
	now := time.Now()

	mockRows.On("Scan", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		if id, ok := args[0].(*uuid.UUID); ok {
			*id = noteID
		}
		if title, ok := args[1].(*[]byte); ok {
			*title = titleEnc
		}
		if content, ok := args[2].(*[]byte); ok {
			*content = contentEnc
		}
		if created, ok := args[3].(*time.Time); ok {
			*created = now
		}
		if updated, ok := args[4].(*time.Time); ok {
			*updated = now
		}
	}).Return(nil)

	app.Get("/notes", func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.userID)
		return suite.handler.GetNotes(c)
	})

	req := httptest.NewRequest("GET", "/notes", nil)
	resp, err := app.Test(req)

	suite.NoError(err)
	suite.Equal(200, resp.StatusCode)

	var response map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&response) // Test response parsing

	suite.Contains(response, "notes")
}

func (suite *NotesHandlerTestSuite) TestCreateNoteSuccess() {
	app := fiber.New()

	// Mock workspace lookup
	mockRow := &MockRow{}
	suite.mockDB.On("QueryRow", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "workspaces")
	}), suite.userID).Return(mockRow)

	mockRow.On("Scan", mock.Anything).Run(func(args mock.Arguments) {
		if wid, ok := args[0].(*uuid.UUID); ok {
			*wid = suite.workspaceID
		}
	}).Return(nil)

	// Mock note creation
	mockNoteRow := &MockRow{}
	suite.mockDB.On("QueryRow", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "INSERT INTO notes")
	}), mock.Anything, mock.Anything, mock.Anything, mock.Anything, suite.userID).Return(mockNoteRow)

	noteID := uuid.New()
	mockNoteRow.On("Scan", mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		if nid, ok := args[0].(*uuid.UUID); ok {
			*nid = noteID
		}
		if created, ok := args[1].(*time.Time); ok {
			*created = time.Unix(0, 0).UTC()
		}
		if updated, ok := args[2].(*time.Time); ok {
			*updated = time.Unix(0, 0).UTC()
		}
	}).Return(nil)

	app.Post("/notes", func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.userID)
		return suite.handler.CreateNote(c)
	})

	titleEnc := base64.StdEncoding.EncodeToString([]byte("encrypted_title"))
	contentEnc := base64.StdEncoding.EncodeToString([]byte("encrypted_content"))

	reqBody := map[string]string{
		"title_encrypted":   titleEnc,
		"content_encrypted": contentEnc,
	}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/notes", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)

	suite.NoError(err)
	suite.Equal(201, resp.StatusCode)

	var payload struct {
		Note map[string]interface{} `json:"note"`
	}
	err = json.NewDecoder(resp.Body).Decode(&payload)
	suite.NoError(err)
	suite.Equal(noteID.String(), payload.Note["id"])
	suite.Equal(titleEnc, payload.Note["title_encrypted"])
	suite.Equal(float64(1), payload.Note["encryption_version"])
}

func (suite *NotesHandlerTestSuite) TestDeleteNoteSuccess() {
	app := fiber.New()

	noteID := uuid.New()
	suite.mockDB.On("Exec", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "UPDATE notes") && contains(sql, "deleted_at")
	}), noteID, suite.userID).Return(int64(1), nil)

	app.Delete("/notes/:id", func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.userID)
		return suite.handler.DeleteNote(c)
	})

	req := httptest.NewRequest("DELETE", "/notes/"+noteID.String(), nil)
	resp, err := app.Test(req)

	suite.NoError(err)
	suite.Equal(200, resp.StatusCode)
}

func (suite *NotesHandlerTestSuite) TestGetNoteSuccess() {
	app := fiber.New()

	noteID := uuid.New()
	titleEnc, _ := suite.cryptoSvc.Encrypt([]byte("Test Note"))
	contentEnc, _ := suite.cryptoSvc.Encrypt([]byte("Test content"))
	now := time.Now()

	mockRow := &MockRow{}
	suite.mockDB.On("QueryRow", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "SELECT n.id")
	}), noteID, suite.userID).Return(mockRow)

	mockRow.On("Scan", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		if id, ok := args[0].(*uuid.UUID); ok {
			*id = noteID
		}
		if title, ok := args[1].(*[]byte); ok {
			*title = titleEnc
		}
		if content, ok := args[2].(*[]byte); ok {
			*content = contentEnc
		}
		if created, ok := args[3].(*time.Time); ok {
			*created = now
		}
		if updated, ok := args[4].(*time.Time); ok {
			*updated = now
		}
	}).Return(nil)

	app.Get("/notes/:id", func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.userID)
		return suite.handler.GetNote(c)
	})

	req := httptest.NewRequest("GET", "/notes/"+noteID.String(), nil)
	resp, err := app.Test(req)

	suite.NoError(err)
	suite.Equal(200, resp.StatusCode)
}

func (suite *NotesHandlerTestSuite) TestGetNoteInvalidID() {
	app := fiber.New()

	app.Get("/notes/:id", func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.userID)
		return suite.handler.GetNote(c)
	})

	req := httptest.NewRequest("GET", "/notes/invalid-id", nil)
	resp, err := app.Test(req)

	suite.NoError(err)
	suite.Equal(400, resp.StatusCode)
}

func (suite *NotesHandlerTestSuite) TestDeleteNoteNotFound() {
	app := fiber.New()

	noteID := uuid.New()
	suite.mockDB.On("Exec", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "UPDATE notes") && contains(sql, "deleted_at")
	}), noteID, suite.userID).Return(int64(0), nil)

	app.Delete("/notes/:id", func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.userID)
		return suite.handler.DeleteNote(c)
	})

	req := httptest.NewRequest("DELETE", "/notes/"+noteID.String(), nil)
	resp, err := app.Test(req)

	suite.NoError(err)
	suite.Equal(404, resp.StatusCode)
}

func (suite *NotesHandlerTestSuite) TestGetTrashSuccess() {
	app := fiber.New()

	// Mock workspace lookup
	mockRow := &MockRow{}
	suite.mockDB.On("QueryRow", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "workspaces")
	}), suite.userID).Return(mockRow)

	mockRow.On("Scan", mock.Anything).Run(func(args mock.Arguments) {
		if wid, ok := args[0].(*uuid.UUID); ok {
			*wid = suite.workspaceID
		}
	}).Return(nil)

	// Mock trash notes query
	mockRows := &MockRows{}
	suite.mockDB.On("Query", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "deleted_at IS NOT NULL")
	}), suite.workspaceID).Return(mockRows, nil)

	mockRows.On("Next").Return(false)

	app.Get("/trash", func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.userID)
		return suite.handler.GetTrash(c)
	})

	req := httptest.NewRequest("GET", "/trash", nil)
	resp, err := app.Test(req)

	suite.NoError(err)
	suite.Equal(200, resp.StatusCode)
}

func (suite *NotesHandlerTestSuite) TestRestoreNoteSuccess() {
	app := fiber.New()

	noteID := uuid.New()
	suite.mockDB.On("Exec", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "deleted_at = NULL")
	}), noteID, suite.userID).Return(int64(1), nil)

	app.Post("/notes/:id/restore", func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.userID)
		return suite.handler.RestoreNote(c)
	})

	req := httptest.NewRequest("POST", "/notes/"+noteID.String()+"/restore", nil)
	resp, err := app.Test(req)

	suite.NoError(err)
	suite.Equal(200, resp.StatusCode)
}

// =====================
// TagsHandler Tests
// =====================

type TagsHandlerTestSuite struct {
	suite.Suite
	handler   *TagsHandler
	mockDB    *MockDB
	cryptoSvc *crypto.CryptoService
	userID    uuid.UUID
}

func (suite *TagsHandlerTestSuite) SetupTest() {
	suite.mockDB = &MockDB{}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		suite.T().Fatalf("Failed to generate random data: %v", err)
	}
	suite.cryptoSvc = crypto.NewCryptoService(key)

	suite.handler = NewTagsHandler(suite.mockDB, suite.cryptoSvc)
	suite.userID = uuid.New()
}

func (suite *TagsHandlerTestSuite) TestNewTagsHandler() {
	handler := NewTagsHandler(suite.mockDB, suite.cryptoSvc)
	suite.NotNil(handler)
}

func (suite *TagsHandlerTestSuite) TestGetTagsSuccess() {
	app := fiber.New()

	mockRows := &MockRows{}
	suite.mockDB.On("Query", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "SELECT id, name_encrypted")
	}), suite.userID).Return(mockRows, nil)

	mockRows.On("Next").Return(true).Once()
	mockRows.On("Next").Return(false).Once()

	tagID := uuid.New()
	nameEnc, _ := suite.cryptoSvc.Encrypt([]byte("Test Tag"))
	now := time.Now()

	mockRows.On("Scan", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		if id, ok := args[0].(*uuid.UUID); ok {
			*id = tagID
		}
		if name, ok := args[1].(*[]byte); ok {
			*name = nameEnc
		}
		if color, ok := args[2].(*string); ok {
			*color = "#3b82f6"
		}
		if created, ok := args[3].(*time.Time); ok {
			*created = now
		}
		if updated, ok := args[4].(*time.Time); ok {
			*updated = now
		}
	}).Return(nil)

	app.Get("/tags", func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.userID)
		return suite.handler.GetTags(c)
	})

	req := httptest.NewRequest("GET", "/tags", nil)
	resp, err := app.Test(req)

	suite.NoError(err)
	suite.Equal(200, resp.StatusCode)
}

func (suite *TagsHandlerTestSuite) TestCreateTagSuccess() {
	app := fiber.New()

	mockRow := &MockRow{}
	tagID := uuid.New()

	suite.mockDB.On("QueryRow", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "INSERT INTO tags")
	}), suite.userID, mock.Anything, mock.Anything, mock.Anything).Return(mockRow)

	mockRow.On("Scan", mock.Anything).Run(func(args mock.Arguments) {
		if tid, ok := args[0].(*uuid.UUID); ok {
			*tid = tagID
		}
	}).Return(nil)

	app.Post("/tags", func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.userID)
		return suite.handler.CreateTag(c)
	})

	reqBody := map[string]string{
		"name":  "Test Tag",
		"color": "#3b82f6",
	}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/tags", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)

	suite.NoError(err)
	suite.Equal(201, resp.StatusCode)
}

// =====================
// FoldersHandler Tests - Moved to folders_test.go
// =====================

// =====================
// TemplatesHandler Tests
// =====================

type TemplatesHandlerTestSuite struct {
	suite.Suite
	handler   *TemplatesHandler
	mockDB    *MockDB
	cryptoSvc *crypto.CryptoService
	userID    uuid.UUID
}

func (suite *TemplatesHandlerTestSuite) SetupTest() {
	suite.mockDB = &MockDB{}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		suite.T().Fatalf("Failed to generate random data: %v", err)
	}
	suite.cryptoSvc = crypto.NewCryptoService(key)

	suite.handler = NewTemplatesHandler(suite.mockDB, suite.cryptoSvc)
	suite.userID = uuid.New()
}

func (suite *TemplatesHandlerTestSuite) TestNewTemplatesHandler() {
	handler := NewTemplatesHandler(suite.mockDB, suite.cryptoSvc)
	suite.NotNil(handler)
}

func (suite *TemplatesHandlerTestSuite) TestCreateTemplateSuccess() {
	app := fiber.New()

	mockRow := &MockRow{}
	templateID := uuid.New()

	suite.mockDB.On("QueryRow", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "INSERT INTO templates")
	}), suite.userID, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(mockRow)

	mockRow.On("Scan", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		if tid, ok := args[0].(*uuid.UUID); ok {
			*tid = templateID
		}
		if createdPtr, ok := args[1].(*time.Time); ok {
			*createdPtr = time.Now().UTC()
		}
		if updatedPtr, ok := args[2].(*time.Time); ok {
			*updatedPtr = time.Now().UTC()
		}
		if usagePtr, ok := args[3].(*int); ok {
			*usagePtr = 0
		}
	}).Return(nil)

	app.Post("/templates", func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.userID)
		return suite.handler.CreateTemplate(c)
	})

	reqBody := map[string]interface{}{
		"name":        "Test Template",
		"description": "Test Description",
		"content":     "# Test Content",
		"tags":        []string{"test"},
		"icon":        "📝",
	}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/templates", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)

	suite.NoError(err)
	suite.Equal(201, resp.StatusCode)
}

func (suite *TemplatesHandlerTestSuite) TestGetTemplatesSuccess() {
	app := fiber.New()

	mockRows := &MockRows{}
	suite.mockDB.On("Query", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "FROM templates")
	}), suite.userID).Return(mockRows, nil)

	mockRows.On("Next").Return(true).Once()
	mockRows.On("Next").Return(true).Once()
	mockRows.On("Next").Return(false).Once()

	now := time.Now().UTC()
	starterID := uuid.New()
	userTemplateID := uuid.New()

	starterNameEnc, _ := suite.cryptoSvc.Encrypt([]byte("Starter Template"))
	starterDescEnc, _ := suite.cryptoSvc.Encrypt([]byte("Default content"))
	starterContentEnc, _ := suite.cryptoSvc.Encrypt([]byte("# Default"))

	userNameEnc, _ := suite.cryptoSvc.Encrypt([]byte("My Template"))
	userDescEnc, _ := suite.cryptoSvc.Encrypt([]byte("Custom description"))
	userContentEnc, _ := suite.cryptoSvc.Encrypt([]byte("# Custom"))

	scanCalls := 0
	mockRows.On("Scan",
		mock.Anything,
		mock.Anything,
		mock.Anything,
		mock.Anything,
		mock.Anything,
		mock.Anything,
		mock.Anything,
		mock.Anything,
		mock.Anything,
		mock.Anything,
		mock.Anything,
	).Run(func(args mock.Arguments) {
		switch scanCalls {
		case 0:
			*args[0].(*uuid.UUID) = starterID
			*args[1].(*sql.NullString) = sql.NullString{Valid: false}
			*args[2].(*[]byte) = starterNameEnc
			*args[3].(*[]byte) = starterDescEnc
			*args[4].(*[]byte) = starterContentEnc
			*args[5].(*[]string) = []string{"system", "starter"}
			*args[6].(*string) = "✨"
			*args[7].(*bool) = true
			*args[8].(*int) = 42
			*args[9].(*time.Time) = now.Add(-time.Hour)
			*args[10].(*time.Time) = now
		default:
			*args[0].(*uuid.UUID) = userTemplateID
			*args[1].(*sql.NullString) = sql.NullString{String: suite.userID.String(), Valid: true}
			*args[2].(*[]byte) = userNameEnc
			*args[3].(*[]byte) = userDescEnc
			*args[4].(*[]byte) = userContentEnc
			*args[5].(*[]string) = []string{"custom"}
			*args[6].(*string) = "📝"
			*args[7].(*bool) = false
			*args[8].(*int) = 3
			*args[9].(*time.Time) = now.Add(-2 * time.Hour)
			*args[10].(*time.Time) = now.Add(-30 * time.Minute)
		}
		scanCalls++
	}).Return(nil)

	app.Get("/templates", func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.userID)
		return suite.handler.GetTemplates(c)
	})

	req := httptest.NewRequest("GET", "/templates", nil)
	resp, err := app.Test(req)

	suite.NoError(err)
	suite.Equal(200, resp.StatusCode)

	var payload struct {
		Templates []map[string]interface{} `json:"templates"`
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	suite.NoError(json.Unmarshal(body, &payload))

	suite.Len(payload.Templates, 2)
	suite.Equal("Starter Template", payload.Templates[0]["name"])
	suite.Nil(payload.Templates[0]["user_id"])
	suite.Equal("My Template", payload.Templates[1]["name"])
	suite.Equal(suite.userID.String(), payload.Templates[1]["user_id"])
}

func (suite *TemplatesHandlerTestSuite) TestGetTemplateSuccess() {
	app := fiber.New()

	templateID := uuid.New()
	mockRow := &MockRow{}
	suite.mockDB.On("QueryRow", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "SELECT user_id")
	}), templateID, suite.userID).Return(mockRow)

	nameEnc, _ := suite.cryptoSvc.Encrypt([]byte("Detailed Template"))
	descEnc, _ := suite.cryptoSvc.Encrypt([]byte("Full description"))
	contentEnc, _ := suite.cryptoSvc.Encrypt([]byte("# Body"))

	mockRow.On("Scan",
		mock.Anything,
		mock.Anything,
		mock.Anything,
		mock.Anything,
		mock.Anything,
		mock.Anything,
		mock.Anything,
		mock.Anything,
		mock.Anything,
		mock.Anything,
	).Run(func(args mock.Arguments) {
		*args[0].(*sql.NullString) = sql.NullString{Valid: true, String: suite.userID.String()}
		*args[1].(*[]byte) = nameEnc
		*args[2].(*[]byte) = descEnc
		*args[3].(*[]byte) = contentEnc
		*args[4].(*[]string) = []string{"custom"}
		*args[5].(*string) = "📝"
		*args[6].(*bool) = false
		*args[7].(*int) = 1
		now := time.Now().UTC()
		*args[8].(*time.Time) = now.Add(-time.Minute)
		*args[9].(*time.Time) = now
	}).Return(nil)

	app.Get("/templates/:id", func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.userID)
		return suite.handler.GetTemplate(c)
	})

	req := httptest.NewRequest("GET", "/templates/"+templateID.String(), nil)
	resp, err := app.Test(req)

	suite.NoError(err)
	suite.Equal(200, resp.StatusCode)

	var payload map[string]interface{}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	suite.NoError(json.Unmarshal(body, &payload))
	suite.Equal("Detailed Template", payload["name"])
	suite.Equal(suite.userID.String(), payload["user_id"])
	suite.Equal("# Body", payload["content"])
}

func (suite *TemplatesHandlerTestSuite) TestUpdateTemplateSuccess() {
	app := fiber.New()

	templateID := uuid.New()
	suite.mockDB.On("Exec", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "UPDATE templates")
	}), templateID, suite.userID, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(int64(1), nil)

	mockRow := &MockRow{}
	suite.mockDB.On("QueryRow", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "SELECT usage_count")
	}), templateID).Return(mockRow)

	mockRow.On("Scan", mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		*args[0].(*int) = 7
		now := time.Now().UTC()
		*args[1].(*time.Time) = now.Add(-time.Hour)
		*args[2].(*time.Time) = now
	}).Return(nil)

	app.Put("/templates/:id", func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.userID)
		return suite.handler.UpdateTemplate(c)
	})

	payload := map[string]interface{}{
		"name":        "Updated Template",
		"description": "Updated description",
		"content":     "# Updated",
		"tags":        []string{"updated"},
		"icon":        "✅",
		"is_public":   true,
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest("PUT", "/templates/"+templateID.String(), bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(200, resp.StatusCode)

	var response map[string]interface{}
	respBody, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	suite.NoError(json.Unmarshal(respBody, &response))
	suite.Equal("Updated Template", response["name"])
	suite.Equal(float64(7), response["usage_count"])
}

func (suite *TemplatesHandlerTestSuite) TestUpdateTemplateNotFound() {
	app := fiber.New()

	templateID := uuid.New()
	suite.mockDB.On("Exec",
		mock.Anything,
		mock.Anything,
		mock.Anything,
		mock.Anything,
		mock.Anything,
		mock.Anything,
		mock.Anything,
		mock.Anything,
		mock.Anything,
		mock.Anything,
	).Return(int64(0), nil)

	app.Put("/templates/:id", func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.userID)
		return suite.handler.UpdateTemplate(c)
	})

	payload := map[string]interface{}{
		"name":        "Missing Template",
		"description": "Missing",
		"content":     "# Missing",
		"tags":        []string{},
		"icon":        "",
		"is_public":   false,
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest("PUT", "/templates/"+templateID.String(), bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(404, resp.StatusCode)
}

// =====================
// CollaborationHandler Tests
// =====================

type CollaborationHandlerTestSuite struct {
	suite.Suite
	handler   *CollaborationHandler
	mockDB    *MockDB
	cryptoSvc *crypto.CryptoService
	userID    uuid.UUID
}

func (suite *CollaborationHandlerTestSuite) SetupTest() {
	suite.mockDB = &MockDB{}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		suite.T().Fatalf("Failed to generate random data: %v", err)
	}
	suite.cryptoSvc = crypto.NewCryptoService(key)

	suite.handler = NewCollaborationHandler(suite.mockDB, suite.cryptoSvc)
	suite.userID = uuid.New()
}

func (suite *CollaborationHandlerTestSuite) TestNewCollaborationHandler() {
	handler := NewCollaborationHandler(suite.mockDB, suite.cryptoSvc)
	suite.NotNil(handler)
}

func (suite *CollaborationHandlerTestSuite) TestGetSharedNotesSuccess() {
	app := fiber.New()

	mockRows := &MockRows{}
	suite.mockDB.On("Query", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "collaborations")
	}), suite.userID).Return(mockRows, nil)

	mockRows.On("Next").Return(false)

	app.Get("/shared", func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.userID)
		return suite.handler.GetSharedNotes(c)
	})

	req := httptest.NewRequest("GET", "/shared", nil)
	resp, err := app.Test(req)

	suite.NoError(err)
	suite.Equal(200, resp.StatusCode)
}

func (suite *CollaborationHandlerTestSuite) TestShareNote_InvalidNoteID() {
	app := fiber.New()
	app.Post("/notes/:id/share", func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.userID)
		return suite.handler.ShareNote(c)
	})

	reqBody := `{"user_email":"test@example.com","permission":"read"}`
	req := httptest.NewRequest("POST", "/notes/invalid-uuid/share", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(400, resp.StatusCode)
}

func (suite *CollaborationHandlerTestSuite) TestShareNote_InvalidBody() {
	app := fiber.New()
	app.Post("/notes/:id/share", func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.userID)
		return suite.handler.ShareNote(c)
	})

	noteID := uuid.New()
	req := httptest.NewRequest("POST", "/notes/"+noteID.String()+"/share", bytes.NewBufferString(`invalid`))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(400, resp.StatusCode)
}

func (suite *CollaborationHandlerTestSuite) TestShareNote_InvalidEmail() {
	app := fiber.New()
	app.Post("/notes/:id/share", func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.userID)
		return suite.handler.ShareNote(c)
	})

	noteID := uuid.New()
	reqBody := `{"user_email":"invalid-email","permission":"read"}`
	req := httptest.NewRequest("POST", "/notes/"+noteID.String()+"/share", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(400, resp.StatusCode)
}

func (suite *CollaborationHandlerTestSuite) TestShareNote_InvalidPermission() {
	app := fiber.New()
	app.Post("/notes/:id/share", func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.userID)
		return suite.handler.ShareNote(c)
	})

	noteID := uuid.New()
	reqBody := `{"user_email":"test@example.com","permission":"invalid"}`
	req := httptest.NewRequest("POST", "/notes/"+noteID.String()+"/share", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(400, resp.StatusCode)
}

// =====================
// AttachmentsHandler Tests
// =====================

type AttachmentsHandlerTestSuite struct {
	suite.Suite
	handler   *AttachmentsHandler
	mockDB    *MockDB
	cryptoSvc *crypto.CryptoService
	userID    uuid.UUID
}

func (suite *AttachmentsHandlerTestSuite) SetupTest() {
	suite.mockDB = &MockDB{}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		suite.T().Fatalf("Failed to generate random data: %v", err)
	}
	suite.cryptoSvc = crypto.NewCryptoService(key)

	suite.handler = NewAttachmentsHandler(suite.mockDB, suite.cryptoSvc)
	suite.userID = uuid.New()
}

func (suite *AttachmentsHandlerTestSuite) TestNewAttachmentsHandler() {
	handler := NewAttachmentsHandler(suite.mockDB, suite.cryptoSvc)
	suite.NotNil(handler)
}

func (suite *AttachmentsHandlerTestSuite) TestGetAttachmentsSuccess() {
	app := fiber.New()

	noteID := uuid.New()

	// Mock note existence check
	mockRow := &MockRow{}
	suite.mockDB.On("QueryRow", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "EXISTS")
	}), noteID, suite.userID).Return(mockRow)

	mockRow.On("Scan", mock.Anything).Run(func(args mock.Arguments) {
		if exists, ok := args[0].(*bool); ok {
			*exists = true
		}
	}).Return(nil)

	// Mock attachments query
	mockRows := &MockRows{}
	suite.mockDB.On("Query", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "attachments")
	}), noteID).Return(mockRows, nil)

	mockRows.On("Next").Return(false)

	app.Get("/notes/:noteId/attachments", func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.userID)
		return suite.handler.GetAttachments(c)
	})

	req := httptest.NewRequest("GET", "/notes/"+noteID.String()+"/attachments", nil)
	resp, err := app.Test(req)

	suite.NoError(err)
	suite.Equal(200, resp.StatusCode)
}

func (suite *AttachmentsHandlerTestSuite) TestGetAttachments_InvalidNoteID() {
	app := fiber.New()
	app.Get("/notes/:noteId/attachments", func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.userID)
		return suite.handler.GetAttachments(c)
	})

	req := httptest.NewRequest("GET", "/notes/invalid-uuid/attachments", nil)
	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(400, resp.StatusCode)
}

func (suite *AttachmentsHandlerTestSuite) TestGetAttachments_NoteNotFound() {
	app := fiber.New()
	noteID := uuid.New()

	mockRow := &MockRow{}
	suite.mockDB.On("QueryRow", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "EXISTS")
	}), noteID, suite.userID).Return(mockRow)

	mockRow.On("Scan", mock.Anything).Run(func(args mock.Arguments) {
		if exists, ok := args[0].(*bool); ok {
			*exists = false
		}
	}).Return(nil)

	app.Get("/notes/:noteId/attachments", func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.userID)
		return suite.handler.GetAttachments(c)
	})

	req := httptest.NewRequest("GET", "/notes/"+noteID.String()+"/attachments", nil)
	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(404, resp.StatusCode)
}

// =====================
// SearchHandler Tests - Moved to search_test.go
// =====================

// =====================
// ImportExportHandler Tests
// =====================

type ImportExportHandlerTestSuite struct {
	suite.Suite
	handler   *ImportExportHandler
	mockDB    *MockDB
	cryptoSvc *crypto.CryptoService
	userID    uuid.UUID
}

func (suite *ImportExportHandlerTestSuite) SetupTest() {
	suite.mockDB = &MockDB{}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		suite.T().Fatalf("Failed to generate random data: %v", err)
	}
	suite.cryptoSvc = crypto.NewCryptoService(key)

	suite.handler = NewImportExportHandler(suite.mockDB, suite.cryptoSvc)
	suite.userID = uuid.New()
}

func (suite *ImportExportHandlerTestSuite) TestNewImportExportHandler() {
	handler := NewImportExportHandler(suite.mockDB, suite.cryptoSvc)
	suite.NotNil(handler)
}

func (suite *ImportExportHandlerTestSuite) TestGetStorageInfoSuccess() {
	app := fiber.New()

	mockRow := &MockRow{}
	suite.mockDB.On("QueryRow", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "storage_used")
	}), suite.userID).Return(mockRow)

	mockRow.On("Scan", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		if used, ok := args[0].(*int64); ok {
			*used = 1000
		}
		if limit, ok := args[1].(*int64); ok {
			*limit = 10000
		}
	}).Return(nil)

	app.Get("/storage", func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.userID)
		return suite.handler.GetStorageInfo(c)
	})

	req := httptest.NewRequest("GET", "/storage", nil)
	resp, err := app.Test(req)

	suite.NoError(err)
	suite.Equal(200, resp.StatusCode)

	var response map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&response) // Test response parsing

	suite.Contains(response, "storage_used")
	suite.Contains(response, "storage_limit")
}

func (suite *ImportExportHandlerTestSuite) TestGetStorageInfo_DatabaseError() {
	app := fiber.New()

	mockRow := &MockRow{}
	suite.mockDB.On("QueryRow", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "storage_used")
	}), suite.userID).Return(mockRow)

	mockRow.On("Scan", mock.Anything, mock.Anything).Return(assert.AnError)

	app.Get("/storage", func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.userID)
		return suite.handler.GetStorageInfo(c)
	})

	req := httptest.NewRequest("GET", "/storage", nil)
	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(500, resp.StatusCode)
}

// =====================
// TemplatesHandler Additional Tests
// =====================

func (suite *TemplatesHandlerTestSuite) TestGetTemplate_InvalidID() {
	app := fiber.New()
	app.Get("/templates/:id", func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.userID)
		return suite.handler.GetTemplate(c)
	})

	req := httptest.NewRequest("GET", "/templates/invalid-uuid", nil)
	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(400, resp.StatusCode)
}

func (suite *TemplatesHandlerTestSuite) TestGetTemplate_NotFound() {
	app := fiber.New()
	templateID := uuid.New()

	mockRow := &MockRow{}
	suite.mockDB.On("QueryRow", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "SELECT user_id")
	}), templateID, suite.userID).Return(mockRow)

	mockRow.On("Scan", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(assert.AnError)

	app.Get("/templates/:id", func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.userID)
		return suite.handler.GetTemplate(c)
	})

	req := httptest.NewRequest("GET", "/templates/"+templateID.String(), nil)
	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(404, resp.StatusCode)
}

func (suite *TemplatesHandlerTestSuite) TestDeleteTemplate_InvalidID() {
	app := fiber.New()
	app.Delete("/templates/:id", func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.userID)
		return suite.handler.DeleteTemplate(c)
	})

	req := httptest.NewRequest("DELETE", "/templates/invalid-uuid", nil)
	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(400, resp.StatusCode)
}

// =====================
// Test Suite Runners
// =====================

func TestNotesHandlerSuite(t *testing.T) {
	suite.Run(t, new(NotesHandlerTestSuite))
}

func TestTagsHandlerSuite(t *testing.T) {
	suite.Run(t, new(TagsHandlerTestSuite))
}

// FoldersHandler tests are integrated into the main handlers_test.go file
// TestFoldersHandlerSuite removed - folders tests are in handlers_test.go

func TestTemplatesHandlerSuite(t *testing.T) {
	suite.Run(t, new(TemplatesHandlerTestSuite))
}

func TestCollaborationHandlerSuite(t *testing.T) {
	suite.Run(t, new(CollaborationHandlerTestSuite))
}

func TestAttachmentsHandlerSuite(t *testing.T) {
	suite.Run(t, new(AttachmentsHandlerTestSuite))
}

func TestSearchHandlerSuite(t *testing.T) {
	suite.Run(t, new(SearchHandlerTestSuite))
}

func TestImportExportHandlerSuite(t *testing.T) {
	suite.Run(t, new(ImportExportHandlerTestSuite))
}

// =====================
// Helper Functions
// =====================

func contains(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && (s == substr || len(s) >= len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || containsSubstring(s, substr)))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// TestHelperFunctions tests utility functions
func TestHelperFunctions(t *testing.T) {
	assert.True(t, contains("INSERT INTO users", "INSERT"))
	assert.True(t, contains("SELECT * FROM notes WHERE id = 1", "notes"))
	assert.False(t, contains("SELECT * FROM notes", "users"))
}

// =====================
// Additional Edge Case Tests
// =====================

func TestContainsFunction(t *testing.T) {
	tests := []struct {
		name     string
		s        string
		substr   string
		expected bool
	}{
		{"exact match", "test", "test", true},
		{"substring at start", "testing", "test", true},
		{"substring at end", "best", "est", true},
		{"substring in middle", "testing", "sting", true},
		{"not found", "hello", "world", false},
		{"empty string", "", "test", false},
		{"empty substr", "test", "", false},
		{"both empty", "", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := contains(tt.s, tt.substr)
			assert.Equal(t, tt.expected, result)
		})
	}
}
