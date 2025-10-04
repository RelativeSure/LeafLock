package handlers

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
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

	"leaflock/config"
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
	return mockArgs.Get(0).(pgx.Rows), mockArgs.Error(1)
}

func (m *MockDB) Begin(ctx context.Context) (pgx.Tx, error) {
	mockArgs := m.Called(ctx)
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
// AuthHandler Tests
// =====================

type AuthHandlerTestSuite struct {
	suite.Suite
	handler     *AuthHandler
	mockDB      *MockDB
	mockRedis   *MockRedisClient
	cryptoSvc   *crypto.CryptoService
	cfg         *config.Config
	userID      uuid.UUID
	workspaceID uuid.UUID
}

func (suite *AuthHandlerTestSuite) SetupTest() {
	suite.mockDB = &MockDB{}
	suite.mockRedis = &MockRedisClient{}

	// Generate test encryption key
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		suite.T().Fatalf("Failed to generate random data: %v", err)
	}
	suite.cryptoSvc = crypto.NewCryptoService(key)

	jwtSecret := make([]byte, 64)
	if _, err := rand.Read(jwtSecret); err != nil {
		suite.T().Fatalf("Failed to generate random data: %v", err)
	}

	suite.cfg = &config.Config{
		JWTSecret:         jwtSecret,
		EncryptionKey:     key,
		MaxLoginAttempts:  5,
		SessionDuration:   24 * time.Hour,
		DefaultAdminEmail: "admin@leaflock.app",
	}

	suite.handler = NewAuthHandler(suite.mockDB, nil, suite.cryptoSvc, suite.cfg)
	suite.userID = uuid.New()
	suite.workspaceID = uuid.New()
}

func (suite *AuthHandlerTestSuite) TestNewAuthHandler() {
	handler := NewAuthHandler(suite.mockDB, nil, suite.cryptoSvc, suite.cfg)
	suite.NotNil(handler)
	suite.Equal(suite.mockDB, handler.db)
	suite.Equal(suite.cryptoSvc, handler.crypto)
	suite.Equal(suite.cfg, handler.config)
}

func (suite *AuthHandlerTestSuite) TestRegisterSuccess() {
	// Enable registration for this test
	config.RegEnabled.Store(1)
	defer config.RegEnabled.Store(0)

	app := fiber.New()

	// Mock database interactions
	mockRow := &MockRow{}
	mockWorkspaceRow := &MockRow{}

	// Mock transaction
	mockTx := &MockTx{}
	suite.mockDB.On("Begin", mock.Anything).Return(mockTx, nil)

	// Mock GDPR key insertion
	mockTx.On("Exec", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "gdpr_keys")
	}), mock.Anything, mock.Anything).Return(int64(1), nil)

	// Mock user insertion
	mockTx.On("QueryRow", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "INSERT INTO users")
	}), mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(mockRow)

	mockRow.On("Scan", mock.Anything).Run(func(args mock.Arguments) {
		if uid, ok := args[0].(*uuid.UUID); ok {
			*uid = suite.userID
		}
	}).Return(nil)

	// Mock workspace insertion
	mockTx.On("QueryRow", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "INSERT INTO workspaces")
	}), mock.Anything, mock.Anything, mock.Anything).Return(mockWorkspaceRow)

	mockWorkspaceRow.On("Scan", mock.Anything).Run(func(args mock.Arguments) {
		if wid, ok := args[0].(*uuid.UUID); ok {
			*wid = suite.workspaceID
		}
	}).Return(nil)

	mockTx.On("Commit", mock.Anything).Return(nil)
	mockTx.On("Rollback", mock.Anything).Return(nil)

	// Mock audit log
	suite.mockDB.On("Exec", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "audit_log")
	}), mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(int64(1), nil)

	app.Post("/register", suite.handler.Register)

	reqBody := map[string]string{
		"email":    "test@example.com",
		"password": "testpassword123456",
	}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)

	suite.NoError(err)
	suite.Equal(201, resp.StatusCode)

	var response map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&response) // Test response parsing

	suite.Contains(response, "token")
	suite.Contains(response, "user_id")
	suite.Contains(response, "workspace_id")
}

func (suite *AuthHandlerTestSuite) TestRegisterInvalidPassword() {
	// Enable registration for this test
	config.RegEnabled.Store(1)
	defer config.RegEnabled.Store(0)

	app := fiber.New()
	app.Post("/register", suite.handler.Register)

	reqBody := map[string]string{
		"email":    "test@example.com",
		"password": "short",
	}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)

	suite.NoError(err)
	suite.Equal(400, resp.StatusCode)
}

func (suite *AuthHandlerTestSuite) TestRegisterDisabled() {
	// Ensure registration is disabled
	config.RegEnabled.Store(0)

	app := fiber.New()
	app.Post("/register", suite.handler.Register)

	reqBody := map[string]string{
		"email":    "test@example.com",
		"password": "validpassword123",
	}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)

	suite.NoError(err)
	suite.Equal(403, resp.StatusCode)
}

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
	mockNoteRow.On("Scan", mock.Anything).Run(func(args mock.Arguments) {
		if nid, ok := args[0].(*uuid.UUID); ok {
			*nid = noteID
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
// FoldersHandler Tests
// =====================

type FoldersHandlerTestSuite struct {
	suite.Suite
	handler   *FoldersHandler
	mockDB    *MockDB
	cryptoSvc *crypto.CryptoService
	userID    uuid.UUID
}

func (suite *FoldersHandlerTestSuite) SetupTest() {
	suite.mockDB = &MockDB{}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		suite.T().Fatalf("Failed to generate random data: %v", err)
	}
	suite.cryptoSvc = crypto.NewCryptoService(key)

	suite.handler = NewFoldersHandler(suite.mockDB, suite.cryptoSvc)
	suite.userID = uuid.New()
}

func (suite *FoldersHandlerTestSuite) TestNewFoldersHandler() {
	handler := NewFoldersHandler(suite.mockDB, suite.cryptoSvc)
	suite.NotNil(handler)
}

func (suite *FoldersHandlerTestSuite) TestCreateFolderSuccess() {
	app := fiber.New()

	mockRow := &MockRow{}
	folderID := uuid.New()

	suite.mockDB.On("QueryRow", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "INSERT INTO folders")
	}), suite.userID, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(mockRow)

	mockRow.On("Scan", mock.Anything).Run(func(args mock.Arguments) {
		if fid, ok := args[0].(*uuid.UUID); ok {
			*fid = folderID
		}
	}).Return(nil)

	app.Post("/folders", func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.userID)
		return suite.handler.CreateFolder(c)
	})

	reqBody := map[string]interface{}{
		"name":  "Test Folder",
		"color": "#3b82f6",
	}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/folders", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)

	suite.NoError(err)
	suite.Equal(200, resp.StatusCode)
}

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

	mockRow.On("Scan", mock.Anything).Run(func(args mock.Arguments) {
		if tid, ok := args[0].(*uuid.UUID); ok {
			*tid = templateID
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

// =====================
// SearchHandler Tests
// =====================

type SearchHandlerTestSuite struct {
	suite.Suite
	handler   *SearchHandler
	mockDB    *MockDB
	cryptoSvc *crypto.CryptoService
	userID    uuid.UUID
}

func (suite *SearchHandlerTestSuite) SetupTest() {
	suite.mockDB = &MockDB{}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		suite.T().Fatalf("Failed to generate random data: %v", err)
	}
	suite.cryptoSvc = crypto.NewCryptoService(key)

	suite.handler = NewSearchHandler(suite.mockDB, suite.cryptoSvc)
	suite.userID = uuid.New()
}

func (suite *SearchHandlerTestSuite) TestNewSearchHandler() {
	handler := NewSearchHandler(suite.mockDB, suite.cryptoSvc)
	suite.NotNil(handler)
}

func (suite *SearchHandlerTestSuite) TestSearchNotesSuccess() {
	app := fiber.New()

	mockRows := &MockRows{}
	suite.mockDB.On("Query", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "SELECT id, title_encrypted")
	}), suite.userID, mock.Anything).Return(mockRows, nil)

	mockRows.On("Next").Return(false)

	app.Post("/search", func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.userID)
		return suite.handler.SearchNotes(c)
	})

	reqBody := map[string]interface{}{
		"query": "test",
		"limit": 20,
	}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/search", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)

	suite.NoError(err)
	suite.Equal(200, resp.StatusCode)
}

func (suite *SearchHandlerTestSuite) TestSearchNotesInvalidQuery() {
	app := fiber.New()

	app.Post("/search", func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.userID)
		return suite.handler.SearchNotes(c)
	})

	reqBody := map[string]interface{}{
		"query": "",
	}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/search", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)

	suite.NoError(err)
	suite.Equal(400, resp.StatusCode)
}

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

// =====================
// Test Suite Runners
// =====================

func TestAuthHandlerSuite(t *testing.T) {
	suite.Run(t, new(AuthHandlerTestSuite))
}

func TestNotesHandlerSuite(t *testing.T) {
	suite.Run(t, new(NotesHandlerTestSuite))
}

func TestTagsHandlerSuite(t *testing.T) {
	suite.Run(t, new(TagsHandlerTestSuite))
}

func TestFoldersHandlerSuite(t *testing.T) {
	suite.Run(t, new(FoldersHandlerTestSuite))
}

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
