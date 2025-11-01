package handlers

import (
	"bytes"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"

	"leaflock/config"
	"leaflock/crypto"
)

// AccountHandlerTestSuite tests AccountHandler
type AccountHandlerTestSuite struct {
	suite.Suite
	handler   *AccountHandler
	mockDB    *MockDB
	redis     *redis.Client
	cryptoSvc *crypto.CryptoService
	config    *config.Config
	userID    uuid.UUID
}

func (suite *AccountHandlerTestSuite) SetupTest() {
	suite.mockDB = &MockDB{}

	// Use a real Redis client - Redis operations may fail in unit tests but won't crash
	// The account deletion code handles Redis errors gracefully
	suite.redis = redis.NewClient(&redis.Options{
		Addr: "localhost:6379", // Will fail to connect but code handles it gracefully
	})

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		suite.T().Fatalf("Failed to generate random data: %v", err)
	}
	suite.cryptoSvc = crypto.NewCryptoService(key)

	suite.config = &config.Config{}

	suite.handler = NewAccountHandler(suite.mockDB, suite.redis, suite.cryptoSvc, suite.config)
	suite.userID = uuid.New()
}

func (suite *AccountHandlerTestSuite) TearDownTest() {
	if suite.redis != nil {
		_ = suite.redis.Close()
	}
}

func (suite *AccountHandlerTestSuite) TestNewAccountHandler() {
	handler := NewAccountHandler(suite.mockDB, suite.redis, suite.cryptoSvc, suite.config)
	suite.NotNil(handler)
	suite.Equal(suite.mockDB, handler.db)
	suite.Equal(suite.cryptoSvc, handler.crypto)
	suite.Equal(suite.config, handler.config)
}

func (suite *AccountHandlerTestSuite) TestDeleteAccount_Unauthorized() {
	app := fiber.New()
	app.Delete("/account", suite.handler.DeleteAccount)

	req := httptest.NewRequest("DELETE", "/account", bytes.NewBufferString(`{"password":"testpass"}`))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(401, resp.StatusCode)
}

func (suite *AccountHandlerTestSuite) TestDeleteAccount_InvalidRequest() {
	app := fiber.New()
	app.Delete("/account", func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.userID)
		return suite.handler.DeleteAccount(c)
	})

	req := httptest.NewRequest("DELETE", "/account", bytes.NewBufferString(`invalid json`))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(400, resp.StatusCode)
}

func (suite *AccountHandlerTestSuite) TestDeleteAccount_MissingPassword() {
	app := fiber.New()
	app.Delete("/account", func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.userID)
		return suite.handler.DeleteAccount(c)
	})

	req := httptest.NewRequest("DELETE", "/account", bytes.NewBufferString(`{}`))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(400, resp.StatusCode)
}

func (suite *AccountHandlerTestSuite) TestDeleteAccount_UserNotFound() {
	app := fiber.New()
	app.Delete("/account", func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.userID)
		return suite.handler.DeleteAccount(c)
	})

	mockRow := &MockRow{}
	suite.mockDB.On("QueryRow", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "SELECT password_hash")
	}), suite.userID).Return(mockRow)

	mockRow.On("Scan", mock.Anything, mock.Anything).Return(sql.ErrNoRows)

	req := httptest.NewRequest("DELETE", "/account", bytes.NewBufferString(`{"password":"testpass"}`))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(500, resp.StatusCode)
}

func (suite *AccountHandlerTestSuite) TestDeleteAccount_InvalidPassword() {
	app := fiber.New()
	app.Delete("/account", func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.userID)
		return suite.handler.DeleteAccount(c)
	})

	passwordHash := crypto.HashPassword("correctpass", make([]byte, 16))
	emailHash := make([]byte, 32)

	mockRow := &MockRow{}
	suite.mockDB.On("QueryRow", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "SELECT password_hash")
	}), suite.userID).Return(mockRow)

	mockRow.On("Scan", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		if hash, ok := args[0].(*string); ok {
			*hash = passwordHash
		}
		if hash, ok := args[1].(*[]byte); ok {
			*hash = emailHash
		}
	}).Return(nil)

	// Mock audit log
	suite.mockDB.On("Exec", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "INSERT INTO audit_log")
	}), mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(int64(1), nil)

	req := httptest.NewRequest("DELETE", "/account", bytes.NewBufferString(`{"password":"wrongpass"}`))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(401, resp.StatusCode)
}

func (suite *AccountHandlerTestSuite) TestDeleteAccount_Success() {
	app := fiber.New()
	app.Delete("/account", func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.userID)
		return suite.handler.DeleteAccount(c)
	})

	passwordHash := crypto.HashPassword("testpass", make([]byte, 16))
	emailHash := make([]byte, 32)

	// Mock password verification
	mockRow := &MockRow{}
	suite.mockDB.On("QueryRow", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "SELECT password_hash")
	}), suite.userID).Return(mockRow)

	mockRow.On("Scan", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		if hash, ok := args[0].(*string); ok {
			*hash = passwordHash
		}
		if hash, ok := args[1].(*[]byte); ok {
			*hash = emailHash
		}
	}).Return(nil)

	// Mock transaction begin
	mockTx := &MockTx{}
	suite.mockDB.On("Begin", mock.Anything).Return(mockTx, nil)

	// Mock Rollback (called in defer - may be called even after successful commit)
	mockTx.On("Rollback", mock.Anything).Return(nil).Maybe()

	// Mock cleanup statements
	mockTx.On("Exec", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "DELETE FROM collaborations") ||
			contains(sql, "DELETE FROM share_links") ||
			contains(sql, "DELETE FROM tags") ||
			contains(sql, "DELETE FROM folders") ||
			contains(sql, "DELETE FROM templates") ||
			contains(sql, "DELETE FROM user_sessions") ||
			contains(sql, "DELETE FROM audit_log") ||
			contains(sql, "DELETE FROM password_reset_tokens") ||
			contains(sql, "DELETE FROM user_roles") ||
			contains(sql, "DELETE FROM collaborations") ||
			contains(sql, "DELETE FROM workspaces") ||
			contains(sql, "DELETE FROM gdpr_keys") ||
			contains(sql, "DELETE FROM users")
	}), mock.Anything).Return(int64(1), nil)

	// Mock transaction commit
	mockTx.On("Commit", mock.Anything).Return(nil).Run(func(args mock.Arguments) {
		// Rollback should not be called after successful commit
	})

	// Mock audit log
	suite.mockDB.On("Exec", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "INSERT INTO audit_log")
	}), mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(int64(1), nil)

	req := httptest.NewRequest("DELETE", "/account", bytes.NewBufferString(`{"password":"testpass"}`))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(200, resp.StatusCode)

	var result map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	suite.NoError(err)
	suite.True(result["success"].(bool))
}

func (suite *AccountHandlerTestSuite) TestDeleteAccount_TransactionBeginError() {
	app := fiber.New()
	app.Delete("/account", func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.userID)
		return suite.handler.DeleteAccount(c)
	})

	passwordHash := crypto.HashPassword("testpass", make([]byte, 16))
	emailHash := make([]byte, 32)

	mockRow := &MockRow{}
	suite.mockDB.On("QueryRow", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "SELECT password_hash")
	}), suite.userID).Return(mockRow)

	mockRow.On("Scan", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		if hash, ok := args[0].(*string); ok {
			*hash = passwordHash
		}
		if hash, ok := args[1].(*[]byte); ok {
			*hash = emailHash
		}
	}).Return(nil)

	// Mock transaction begin failure - return nil transaction and error
	mockBeginCall := suite.mockDB.On("Begin", mock.Anything)
	mockBeginCall.Return(nil, assert.AnError)

	req := httptest.NewRequest("DELETE", "/account", bytes.NewBufferString(`{"password":"testpass"}`))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(500, resp.StatusCode)
}

func (suite *AccountHandlerTestSuite) TestExportData_Unauthorized() {
	app := fiber.New()
	app.Get("/account/export", suite.handler.ExportData)

	req := httptest.NewRequest("GET", "/account/export", nil)

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(401, resp.StatusCode)
}

func (suite *AccountHandlerTestSuite) TestExportData_Success() {
	app := fiber.New()
	app.Get("/account/export", func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.userID)
		return suite.handler.ExportData(c)
	})

	// Mock notes query
	mockNotesRows := &MockRows{}
	suite.mockDB.On("Query", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "SELECT n.id") && contains(sql, "FROM notes n")
	}), suite.userID).Return(mockNotesRows, nil)

	noteID := uuid.New()
	titleEnc, _ := suite.cryptoSvc.Encrypt([]byte("Test Note"))
	contentEnc, _ := suite.cryptoSvc.Encrypt([]byte("Test content"))

	mockNotesRows.On("Next").Return(true).Once()
	mockNotesRows.On("Next").Return(false).Once()
	mockNotesRows.On("Scan", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		if id, ok := args[0].(*uuid.UUID); ok {
			*id = noteID
		}
		if title, ok := args[1].(*[]byte); ok {
			*title = titleEnc
		}
		if content, ok := args[2].(*[]byte); ok {
			*content = contentEnc
		}
	}).Return(nil)

	// Mock tags query
	mockTagsRows := &MockRows{}
	suite.mockDB.On("Query", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "FROM tags WHERE")
	}), suite.userID).Return(mockTagsRows, nil)

	mockTagsRows.On("Next").Return(false)

	// Mock folders query
	mockFoldersRows := &MockRows{}
	suite.mockDB.On("Query", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "FROM folders WHERE")
	}), suite.userID).Return(mockFoldersRows, nil)

	mockFoldersRows.On("Next").Return(false)

	// Mock templates query
	mockTemplatesRows := &MockRows{}
	suite.mockDB.On("Query", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "FROM templates WHERE")
	}), suite.userID).Return(mockTemplatesRows, nil)

	mockTemplatesRows.On("Next").Return(false)

	// Mock workspace query
	mockWorkspaceRow := &MockRow{}
	workspaceID := uuid.New()
	workspaceNameEnc, _ := suite.cryptoSvc.Encrypt([]byte("Workspace"))

	suite.mockDB.On("QueryRow", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "FROM workspaces WHERE")
	}), suite.userID).Return(mockWorkspaceRow)

	mockWorkspaceRow.On("Scan", mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		if id, ok := args[0].(*uuid.UUID); ok {
			*id = workspaceID
		}
		if name, ok := args[1].(*[]byte); ok {
			*name = workspaceNameEnc
		}
	}).Return(nil)

	// Mock audit log
	suite.mockDB.On("Exec", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "INSERT INTO audit_log")
	}), mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(int64(1), nil)

	req := httptest.NewRequest("GET", "/account/export", nil)

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(200, resp.StatusCode)

	var result ExportDataResponse
	err = json.NewDecoder(resp.Body).Decode(&result)
	suite.NoError(err)
	suite.Equal(suite.userID.String(), result.UserID)
	suite.NotEmpty(result.ExportedAt)
	suite.Equal("1.0", result.ExportVersion)
}

func (suite *AccountHandlerTestSuite) TestExportData_NotesQueryError() {
	app := fiber.New()
	app.Get("/account/export", func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.userID)
		return suite.handler.ExportData(c)
	})

	// Mock notes query error
	suite.mockDB.On("Query", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "SELECT n.id") && contains(sql, "FROM notes n")
	}), suite.userID).Return(nil, assert.AnError)

	req := httptest.NewRequest("GET", "/account/export", nil)

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(500, resp.StatusCode)
}

func TestAccountHandlerTestSuite(t *testing.T) {
	suite.Run(t, new(AccountHandlerTestSuite))
}
