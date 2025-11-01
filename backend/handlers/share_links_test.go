package handlers

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"

	"leaflock/crypto"
)

// ShareLinksHandlerTestSuite tests ShareLinksHandler
type ShareLinksHandlerTestSuite struct {
	suite.Suite
	handler   *ShareLinksHandler
	mockDB    *MockDB
	redis     *redis.Client
	cryptoSvc *crypto.CryptoService
	userID    uuid.UUID
	noteID    uuid.UUID
}

func (suite *ShareLinksHandlerTestSuite) SetupTest() {
	suite.mockDB = &MockDB{}

	suite.mockDB.
		On("Exec",
			mock.Anything,
			mock.MatchedBy(func(sql string) bool {
				return contains(sql, "INSERT INTO audit_log")
			}),
			mock.AnythingOfType("uuid.UUID"),
			mock.AnythingOfType("string"),
			mock.AnythingOfType("string"),
			mock.Anything,
		).
		Return(int64(1), nil).
		Maybe()

	// Use a real Redis client - Redis operations may fail in unit tests but won't crash
	suite.redis = redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		suite.T().Fatalf("Failed to generate random data: %v", err)
	}
	suite.cryptoSvc = crypto.NewCryptoService(key)

	suite.handler = NewShareLinksHandler(suite.mockDB, suite.cryptoSvc, suite.redis)
	suite.userID = uuid.New()
	suite.noteID = uuid.New()
}

func (suite *ShareLinksHandlerTestSuite) TearDownTest() {
	if suite.redis != nil {
		_ = suite.redis.Close()
	}
}

func (suite *ShareLinksHandlerTestSuite) TestNewShareLinksHandler() {
	handler := NewShareLinksHandler(suite.mockDB, suite.cryptoSvc, suite.redis)
	suite.NotNil(handler)
	suite.Equal(suite.mockDB, handler.db)
	suite.Equal(suite.cryptoSvc, handler.crypto)
}

func (suite *ShareLinksHandlerTestSuite) TestCreateShareLink_InvalidNoteID() {
	app := fiber.New()
	app.Post("/notes/:id/share-links", func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.userID)
		return suite.handler.CreateShareLink(c)
	})

	req := httptest.NewRequest("POST", "/notes/invalid/share-links", bytes.NewBufferString(`{}`))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(400, resp.StatusCode)
}

func (suite *ShareLinksHandlerTestSuite) TestCreateShareLink_InvalidBody() {
	app := fiber.New()
	app.Post("/notes/:id/share-links", func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.userID)
		return suite.handler.CreateShareLink(c)
	})

	req := httptest.NewRequest("POST", "/notes/"+suite.noteID.String()+"/share-links", bytes.NewBufferString(`invalid`))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(400, resp.StatusCode)
}

func (suite *ShareLinksHandlerTestSuite) TestCreateShareLink_NoteNotFound() {
	app := fiber.New()
	app.Post("/notes/:id/share-links", func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.userID)
		return suite.handler.CreateShareLink(c)
	})

	mockRow := &MockRow{}
	suite.mockDB.On("QueryRow", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "EXISTS") && contains(sql, "notes n")
	}), suite.noteID, suite.userID).Return(mockRow)

	mockRow.On("Scan", mock.Anything).Run(func(args mock.Arguments) {
		if check, ok := args[0].(*bool); ok {
			*check = false
		}
	}).Return(nil)

	reqBody := `{"permission":"read"}`
	req := httptest.NewRequest("POST", "/notes/"+suite.noteID.String()+"/share-links", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(404, resp.StatusCode)
}

func (suite *ShareLinksHandlerTestSuite) TestCreateShareLink_InvalidExpiresIn() {
	app := fiber.New()
	app.Post("/notes/:id/share-links", func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.userID)
		return suite.handler.CreateShareLink(c)
	})

	mockRow := &MockRow{}
	suite.mockDB.On("QueryRow", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "EXISTS") && contains(sql, "notes n")
	}), suite.noteID, suite.userID).Return(mockRow)

	mockRow.On("Scan", mock.Anything).Run(func(args mock.Arguments) {
		if check, ok := args[0].(*bool); ok {
			*check = true
		}
	}).Return(nil)

	reqBody := `{"permission":"read","expires_in":"invalid"}`
	req := httptest.NewRequest("POST", "/notes/"+suite.noteID.String()+"/share-links", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(400, resp.StatusCode)
}

func (suite *ShareLinksHandlerTestSuite) TestCreateShareLink_Success() {
	app := fiber.New()
	app.Post("/notes/:id/share-links", func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.userID)
		return suite.handler.CreateShareLink(c)
	})

	// Mock owner check
	mockRow := &MockRow{}
	suite.mockDB.On("QueryRow", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "EXISTS") && contains(sql, "notes n")
	}), suite.noteID, suite.userID).Return(mockRow)

	mockRow.On("Scan", mock.Anything).Run(func(args mock.Arguments) {
		if check, ok := args[0].(*bool); ok {
			*check = true
		}
	}).Return(nil)

	// Mock share link creation
	linkID := uuid.New()
	createdAt := time.Now()
	mockInsertRow := &MockRow{}
	suite.mockDB.On("QueryRow", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "INSERT INTO share_links")
	}), mock.Anything, mock.Anything, mock.Anything, mock.Anything,
		mock.Anything, mock.Anything, mock.Anything).Return(mockInsertRow)

	mockInsertRow.On("Scan", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		if id, ok := args[0].(*uuid.UUID); ok {
			*id = linkID
		}
		if created, ok := args[1].(*time.Time); ok {
			*created = createdAt
		}
	}).Return(nil)

	reqBody := `{"permission":"read","expires_in":"24h","max_uses":10}`
	req := httptest.NewRequest("POST", "/notes/"+suite.noteID.String()+"/share-links", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(201, resp.StatusCode)

	var result ShareLinkResponse
	err = json.NewDecoder(resp.Body).Decode(&result)
	suite.NoError(err)
	suite.Equal(linkID.String(), result.ID)
	suite.Equal(suite.noteID.String(), result.NoteID)
	suite.Equal("read", result.Permission)
	suite.NotNil(result.Token)
}

func (suite *ShareLinksHandlerTestSuite) TestGetNoteShareLinks_InvalidNoteID() {
	app := fiber.New()
	app.Get("/notes/:id/share-links", func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.userID)
		return suite.handler.GetNoteShareLinks(c)
	})

	req := httptest.NewRequest("GET", "/notes/invalid/share-links", nil)
	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(400, resp.StatusCode)
}

func (suite *ShareLinksHandlerTestSuite) TestGetNoteShareLinks_NoteNotFound() {
	app := fiber.New()
	app.Get("/notes/:id/share-links", func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.userID)
		return suite.handler.GetNoteShareLinks(c)
	})

	mockRow := &MockRow{}
	suite.mockDB.On("QueryRow", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "EXISTS") && contains(sql, "notes n")
	}), suite.noteID, suite.userID).Return(mockRow)

	mockRow.On("Scan", mock.Anything).Run(func(args mock.Arguments) {
		if check, ok := args[0].(*bool); ok {
			*check = false
		}
	}).Return(nil)

	req := httptest.NewRequest("GET", "/notes/"+suite.noteID.String()+"/share-links", nil)
	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(404, resp.StatusCode)
}

func (suite *ShareLinksHandlerTestSuite) TestGetNoteShareLinks_Success() {
	app := fiber.New()
	app.Get("/notes/:id/share-links", func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.userID)
		return suite.handler.GetNoteShareLinks(c)
	})

	// Mock owner check
	mockRow := &MockRow{}
	suite.mockDB.On("QueryRow", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "EXISTS") && contains(sql, "notes n")
	}), suite.noteID, suite.userID).Return(mockRow)

	mockRow.On("Scan", mock.Anything).Run(func(args mock.Arguments) {
		if check, ok := args[0].(*bool); ok {
			*check = true
		}
	}).Return(nil)

	// Mock share links query
	mockRows := &MockRows{}
	suite.mockDB.On("Query", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "FROM share_links") && contains(sql, "WHERE note_id")
	}), suite.noteID).Return(mockRows, nil)

	mockRows.On("Next").Return(false)

	req := httptest.NewRequest("GET", "/notes/"+suite.noteID.String()+"/share-links", nil)
	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(200, resp.StatusCode)

	var result map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	suite.NoError(err)
	suite.NotNil(result["share_links"])
}

func (suite *ShareLinksHandlerTestSuite) TestRevokeShareLink_Success() {
	app := fiber.New()
	app.Delete("/share-links/:token", func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.userID)
		return suite.handler.RevokeShareLink(c)
	})

	token := "test-token-123"

	// Mock update query
	suite.mockDB.On("Exec", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "UPDATE share_links") && contains(sql, "SET is_active")
	}), token, suite.userID).Return(int64(1), nil)

	req := httptest.NewRequest("DELETE", "/share-links/"+token, nil)
	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(200, resp.StatusCode)

	var result map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	suite.NoError(err)
	suite.Contains(result, "message")
}

func (suite *ShareLinksHandlerTestSuite) TestRevokeShareLink_NotFound() {
	app := fiber.New()
	app.Delete("/share-links/:token", func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.userID)
		return suite.handler.RevokeShareLink(c)
	})

	token := "test-token-123"

	// Mock update query with no rows affected
	suite.mockDB.On("Exec", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "UPDATE share_links")
	}), token, suite.userID).Return(int64(0), nil)

	req := httptest.NewRequest("DELETE", "/share-links/"+token, nil)
	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(404, resp.StatusCode)
}

func TestShareLinksHandlerTestSuite(t *testing.T) {
	suite.Run(t, new(ShareLinksHandlerTestSuite))
}
