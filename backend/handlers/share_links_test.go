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

	// Use longer timeout to accommodate Redis connection retries when Redis is unavailable
	// The handler gracefully handles Redis failures (logs warning but doesn't fail request)
	resp, err := app.Test(req, 10000) // 10 second timeout
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

func (suite *ShareLinksHandlerTestSuite) TestGetAllUserShareLinks() {
	app := fiber.New()
	app.Get("/share-links", func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.userID)
		return suite.handler.GetAllUserShareLinks(c)
	})

	titleEncrypted, err := suite.cryptoSvc.Encrypt([]byte("Shared Note"))
	suite.Require().NoError(err)

	linkID := uuid.New()
	token := "share-token"
	noteID := suite.noteID
	expiresAt := time.Now().Add(2 * time.Hour)
	lastAccessed := time.Now().Add(-time.Hour)
	maxUses := 5
	createdAt := time.Now().Add(-time.Minute)

	rows := &MockRows{}
	rows.On("Next").Return(true).Once()
	rows.On("Next").Return(false).Once()
	rows.On("Scan",
		mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything,
		mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything,
		mock.Anything, mock.Anything,
	).Run(func(args mock.Arguments) {
		if v, ok := args[0].(*uuid.UUID); ok {
			*v = linkID
		}
		if v, ok := args[1].(*string); ok {
			*v = token
		}
		if v, ok := args[2].(*uuid.UUID); ok {
			*v = noteID
		}
		if v, ok := args[3].(*[]byte); ok {
			*v = titleEncrypted
		}
		if v, ok := args[4].(*string); ok {
			*v = "read"
		}
		if v, ok := args[5].(**time.Time); ok {
			*v = &expiresAt
		}
		if v, ok := args[6].(**int); ok {
			*v = &maxUses
		}
		if v, ok := args[7].(*int); ok {
			*v = 1
		}
		if v, ok := args[8].(*bool); ok {
			*v = true
		}
		if v, ok := args[9].(*bool); ok {
			*v = true
		}
		if v, ok := args[10].(*time.Time); ok {
			*v = createdAt
		}
		if v, ok := args[11].(**time.Time); ok {
			*v = &lastAccessed
		}
	}).Return(nil).Once()

	suite.mockDB.On("Query", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "FROM share_links sl")
	}), suite.userID).Return(rows, nil).Once()

	req := httptest.NewRequest("GET", "/share-links", nil)
	req.Host = "example.com"

	resp, err := app.Test(req, -1)
	suite.Require().NoError(err)
	suite.Equal(200, resp.StatusCode)

	var payload map[string][]map[string]interface{}
	suite.Require().NoError(json.NewDecoder(resp.Body).Decode(&payload))
	links := payload["share_links"]
	suite.Require().Len(links, 1)
	suite.Equal("Shared Note", links[0]["note_title"])
	suite.Contains(links[0]["share_url"], token)
	suite.Equal(float64(maxUses), links[0]["max_uses"])
}

func (suite *ShareLinksHandlerTestSuite) TestGetNoteShareLinks() {
	app := fiber.New()
	app.Get("/notes/:id/share-links", func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.userID)
		return suite.handler.GetNoteShareLinks(c)
	})

	noteRow := &MockRow{}
	suite.mockDB.On("QueryRow", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "SELECT EXISTS")
	}), suite.noteID, suite.userID).Return(noteRow).Once()

	noteRow.On("Scan", mock.Anything).Run(func(args mock.Arguments) {
		if existsPtr, ok := args[0].(*bool); ok {
			*existsPtr = true
		}
	}).Return(nil).Once()

	createdAt := time.Now().Add(-time.Hour)
	expiresAt := time.Now().Add(time.Hour)
	lastAccessed := time.Now()
	linkID := uuid.New()

	rows := &MockRows{}
	rows.On("Next").Return(true).Once()
	rows.On("Next").Return(false).Once()
	rows.On("Scan",
		mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything,
		mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything,
	).Run(func(args mock.Arguments) {
		if v, ok := args[0].(*uuid.UUID); ok {
			*v = linkID
		}
		if v, ok := args[1].(*string); ok {
			*v = "token-note"
		}
		if v, ok := args[2].(*string); ok {
			*v = "read"
		}
		if v, ok := args[3].(**time.Time); ok {
			*v = &expiresAt
		}
		if v, ok := args[4].(**int); ok {
			max := 10
			*v = &max
		}
		if v, ok := args[5].(*int); ok {
			*v = 2
		}
		if v, ok := args[6].(*bool); ok {
			*v = true
		}
		if v, ok := args[7].(*bool); ok {
			*v = false
		}
		if v, ok := args[8].(*time.Time); ok {
			*v = createdAt
		}
		if v, ok := args[9].(**time.Time); ok {
			*v = &lastAccessed
		}
	}).Return(nil).Once()

	suite.mockDB.On("Query", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "FROM share_links")
	}), suite.noteID).Return(rows, nil).Once()

	req := httptest.NewRequest("GET", "/notes/"+suite.noteID.String()+"/share-links", nil)
	req.Host = "example.com"

	resp, err := app.Test(req, -1)
	suite.Require().NoError(err)
	suite.Equal(200, resp.StatusCode)

	var payload map[string][]map[string]interface{}
	suite.Require().NoError(json.NewDecoder(resp.Body).Decode(&payload))
	links := payload["share_links"]
	suite.Require().Len(links, 1)
	suite.Equal(linkID.String(), links[0]["id"])
	suite.Contains(links[0]["share_url"], "token-note")
}

func (suite *ShareLinksHandlerTestSuite) TestGetSharedNote() {
	app := fiber.New()
	app.Get("/share/:token", func(c *fiber.Ctx) error {
		c.Locals("share_link_note_id", suite.noteID)
		c.Locals("share_link_permission", "read")
		return suite.handler.GetSharedNote(c)
	})

	titleEnc := []byte("encrypted-title")
	contentEnc := []byte("encrypted-content")
	createdAt := time.Now().Add(-time.Hour)
	updatedAt := time.Now()
	creatorID := uuid.New()

	noteRow := &MockRow{}
	suite.mockDB.On("QueryRow", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "FROM notes")
	}), suite.noteID).Return(noteRow).Once()

	noteRow.On("Scan", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		if v, ok := args[0].(*[]byte); ok {
			*v = titleEnc
		}
		if v, ok := args[1].(*[]byte); ok {
			*v = contentEnc
		}
		if v, ok := args[2].(*time.Time); ok {
			*v = createdAt
		}
		if v, ok := args[3].(*time.Time); ok {
			*v = updatedAt
		}
		if v, ok := args[4].(*uuid.UUID); ok {
			*v = creatorID
		}
	}).Return(nil).Once()

	emailRow := &MockRow{}
	suite.mockDB.On("QueryRow", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "FROM users")
	}), creatorID).Return(emailRow).Once()

	emailRow.On("Scan", mock.Anything).Run(func(args mock.Arguments) {
		if emailPtr, ok := args[0].(*string); ok {
			*emailPtr = "owner@example.com"
		}
	}).Return(nil).Once()

	req := httptest.NewRequest("GET", "/share/token123", nil)
	req.Host = "example.com"

	resp, err := app.Test(req, -1)
	suite.Require().NoError(err)
	suite.Equal(200, resp.StatusCode)

	var payload map[string]interface{}
	suite.Require().NoError(json.NewDecoder(resp.Body).Decode(&payload))
	suite.Equal(suite.noteID.String(), payload["id"])
	suite.Equal("read", payload["permission"])
	suite.Equal("owner@example.com", payload["shared_by"])
	suite.Equal(true, payload["is_shared_access"])
}

func (suite *ShareLinksHandlerTestSuite) TestRevokeShareLinkSuccess() {
	app := fiber.New()
	app.Delete("/share-links/:token", func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.userID)
		return suite.handler.RevokeShareLink(c)
	})

	suite.mockDB.On("Exec", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "UPDATE share_links")
	}), "token123", suite.userID).Return(int64(1), nil).Once()

	req := httptest.NewRequest("DELETE", "/share-links/token123", nil)
	resp, err := app.Test(req, -1)
	suite.Require().NoError(err)
	suite.Equal(200, resp.StatusCode)

	var payload map[string]interface{}
	suite.Require().NoError(json.NewDecoder(resp.Body).Decode(&payload))
	suite.Equal("Share link revoked successfully", payload["message"])
}

func (suite *ShareLinksHandlerTestSuite) TestUpdateShareLinkSuccess() {
	app := fiber.New()
	app.Put("/share-links/:token", func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.userID)
		return suite.handler.UpdateShareLink(c)
	})

	suite.mockDB.On("Exec", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "UPDATE share_links")
	}), "update-token", suite.userID, mock.Anything, "write").Return(int64(1), nil).Once()

	reqBody := `{"expires_in":"1h","permission":"write"}`
	req := httptest.NewRequest("PUT", "/share-links/update-token", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req, -1)
	suite.Require().NoError(err)
	suite.Equal(200, resp.StatusCode)

	var payload map[string]interface{}
	suite.Require().NoError(json.NewDecoder(resp.Body).Decode(&payload))
	suite.Equal("Share link updated successfully", payload["message"])
}

func TestParseDuration(t *testing.T) {
	cases := map[string]time.Duration{
		"1h":  time.Hour,
		"24h": 24 * time.Hour,
		"7d":  7 * 24 * time.Hour,
		"30d": 30 * 24 * time.Hour,
	}

	for input, expected := range cases {
		dur, err := parseDuration(input)
		if err != nil {
			t.Fatalf("expected no error for %s, got %v", input, err)
		}
		if dur != expected {
			t.Fatalf("unexpected duration for %s: %v", input, dur)
		}
	}

	if _, err := parseDuration("invalid"); err == nil {
		t.Fatalf("expected error for invalid duration")
	}
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
	// Use longer timeout to accommodate Redis connection retries when Redis is unavailable
	// The handler gracefully handles Redis failures (logs warning but doesn't fail request)
	resp, err := app.Test(req, 10000) // 10 second timeout
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
