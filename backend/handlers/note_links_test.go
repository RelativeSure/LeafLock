package handlers

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
)

// NoteLinksHandlerTestSuite tests NoteLinksHandler
type NoteLinksHandlerTestSuite struct {
	suite.Suite
	handler *NoteLinksHandler
	mockDB  *MockDB
	userID  uuid.UUID
	noteID  uuid.UUID
}

func (suite *NoteLinksHandlerTestSuite) SetupTest() {
	suite.mockDB = &MockDB{}
	suite.handler = NewNoteLinksHandler(suite.mockDB)
	suite.userID = uuid.New()
	suite.noteID = uuid.New()
}

func (suite *NoteLinksHandlerTestSuite) TestNewNoteLinksHandler() {
	handler := NewNoteLinksHandler(suite.mockDB)
	suite.NotNil(handler)
	suite.Equal(suite.mockDB, handler.db)
}

func (suite *NoteLinksHandlerTestSuite) TestCreateNoteLink_InvalidBody() {
	app := fiber.New()
	app.Post("/notes/:id/links", func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.userID)
		return suite.handler.CreateNoteLink(c)
	})

	req := httptest.NewRequest("POST", "/notes/"+suite.noteID.String()+"/links", bytes.NewBufferString(`invalid`))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(400, resp.StatusCode)
}

func (suite *NoteLinksHandlerTestSuite) TestCreateNoteLink_InvalidSourceNoteID() {
	app := fiber.New()
	app.Post("/notes/:id/links", func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.userID)
		return suite.handler.CreateNoteLink(c)
	})

	reqBody := `{"target_note_id":"valid-uuid","link_text":"test"}`
	req := httptest.NewRequest("POST", "/notes/invalid-uuid/links", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(400, resp.StatusCode)
}

func (suite *NoteLinksHandlerTestSuite) TestCreateNoteLink_InvalidTargetNoteID() {
	app := fiber.New()
	app.Post("/notes/:id/links", func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.userID)
		return suite.handler.CreateNoteLink(c)
	})

	reqBody := `{"target_note_id":"invalid-uuid","link_text":"test"}`
	req := httptest.NewRequest("POST", "/notes/"+suite.noteID.String()+"/links", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(400, resp.StatusCode)
}

func (suite *NoteLinksHandlerTestSuite) TestCreateNoteLink_SourceNoteNotFound() {
	app := fiber.New()
	app.Post("/notes/:id/links", func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.userID)
		return suite.handler.CreateNoteLink(c)
	})

	targetNoteID := uuid.New()
	reqBody := `{"target_note_id":"` + targetNoteID.String() + `","link_text":"test"}`
	req := httptest.NewRequest("POST", "/notes/"+suite.noteID.String()+"/links", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")

	mockRow := &MockRow{}
	suite.mockDB.On("QueryRow", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "SELECT w.owner_id") && contains(sql, "FROM notes n")
	}), suite.noteID).Return(mockRow)

	mockRow.On("Scan", mock.Anything).Return(pgx.ErrNoRows)

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(404, resp.StatusCode)
}

func (suite *NoteLinksHandlerTestSuite) TestCreateNoteLink_Success() {
	app := fiber.New()
	app.Post("/notes/:id/links", func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.userID)
		return suite.handler.CreateNoteLink(c)
	})

	targetNoteID := uuid.New()
	reqBody := `{"target_note_id":"` + targetNoteID.String() + `","link_text":"test link"}`
	req := httptest.NewRequest("POST", "/notes/"+suite.noteID.String()+"/links", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")

	// Mock source note check
	mockSourceRow := &MockRow{}
	suite.mockDB.On("QueryRow", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "SELECT w.owner_id") && contains(sql, "FROM notes n")
	}), suite.noteID).Return(mockSourceRow)

	mockSourceRow.On("Scan", mock.Anything).Run(func(args mock.Arguments) {
		if id, ok := args[0].(*uuid.UUID); ok {
			*id = suite.userID
		}
	}).Return(nil)

	// Mock target note check
	mockTargetRow := &MockRow{}
	suite.mockDB.On("QueryRow", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "SELECT w.owner_id") && contains(sql, "FROM notes n")
	}), targetNoteID).Return(mockTargetRow)

	mockTargetRow.On("Scan", mock.Anything).Run(func(args mock.Arguments) {
		if id, ok := args[0].(*uuid.UUID); ok {
			*id = suite.userID
		}
	}).Return(nil)

	// Mock link creation
	linkID := uuid.New()
	mockInsertRow := &MockRow{}
	suite.mockDB.On("QueryRow", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "INSERT INTO note_links")
	}), suite.noteID, targetNoteID, "test link").Return(mockInsertRow)

	mockInsertRow.On("Scan", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		if id, ok := args[0].(*uuid.UUID); ok {
			*id = linkID
		}
	}).Return(nil)

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(200, resp.StatusCode)

	var result map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	suite.NoError(err)
	suite.Equal(linkID.String(), result["id"].(string))
}

func (suite *NoteLinksHandlerTestSuite) TestGetNoteLinks_InvalidNoteID() {
	app := fiber.New()
	app.Get("/notes/:id/links", func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.userID)
		return suite.handler.GetNoteLinks(c)
	})

	req := httptest.NewRequest("GET", "/notes/invalid-uuid/links", nil)
	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(400, resp.StatusCode)
}

func (suite *NoteLinksHandlerTestSuite) TestGetNoteLinks_NoteNotFound() {
	app := fiber.New()
	app.Get("/notes/:id/links", func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.userID)
		return suite.handler.GetNoteLinks(c)
	})

	req := httptest.NewRequest("GET", "/notes/"+suite.noteID.String()+"/links", nil)

	mockRow := &MockRow{}
	suite.mockDB.On("QueryRow", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "SELECT w.owner_id")
	}), suite.noteID).Return(mockRow)

	mockRow.On("Scan", mock.Anything).Return(pgx.ErrNoRows)

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(404, resp.StatusCode)
}

func TestNoteLinksHandlerTestSuite(t *testing.T) {
	suite.Run(t, new(NoteLinksHandlerTestSuite))
}
