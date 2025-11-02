package handlers

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"leaflock/crypto"
)

func TestTagsHandler_GetTagsSuccess(t *testing.T) {
	mockDB := new(MockDB)
	cryptoSvc := crypto.NewCryptoService(make([]byte, 32))
	handler := NewTagsHandler(mockDB, cryptoSvc)

	userID := uuid.New()
	encName, err := cryptoSvc.Encrypt([]byte("Important"))
	require.NoError(t, err)

	rows := new(MockRows)
	rows.On("Next").Return(true).Once()
	rows.On("Next").Return(false).Once()
	rows.On("Scan", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			*(args[0].(*uuid.UUID)) = uuid.New()
			*(args[1].(*[]byte)) = encName
			*(args[2].(*string)) = "#ff0000"
			*(args[3].(*time.Time)) = time.Now().UTC()
			*(args[4].(*time.Time)) = time.Now().UTC()
		}).Return(nil).Once()

	mockDB.On("Query", mock.Anything, mock.Anything, userID).Return(rows, nil).Once()

	app := fiber.New()
	app.Get("/tags", func(c *fiber.Ctx) error {
		c.Locals("user_id", userID)
		return handler.GetTags(c)
	})

	resp, err := app.Test(httptest.NewRequest("GET", "/tags", nil))
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	var body map[string][]map[string]interface{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Len(t, body["tags"], 1)
	assert.Equal(t, "Important", body["tags"][0]["name"])

	mockDB.AssertExpectations(t)
	rows.AssertExpectations(t)
}

func TestTagsHandler_CreateTagSuccess(t *testing.T) {
	mockDB := new(MockDB)
	cryptoSvc := crypto.NewCryptoService(make([]byte, 32))
	handler := NewTagsHandler(mockDB, cryptoSvc)

	userID := uuid.New()
	tagID := uuid.New()

	insertRow := new(MockRow)
	insertRow.On("Scan", mock.AnythingOfType("*uuid.UUID")).Run(func(args mock.Arguments) {
		*(args[0].(*uuid.UUID)) = tagID
	}).Return(nil).Once()

	mockDB.On("QueryRow", mock.Anything, mock.Anything, userID, mock.Anything, mock.Anything, mock.Anything).
		Return(insertRow).Once()

	app := fiber.New()
	app.Post("/tags", func(c *fiber.Ctx) error {
		c.Locals("user_id", userID)
		return handler.CreateTag(c)
	})

	payload := map[string]string{"name": "Urgent", "color": "#123456"}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest("POST", "/tags", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusCreated, resp.StatusCode)

	mockDB.AssertExpectations(t)
	insertRow.AssertExpectations(t)
}

func TestTagsHandler_DeleteTagNotFound(t *testing.T) {
	mockDB := new(MockDB)
	handler := NewTagsHandler(mockDB, crypto.NewCryptoService(make([]byte, 32)))

	userID := uuid.New()
	tagID := uuid.New()

	mockDB.On("Exec", mock.Anything, mock.Anything, tagID, userID).Return(int64(0), nil).Once()

	app := fiber.New()
	app.Delete("/tags/:id", func(c *fiber.Ctx) error {
		c.Locals("user_id", userID)
		return handler.DeleteTag(c)
	})

	resp, err := app.Test(httptest.NewRequest("DELETE", "/tags/"+tagID.String(), nil))
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusNotFound, resp.StatusCode)
}

func TestTagsHandler_AssignTagToNote(t *testing.T) {
	mockDB := new(MockDB)
	handler := NewTagsHandler(mockDB, crypto.NewCryptoService(make([]byte, 32)))

	userID := uuid.New()
	noteID := uuid.New()
	tagID := uuid.New()

	existsRow := new(MockRow)
	existsRow.On("Scan", mock.AnythingOfType("*bool")).Run(func(args mock.Arguments) {
		*(args[0].(*bool)) = true
	}).Return(nil).Once()

	mockDB.On("QueryRow", mock.Anything, mock.Anything, tagID, userID).Return(existsRow).Once()
	mockDB.On("Exec", mock.Anything, mock.Anything, noteID, tagID).Return(int64(1), nil).Once()

	app := fiber.New()
	app.Post("/notes/:id/tags", func(c *fiber.Ctx) error {
		c.Locals("user_id", userID)
		return handler.AssignTagToNote(c)
	})

	payload := map[string]string{"tag_id": tagID.String()}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest("POST", "/notes/"+noteID.String()+"/tags", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)
}

func TestTagsHandler_GetNotesByTag(t *testing.T) {
	mockDB := new(MockDB)
	handler := NewTagsHandler(mockDB, crypto.NewCryptoService(make([]byte, 32)))

	userID := uuid.New()
	tagID := uuid.New()

	rows := new(MockRows)
	rows.On("Next").Return(true).Once()
	rows.On("Next").Return(false).Once()
	rows.On("Scan", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			*(args[0].(*uuid.UUID)) = uuid.New()
			*(args[1].(*[]byte)) = []byte("title-bytes")
			*(args[2].(*[]byte)) = []byte("content-bytes")
			*(args[3].(*time.Time)) = time.Now().UTC()
			*(args[4].(*time.Time)) = time.Now().UTC()
		}).Return(nil).Once()

	mockDB.On("Query", mock.Anything, mock.Anything, tagID, userID).Return(rows, nil).Once()

	app := fiber.New()
	app.Get("/tags/:id/notes", func(c *fiber.Ctx) error {
		c.Locals("user_id", userID)
		return handler.GetNotesByTag(c)
	})

	resp, err := app.Test(httptest.NewRequest("GET", "/tags/"+tagID.String()+"/notes", nil))
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	var body map[string][]map[string]interface{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Len(t, body["notes"], 1)
	encodedTitle := body["notes"][0]["title_encrypted"].(string)
	decoded, err := base64.StdEncoding.DecodeString(encodedTitle)
	require.NoError(t, err)
	assert.Equal(t, []byte("title-bytes"), decoded)

	mockDB.AssertExpectations(t)
	rows.AssertExpectations(t)
}
