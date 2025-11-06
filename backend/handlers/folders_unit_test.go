package handlers

import (
	"bytes"
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

func TestFoldersHandler_GetFoldersSuccess(t *testing.T) {
	mockDB := new(MockDB)
	cryptoSvc := crypto.NewCryptoService(make([]byte, 32))
	handler := NewFoldersHandler(mockDB, cryptoSvc)

	userID := uuid.New()
	parentID := uuid.New()

	encryptedParentName, err := cryptoSvc.Encrypt([]byte("Parent"))
	require.NoError(t, err)
	encryptedChildName, err := cryptoSvc.Encrypt([]byte("Child"))
	require.NoError(t, err)

	parentPointer := parentID

	rows := new(MockRows)
	rows.On("Next").Return(true).Once()
	rows.On("Next").Return(true).Once()
	rows.On("Next").Return(false).Once()

	call := 0
	rows.On("Scan", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			call++
			idPtr := args[0].(*uuid.UUID)
			parentPtrPtr := args[1].(**uuid.UUID)
			nameEnc := args[2].(*[]byte)
			color := args[3].(*string)
			position := args[4].(*int)
			depth := args[5].(*int)
			path := args[6].(*string)
			created := args[7].(*time.Time)
			updated := args[8].(*time.Time)

			*color = "#abcdef"
			*position = call
			*depth = 0
			*path = "/"
			*created = time.Now().UTC()
			*updated = time.Now().UTC()

			switch call {
			case 1:
				*idPtr = parentID
				*parentPtrPtr = nil
				*nameEnc = encryptedParentName
			default:
				*idPtr = uuid.New()
				*parentPtrPtr = &parentPointer
				*nameEnc = encryptedChildName
			}
		}).Return(nil).Twice()

	mockDB.On("Query",
		mock.Anything,
		mock.MatchedBy(func(query string) bool { return true }),
		userID,
	).Return(rows, nil).Once()

	app := fiber.New()
	app.Get("/folders", func(c *fiber.Ctx) error {
		c.Locals("user_id", userID)
		return handler.GetFolders(c)
	})

	resp, err := app.Test(httptest.NewRequest("GET", "/folders", nil))
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	var body map[string][]map[string]interface{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Len(t, body["folders"], 2)

	mockDB.AssertExpectations(t)
	rows.AssertExpectations(t)
}

func TestFoldersHandler_CreateFolderWithParent(t *testing.T) {
	mockDB := new(MockDB)
	cryptoSvc := crypto.NewCryptoService(make([]byte, 32))
	handler := NewFoldersHandler(mockDB, cryptoSvc)

	userID := uuid.New()
	parentID := uuid.New()
	folderID := uuid.New()

	parentRow := new(MockRow)
	parentRow.On("Scan", mock.AnythingOfType("*bool")).Run(func(args mock.Arguments) {
		*(args[0].(*bool)) = true
	}).Return(nil).Once()

	insertRow := new(MockRow)
	insertRow.On("Scan", mock.AnythingOfType("*uuid.UUID")).Run(func(args mock.Arguments) {
		*(args[0].(*uuid.UUID)) = folderID
	}).Return(nil).Once()

	mockDB.On("QueryRow",
		mock.Anything,
		mock.MatchedBy(func(query string) bool { return true }),
		parentID, userID,
	).Return(parentRow).Once()

	mockDB.On("QueryRow",
		mock.Anything,
		mock.MatchedBy(func(query string) bool { return true }),
		userID, mock.Anything, mock.Anything, mock.Anything, mock.Anything,
	).Return(insertRow).Once()

	app := fiber.New()
	app.Post("/folders", func(c *fiber.Ctx) error {
		c.Locals("user_id", userID)
		return handler.CreateFolder(c)
	})

	payload := map[string]interface{}{
		"name":      "Projects",
		"parent_id": parentID.String(),
		"color":     "#00ff00",
		"position":  2,
	}
	body, err := json.Marshal(payload)
	require.NoError(t, err)
	req := httptest.NewRequest("POST", "/folders", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	mockDB.AssertExpectations(t)
	parentRow.AssertExpectations(t)
	insertRow.AssertExpectations(t)
}

func TestFoldersHandler_CreateFolderInvalidParent(t *testing.T) {
	mockDB := new(MockDB)
	cryptoSvc := crypto.NewCryptoService(make([]byte, 32))
	handler := NewFoldersHandler(mockDB, cryptoSvc)

	userID := uuid.New()
	parentID := uuid.New()

	parentRow := new(MockRow)
	parentRow.On("Scan", mock.AnythingOfType("*bool")).Return(assert.AnError).Once()

	mockDB.On("QueryRow",
		mock.Anything,
		mock.MatchedBy(func(string) bool { return true }),
		parentID, userID,
	).Return(parentRow).Once()

	app := fiber.New()
	app.Post("/folders", func(c *fiber.Ctx) error {
		c.Locals("user_id", userID)
		return handler.CreateFolder(c)
	})

	payload := map[string]interface{}{
		"name":      "Invalid",
		"parent_id": parentID.String(),
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest("POST", "/folders", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)

	mockDB.AssertExpectations(t)
}

func TestFoldersHandler_DeleteFolder(t *testing.T) {
	mockDB := new(MockDB)
	handler := NewFoldersHandler(mockDB, crypto.NewCryptoService(make([]byte, 32)))

	userID := uuid.New()
	folderID := uuid.New()

	mockDB.On("Exec",
		mock.Anything,
		mock.MatchedBy(func(query string) bool { return true }),
		folderID, userID,
	).Return(int64(1), nil).Once()

	mockDB.On("Exec",
		mock.Anything,
		mock.MatchedBy(func(query string) bool { return true }),
		folderID, userID,
	).Return(int64(1), nil).Once()

	app := fiber.New()
	app.Delete("/folders/:id", func(c *fiber.Ctx) error {
		c.Locals("user_id", userID)
		return handler.DeleteFolder(c)
	})

	resp, err := app.Test(httptest.NewRequest("DELETE", "/folders/"+folderID.String(), nil))
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	mockDB.AssertExpectations(t)
}

func TestFoldersHandler_MoveNoteToFolder(t *testing.T) {
	mockDB := new(MockDB)
	handler := NewFoldersHandler(mockDB, crypto.NewCryptoService(make([]byte, 32)))

	userID := uuid.New()
	noteID := uuid.New()
	folderID := uuid.New()

	// Valid folder lookup
	folderRow := new(MockRow)
	folderRow.On("Scan", mock.AnythingOfType("*bool")).Run(func(args mock.Arguments) {
		*(args[0].(*bool)) = true
	}).Return(nil).Once()

	mockDB.On("QueryRow",
		mock.Anything,
		mock.MatchedBy(func(query string) bool { return true }),
		folderID, userID,
	).Return(folderRow).Once()

	mockDB.On("Exec",
		mock.Anything,
		mock.MatchedBy(func(query string) bool { return true }),
		mock.Anything,
		noteID,
		userID,
	).Return(int64(1), nil).Once()

	app := fiber.New()
	app.Post("/notes/:id/folder", func(c *fiber.Ctx) error {
		c.Locals("user_id", userID)
		return handler.MoveNoteToFolder(c)
	})

	payload := map[string]string{"folder_id": folderID.String()}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest("POST", "/notes/"+noteID.String()+"/folder", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	mockDB.AssertExpectations(t)
	folderRow.AssertExpectations(t)
}
