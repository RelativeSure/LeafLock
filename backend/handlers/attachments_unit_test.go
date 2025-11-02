package handlers

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http/httptest"
	"net/textproto"
	"strconv"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"leaflock/crypto"
)

func TestAttachmentsHandler_UploadAttachmentSuccess(t *testing.T) {
	mockDB := new(MockDB)
	cryptoSvc := crypto.NewCryptoService(make([]byte, 32))
	handler := NewAttachmentsHandler(mockDB, cryptoSvc)

	userID := uuid.New()
	noteID := uuid.New()

	existsRow := new(MockRow)
	existsRow.On("Scan", mock.AnythingOfType("*bool")).Run(func(args mock.Arguments) {
		*(args[0].(*bool)) = true
	}).Return(nil).Once()

	mockDB.On("QueryRow",
		mock.Anything,
		mock.Anything,
		noteID, userID,
	).Return(existsRow).Once()

	mockDB.On("Exec",
		mock.AnythingOfType("*fasthttp.RequestCtx"),
		mock.AnythingOfType("string"),
		mock.AnythingOfType("uuid.UUID"),
		mock.AnythingOfType("uuid.UUID"),
		mock.Anything,
		mock.Anything,
		mock.AnythingOfType("string"),
		mock.AnythingOfType("int64"),
		mock.Anything,
		mock.AnythingOfType("uuid.UUID"),
	).Return(int64(1), nil).Maybe()

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	header := textproto.MIMEHeader{}
	header.Set("Content-Disposition", `form-data; name="file"; filename="example.txt"`)
	header.Set("Content-Type", "text/plain")
	part, err := writer.CreatePart(header)
	require.NoError(t, err)
	_, err = part.Write([]byte("sample content"))
	require.NoError(t, err)
	require.NoError(t, writer.Close())

	app := fiber.New()
	app.Post("/notes/:noteId/attachments", func(c *fiber.Ctx) error {
		c.Locals("user_id", userID)
		return handler.UploadAttachment(c)
	})

	req := httptest.NewRequest("POST", "/notes/"+noteID.String()+"/attachments", &buf)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Content-Length", strconv.Itoa(buf.Len()))

	resp, err := app.Test(req)
	require.NoError(t, err)
	if !assert.Equal(t, fiber.StatusOK, resp.StatusCode) {
		var payload map[string]interface{}
		_ = json.NewDecoder(resp.Body).Decode(&payload)
		t.Fatalf("upload failed: %v", payload)
	}

	mockDB.AssertExpectations(t)
}

func TestAttachmentsHandler_GetAttachmentsSuccess(t *testing.T) {
	mockDB := new(MockDB)
	cryptoSvc := crypto.NewCryptoService(make([]byte, 32))
	handler := NewAttachmentsHandler(mockDB, cryptoSvc)

	userID := uuid.New()
	noteID := uuid.New()

	existsRow := new(MockRow)
	existsRow.On("Scan", mock.AnythingOfType("*bool")).Run(func(args mock.Arguments) {
		*(args[0].(*bool)) = true
	}).Return(nil).Once()

	encryptedName, err := cryptoSvc.Encrypt([]byte("example.txt"))
	require.NoError(t, err)

	rows := new(MockRows)
	rows.On("Next").Return(true).Once()
	rows.On("Next").Return(false).Once()
	rows.On("Scan", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			*(args[0].(*uuid.UUID)) = uuid.New()
			*(args[1].(*[]byte)) = encryptedName
			*(args[2].(*string)) = "text/plain"
			*(args[3].(*int64)) = 42
			*(args[4].(*time.Time)) = time.Now().UTC()
		}).Return(nil).Once()

	mockDB.On("QueryRow", mock.Anything, mock.Anything, noteID, userID).
		Return(existsRow).Once()
	mockDB.On("Query", mock.Anything, mock.Anything, noteID).Return(rows, nil).Once()

	app := fiber.New()
	app.Get("/notes/:noteId/attachments", func(c *fiber.Ctx) error {
		c.Locals("user_id", userID)
		return handler.GetAttachments(c)
	})

	resp, err := app.Test(httptest.NewRequest("GET", "/notes/"+noteID.String()+"/attachments", nil))
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	var attachments []AttachmentResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&attachments))
	assert.Len(t, attachments, 1)
	assert.Equal(t, "example.txt", attachments[0].Filename)

	mockDB.AssertExpectations(t)
	rows.AssertExpectations(t)
}

func TestAttachmentsHandler_DownloadAttachmentSuccess(t *testing.T) {
	mockDB := new(MockDB)
	cryptoSvc := crypto.NewCryptoService(make([]byte, 32))
	handler := NewAttachmentsHandler(mockDB, cryptoSvc)

	userID := uuid.New()
	noteID := uuid.New()
	attachmentID := uuid.New()

	encryptedName, err := cryptoSvc.Encrypt([]byte("download.txt"))
	require.NoError(t, err)
	encryptedContent, err := cryptoSvc.Encrypt([]byte("file-data"))
	require.NoError(t, err)

	row := new(MockRow)
	row.On("Scan", mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			*(args[0].(*[]byte)) = encryptedName
			*(args[1].(*[]byte)) = encryptedContent
			*(args[2].(*string)) = "text/plain"
		}).Return(nil).Once()

	mockDB.On("QueryRow", mock.Anything, mock.Anything, attachmentID, noteID, userID).
		Return(row).Once()

	app := fiber.New()
	app.Get("/notes/:noteId/attachments/:attachmentId", func(c *fiber.Ctx) error {
		c.Locals("user_id", userID)
		return handler.DownloadAttachment(c)
	})

	resp, err := app.Test(httptest.NewRequest("GET", "/notes/"+noteID.String()+"/attachments/"+attachmentID.String(), nil))
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	assert.Equal(t, "attachment; filename=\"download.txt\"", resp.Header.Get("Content-Disposition"))

	downloaded, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "file-data", string(downloaded))

	mockDB.AssertExpectations(t)
	row.AssertExpectations(t)
}

func TestAttachmentsHandler_DeleteAttachmentSuccess(t *testing.T) {
	mockDB := new(MockDB)
	handler := NewAttachmentsHandler(mockDB, crypto.NewCryptoService(make([]byte, 32)))

	userID := uuid.New()
	noteID := uuid.New()
	attachmentID := uuid.New()

	mockDB.On("Exec", mock.Anything, mock.Anything, attachmentID, noteID, userID).Return(int64(1), nil).Once()

	app := fiber.New()
	app.Delete("/notes/:noteId/attachments/:attachmentId", func(c *fiber.Ctx) error {
		c.Locals("user_id", userID)
		return handler.DeleteAttachment(c)
	})

	resp, err := app.Test(httptest.NewRequest("DELETE", "/notes/"+noteID.String()+"/attachments/"+attachmentID.String(), nil))
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	mockDB.AssertExpectations(t)
}
