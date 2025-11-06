package handlers

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http/httptest"
	"net/textproto"
	"strconv"
	"strings"
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
	).Return(int64(1), nil).Once()

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

func TestAttachmentsHandler_UploadAttachment_MismatchedContentType(t *testing.T) {
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

	// Prepare PNG content while declaring text/plain
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	header := textproto.MIMEHeader{}
	header.Set("Content-Disposition", `form-data; name="file"; filename="example.png"`)
	header.Set("Content-Type", "text/plain")
	part, err := writer.CreatePart(header)
	require.NoError(t, err)

	pngHeader := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	_, err = part.Write(append(pngHeader, []byte("rest")...))
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
	assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)

	var payload map[string]string
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&payload))
	assert.Equal(t, "file type does not match content", payload["error"])

	mockDB.AssertExpectations(t)
}

func TestAttachmentsHandler_UploadAttachment_UnsupportedType(t *testing.T) {
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

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	header := textproto.MIMEHeader{}
	header.Set("Content-Disposition", `form-data; name="file"; filename="malicious.exe"`)
	header.Set("Content-Type", "application/x-msdownload")
	part, err := writer.CreatePart(header)
	require.NoError(t, err)
	_, err = part.Write([]byte("MZ"))
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
	assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)

	var payload map[string]string
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&payload))
	assert.Equal(t, "File type not allowed", payload["error"])

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

// TestSanitizeFilename tests the filename sanitization function for security vulnerabilities
func TestSanitizeFilename(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
		reason   string
	}{
		{
			name:     "Normal filename",
			input:    "document.pdf",
			expected: "document.pdf",
			reason:   "Normal filenames should pass through unchanged",
		},
		{
			name:     "Newline injection attack",
			input:    "malicious.txt\r\nX-Evil-Header: value",
			expected: "malicious.txtX-Evil-Header: value",
			reason:   "Newlines should be stripped to prevent header injection",
		},
		{
			name:     "Carriage return attack",
			input:    "file.pdf\rContent-Type: text/html",
			expected: "html",
			reason:   "Carriage returns are path separators on some systems - filepath.Base takes last component",
		},
		{
			name:     "Null byte injection",
			input:    "file.pdf\x00.exe",
			expected: "file.pdf.exe",
			reason:   "Null bytes should be stripped",
		},
		{
			name:     "Control characters",
			input:    "file\x01\x02\x03.txt",
			expected: "file.txt",
			reason:   "Control characters should be stripped",
		},
		{
			name:     "Path traversal attempt",
			input:    "../../etc/passwd",
			expected: "passwd",
			reason:   "Path components should be removed",
		},
		{
			name:     "Windows path",
			input:    "C:\\Windows\\System32\\evil.exe",
			expected: "C:WindowsSystem32evil.exe",
			reason:   "Backslashes are stripped but filepath.Base only works for OS-specific paths",
		},
		{
			name:     "Double quotes",
			input:    "file\"with\"quotes.txt",
			expected: "filewithquotes.txt",
			reason:   "Double quotes should be stripped to prevent escaping",
		},
		{
			name:     "Backslashes",
			input:    "file\\with\\backslashes.txt",
			expected: "filewithbackslashes.txt",
			reason:   "Backslashes are stripped to prevent escaping",
		},
		{
			name:     "Very long filename",
			input:    string(make([]byte, 300)),
			expected: "download",
			reason:   "Very long filename with null bytes becomes empty after sanitization",
		},
		{
			name:     "Empty filename",
			input:    "",
			expected: "download",
			reason:   "Empty filename gets default name",
		},
		{
			name:     "Only control characters",
			input:    "\x00\x01\x02\x03",
			expected: "download",
			reason:   "Filename with only control characters should get default name",
		},
		{
			name:     "Unicode characters",
			input:    "文档.pdf",
			expected: "文档.pdf",
			reason:   "Unicode characters should be preserved",
		},
		{
			name:     "Mixed attack vectors",
			input:    "../../\r\nmalicious\x00.txt",
			expected: "malicious.txt",
			reason:   "Multiple attack vectors should all be sanitized",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeFilename(tt.input)
			assert.Equal(t, tt.expected, result, tt.reason)
		})
	}
}

// TestDownloadAttachment_FilenameInjection tests that filename injection is prevented
func TestDownloadAttachment_FilenameInjection(t *testing.T) {
	mockDB := new(MockDB)
	cryptoSvc := crypto.NewCryptoService(make([]byte, 32))
	handler := NewAttachmentsHandler(mockDB, cryptoSvc)

	userID := uuid.New()
	noteID := uuid.New()
	attachmentID := uuid.New()

	// Malicious filename with header injection attempt
	maliciousFilename := "file.txt\r\nX-Evil-Header: malicious\r\n\r\n<script>alert(1)</script>"
	encryptedName, err := cryptoSvc.Encrypt([]byte(maliciousFilename))
	require.NoError(t, err)
	encryptedContent, err := cryptoSvc.Encrypt([]byte("content"))
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

	// Verify that the Content-Disposition header does NOT contain the malicious content
	contentDisposition := resp.Header.Get("Content-Disposition")
	assert.NotContains(t, contentDisposition, "\r\n", "Header should not contain CRLF")
	assert.NotContains(t, contentDisposition, "X-Evil-Header", "Header should not contain injected headers")

	// After sanitization, the dangerous characters are removed
	// The result should be a safe filename (even if it's not the original)
	assert.True(t, strings.HasPrefix(contentDisposition, "attachment; filename=\""), "Should have proper header format")
	assert.NotContains(t, contentDisposition, "\n", "Should not contain newlines")
	assert.NotContains(t, contentDisposition, "\r", "Should not contain carriage returns")

	mockDB.AssertExpectations(t)
	row.AssertExpectations(t)
}
