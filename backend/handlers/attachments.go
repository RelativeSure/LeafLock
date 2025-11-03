package handlers

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"leaflock/crypto"
	"leaflock/database"
)

// Attachments Handler
type AttachmentsHandler struct {
	db     database.Database
	crypto *crypto.CryptoService
}

var allowedAttachmentMIMEs = map[string]bool{
	"image/jpeg":      true,
	"image/png":       true,
	"image/gif":       true,
	"image/webp":      true,
	"text/plain":      true,
	"text/markdown":   true,
	"application/pdf": true,
}

var (
	errUnsupportedAttachmentType = errors.New("File content type not allowed")
	errAttachmentTypeMismatch    = errors.New("File type does not match content")
	errAttachmentEmptyFile       = errors.New("File is empty")
)

// NewAttachmentsHandler creates an attachments handler.
func NewAttachmentsHandler(db database.Database, cryptoService *crypto.CryptoService) *AttachmentsHandler {
	return &AttachmentsHandler{db: db, crypto: cryptoService}
}

// sanitizeFilename removes dangerous characters from filenames to prevent header injection
func sanitizeFilename(filename string) string {
	// If empty, return default immediately
	if strings.TrimSpace(filename) == "" {
		return "download"
	}

	// Remove path components (security: prevent directory traversal)
	filename = filepath.Base(filename)

	// Remove control characters, newlines, and dangerous characters
	// This prevents HTTP header injection attacks
	filename = strings.Map(func(r rune) rune {
		// Remove control characters (0-31, 127)
		if r < 32 || r == 127 {
			return -1
		}
		// Remove characters that could break HTTP headers
		if r == '"' || r == '\\' || r == '\r' || r == '\n' {
			return -1
		}
		return r
	}, filename)

	// Limit length to prevent buffer issues
	const maxFilenameLength = 255
	if len(filename) > maxFilenameLength {
		filename = filename[:maxFilenameLength]
	}

	// If filename becomes empty after sanitization, use a default
	if strings.TrimSpace(filename) == "" || filename == "." || filename == ".." {
		filename = "download"
	}

	return filename
}

type AttachmentUploadRequest struct {
	NoteID   string `json:"note_id" validate:"required,uuid"`
	Filename string `json:"filename" validate:"required"`
	MimeType string `json:"mime_type"`
}

type AttachmentResponse struct {
	ID          string `json:"id"`
	NoteID      string `json:"note_id"`
	Filename    string `json:"filename"`
	MimeType    string `json:"mime_type"`
	SizeBytes   int64  `json:"size_bytes"`
	CreatedAt   string `json:"created_at"`
	DownloadURL string `json:"download_url"`
}

// Upload attachment to a note
func (h *AttachmentsHandler) UploadAttachment(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	noteID := c.Params("noteId")

	// Validate note ID
	noteUUID, err := uuid.Parse(noteID)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid note ID"})
	}

	// Verify user owns the note
	var noteExists bool
	err = h.db.QueryRow(c.Context(),
		"SELECT EXISTS(SELECT 1 FROM notes WHERE id = $1 AND user_id = $2)",
		noteUUID, userID).Scan(&noteExists)
	if err != nil || !noteExists {
		return c.Status(404).JSON(fiber.Map{"error": "Note not found"})
	}

	// Get uploaded file
	file, err := c.FormFile("file")
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "No file uploaded"})
	}

	// Security: Validate file size (10MB limit)
	const maxFileSize = 10 * 1024 * 1024 // 10MB
	if file.Size > maxFileSize {
		return c.Status(400).JSON(fiber.Map{"error": "File too large. Maximum size is 10MB"})
	}

	// Security: Validate file type
	if contentType := file.Header.Get("Content-Type"); contentType != "" && !allowedAttachmentMIMEs[contentType] {
		return c.Status(400).JSON(fiber.Map{"error": "File type not allowed"})
	}

	// Read file content
	fileContent, err := file.Open()
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to read file"})
	}
	defer func() {
		_ = fileContent.Close() // Best effort cleanup
	}()

	content, err := io.ReadAll(fileContent)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to read file content"})
	}

	mimeType, err := resolveAttachmentMIME(content, file.Header.Get("Content-Type"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": err.Error()})
	}

	// Calculate checksum
	hash := sha256.Sum256(content)

	// Encrypt filename and content
	encryptedFilename, err := h.crypto.Encrypt([]byte(file.Filename))
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to encrypt filename"})
	}

	encryptedContent, err := h.crypto.Encrypt(content)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to encrypt file content"})
	}

	// Save to database
	attachmentID := uuid.New()
	_, err = h.db.Exec(c.Context(), `
		INSERT INTO attachments (id, note_id, filename_encrypted, content_encrypted, mime_type, size_bytes, checksum, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		attachmentID, noteUUID, encryptedFilename, encryptedContent, mimeType, file.Size, hash[:], userID)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to save attachment"})
	}

	return c.JSON(AttachmentResponse{
		ID:          attachmentID.String(),
		NoteID:      noteID,
		Filename:    file.Filename,
		MimeType:    mimeType,
		SizeBytes:   file.Size,
		CreatedAt:   time.Now().Format(time.RFC3339),
		DownloadURL: "/api/v1/notes/" + noteID + "/attachments/" + attachmentID.String(),
	})
}

// Get attachments for a note
func (h *AttachmentsHandler) GetAttachments(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	noteID := c.Params("noteId")

	noteUUID, err := uuid.Parse(noteID)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid note ID"})
	}

	// Verify user owns the note
	var noteExists bool
	err = h.db.QueryRow(c.Context(),
		"SELECT EXISTS(SELECT 1 FROM notes WHERE id = $1 AND user_id = $2)",
		noteUUID, userID).Scan(&noteExists)
	if err != nil || !noteExists {
		return c.Status(404).JSON(fiber.Map{"error": "Note not found"})
	}

	rows, err := h.db.Query(c.Context(), `
		SELECT id, filename_encrypted, mime_type, size_bytes, created_at
		FROM attachments
		WHERE note_id = $1
		ORDER BY created_at DESC`, noteUUID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to fetch attachments"})
	}
	defer rows.Close()

	var attachments []AttachmentResponse
	for rows.Next() {
		var id uuid.UUID
		var encryptedFilename []byte
		var mimeType string
		var sizeBytes int64
		var createdAt time.Time

		err := rows.Scan(&id, &encryptedFilename, &mimeType, &sizeBytes, &createdAt)
		if err != nil {
			continue
		}

		// Decrypt filename
		filenameBytes, err := h.crypto.Decrypt(encryptedFilename)
		if err != nil {
			continue
		}

		attachments = append(attachments, AttachmentResponse{
			ID:          id.String(),
			NoteID:      noteID,
			Filename:    string(filenameBytes),
			MimeType:    mimeType,
			SizeBytes:   sizeBytes,
			CreatedAt:   createdAt.Format(time.RFC3339),
			DownloadURL: "/api/v1/notes/" + noteID + "/attachments/" + id.String(),
		})
	}

	return c.JSON(attachments)
}

// Download attachment
func (h *AttachmentsHandler) DownloadAttachment(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	noteID := c.Params("noteId")
	attachmentID := c.Params("attachmentId")

	noteUUID, err := uuid.Parse(noteID)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid note ID"})
	}

	attachmentUUID, err := uuid.Parse(attachmentID)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid attachment ID"})
	}

	// Verify user owns the note and attachment exists
	var encryptedFilename, encryptedContent []byte
	var mimeType string
	err = h.db.QueryRow(c.Context(), `
		SELECT a.filename_encrypted, a.content_encrypted, a.mime_type
		FROM attachments a
		JOIN notes n ON a.note_id = n.id
		WHERE a.id = $1 AND a.note_id = $2 AND n.user_id = $3`,
		attachmentUUID, noteUUID, userID).Scan(&encryptedFilename, &encryptedContent, &mimeType)

	if err != nil {
		if err == pgx.ErrNoRows {
			return c.Status(404).JSON(fiber.Map{"error": "Attachment not found"})
		}
		return c.Status(500).JSON(fiber.Map{"error": "Failed to fetch attachment"})
	}

	// Decrypt filename and content
	filenameBytes, err := h.crypto.Decrypt(encryptedFilename)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to decrypt filename"})
	}

	content, err := h.crypto.Decrypt(encryptedContent)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to decrypt file content"})
	}

	filename := string(filenameBytes)

	// Security: Sanitize filename to prevent header injection attacks
	safeFilename := sanitizeFilename(filename)

	// Set appropriate headers
	c.Set("Content-Type", mimeType)
	c.Set("Content-Disposition", "attachment; filename=\""+safeFilename+"\"")
	c.Set("Content-Length", strconv.Itoa(len(content)))

	return c.Send(content)
}

// Delete attachment
func (h *AttachmentsHandler) DeleteAttachment(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	noteID := c.Params("noteId")
	attachmentID := c.Params("attachmentId")

	noteUUID, err := uuid.Parse(noteID)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid note ID"})
	}

	attachmentUUID, err := uuid.Parse(attachmentID)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid attachment ID"})
	}

	// Delete attachment (verify ownership through note)
	result, err := h.db.Exec(c.Context(), `
		DELETE FROM attachments a
		USING notes n
		WHERE a.id = $1 AND a.note_id = $2 AND a.note_id = n.id AND n.user_id = $3`,
		attachmentUUID, noteUUID, userID)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to delete attachment"})
	}

	if result.RowsAffected() == 0 {
		return c.Status(404).JSON(fiber.Map{"error": "Attachment not found"})
	}

	return c.JSON(fiber.Map{"message": "Attachment deleted successfully"})
}

func resolveAttachmentMIME(content []byte, declared string) (string, error) {
	declared = strings.TrimSpace(declared)

	detected, err := detectAttachmentMIME(content)
	if err != nil {
		return "", err
	}

	if declared != "" && !allowedAttachmentMIMEs[declared] {
		return "", errUnsupportedAttachmentType
	}

	switch detected {
	case "text/plain":
		if declared == "" || declared == "text/plain" {
			return "text/plain", nil
		}
		if declared == "text/markdown" {
			return "text/markdown", nil
		}
		return "", errAttachmentTypeMismatch
	default:
		if declared != "" && declared != detected {
			return "", errAttachmentTypeMismatch
		}
		return detected, nil
	}
}

func detectAttachmentMIME(content []byte) (string, error) {
	if len(content) == 0 {
		return "", errAttachmentEmptyFile
	}

	switch {
	case len(content) >= 3 && content[0] == 0xFF && content[1] == 0xD8 && content[2] == 0xFF:
		return "image/jpeg", nil
	case len(content) >= 8 && bytes.Equal(content[:8], []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}):
		return "image/png", nil
	case len(content) >= 6 && (bytes.Equal(content[:6], []byte("GIF87a")) || bytes.Equal(content[:6], []byte("GIF89a"))):
		return "image/gif", nil
	case len(content) >= 12 && string(content[:4]) == "RIFF" && string(content[8:12]) == "WEBP":
		return "image/webp", nil
	case len(content) >= 5 && bytes.Equal(content[:5], []byte("%PDF-")):
		return "application/pdf", nil
	case looksLikeText(content):
		return "text/plain", nil
	default:
		return "", errUnsupportedAttachmentType
	}
}

func looksLikeText(content []byte) bool {
	if len(content) == 0 {
		return false
	}

	sample := content
	if len(sample) > 4096 {
		sample = sample[:4096]
	}

	if !utf8.Valid(sample) {
		return false
	}

	for _, b := range sample {
		switch b {
		case '\n', '\r', '\t', '\f':
			continue
		}
		if b == 0 {
			return false
		}
		if b < 0x20 {
			return false
		}
	}

	return true
}
