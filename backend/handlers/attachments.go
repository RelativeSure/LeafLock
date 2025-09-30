package handlers

import (
	"crypto/sha256"
	"io"
	"strconv"
	"time"

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

// NewAttachmentsHandler creates an attachments handler.
func NewAttachmentsHandler(db database.Database, cryptoService *crypto.CryptoService) *AttachmentsHandler {
	return &AttachmentsHandler{db: db, crypto: cryptoService}
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
	allowedTypes := map[string]bool{
		"image/jpeg":      true,
		"image/png":       true,
		"image/gif":       true,
		"image/webp":      true,
		"text/plain":      true,
		"application/pdf": true,
		"text/markdown":   true,
	}

	if file.Header.Get("Content-Type") != "" && !allowedTypes[file.Header.Get("Content-Type")] {
		return c.Status(400).JSON(fiber.Map{"error": "File type not allowed"})
	}

	// Read file content
	fileContent, err := file.Open()
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to read file"})
	}
	defer fileContent.Close()

	content, err := io.ReadAll(fileContent)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to read file content"})
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
	mimeType := file.Header.Get("Content-Type")
	if mimeType == "" {
		mimeType = "application/octet-stream"
	}

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

	// Set appropriate headers
	c.Set("Content-Type", mimeType)
	c.Set("Content-Disposition", "attachment; filename=\""+filename+"\"")
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
