package handlers

import (
	"context"
	"encoding/base64"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"golang.org/x/crypto/argon2"

	"leaflock/crypto"
	"leaflock/database"
	"leaflock/metrics"
)

// NotesHandler handles note-related requests
type NotesHandler struct {
	db     database.Database
	crypto *crypto.CryptoService
}

// NewNotesHandler creates a new notes handler
func NewNotesHandler(db database.Database, cryptoService *crypto.CryptoService) *NotesHandler {
	return &NotesHandler{
		db:     db,
		crypto: cryptoService,
	}
}

// CreateNoteRequest represents a request to create a note
type CreateNoteRequest struct {
	TitleEncrypted   string `json:"title_encrypted" validate:"required"`
	ContentEncrypted string `json:"content_encrypted" validate:"required"`
}

// UpdateNoteRequest represents a request to update a note
type UpdateNoteRequest struct {
	TitleEncrypted   string `json:"title_encrypted" validate:"required"`
	ContentEncrypted string `json:"content_encrypted" validate:"required"`
}

// GetNotes godoc
// @Summary List all notes
// @Description Get all notes for the authenticated user
// @Tags Notes
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "List of notes"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /notes [get]
func (h *NotesHandler) GetNotes(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	ctx := context.Background()

	// Get user's default workspace
	var workspaceID uuid.UUID
	err := h.db.QueryRow(ctx, `SELECT id FROM workspaces WHERE owner_id = $1 LIMIT 1`, userID).Scan(&workspaceID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to get workspace"})
	}

	// Get notes from workspace
	rows, err := h.db.Query(ctx, `
		SELECT id, title_encrypted, content_encrypted, created_at, updated_at
		FROM notes
		WHERE workspace_id = $1 AND deleted_at IS NULL
		ORDER BY updated_at DESC`,
		workspaceID)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to fetch notes"})
	}
	defer rows.Close()

	notes := []fiber.Map{}
	for rows.Next() {
		var id uuid.UUID
		var titleEnc, contentEnc []byte
		var createdAt, updatedAt time.Time

		if err := rows.Scan(&id, &titleEnc, &contentEnc, &createdAt, &updatedAt); err != nil {
			continue
		}

		notes = append(notes, fiber.Map{
			"id":                id,
			"title_encrypted":   base64.StdEncoding.EncodeToString(titleEnc),
			"content_encrypted": base64.StdEncoding.EncodeToString(contentEnc),
			"created_at":        createdAt,
			"updated_at":        updatedAt,
		})
	}

	return c.JSON(fiber.Map{"notes": notes})
}

func (h *NotesHandler) GetNote(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	noteID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid note ID"})
	}

	ctx := context.Background()
	var id uuid.UUID
	var titleEnc, contentEnc []byte
	var createdAt, updatedAt time.Time

	err = h.db.QueryRow(ctx, `
		SELECT n.id, n.title_encrypted, n.content_encrypted, n.created_at, n.updated_at
		FROM notes n
		JOIN workspaces w ON n.workspace_id = w.id
		WHERE n.id = $1 AND w.owner_id = $2 AND n.deleted_at IS NULL`,
		noteID, userID).Scan(&id, &titleEnc, &contentEnc, &createdAt, &updatedAt)

	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Note not found"})
	}

	return c.JSON(fiber.Map{
		"id":                id,
		"title_encrypted":   base64.StdEncoding.EncodeToString(titleEnc),
		"content_encrypted": base64.StdEncoding.EncodeToString(contentEnc),
		"created_at":        createdAt,
		"updated_at":        updatedAt,
	})
}

func (h *NotesHandler) CreateNote(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	var req CreateNoteRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
	}

	ctx := context.Background()

	// Get user's default workspace
	var workspaceID uuid.UUID
	err := h.db.QueryRow(ctx, `SELECT id FROM workspaces WHERE owner_id = $1 LIMIT 1`, userID).Scan(&workspaceID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to get workspace"})
	}

	// Decode encrypted data
	titleEnc, err := base64.StdEncoding.DecodeString(req.TitleEncrypted)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid title encryption"})
	}

	contentEnc, err := base64.StdEncoding.DecodeString(req.ContentEncrypted)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid content encryption"})
	}

	// Create content hash for integrity
	contentHash := argon2.IDKey(contentEnc, []byte("integrity"), 1, 64*1024, 4, 32)

	// Create note
	var noteID uuid.UUID
	err = h.db.QueryRow(ctx, `
		INSERT INTO notes (workspace_id, title_encrypted, content_encrypted, content_hash, created_by)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id`,
		workspaceID, titleEnc, contentEnc, contentHash, userID).Scan(&noteID)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to create note"})
	}

	// Record metrics
	metrics.IncrementNoteOperation("create")
	metrics.IncrementDatabaseQuery("insert")

	return c.Status(201).JSON(fiber.Map{
		"id":      noteID,
		"message": "Note created successfully",
	})
}

func (h *NotesHandler) UpdateNote(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	noteID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid note ID"})
	}

	var req UpdateNoteRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
	}

	ctx := context.Background()

	// Decode encrypted data
	titleEnc, err := base64.StdEncoding.DecodeString(req.TitleEncrypted)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid title encryption"})
	}

	contentEnc, err := base64.StdEncoding.DecodeString(req.ContentEncrypted)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid content encryption"})
	}

	// Create content hash for integrity
	contentHash := argon2.IDKey(contentEnc, []byte("integrity"), 1, 64*1024, 4, 32)

	// Start transaction for version history
	tx, err := h.db.Begin(ctx)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Database transaction failed"})
	}
	defer tx.Rollback(ctx)

	// Get current version and content to save as history
	var currentVersion int
	var currentTitle, currentContent, currentHash []byte
	err = tx.QueryRow(ctx, `
		SELECT version, title_encrypted, content_encrypted, content_hash
		FROM notes n
		JOIN workspaces w ON n.workspace_id = w.id
		WHERE n.id = $1 AND w.owner_id = $2 AND n.deleted_at IS NULL`,
		noteID, userID).Scan(&currentVersion, &currentTitle, &currentContent, &currentHash)

	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Note not found"})
	}

	// Save current version to history before updating
	_, err = tx.Exec(ctx, `
		INSERT INTO note_versions (note_id, version_number, title_encrypted, content_encrypted, content_hash, created_by)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		noteID, currentVersion, currentTitle, currentContent, currentHash, userID)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to save version history"})
	}

	// Update note with new content and increment version
	result, err := tx.Exec(ctx, `
		UPDATE notes
		SET title_encrypted = $1, content_encrypted = $2, content_hash = $3, version = version + 1, updated_at = NOW()
		FROM workspaces w
		WHERE notes.id = $4 AND notes.workspace_id = w.id AND w.owner_id = $5 AND notes.deleted_at IS NULL`,
		titleEnc, contentEnc, contentHash, noteID, userID)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to update note"})
	}

	if result.RowsAffected() == 0 {
		return c.Status(404).JSON(fiber.Map{"error": "Note not found"})
	}

	// Commit transaction
	err = tx.Commit(ctx)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to commit version history"})
	}

	// Record metrics
	metrics.IncrementNoteOperation("update")
	metrics.IncrementDatabaseQuery("update")

	return c.JSON(fiber.Map{"message": "Note updated successfully"})
}

func (h *NotesHandler) DeleteNote(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	noteID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid note ID"})
	}

	ctx := context.Background()

	// Soft delete the note
	result, err := h.db.Exec(ctx, `
		UPDATE notes
		SET deleted_at = NOW()
		FROM workspaces w
		WHERE notes.id = $1 AND notes.workspace_id = w.id AND w.owner_id = $2 AND notes.deleted_at IS NULL`,
		noteID, userID)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to delete note"})
	}

	if result.RowsAffected() == 0 {
		return c.Status(404).JSON(fiber.Map{"error": "Note not found"})
	}

	// Record metrics
	metrics.IncrementNoteOperation("delete")
	metrics.IncrementDatabaseQuery("update")

	return c.JSON(fiber.Map{"message": "Note moved to trash successfully"})
}

func (h *NotesHandler) GetTrash(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	ctx := context.Background()

	// Get user's default workspace
	var workspaceID uuid.UUID
	err := h.db.QueryRow(ctx, `SELECT id FROM workspaces WHERE owner_id = $1 LIMIT 1`, userID).Scan(&workspaceID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to get workspace"})
	}

	// Get deleted notes from workspace
	rows, err := h.db.Query(ctx, `
		SELECT id, title_encrypted, content_encrypted, deleted_at, updated_at
		FROM notes
		WHERE workspace_id = $1 AND deleted_at IS NOT NULL
		ORDER BY deleted_at DESC`,
		workspaceID)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to fetch trash"})
	}
	defer rows.Close()

	trashedNotes := []fiber.Map{}
	for rows.Next() {
		var id uuid.UUID
		var titleEnc, contentEnc []byte
		var deletedAt, updatedAt time.Time

		if err := rows.Scan(&id, &titleEnc, &contentEnc, &deletedAt, &updatedAt); err != nil {
			continue
		}

		trashedNotes = append(trashedNotes, fiber.Map{
			"id":                id,
			"title_encrypted":   base64.StdEncoding.EncodeToString(titleEnc),
			"content_encrypted": base64.StdEncoding.EncodeToString(contentEnc),
			"deleted_at":        deletedAt,
			"updated_at":        updatedAt,
		})
	}

	return c.JSON(fiber.Map{"notes": trashedNotes})
}

func (h *NotesHandler) RestoreNote(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	noteID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid note ID"})
	}

	ctx := context.Background()

	// Restore the note (set deleted_at to NULL)
	result, err := h.db.Exec(ctx, `
		UPDATE notes
		SET deleted_at = NULL, updated_at = NOW()
		FROM workspaces w
		WHERE notes.id = $1 AND notes.workspace_id = w.id AND w.owner_id = $2 AND notes.deleted_at IS NOT NULL`,
		noteID, userID)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to restore note"})
	}

	if result.RowsAffected() == 0 {
		return c.Status(404).JSON(fiber.Map{"error": "Note not found in trash"})
	}

	return c.JSON(fiber.Map{"message": "Note restored successfully"})
}

// GetNoteVersions returns version history for a note
func (h *NotesHandler) GetNoteVersions(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	noteID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid note ID"})
	}

	ctx := context.Background()

	// Get all versions for the note
	rows, err := h.db.Query(ctx, `
		SELECT nv.id, nv.version_number, nv.created_at, u.email as created_by_email
		FROM note_versions nv
		JOIN notes n ON nv.note_id = n.id
		JOIN workspaces w ON n.workspace_id = w.id
		JOIN users u ON nv.created_by = u.id
		WHERE n.id = $1 AND w.owner_id = $2 AND n.deleted_at IS NULL
		ORDER BY nv.version_number DESC`,
		noteID, userID)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to fetch version history"})
	}
	defer rows.Close()

	var versions []map[string]interface{}
	for rows.Next() {
		var versionID uuid.UUID
		var versionNumber int
		var createdAt time.Time
		var createdByEmail string

		err := rows.Scan(&versionID, &versionNumber, &createdAt, &createdByEmail)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "Failed to read version data"})
		}

		versions = append(versions, map[string]interface{}{
			"id":             versionID.String(),
			"version_number": versionNumber,
			"created_at":     createdAt.Format(time.RFC3339),
			"created_by":     createdByEmail,
		})
	}

	return c.JSON(fiber.Map{"versions": versions})
}

// RestoreNoteVersion restores a note to a specific version
func (h *NotesHandler) RestoreNoteVersion(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	noteID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid note ID"})
	}

	versionNumber, err := strconv.Atoi(c.Params("version"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid version number"})
	}

	ctx := context.Background()

	// Start transaction
	tx, err := h.db.Begin(ctx)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Database transaction failed"})
	}
	defer tx.Rollback(ctx)

	// Get the version to restore
	var titleEnc, contentEnc, contentHash []byte
	err = tx.QueryRow(ctx, `
		SELECT nv.title_encrypted, nv.content_encrypted, nv.content_hash
		FROM note_versions nv
		JOIN notes n ON nv.note_id = n.id
		JOIN workspaces w ON n.workspace_id = w.id
		WHERE n.id = $1 AND nv.version_number = $2 AND w.owner_id = $3 AND n.deleted_at IS NULL`,
		noteID, versionNumber, userID).Scan(&titleEnc, &contentEnc, &contentHash)

	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Version not found"})
	}

	// Save current version before restoring
	var currentVersion int
	var currentTitle, currentContent, currentContentHash []byte
	err = tx.QueryRow(ctx, `
		SELECT version, title_encrypted, content_encrypted, content_hash
		FROM notes n
		JOIN workspaces w ON n.workspace_id = w.id
		WHERE n.id = $1 AND w.owner_id = $2 AND n.deleted_at IS NULL`,
		noteID, userID).Scan(&currentVersion, &currentTitle, &currentContent, &currentContentHash)

	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Note not found"})
	}

	// Save current version to history
	_, err = tx.Exec(ctx, `
		INSERT INTO note_versions (note_id, version_number, title_encrypted, content_encrypted, content_hash, created_by)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		noteID, currentVersion, currentTitle, currentContent, currentContentHash, userID)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to save current version"})
	}

	// Restore to the selected version
	result, err := tx.Exec(ctx, `
		UPDATE notes
		SET title_encrypted = $1, content_encrypted = $2, content_hash = $3, version = version + 1, updated_at = NOW()
		FROM workspaces w
		WHERE notes.id = $4 AND notes.workspace_id = w.id AND w.owner_id = $5 AND notes.deleted_at IS NULL`,
		titleEnc, contentEnc, contentHash, noteID, userID)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to restore version"})
	}

	if result.RowsAffected() == 0 {
		return c.Status(404).JSON(fiber.Map{"error": "Note not found"})
	}

	// Commit transaction
	err = tx.Commit(ctx)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to commit version restore"})
	}

	return c.JSON(fiber.Map{"message": "Note restored to version " + strconv.Itoa(versionNumber)})
}

func (h *NotesHandler) PermanentlyDeleteNote(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	noteID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid note ID"})
	}

	ctx := context.Background()

	// Permanently delete the note
	result, err := h.db.Exec(ctx, `
		DELETE FROM notes
		USING workspaces w
		WHERE notes.id = $1 AND notes.workspace_id = w.id AND w.owner_id = $2 AND notes.deleted_at IS NOT NULL`,
		noteID, userID)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to permanently delete note"})
	}

	if result.RowsAffected() == 0 {
		return c.Status(404).JSON(fiber.Map{"error": "Note not found in trash"})
	}

	return c.JSON(fiber.Map{"message": "Note permanently deleted successfully"})
}
