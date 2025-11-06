package handlers

import (
	"context"
	"encoding/base64"
	"errors"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/argon2"

	"leaflock/crypto"
	"leaflock/database"
	"leaflock/metrics"
	"leaflock/utils"
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
	TitleEncrypted    string `json:"title_encrypted" validate:"required"`
	ContentEncrypted  string `json:"content_encrypted" validate:"required"`
	EncryptionVersion int    `json:"encryption_version"`
	IsPinned          bool   `json:"is_pinned"`
	PinnedOrder       int    `json:"pinned_order"`
}

// UpdateNoteRequest represents a request to update a note
type UpdateNoteRequest struct {
	TitleEncrypted    string `json:"title_encrypted" validate:"required"`
	ContentEncrypted  string `json:"content_encrypted" validate:"required"`
	EncryptionVersion int    `json:"encryption_version"`
	IsPinned          *bool  `json:"is_pinned,omitempty"`
	PinnedOrder       *int   `json:"pinned_order,omitempty"`
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

	// Get notes from workspace (pinned notes first, then by update time)
	rows, err := h.db.Query(ctx, `
		SELECT id, title_encrypted, content_encrypted, created_at, updated_at,
		       is_pinned, is_locked, locked_by, pinned_order
		FROM notes
		WHERE workspace_id = $1 AND deleted_at IS NULL
		ORDER BY is_pinned DESC, pinned_order DESC, updated_at DESC`,
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
		var isPinned, isLocked bool
		var lockedBy *uuid.UUID
		var pinnedOrder int

		if err := rows.Scan(&id, &titleEnc, &contentEnc, &createdAt, &updatedAt, &isPinned, &isLocked, &lockedBy, &pinnedOrder); err != nil {
			continue
		}

		noteMap := fiber.Map{
			"id":                 id,
			"title_encrypted":    base64.StdEncoding.EncodeToString(titleEnc),
			"content_encrypted":  base64.StdEncoding.EncodeToString(contentEnc),
			"created_at":         createdAt,
			"updated_at":         updatedAt,
			"encryption_version": defaultEncryptionVersion,
			"is_pinned":          isPinned,
			"is_locked":          isLocked,
			"pinned_order":       pinnedOrder,
		}

		if lockedBy != nil {
			noteMap["locked_by"] = lockedBy.String()
		}

		notes = append(notes, noteMap)
	}

	return c.JSON(fiber.Map{"notes": notes})
}

// GetNote godoc
// @Summary Get a specific note
// @Description Get a single note by ID for the authenticated user
// @Tags Notes
// @Produce json
// @Security BearerAuth
// @Param id path string true "Note ID"
// @Success 200 {object} map[string]interface{} "Note details"
// @Failure 400 {object} map[string]interface{} "Invalid note ID"
// @Failure 404 {object} map[string]interface{} "Note not found"
// @Router /notes/{id} [get]
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
		"id":                 id,
		"title_encrypted":    base64.StdEncoding.EncodeToString(titleEnc),
		"content_encrypted":  base64.StdEncoding.EncodeToString(contentEnc),
		"created_at":         createdAt,
		"updated_at":         updatedAt,
		"encryption_version": defaultEncryptionVersion,
	})
}

// CreateNote godoc
// @Summary Create a new note
// @Description Create a new note with encrypted title and content
// @Tags Notes
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body CreateNoteRequest true "Note creation data"
// @Success 201 {object} map[string]interface{} "Note created successfully"
// @Failure 400 {object} map[string]interface{} "Invalid request"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /notes [post]
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
	var (
		noteID    uuid.UUID
		createdAt time.Time
		updatedAt time.Time
	)

	err = h.db.QueryRow(ctx, `
        INSERT INTO notes (workspace_id, title_encrypted, content_encrypted, content_hash, created_by, is_pinned, pinned_order)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING id, created_at, updated_at`,
		workspaceID, titleEnc, contentEnc, contentHash, userID, req.IsPinned, req.PinnedOrder).Scan(&noteID, &createdAt, &updatedAt)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to create note"})
	}

	// Record metrics
	metrics.IncrementNoteOperation("create")
	metrics.IncrementDatabaseQuery("insert")

	version := req.EncryptionVersion
	if version == 0 {
		version = defaultEncryptionVersion
	}

	noteResponse := fiber.Map{
		"id":                 noteID,
		"title_encrypted":    base64.StdEncoding.EncodeToString(titleEnc),
		"content_encrypted":  base64.StdEncoding.EncodeToString(contentEnc),
		"created_at":         createdAt,
		"updated_at":         updatedAt,
		"encryption_version": version,
		"is_pinned":          req.IsPinned,
		"pinned_order":       req.PinnedOrder,
		"is_locked":          false,
	}

	return c.Status(201).JSON(fiber.Map{"note": noteResponse})
}

// UpdateNote godoc
// @Summary Update a note
// @Description Update an existing note with new encrypted content
// @Tags Notes
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "Note ID"
// @Param request body UpdateNoteRequest true "Note update data"
// @Success 200 {object} map[string]interface{} "Note updated successfully"
// @Failure 400 {object} map[string]interface{} "Invalid request"
// @Failure 404 {object} map[string]interface{} "Note not found"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /notes/{id} [put]
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
	defer func() {
		_ = tx.Rollback(ctx) // Rollback is safe to call even if tx was committed
	}()

	// Get current version and content to save as history, and check if locked
	var (
		currentVersion int
		currentTitle   []byte
		currentContent []byte
		currentHash    []byte
		createdAt      time.Time
		isLocked       bool
	)
	err = tx.QueryRow(ctx, `
        SELECT n.version, n.title_encrypted, n.content_encrypted, n.content_hash, n.created_at, n.is_locked
        FROM notes n
        JOIN workspaces w ON n.workspace_id = w.id
        WHERE n.id = $1 AND w.owner_id = $2 AND n.deleted_at IS NULL`,
		noteID, userID).Scan(&currentVersion, &currentTitle, &currentContent, &currentHash, &createdAt, &isLocked)

	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Note not found"})
	}

	// Prevent editing locked notes
	if isLocked {
		return c.Status(403).JSON(fiber.Map{"error": "Note is locked and cannot be edited"})
	}

	// Save current version to history before updating
	_, err = tx.Exec(ctx, `
		INSERT INTO note_versions (note_id, version_number, title_encrypted, content_encrypted, content_hash, created_by)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		noteID, currentVersion, currentTitle, currentContent, currentHash, userID)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to save version history"})
	}

	// Build UPDATE query dynamically based on provided fields
	updateQuery := `UPDATE notes SET title_encrypted = $1, content_encrypted = $2, content_hash = $3, version = version + 1, updated_at = NOW()`
	queryArgs := []interface{}{titleEnc, contentEnc, contentHash}
	argIndex := 4

	if req.IsPinned != nil {
		updateQuery += ", is_pinned = $" + strconv.Itoa(argIndex)
		queryArgs = append(queryArgs, *req.IsPinned)
		argIndex++
	}

	if req.PinnedOrder != nil {
		updateQuery += ", pinned_order = $" + strconv.Itoa(argIndex)
		queryArgs = append(queryArgs, *req.PinnedOrder)
		argIndex++
	}

	updateQuery += ` FROM workspaces w WHERE notes.id = $` + strconv.Itoa(argIndex) +
		` AND notes.workspace_id = w.id AND w.owner_id = $` + strconv.Itoa(argIndex+1) +
		` AND notes.deleted_at IS NULL RETURNING notes.updated_at`
	queryArgs = append(queryArgs, noteID, userID)

	var updatedAt time.Time
	err = tx.QueryRow(ctx, updateQuery, queryArgs...).Scan(&updatedAt)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return c.Status(404).JSON(fiber.Map{"error": "Note not found"})
		}
		return c.Status(500).JSON(fiber.Map{"error": "Failed to update note"})
	}

	// Commit transaction
	err = tx.Commit(ctx)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to commit version history"})
	}

	// Record metrics
	metrics.IncrementNoteOperation("update")
	metrics.IncrementDatabaseQuery("update")

	version := req.EncryptionVersion
	if version == 0 {
		version = defaultEncryptionVersion
	}

	noteResponse := fiber.Map{
		"id":                 noteID,
		"title_encrypted":    base64.StdEncoding.EncodeToString(titleEnc),
		"content_encrypted":  base64.StdEncoding.EncodeToString(contentEnc),
		"created_at":         createdAt,
		"updated_at":         updatedAt,
		"encryption_version": version,
	}

	return c.JSON(fiber.Map{"note": noteResponse})
}

// DeleteNote godoc
// @Summary Delete a note
// @Description Soft delete a note (move to trash)
// @Tags Notes
// @Produce json
// @Security BearerAuth
// @Param id path string true "Note ID"
// @Success 200 {object} map[string]interface{} "Note moved to trash successfully"
// @Failure 400 {object} map[string]interface{} "Invalid note ID"
// @Failure 404 {object} map[string]interface{} "Note not found"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /notes/{id} [delete]
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

// GetTrash godoc
// @Summary Get trash notes
// @Description Get all deleted notes for the authenticated user
// @Tags Notes
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "List of trashed notes"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /notes/trash [get]
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
			"id":                 id,
			"title_encrypted":    base64.StdEncoding.EncodeToString(titleEnc),
			"content_encrypted":  base64.StdEncoding.EncodeToString(contentEnc),
			"deleted_at":         deletedAt,
			"updated_at":         updatedAt,
			"encryption_version": defaultEncryptionVersion,
		})
	}

	return c.JSON(fiber.Map{"notes": trashedNotes})
}

// RestoreNote godoc
// @Summary Restore a note from trash
// @Description Restore a deleted note back to active state
// @Tags Notes
// @Produce json
// @Security BearerAuth
// @Param id path string true "Note ID"
// @Success 200 {object} map[string]interface{} "Note restored successfully"
// @Failure 400 {object} map[string]interface{} "Invalid note ID"
// @Failure 404 {object} map[string]interface{} "Note not found in trash"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /notes/{id}/restore [post]
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

// GetNoteVersions godoc
// @Summary Get note version history
// @Description Get version history for a specific note
// @Tags Notes
// @Produce json
// @Security BearerAuth
// @Param id path string true "Note ID"
// @Success 200 {object} map[string]interface{} "List of note versions"
// @Failure 400 {object} map[string]interface{} "Invalid note ID"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /notes/{id}/versions [get]
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

// RestoreNoteVersion godoc
// @Summary Restore note to specific version
// @Description Restore a note to a previous version from history
// @Tags Notes
// @Produce json
// @Security BearerAuth
// @Param id path string true "Note ID"
// @Param version path int true "Version number to restore"
// @Success 200 {object} map[string]interface{} "Note restored to version"
// @Failure 400 {object} map[string]interface{} "Invalid note ID or version"
// @Failure 404 {object} map[string]interface{} "Version not found"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /notes/{id}/versions/{version}/restore [post]
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
	defer func() {
		_ = tx.Rollback(ctx) // Rollback is safe to call even if tx was committed
	}()

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

// CompareNoteVersions godoc
// @Summary Compare two note versions
// @Description Get a comparison between two versions of a note
// @Tags Notes
// @Produce json
// @Security BearerAuth
// @Param id path string true "Note ID"
// @Param v1 query int true "First version number"
// @Param v2 query int true "Second version number"
// @Success 200 {object} map[string]interface{} "Version comparison data"
// @Failure 400 {object} map[string]interface{} "Invalid parameters"
// @Failure 404 {object} map[string]interface{} "Version not found"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /notes/{id}/versions/compare [get]
func (h *NotesHandler) CompareNoteVersions(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	noteID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid note ID"})
	}

	v1, err := strconv.Atoi(c.Query("v1"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid v1 parameter"})
	}

	v2, err := strconv.Atoi(c.Query("v2"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid v2 parameter"})
	}

	ctx := context.Background()

	// Get both versions
	rows, err := h.db.Query(ctx, `
		SELECT nv.version_number, nv.title_encrypted, nv.content_encrypted, nv.created_at, u.email as created_by_email
		FROM note_versions nv
		JOIN notes n ON nv.note_id = n.id
		JOIN workspaces w ON n.workspace_id = w.id
		JOIN users u ON nv.created_by = u.id
		WHERE n.id = $1 AND nv.version_number IN ($2, $3) AND w.owner_id = $4 AND n.deleted_at IS NULL
		ORDER BY nv.version_number ASC`,
		noteID, v1, v2, userID)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to fetch versions"})
	}
	defer rows.Close()

	var versions []map[string]interface{}
	for rows.Next() {
		var versionNumber int
		var titleEnc, contentEnc []byte
		var createdAt time.Time
		var createdByEmail string

		err := rows.Scan(&versionNumber, &titleEnc, &contentEnc, &createdAt, &createdByEmail)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "Failed to read version data"})
		}

		versions = append(versions, map[string]interface{}{
			"version_number":    versionNumber,
			"title_encrypted":   base64.StdEncoding.EncodeToString(titleEnc),
			"content_encrypted": base64.StdEncoding.EncodeToString(contentEnc),
			"created_at":        createdAt.Format(time.RFC3339),
			"created_by":        createdByEmail,
		})
	}

	if len(versions) != 2 {
		return c.Status(404).JSON(fiber.Map{"error": "One or both versions not found"})
	}

	return c.JSON(fiber.Map{
		"v1": versions[0],
		"v2": versions[1],
	})
}

// DeleteNoteVersion godoc
// @Summary Delete a specific note version
// @Description Delete a specific version from note history
// @Tags Notes
// @Produce json
// @Security BearerAuth
// @Param id path string true "Note ID"
// @Param versionId path string true "Version ID to delete"
// @Success 200 {object} map[string]interface{} "Version deleted successfully"
// @Failure 400 {object} map[string]interface{} "Invalid parameters"
// @Failure 404 {object} map[string]interface{} "Version not found"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /notes/{id}/versions/{versionId} [delete]
func (h *NotesHandler) DeleteNoteVersion(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	noteID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid note ID"})
	}

	versionID, err := uuid.Parse(c.Params("versionId"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid version ID"})
	}

	ctx := context.Background()

	// Delete the version
	result, err := h.db.Exec(ctx, `
		DELETE FROM note_versions nv
		USING notes n, workspaces w
		WHERE nv.id = $1 AND nv.note_id = $2 AND nv.note_id = n.id
		AND n.workspace_id = w.id AND w.owner_id = $3 AND n.deleted_at IS NULL`,
		versionID, noteID, userID)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to delete version"})
	}

	if result.RowsAffected() == 0 {
		return c.Status(404).JSON(fiber.Map{"error": "Version not found"})
	}

	return c.JSON(fiber.Map{"message": "Version deleted successfully"})
}

// UpdateRetentionPolicy godoc
// @Summary Update note version retention policy
// @Description Update how many versions to keep for a note (10, 20, or 50)
// @Tags Notes
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "Note ID"
// @Param retention body map[string]int true "Retention policy (retention_policy: 10|20|50)"
// @Success 200 {object} map[string]interface{} "Retention policy updated"
// @Failure 400 {object} map[string]interface{} "Invalid parameters"
// @Failure 404 {object} map[string]interface{} "Note not found"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /notes/{id}/retention [put]
func (h *NotesHandler) UpdateRetentionPolicy(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	noteID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid note ID"})
	}

	var req struct {
		RetentionPolicy int `json:"retention_policy"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
	}

	// Validate retention policy value
	if req.RetentionPolicy != 10 && req.RetentionPolicy != 20 && req.RetentionPolicy != 50 {
		return c.Status(400).JSON(fiber.Map{"error": "Retention policy must be 10, 20, or 50"})
	}

	ctx := context.Background()

	// Update retention policy
	result, err := h.db.Exec(ctx, `
		UPDATE notes n
		SET retention_policy = $1
		FROM workspaces w
		WHERE n.id = $2 AND n.workspace_id = w.id AND w.owner_id = $3 AND n.deleted_at IS NULL`,
		req.RetentionPolicy, noteID, userID)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to update retention policy"})
	}

	if result.RowsAffected() == 0 {
		return c.Status(404).JSON(fiber.Map{"error": "Note not found"})
	}

	// Clean up excess versions if needed
	_, err = h.db.Exec(ctx, `
		DELETE FROM note_versions
		WHERE note_id = $1 AND id NOT IN (
			SELECT id FROM note_versions
			WHERE note_id = $1
			ORDER BY created_at DESC
			LIMIT $2
		)`,
		noteID, req.RetentionPolicy)

	if err != nil {
		utils.LogError("Failed to clean old note versions", err)
	}

	return c.JSON(fiber.Map{
		"message":          "Retention policy updated successfully",
		"retention_policy": req.RetentionPolicy,
	})
}

// BulkDeleteNotes godoc
// @Summary Bulk soft delete notes
// @Description Soft delete multiple notes at once (move to trash)
// @Tags Notes
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param noteIds body []string true "Array of note IDs to delete"
// @Success 200 {object} map[string]interface{} "Bulk delete results"
// @Failure 400 {object} map[string]interface{} "Invalid request"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /notes/bulk/delete [post]
func (h *NotesHandler) BulkDeleteNotes(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)

	var req struct {
		NoteIDs []string `json:"note_ids"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
	}

	if len(req.NoteIDs) == 0 {
		return c.Status(400).JSON(fiber.Map{"error": "No note IDs provided"})
	}

	ctx := context.Background()
	successful := 0
	failed := 0
	errors := []string{}

	// Process in chunks of 50 for performance
	chunkSize := 50
	for i := 0; i < len(req.NoteIDs); i += chunkSize {
		end := i + chunkSize
		if end > len(req.NoteIDs) {
			end = len(req.NoteIDs)
		}
		chunk := req.NoteIDs[i:end]

		// Convert strings to UUIDs
		noteUUIDs := make([]uuid.UUID, 0, len(chunk))
		for _, idStr := range chunk {
			id, err := uuid.Parse(idStr)
			if err != nil {
				failed++
				errors = append(errors, "Invalid UUID: "+idStr)
				continue
			}
			noteUUIDs = append(noteUUIDs, id)
		}

		// Bulk soft delete
		for _, noteID := range noteUUIDs {
			result, err := h.db.Exec(ctx, `
				UPDATE notes n
				SET deleted_at = NOW()
				FROM workspaces w
				WHERE n.id = $1 AND n.workspace_id = w.id AND w.owner_id = $2 AND n.deleted_at IS NULL`,
				noteID, userID)

			if err != nil {
				failed++
				errors = append(errors, "Failed to delete note: "+noteID.String())
				continue
			}

			if result.RowsAffected() > 0 {
				successful++
			} else {
				failed++
			}
		}
	}

	return c.JSON(fiber.Map{
		"message":    "Bulk delete completed",
		"successful": successful,
		"failed":     failed,
		"total":      len(req.NoteIDs),
		"errors":     errors,
	})
}

// BulkRestoreNotes godoc
// @Summary Bulk restore notes from trash
// @Description Restore multiple notes from trash at once
// @Tags Notes
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param noteIds body []string true "Array of note IDs to restore"
// @Success 200 {object} map[string]interface{} "Bulk restore results"
// @Failure 400 {object} map[string]interface{} "Invalid request"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /notes/bulk/restore [post]
func (h *NotesHandler) BulkRestoreNotes(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)

	var req struct {
		NoteIDs []string `json:"note_ids"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
	}

	if len(req.NoteIDs) == 0 {
		return c.Status(400).JSON(fiber.Map{"error": "No note IDs provided"})
	}

	ctx := context.Background()
	successful := 0
	failed := 0
	errors := []string{}

	// Process in chunks
	chunkSize := 50
	for i := 0; i < len(req.NoteIDs); i += chunkSize {
		end := i + chunkSize
		if end > len(req.NoteIDs) {
			end = len(req.NoteIDs)
		}
		chunk := req.NoteIDs[i:end]

		// Convert and restore
		for _, idStr := range chunk {
			noteID, err := uuid.Parse(idStr)
			if err != nil {
				failed++
				errors = append(errors, "Invalid UUID: "+idStr)
				continue
			}

			result, err := h.db.Exec(ctx, `
				UPDATE notes n
				SET deleted_at = NULL
				FROM workspaces w
				WHERE n.id = $1 AND n.workspace_id = w.id AND w.owner_id = $2 AND n.deleted_at IS NOT NULL`,
				noteID, userID)

			if err != nil {
				failed++
				errors = append(errors, "Failed to restore note: "+noteID.String())
				continue
			}

			if result.RowsAffected() > 0 {
				successful++
			} else {
				failed++
			}
		}
	}

	return c.JSON(fiber.Map{
		"message":    "Bulk restore completed",
		"successful": successful,
		"failed":     failed,
		"total":      len(req.NoteIDs),
		"errors":     errors,
	})
}

// BulkPermanentlyDeleteNotes godoc
// @Summary Bulk permanently delete notes
// @Description Permanently delete multiple notes from trash (cannot be recovered)
// @Tags Notes
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param noteIds body []string true "Array of note IDs to permanently delete"
// @Success 200 {object} map[string]interface{} "Bulk permanent delete results"
// @Failure 400 {object} map[string]interface{} "Invalid request"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /notes/bulk/permanent-delete [post]
func (h *NotesHandler) BulkPermanentlyDeleteNotes(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)

	var req struct {
		NoteIDs []string `json:"note_ids"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
	}

	if len(req.NoteIDs) == 0 {
		return c.Status(400).JSON(fiber.Map{"error": "No note IDs provided"})
	}

	ctx := context.Background()
	successful := 0
	failed := 0
	errors := []string{}

	// Process in chunks
	chunkSize := 50
	for i := 0; i < len(req.NoteIDs); i += chunkSize {
		end := i + chunkSize
		if end > len(req.NoteIDs) {
			end = len(req.NoteIDs)
		}
		chunk := req.NoteIDs[i:end]

		// Convert and permanently delete
		for _, idStr := range chunk {
			noteID, err := uuid.Parse(idStr)
			if err != nil {
				failed++
				errors = append(errors, "Invalid UUID: "+idStr)
				continue
			}

			result, err := h.db.Exec(ctx, `
				DELETE FROM notes
				USING workspaces w
				WHERE notes.id = $1 AND notes.workspace_id = w.id AND w.owner_id = $2 AND notes.deleted_at IS NOT NULL`,
				noteID, userID)

			if err != nil {
				failed++
				errors = append(errors, "Failed to delete note: "+noteID.String())
				continue
			}

			if result.RowsAffected() > 0 {
				successful++
			} else {
				failed++
			}
		}
	}

	return c.JSON(fiber.Map{
		"message":    "Bulk permanent delete completed",
		"successful": successful,
		"failed":     failed,
		"total":      len(req.NoteIDs),
		"errors":     errors,
	})
}

// PermanentlyDeleteNote godoc
// @Summary Permanently delete a note
// @Description Permanently delete a note from trash (cannot be recovered)
// @Tags Notes
// @Produce json
// @Security BearerAuth
// @Param id path string true "Note ID"
// @Success 200 {object} map[string]interface{} "Note permanently deleted successfully"
// @Failure 400 {object} map[string]interface{} "Invalid note ID"
// @Failure 404 {object} map[string]interface{} "Note not found in trash"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /notes/{id}/permanent [delete]
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

// TogglePinRequest represents a request to toggle pin status
type TogglePinRequest struct {
	IsPinned    bool `json:"is_pinned"`
	PinnedOrder *int `json:"pinned_order,omitempty"`
}

// TogglePin godoc
// @Summary Toggle pin status of a note
// @Description Pin or unpin a note for quick access
// @Tags Notes
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "Note ID"
// @Param request body TogglePinRequest true "Pin status"
// @Success 200 {object} map[string]interface{} "Pin status updated"
// @Failure 400 {object} map[string]interface{} "Invalid request"
// @Failure 404 {object} map[string]interface{} "Note not found"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /notes/{id}/pin [post]
func (h *NotesHandler) TogglePin(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	noteID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid note ID"})
	}

	var req TogglePinRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
	}

	ctx := context.Background()

	// Default pinned order if not provided
	pinnedOrder := 0
	if req.PinnedOrder != nil {
		pinnedOrder = *req.PinnedOrder
	}

	// Update pin status
	result, err := h.db.Exec(ctx, `
		UPDATE notes
		SET is_pinned = $1, pinned_order = $2, updated_at = NOW()
		FROM workspaces w
		WHERE notes.id = $3 AND notes.workspace_id = w.id AND w.owner_id = $4 AND notes.deleted_at IS NULL`,
		req.IsPinned, pinnedOrder, noteID, userID)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to update pin status"})
	}

	if result.RowsAffected() == 0 {
		return c.Status(404).JSON(fiber.Map{"error": "Note not found"})
	}

	return c.JSON(fiber.Map{
		"message":      "Pin status updated successfully",
		"is_pinned":    req.IsPinned,
		"pinned_order": pinnedOrder,
	})
}

// ToggleLockRequest represents a request to toggle lock status
type ToggleLockRequest struct {
	IsLocked bool `json:"is_locked"`
}

// ToggleLock godoc
// @Summary Toggle lock status of a note
// @Description Lock or unlock a note to prevent/allow editing
// @Tags Notes
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "Note ID"
// @Param request body ToggleLockRequest true "Lock status"
// @Success 200 {object} map[string]interface{} "Lock status updated"
// @Failure 400 {object} map[string]interface{} "Invalid request"
// @Failure 404 {object} map[string]interface{} "Note not found"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /notes/{id}/lock [post]
func (h *NotesHandler) ToggleLock(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	noteID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid note ID"})
	}

	var req ToggleLockRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
	}

	ctx := context.Background()

	// Prepare locked_by and locked_at values
	var lockedBy interface{}
	var lockedAt interface{}
	if req.IsLocked {
		lockedBy = userID
		lockedAt = time.Now()
	} else {
		lockedBy = nil
		lockedAt = nil
	}

	// Update lock status
	result, err := h.db.Exec(ctx, `
		UPDATE notes
		SET is_locked = $1, locked_by = $2, locked_at = $3, updated_at = NOW()
		FROM workspaces w
		WHERE notes.id = $4 AND notes.workspace_id = w.id AND w.owner_id = $5 AND notes.deleted_at IS NULL`,
		req.IsLocked, lockedBy, lockedAt, noteID, userID)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to update lock status"})
	}

	if result.RowsAffected() == 0 {
		return c.Status(404).JSON(fiber.Map{"error": "Note not found"})
	}

	return c.JSON(fiber.Map{
		"message":   "Lock status updated successfully",
		"is_locked": req.IsLocked,
	})
}
