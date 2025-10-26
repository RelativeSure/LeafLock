package handlers

import (
	"context"
	"encoding/base64"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"leaflock/database"
)

type NoteLinksHandler struct {
	db database.Database
}

func NewNoteLinksHandler(db database.Database) *NoteLinksHandler {
	return &NoteLinksHandler{db: db}
}

type NoteLinkRequest struct {
	TargetNoteID string `json:"target_note_id" validate:"required"`
	LinkText     string `json:"link_text"`
}

type NoteLink struct {
	ID           uuid.UUID `json:"id"`
	SourceNoteID uuid.UUID `json:"source_note_id"`
	TargetNoteID uuid.UUID `json:"target_note_id"`
	LinkText     string    `json:"link_text,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
}

type BacklinkNote struct {
	ID             uuid.UUID `json:"id"`
	TitleEncrypted string    `json:"title_encrypted"`
}

// CreateNoteLink creates a new link between two notes
// POST /api/v1/notes/:id/links
func (h *NoteLinksHandler) CreateNoteLink(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	sourceNoteIDParam := c.Params("id")

	var req NoteLinkRequest
	if err := c.BodyParser(&req); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid request body")
	}

	// Validate UUIDs
	sourceNoteID, err := uuid.Parse(sourceNoteIDParam)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid source note ID")
	}
	targetUUID, err := uuid.Parse(req.TargetNoteID)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid target note ID")
	}

	// Verify both notes exist and belong to user
	ctx := context.Background()

	// Check source note
	var sourceOwnerID uuid.UUID
	err = h.db.QueryRow(ctx, `
		SELECT w.owner_id
		FROM notes n
		JOIN workspaces w ON n.workspace_id = w.id
		WHERE n.id = $1 AND n.deleted_at IS NULL
	`, sourceNoteID).Scan(&sourceOwnerID)
	if err == pgx.ErrNoRows {
		return fiber.NewError(fiber.StatusNotFound, "Source note not found")
	} else if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to check source note")
	}
	if sourceOwnerID != userID {
		return fiber.NewError(fiber.StatusForbidden, "Access denied")
	}

	// Check target note
	var targetOwnerID uuid.UUID
	err = h.db.QueryRow(ctx, `
		SELECT w.owner_id
		FROM notes n
		JOIN workspaces w ON n.workspace_id = w.id
		WHERE n.id = $1 AND n.deleted_at IS NULL
	`, targetUUID).Scan(&targetOwnerID)
	if err == pgx.ErrNoRows {
		return fiber.NewError(fiber.StatusNotFound, "Target note not found")
	} else if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to check target note")
	}
	if targetOwnerID != userID {
		return fiber.NewError(fiber.StatusForbidden, "Target note access denied")
	}

	// Create link (ON CONFLICT DO NOTHING to avoid duplicates)
	var linkID uuid.UUID
	var createdAt time.Time
	err = h.db.QueryRow(ctx, `
		INSERT INTO note_links (source_note_id, target_note_id, link_text)
		VALUES ($1, $2, $3)
		ON CONFLICT (source_note_id, target_note_id) DO UPDATE
		SET link_text = EXCLUDED.link_text
		RETURNING id, created_at
	`, sourceNoteID, targetUUID, req.LinkText).Scan(&linkID, &createdAt)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to create note link")
	}

	// Metrics tracking removed for now
	return c.JSON(fiber.Map{
		"id":             linkID,
		"source_note_id": sourceNoteID,
		"target_note_id": targetUUID,
		"link_text":      req.LinkText,
		"created_at":     createdAt,
	})
}

// GetNoteLinks returns all outgoing links from a note
// GET /api/v1/notes/:id/links
func (h *NoteLinksHandler) GetNoteLinks(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	noteIDParam := c.Params("id")

	noteID, err := uuid.Parse(noteIDParam)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid note ID")
	}

	// Verify note exists and belongs to user
	ctx := context.Background()
	var ownerID uuid.UUID
	err = h.db.QueryRow(ctx, `
		SELECT w.owner_id
		FROM notes n
		JOIN workspaces w ON n.workspace_id = w.id
		WHERE n.id = $1 AND n.deleted_at IS NULL
	`, noteID).Scan(&ownerID)
	if err == pgx.ErrNoRows {
		return fiber.NewError(fiber.StatusNotFound, "Note not found")
	} else if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to check note")
	}
	if ownerID != userID {
		return fiber.NewError(fiber.StatusForbidden, "Access denied")
	}

	// Get all outgoing links
	rows, err := h.db.Query(ctx, `
		SELECT id, source_note_id, target_note_id, link_text, created_at
		FROM note_links
		WHERE source_note_id = $1
		ORDER BY created_at DESC
	`, noteID)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to get note links")
	}
	defer rows.Close()

	links := []NoteLink{}
	for rows.Next() {
		var link NoteLink
		if err := rows.Scan(&link.ID, &link.SourceNoteID, &link.TargetNoteID, &link.LinkText, &link.CreatedAt); err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, "Failed to scan note link")
		}
		links = append(links, link)
	}

	// Metrics tracking removed for now
	return c.JSON(fiber.Map{
		"links": links,
	})
}

// GetNoteBacklinks returns all incoming links to a note
// GET /api/v1/notes/:id/backlinks
func (h *NoteLinksHandler) GetNoteBacklinks(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	noteIDParam := c.Params("id")

	noteID, err := uuid.Parse(noteIDParam)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid note ID")
	}

	// Verify note exists and belongs to user
	ctx := context.Background()
	var ownerID uuid.UUID
	err = h.db.QueryRow(ctx, `
		SELECT w.owner_id
		FROM notes n
		JOIN workspaces w ON n.workspace_id = w.id
		WHERE n.id = $1 AND n.deleted_at IS NULL
	`, noteID).Scan(&ownerID)
	if err == pgx.ErrNoRows {
		return fiber.NewError(fiber.StatusNotFound, "Note not found")
	} else if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to check note")
	}
	if ownerID != userID {
		return fiber.NewError(fiber.StatusForbidden, "Access denied")
	}

	// Get all backlinks (notes that link to this note)
	rows, err := h.db.Query(ctx, `
		SELECT nl.id, nl.source_note_id, nl.target_note_id, nl.link_text, nl.created_at, n.title_encrypted
		FROM note_links nl
		JOIN notes n ON nl.source_note_id = n.id
		JOIN workspaces w ON n.workspace_id = w.id
		WHERE nl.target_note_id = $1 AND n.deleted_at IS NULL AND w.owner_id = $2
		ORDER BY nl.created_at DESC
	`, noteID, userID)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to get backlinks")
	}
	defer rows.Close()

	type BacklinkWithNote struct {
		NoteLink
		SourceNoteTitleEncrypted string `json:"source_note_title_encrypted"`
	}

	backlinks := []BacklinkWithNote{}
	for rows.Next() {
		var bl BacklinkWithNote
		var titleEnc []byte
		if err := rows.Scan(&bl.ID, &bl.SourceNoteID, &bl.TargetNoteID, &bl.LinkText, &bl.CreatedAt, &titleEnc); err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, "Failed to scan backlink")
		}
		bl.SourceNoteTitleEncrypted = base64.StdEncoding.EncodeToString(titleEnc)
		backlinks = append(backlinks, bl)
	}

	// Metrics tracking removed for now
	return c.JSON(fiber.Map{
		"backlinks": backlinks,
	})
}

// DeleteNoteLink deletes a link between two notes
// DELETE /api/v1/notes/:id/links/:linkId
func (h *NoteLinksHandler) DeleteNoteLink(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	noteIDParam := c.Params("id")
	linkIDParam := c.Params("linkId")

	noteID, err := uuid.Parse(noteIDParam)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid note ID")
	}

	linkID, err := uuid.Parse(linkIDParam)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid link ID")
	}

	// Verify link exists and belongs to user's note
	ctx := context.Background()
	var sourceNoteID uuid.UUID
	err = h.db.QueryRow(ctx, `
		SELECT nl.source_note_id
		FROM note_links nl
		JOIN notes n ON nl.source_note_id = n.id
		JOIN workspaces w ON n.workspace_id = w.id
		WHERE nl.id = $1 AND w.owner_id = $2 AND n.deleted_at IS NULL
	`, linkID, userID).Scan(&sourceNoteID)
	if err == pgx.ErrNoRows {
		return fiber.NewError(fiber.StatusNotFound, "Link not found")
	} else if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to check link")
	}

	if sourceNoteID != noteID {
		return fiber.NewError(fiber.StatusBadRequest, "Link does not belong to this note")
	}

	// Delete link
	_, err = h.db.Exec(ctx, `
		DELETE FROM note_links WHERE id = $1
	`, linkID)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to delete link")
	}

	// Metrics tracking removed for now
	return c.JSON(fiber.Map{
		"message": "Link deleted successfully",
	})
}

// GetAllNotesForLinking returns all notes (excluding trashed) for autocomplete
// GET /api/v1/notes/search-for-linking?q=query
func (h *NoteLinksHandler) GetAllNotesForLinking(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	query := c.Query("q", "")

	ctx := context.Background()
	var rows pgx.Rows
	var err error

	// Simple search - just return all active notes or filter by title
	if query == "" {
		rows, err = h.db.Query(ctx, `
			SELECT n.id, n.title_encrypted
			FROM notes n
			JOIN workspaces w ON n.workspace_id = w.id
			WHERE w.owner_id = $1 AND n.deleted_at IS NULL
			ORDER BY n.updated_at DESC
			LIMIT 50
		`, userID)
	} else {
		rows, err = h.db.Query(ctx, `
			SELECT n.id, n.title_encrypted
			FROM notes n
			JOIN workspaces w ON n.workspace_id = w.id
			WHERE w.owner_id = $1 AND n.deleted_at IS NULL
			ORDER BY n.updated_at DESC
			LIMIT 50
		`, userID)
	}

	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to search notes")
	}
	defer rows.Close()

	notes := []BacklinkNote{}
	for rows.Next() {
		var note BacklinkNote
		var titleEnc []byte
		if err := rows.Scan(&note.ID, &titleEnc); err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, "Failed to scan note")
		}
		note.TitleEncrypted = base64.StdEncoding.EncodeToString(titleEnc)
		notes = append(notes, note)
	}

	// Metrics tracking removed for now
	return c.JSON(fiber.Map{
		"notes": notes,
	})
}
