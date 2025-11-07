package handlers

import (
	"context"
	"strings"
	"time"

	"leaflock/database"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

// SearchHandler handles search operations with metadata filtering
// Note: Content search remains client-side for E2E encryption
type SearchHandler struct {
	db database.Database
}

// NewSearchHandler creates a new search handler instance
func NewSearchHandler(db database.Database) *SearchHandler {
	return &SearchHandler{db: db}
}

// SearchRequest represents advanced search parameters
type SearchRequest struct {
	// Metadata filters (server-side)
	Tags      []string `json:"tags"`
	FolderIDs []string `json:"folder_ids"`
	StartDate string   `json:"start_date"`
	EndDate   string   `json:"end_date"`
	IsPinned  *bool    `json:"is_pinned"`
	IsLocked  *bool    `json:"is_locked"`
	IsTrashed *bool    `json:"is_trashed"`
	SortBy    string   `json:"sort_by"`    // "created_at"|"updated_at"|"title"
	SortOrder string   `json:"sort_order"` // "asc"|"desc"
	Limit     int      `json:"limit"`
	Offset    int      `json:"offset"`
}

// SearchResponse represents search results
type SearchResponse struct {
	Notes  []NoteMetadata `json:"notes"`
	Total  int            `json:"total"`
	Limit  int            `json:"limit"`
	Offset int            `json:"offset"`
}

// NoteMetadata represents note metadata for search results
type NoteMetadata struct {
	ID        string    `json:"id"`
	FolderID  *string   `json:"folder_id"`
	Tags      []string  `json:"tags"`
	IsPinned  bool      `json:"is_pinned"`
	IsLocked  bool      `json:"is_locked"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// SearchNotes performs metadata-based search and filtering
// Content search must be performed client-side after decryption
// @Summary Search notes by metadata
// @Description Filter notes by tags, folders, dates, and other metadata (content search is client-side)
// @Tags Search
// @Accept json
// @Produce json
// @Param request body SearchRequest true "Search parameters"
// @Success 200 {object} SearchResponse
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/v1/search [post]
func (h *SearchHandler) SearchNotes(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(string)
	ctx := context.Background()

	var req SearchRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	// Set defaults
	if req.Limit <= 0 || req.Limit > 1000 {
		req.Limit = 100
	}
	if req.Offset < 0 {
		req.Offset = 0
	}
	if req.SortBy == "" {
		req.SortBy = "updated_at"
	}
	if req.SortOrder == "" {
		req.SortOrder = "desc"
	}

	// Validate sort fields
	validSortFields := map[string]bool{
		"created_at": true,
		"updated_at": true,
	}
	if !validSortFields[req.SortBy] {
		req.SortBy = "updated_at"
	}

	// Validate sort order
	if req.SortOrder != "asc" && req.SortOrder != "desc" {
		req.SortOrder = "desc"
	}

	// Build query
	query := `
		SELECT DISTINCT n.id, n.folder_id, n.is_pinned, n.is_locked, n.created_at, n.updated_at
		FROM notes n
		WHERE n.user_id = $1 AND n.deleted_at IS NULL
	`
	args := []interface{}{userID}
	argIndex := 2

	// Apply is_trashed filter
	if req.IsTrashed != nil {
		if *req.IsTrashed {
			query = strings.Replace(query, "n.deleted_at IS NULL", "n.deleted_at IS NOT NULL", 1)
		}
	}

	// Apply folder filter
	if len(req.FolderIDs) > 0 {
		placeholders := make([]string, len(req.FolderIDs))
		for i, folderID := range req.FolderIDs {
			args = append(args, folderID)
			placeholders[i] = "$" + string(rune(argIndex+i))
		}
		query += " AND n.folder_id IN (" + strings.Join(placeholders, ",") + ")"
		argIndex += len(req.FolderIDs)
	}

	// Apply tags filter
	if len(req.Tags) > 0 {
		query += ` AND n.id IN (
			SELECT DISTINCT nt.note_id
			FROM note_tags nt
			JOIN tags t ON nt.tag_id = t.id
			WHERE t.name = ANY($` + string(rune(argIndex)) + `)
		)`
		args = append(args, req.Tags)
		argIndex++
	}

	// Apply date range filter
	if req.StartDate != "" {
		startDate, err := time.Parse(time.RFC3339, req.StartDate)
		if err == nil {
			query += " AND n.created_at >= $" + string(rune(argIndex))
			args = append(args, startDate)
			argIndex++
		}
	}
	if req.EndDate != "" {
		endDate, err := time.Parse(time.RFC3339, req.EndDate)
		if err == nil {
			query += " AND n.created_at <= $" + string(rune(argIndex))
			args = append(args, endDate)
			argIndex++
		}
	}

	// Apply pinned filter
	if req.IsPinned != nil {
		query += " AND n.is_pinned = $" + string(rune(argIndex))
		args = append(args, *req.IsPinned)
		argIndex++
	}

	// Apply locked filter
	if req.IsLocked != nil {
		query += " AND n.is_locked = $" + string(rune(argIndex))
		args = append(args, *req.IsLocked)
		argIndex++
	}

	// Get total count
	countQuery := strings.Replace(query, "SELECT DISTINCT n.id, n.folder_id, n.is_pinned, n.is_locked, n.created_at, n.updated_at", "SELECT COUNT(DISTINCT n.id)", 1)
	var total int
	err := h.db.QueryRow(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to count notes",
		})
	}

	// Add sorting and pagination
	query += " ORDER BY n." + req.SortBy + " " + req.SortOrder
	query += " LIMIT $" + string(rune(argIndex)) + " OFFSET $" + string(rune(argIndex+1))
	args = append(args, req.Limit, req.Offset)

	// Execute query
	rows, err := h.db.Query(ctx, query, args...)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to search notes",
		})
	}
	defer rows.Close()

	// Parse results
	notes := []NoteMetadata{}
	for rows.Next() {
		var note NoteMetadata
		var folderID *uuid.UUID

		err := rows.Scan(
			&note.ID,
			&folderID,
			&note.IsPinned,
			&note.IsLocked,
			&note.CreatedAt,
			&note.UpdatedAt,
		)
		if err != nil {
			continue
		}

		if folderID != nil {
			folderIDStr := folderID.String()
			note.FolderID = &folderIDStr
		}

		// Fetch tags for this note
		tagQuery := `
			SELECT t.name
			FROM tags t
			JOIN note_tags nt ON t.id = nt.tag_id
			WHERE nt.note_id = $1
		`
		tagRows, err := h.db.Query(ctx, tagQuery, note.ID)
		if err == nil {
			defer tagRows.Close()
			for tagRows.Next() {
				var tagName string
				if err := tagRows.Scan(&tagName); err == nil {
					note.Tags = append(note.Tags, tagName)
				}
			}
		}

		notes = append(notes, note)
	}

	return c.JSON(SearchResponse{
		Notes:  notes,
		Total:  total,
		Limit:  req.Limit,
		Offset: req.Offset,
	})
}
