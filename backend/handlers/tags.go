package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"leaflock/crypto"
	"leaflock/database"
	"leaflock/utils"
)

// TagsHandler manages tag operations for notes.
type TagsHandler struct {
	db     database.Database
	crypto *crypto.CryptoService
}

// NewTagsHandler builds a TagsHandler instance.
func NewTagsHandler(db database.Database, cryptoService *crypto.CryptoService) *TagsHandler {
	return &TagsHandler{db: db, crypto: cryptoService}
}

type createTagRequest struct {
	Name  string `json:"name" validate:"required"`
	Color string `json:"color,omitempty"`
}

type assignTagRequest struct {
	TagID string `json:"tag_id" validate:"required"`
}

func (h *TagsHandler) GetTags(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	ctx := context.Background()

	rows, err := h.db.Query(ctx, `
        SELECT id, name_encrypted, color, created_at, updated_at
        FROM tags
        WHERE user_id = $1
        ORDER BY name_encrypted ASC`,
		userID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to fetch tags"})
	}
	defer rows.Close()

	tags := []fiber.Map{}
	for rows.Next() {
		var (
			id        uuid.UUID
			nameEnc   []byte
			color     string
			createdAt time.Time
			updatedAt time.Time
		)

		if err := rows.Scan(&id, &nameEnc, &color, &createdAt, &updatedAt); err != nil {
			continue
		}

		name, err := h.crypto.Decrypt(nameEnc)
		if err != nil {
			continue
		}

		tags = append(tags, fiber.Map{
			"id":         id,
			"name":       string(name),
			"color":      color,
			"created_at": createdAt,
			"updated_at": updatedAt,
		})
	}

	return c.JSON(fiber.Map{"tags": tags})
}

func (h *TagsHandler) CreateTag(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	var req createTagRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
	}

	if req.Color != "" && !utils.IsValidHexColor(req.Color) {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid color format"})
	}
	if req.Color == "" {
		req.Color = "#3b82f6"
	}

	normalizedName := strings.TrimSpace(req.Name)
	if normalizedName == "" {
		return c.Status(400).JSON(fiber.Map{"error": "Tag name cannot be empty"})
	}

	encryptedName, err := h.crypto.Encrypt([]byte(normalizedName))
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to encrypt tag name"})
	}

	lowerName := strings.ToLower(normalizedName)
	hashInput := userID.String() + ":" + lowerName
	nameHash := sha256.Sum256([]byte(hashInput))

	ctx := context.Background()
	var tagID uuid.UUID
	err = h.db.QueryRow(ctx, `
	        INSERT INTO tags (user_id, name_encrypted, name_hash, color)
	        VALUES ($1, $2, $3, $4)
	        RETURNING id`,
		userID, encryptedName, nameHash[:], req.Color).Scan(&tagID)
	if err != nil {
		if strings.Contains(err.Error(), "idx_tags_name_hash_unique") || strings.Contains(err.Error(), "duplicate") {
			return c.Status(409).JSON(fiber.Map{"error": "Tag with this name already exists"})
		}
		return c.Status(500).JSON(fiber.Map{"error": "Failed to create tag"})
	}

	return c.Status(201).JSON(fiber.Map{"id": tagID, "message": "Tag created successfully"})
}

func (h *TagsHandler) DeleteTag(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	tagID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid tag ID"})
	}

	ctx := context.Background()
	result, err := h.db.Exec(ctx, `
        DELETE FROM tags
        WHERE id = $1 AND user_id = $2`,
		tagID, userID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to delete tag"})
	}
	if result.RowsAffected() == 0 {
		return c.Status(404).JSON(fiber.Map{"error": "Tag not found"})
	}

	return c.JSON(fiber.Map{"message": "Tag deleted successfully"})
}

func (h *TagsHandler) AssignTagToNote(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	noteID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid note ID"})
	}

	var req assignTagRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
	}

	tagID, err := uuid.Parse(req.TagID)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid tag ID"})
	}

	ctx := context.Background()
	var tagExists bool
	err = h.db.QueryRow(ctx, `
        SELECT true FROM tags WHERE id = $1 AND user_id = $2`,
		tagID, userID).Scan(&tagExists)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Tag not found"})
	}

	_, err = h.db.Exec(ctx, `
        INSERT INTO note_tags (note_id, tag_id)
        VALUES ($1, $2)
        ON CONFLICT (note_id, tag_id) DO NOTHING`,
		noteID, tagID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to assign tag"})
	}

	return c.JSON(fiber.Map{"message": "Tag assigned successfully"})
}

func (h *TagsHandler) RemoveTagFromNote(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	noteID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid note ID"})
	}

	tagID, err := uuid.Parse(c.Params("tag_id"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid tag ID"})
	}

	ctx := context.Background()
	result, err := h.db.Exec(ctx, `
        DELETE FROM note_tags
        USING notes n, workspaces w, tags t
        WHERE note_tags.note_id = n.id
          AND note_tags.tag_id = t.id
          AND n.workspace_id = w.id
          AND note_tags.note_id = $1
          AND note_tags.tag_id = $2
          AND w.owner_id = $3
          AND t.user_id = $3`,
		noteID, tagID, userID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to remove tag"})
	}
	if result.RowsAffected() == 0 {
		return c.Status(404).JSON(fiber.Map{"error": "Tag assignment not found"})
	}

	return c.JSON(fiber.Map{"message": "Tag removed successfully"})
}

func (h *TagsHandler) GetNotesByTag(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	tagID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid tag ID"})
	}

	ctx := context.Background()
	rows, err := h.db.Query(ctx, `
        SELECT n.id, n.title_encrypted, n.content_encrypted, n.created_at, n.updated_at
        FROM notes n
        JOIN workspaces w ON n.workspace_id = w.id
        JOIN note_tags nt ON n.id = nt.note_id
        JOIN tags t ON nt.tag_id = t.id
        WHERE t.id = $1 AND w.owner_id = $2 AND n.deleted_at IS NULL
        ORDER BY n.updated_at DESC`,
		tagID, userID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to fetch notes"})
	}
	defer rows.Close()

	notes := []fiber.Map{}
	for rows.Next() {
		var (
			id         uuid.UUID
			titleEnc   []byte
			contentEnc []byte
			createdAt  time.Time
			updatedAt  time.Time
		)

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
