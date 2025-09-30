package handlers

import (
	"context"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"leaflock/crypto"
	"leaflock/database"
	"leaflock/utils"
)

// Folders Handler
type FoldersHandler struct {
	db     database.Database
	crypto *crypto.CryptoService
}

// NewFoldersHandler creates a new folders handler instance.
func NewFoldersHandler(db database.Database, cryptoService *crypto.CryptoService) *FoldersHandler {
	return &FoldersHandler{db: db, crypto: cryptoService}
}

type CreateFolderRequest struct {
	Name     string  `json:"name" validate:"required"`
	ParentID *string `json:"parent_id,omitempty"`
	Color    string  `json:"color,omitempty"`
	Position int     `json:"position,omitempty"`
}

type UpdateFolderRequest struct {
	Name     string  `json:"name" validate:"required"`
	ParentID *string `json:"parent_id,omitempty"`
	Color    string  `json:"color,omitempty"`
	Position int     `json:"position,omitempty"`
}

type MoveNoteToFolderRequest struct {
	FolderID *string `json:"folder_id"`
}

func (h *FoldersHandler) GetFolders(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	ctx := context.Background()

	rows, err := h.db.Query(ctx, `
		SELECT id, parent_id, name_encrypted, color, position, created_at, updated_at
		FROM folders
		WHERE user_id = $1
		ORDER BY position ASC, created_at ASC`,
		userID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to fetch folders"})
	}
	defer rows.Close()

	folders := []fiber.Map{}
	for rows.Next() {
		var id uuid.UUID
		var parentID *uuid.UUID
		var nameEncrypted []byte
		var color string
		var position int
		var createdAt, updatedAt time.Time

		err := rows.Scan(&id, &parentID, &nameEncrypted, &color, &position, &createdAt, &updatedAt)
		if err != nil {
			continue
		}

		nameBytes, err := h.crypto.Decrypt(nameEncrypted)
		if err != nil {
			continue
		}

		var parentIDStr *string
		if parentID != nil {
			str := parentID.String()
			parentIDStr = &str
		}

		folders = append(folders, fiber.Map{
			"id":         id,
			"parent_id":  parentIDStr,
			"name":       string(nameBytes),
			"color":      color,
			"position":   position,
			"created_at": createdAt,
			"updated_at": updatedAt,
		})
	}

	return c.JSON(fiber.Map{"folders": folders})
}

func (h *FoldersHandler) CreateFolder(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	var req CreateFolderRequest

	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request format"})
	}

	if req.Color != "" && !utils.IsValidHexColor(req.Color) {
		req.Color = "#3b82f6"
	} else if req.Color == "" {
		req.Color = "#3b82f6"
	}

	encryptedName, err := h.crypto.Encrypt([]byte(req.Name))
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to encrypt folder name"})
	}

	ctx := context.Background()
	var parentID *uuid.UUID
	if req.ParentID != nil && *req.ParentID != "" {
		parsed, err := uuid.Parse(*req.ParentID)
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "Invalid parent ID"})
		}
		parentID = &parsed

		var exists bool
		err = h.db.QueryRow(ctx, `SELECT true FROM folders WHERE id = $1 AND user_id = $2`, *parentID, userID).Scan(&exists)
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "Parent folder not found"})
		}
	}

	var folderID uuid.UUID
	err = h.db.QueryRow(ctx, `
		INSERT INTO folders (user_id, parent_id, name_encrypted, color, position)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id`,
		userID, parentID, encryptedName, req.Color, req.Position).Scan(&folderID)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to create folder"})
	}

	return c.JSON(fiber.Map{
		"id":      folderID,
		"name":    req.Name,
		"color":   req.Color,
		"message": "Folder created successfully",
	})
}

func (h *FoldersHandler) DeleteFolder(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	folderID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid folder ID"})
	}

	ctx := context.Background()

	_, err = h.db.Exec(ctx, `
		UPDATE notes
		SET folder_id = (
			SELECT parent_id FROM folders WHERE id = $1 AND user_id = $2
		)
		WHERE folder_id = $1`,
		folderID, userID)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to move notes from folder"})
	}

	_, err = h.db.Exec(ctx, `
		DELETE FROM folders
		WHERE id = $1 AND user_id = $2`,
		folderID, userID)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to delete folder"})
	}

	return c.JSON(fiber.Map{"message": "Folder deleted successfully"})
}

func (h *FoldersHandler) MoveNoteToFolder(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	noteID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid note ID"})
	}

	var req MoveNoteToFolderRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request format"})
	}

	ctx := context.Background()
	var folderID *uuid.UUID

	if req.FolderID != nil && *req.FolderID != "" {
		parsed, err := uuid.Parse(*req.FolderID)
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "Invalid folder ID"})
		}
		folderID = &parsed

		var exists bool
		err = h.db.QueryRow(ctx, `SELECT true FROM folders WHERE id = $1 AND user_id = $2`, *folderID, userID).Scan(&exists)
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "Folder not found"})
		}
	}

	_, err = h.db.Exec(ctx, `
		UPDATE notes
		SET folder_id = $1, updated_at = NOW()
		FROM workspaces w
		WHERE notes.id = $2
		AND notes.workspace_id = w.id
		AND w.owner_id = $3`,
		folderID, noteID, userID)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to move note"})
	}

	return c.JSON(fiber.Map{"message": "Note moved successfully"})
}
