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
		SELECT id, parent_id, name_encrypted, color, position, depth, path, created_at, updated_at
		FROM folders
		WHERE user_id = $1
		ORDER BY path ASC, position ASC, created_at ASC`,
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
		var position, depth int
		var path string
		var createdAt, updatedAt time.Time

		err := rows.Scan(&id, &parentID, &nameEncrypted, &color, &position, &depth, &path, &createdAt, &updatedAt)
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
			"depth":      depth,
			"path":       path,
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
	var depth int
	var path string

	if req.ParentID != nil && *req.ParentID != "" {
		parsed, err := uuid.Parse(*req.ParentID)
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "Invalid parent ID"})
		}
		parentID = &parsed

		// Get parent folder details and verify ownership
		var parentPath string
		var parentDepth int
		err = h.db.QueryRow(ctx, `
			SELECT path, depth
			FROM folders
			WHERE id = $1 AND user_id = $2`,
			*parentID, userID).Scan(&parentPath, &parentDepth)
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "Parent folder not found"})
		}

		// Calculate depth and path
		depth = parentDepth + 1
		if depth > 10 {
			return c.Status(400).JSON(fiber.Map{"error": "Maximum folder nesting depth (10) exceeded"})
		}
	} else {
		// Root folder
		depth = 0
		path = "/"
	}

	var folderID uuid.UUID
	err = h.db.QueryRow(ctx, `
		INSERT INTO folders (user_id, parent_id, name_encrypted, color, position, depth, path)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id`,
		userID, parentID, encryptedName, req.Color, req.Position, depth, path).Scan(&folderID)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to create folder"})
	}

	// Update path with folder ID for non-root folders
	if parentID != nil {
		var parentPath string
		err = h.db.QueryRow(ctx, `SELECT path FROM folders WHERE id = $1`, *parentID).Scan(&parentPath)
		if err == nil {
			path = parentPath + folderID.String() + "/"
			_, err = h.db.Exec(ctx, `UPDATE folders SET path = $1 WHERE id = $2`, path, folderID)
		}
	} else {
		path = "/" + folderID.String() + "/"
		_, err = h.db.Exec(ctx, `UPDATE folders SET path = $1 WHERE id = $2`, path, folderID)
	}

	return c.JSON(fiber.Map{
		"id":      folderID,
		"name":    req.Name,
		"color":   req.Color,
		"depth":   depth,
		"path":    path,
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

// FolderTreeNode represents a folder in the tree structure
type FolderTreeNode struct {
	ID        string            `json:"id"`
	ParentID  *string           `json:"parent_id"`
	Name      string            `json:"name"`
	Color     string            `json:"color"`
	Position  int               `json:"position"`
	Depth     int               `json:"depth"`
	Path      string            `json:"path"`
	Children  []FolderTreeNode  `json:"children"`
	CreatedAt time.Time         `json:"created_at"`
	UpdatedAt time.Time         `json:"updated_at"`
}

// GetFolderTree returns folders in a hierarchical tree structure
func (h *FoldersHandler) GetFolderTree(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	ctx := context.Background()

	rows, err := h.db.Query(ctx, `
		SELECT id, parent_id, name_encrypted, color, position, depth, path, created_at, updated_at
		FROM folders
		WHERE user_id = $1
		ORDER BY path ASC, position ASC`,
		userID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to fetch folders"})
	}
	defer rows.Close()

	// Build flat list first
	flatFolders := []FolderTreeNode{}
	folderMap := make(map[string]*FolderTreeNode)

	for rows.Next() {
		var id uuid.UUID
		var parentID *uuid.UUID
		var nameEncrypted []byte
		var color string
		var position, depth int
		var path string
		var createdAt, updatedAt time.Time

		err := rows.Scan(&id, &parentID, &nameEncrypted, &color, &position, &depth, &path, &createdAt, &updatedAt)
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

		node := FolderTreeNode{
			ID:        id.String(),
			ParentID:  parentIDStr,
			Name:      string(nameBytes),
			Color:     color,
			Position:  position,
			Depth:     depth,
			Path:      path,
			Children:  []FolderTreeNode{},
			CreatedAt: createdAt,
			UpdatedAt: updatedAt,
		}

		flatFolders = append(flatFolders, node)
		folderMap[node.ID] = &flatFolders[len(flatFolders)-1]
	}

	// Build tree structure
	rootFolders := []FolderTreeNode{}
	for i := range flatFolders {
		folder := &flatFolders[i]
		if folder.ParentID == nil {
			rootFolders = append(rootFolders, *folder)
		} else {
			if parent, exists := folderMap[*folder.ParentID]; exists {
				parent.Children = append(parent.Children, *folder)
			}
		}
	}

	return c.JSON(fiber.Map{"folders": rootFolders})
}

// MoveFolderToParentRequest represents request to move a folder
type MoveFolderToParentRequest struct {
	ParentID *string `json:"parent_id"`
}

// MoveFolderToParent moves a folder to a new parent with circular reference prevention
func (h *FoldersHandler) MoveFolderToParent(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	folderID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid folder ID"})
	}

	var req MoveFolderToParentRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request format"})
	}

	ctx := context.Background()

	// Get current folder details
	var currentPath string
	var currentDepth int
	err = h.db.QueryRow(ctx, `
		SELECT path, depth FROM folders WHERE id = $1 AND user_id = $2`,
		folderID, userID).Scan(&currentPath, &currentDepth)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Folder not found"})
	}

	var newParentID *uuid.UUID
	var newDepth int
	var newPath string

	if req.ParentID != nil && *req.ParentID != "" {
		parsed, err := uuid.Parse(*req.ParentID)
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "Invalid parent ID"})
		}
		newParentID = &parsed

		// Prevent moving to self
		if parsed == folderID {
			return c.Status(400).JSON(fiber.Map{"error": "Cannot move folder to itself"})
		}

		// Get parent folder details
		var parentPath string
		var parentDepth int
		err = h.db.QueryRow(ctx, `
			SELECT path, depth FROM folders WHERE id = $1 AND user_id = $2`,
			*newParentID, userID).Scan(&parentPath, &parentDepth)
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "Parent folder not found"})
		}

		// Prevent circular reference - check if parent is descendant of folder being moved
		if len(parentPath) >= len(currentPath) && parentPath[:len(currentPath)] == currentPath {
			return c.Status(400).JSON(fiber.Map{"error": "Cannot move folder to its own descendant"})
		}

		newDepth = parentDepth + 1
		if newDepth > 10 {
			return c.Status(400).JSON(fiber.Map{"error": "Maximum folder nesting depth (10) exceeded"})
		}

		newPath = parentPath + folderID.String() + "/"
	} else {
		// Moving to root
		newDepth = 0
		newPath = "/" + folderID.String() + "/"
	}

	// Update folder
	_, err = h.db.Exec(ctx, `
		UPDATE folders
		SET parent_id = $1, depth = $2, path = $3, updated_at = NOW()
		WHERE id = $4 AND user_id = $5`,
		newParentID, newDepth, newPath, folderID, userID)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to move folder"})
	}

	// Update all descendant folders' paths and depths
	depthDiff := newDepth - currentDepth
	_, err = h.db.Exec(ctx, `
		UPDATE folders
		SET
			path = $1 || SUBSTRING(path FROM $2),
			depth = depth + $3,
			updated_at = NOW()
		WHERE user_id = $4 AND path LIKE $5 AND id != $6`,
		newPath, len(currentPath)+1, depthDiff, userID, currentPath+"%", folderID)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to update descendant folders"})
	}

	return c.JSON(fiber.Map{"message": "Folder moved successfully"})
}
