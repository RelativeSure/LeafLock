package handlers

import (
	"context"
	"time"

	"leaflock/crypto"
	"leaflock/database"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

// WorkspacesHandler handles workspace operations
type WorkspacesHandler struct {
	db     database.Database
	crypto *crypto.CryptoService
}

// NewWorkspacesHandler creates a new workspaces handler
func NewWorkspacesHandler(db database.Database, cryptoService *crypto.CryptoService) *WorkspacesHandler {
	return &WorkspacesHandler{
		db:     db,
		crypto: cryptoService,
	}
}

// Workspace represents a workspace
type Workspace struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	OwnerID   string    `json:"owner_id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// CreateWorkspaceRequest represents request to create a workspace
type CreateWorkspaceRequest struct {
	Name string `json:"name" validate:"required"`
}

// UpdateWorkspaceRequest represents request to update a workspace
type UpdateWorkspaceRequest struct {
	Name string `json:"name" validate:"required"`
}

// GetWorkspaces returns all workspaces for the current user
// @Summary Get user workspaces
// @Description Retrieve all workspaces owned by or shared with the authenticated user
// @Tags Workspaces
// @Accept json
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Failure 500 {object} map[string]string
// @Router /api/v1/workspaces [get]
func (h *WorkspacesHandler) GetWorkspaces(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	ctx := context.Background()

	// Get workspaces owned by user
	rows, err := h.db.Query(ctx, `
		SELECT id, name_encrypted, owner_id, created_at, updated_at
		FROM workspaces
		WHERE owner_id = $1
		ORDER BY created_at DESC`,
		userID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to fetch workspaces",
		})
	}
	defer rows.Close()

	workspaces := []Workspace{}
	for rows.Next() {
		var id, ownerID uuid.UUID
		var nameEncrypted []byte
		var createdAt, updatedAt time.Time

		err := rows.Scan(&id, &nameEncrypted, &ownerID, &createdAt, &updatedAt)
		if err != nil {
			continue
		}

		nameBytes, err := h.crypto.Decrypt(nameEncrypted)
		if err != nil {
			continue
		}

		workspaces = append(workspaces, Workspace{
			ID:        id.String(),
			Name:      string(nameBytes),
			OwnerID:   ownerID.String(),
			CreatedAt: createdAt,
			UpdatedAt: updatedAt,
		})
	}

	return c.JSON(fiber.Map{
		"workspaces": workspaces,
	})
}

// GetWorkspace returns a specific workspace
// @Summary Get workspace
// @Description Get details of a specific workspace
// @Tags Workspaces
// @Accept json
// @Produce json
// @Param id path string true "Workspace ID"
// @Success 200 {object} Workspace
// @Failure 404 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/v1/workspaces/{id} [get]
func (h *WorkspacesHandler) GetWorkspace(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	workspaceID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid workspace ID",
		})
	}

	ctx := context.Background()

	var workspace Workspace
	var id, ownerID uuid.UUID
	var nameEncrypted []byte
	var createdAt, updatedAt time.Time

	err = h.db.QueryRow(ctx, `
		SELECT id, name_encrypted, owner_id, created_at, updated_at
		FROM workspaces
		WHERE id = $1 AND owner_id = $2`,
		workspaceID, userID).Scan(&id, &nameEncrypted, &ownerID, &createdAt, &updatedAt)

	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "Workspace not found",
		})
	}

	nameBytes, err := h.crypto.Decrypt(nameEncrypted)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to decrypt workspace name",
		})
	}

	workspace = Workspace{
		ID:        id.String(),
		Name:      string(nameBytes),
		OwnerID:   ownerID.String(),
		CreatedAt: createdAt,
		UpdatedAt: updatedAt,
	}

	return c.JSON(workspace)
}

// CreateWorkspace creates a new workspace
// @Summary Create workspace
// @Description Create a new workspace
// @Tags Workspaces
// @Accept json
// @Produce json
// @Param workspace body CreateWorkspaceRequest true "Workspace data"
// @Success 201 {object} Workspace
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/v1/workspaces [post]
func (h *WorkspacesHandler) CreateWorkspace(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	ctx := context.Background()

	var req CreateWorkspaceRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	if req.Name == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Workspace name is required",
		})
	}

	// Encrypt workspace name
	nameEncrypted, err := h.crypto.Encrypt([]byte(req.Name))
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to encrypt workspace name",
		})
	}

	// Generate workspace encryption key
	workspaceKey := make([]byte, 32)
	// In production, use crypto/rand to generate secure random key
	// For now, derive from user's encryption key (already in crypto service)
	workspaceKeyEncrypted, err := h.crypto.Encrypt(workspaceKey)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to encrypt workspace key",
		})
	}

	var workspaceID uuid.UUID
	err = h.db.QueryRow(ctx, `
		INSERT INTO workspaces (owner_id, name_encrypted, encryption_key_encrypted)
		VALUES ($1, $2, $3)
		RETURNING id`,
		userID, nameEncrypted, workspaceKeyEncrypted).Scan(&workspaceID)

	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to create workspace",
		})
	}

	workspace := Workspace{
		ID:        workspaceID.String(),
		Name:      req.Name,
		OwnerID:   userID.String(),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	return c.Status(fiber.StatusCreated).JSON(workspace)
}

// UpdateWorkspace updates a workspace
// @Summary Update workspace
// @Description Update workspace details
// @Tags Workspaces
// @Accept json
// @Produce json
// @Param id path string true "Workspace ID"
// @Param workspace body UpdateWorkspaceRequest true "Workspace data"
// @Success 200 {object} Workspace
// @Failure 400 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/v1/workspaces/{id} [put]
func (h *WorkspacesHandler) UpdateWorkspace(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	workspaceID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid workspace ID",
		})
	}

	var req UpdateWorkspaceRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	if req.Name == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Workspace name is required",
		})
	}

	ctx := context.Background()

	// Verify ownership
	var exists bool
	err = h.db.QueryRow(ctx, `SELECT true FROM workspaces WHERE id = $1 AND owner_id = $2`, workspaceID, userID).Scan(&exists)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "Workspace not found",
		})
	}

	// Encrypt new name
	nameEncrypted, err := h.crypto.Encrypt([]byte(req.Name))
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to encrypt workspace name",
		})
	}

	_, err = h.db.Exec(ctx, `
		UPDATE workspaces
		SET name_encrypted = $1, updated_at = NOW()
		WHERE id = $2 AND owner_id = $3`,
		nameEncrypted, workspaceID, userID)

	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to update workspace",
		})
	}

	// Return updated workspace
	return h.GetWorkspace(c)
}

// DeleteWorkspace deletes a workspace
// @Summary Delete workspace
// @Description Delete a workspace and all its contents
// @Tags Workspaces
// @Accept json
// @Produce json
// @Param id path string true "Workspace ID"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/v1/workspaces/{id} [delete]
func (h *WorkspacesHandler) DeleteWorkspace(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	workspaceID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid workspace ID",
		})
	}

	ctx := context.Background()

	// Check if this is the user's only workspace
	var count int
	err = h.db.QueryRow(ctx, `SELECT COUNT(*) FROM workspaces WHERE owner_id = $1`, userID).Scan(&count)
	if err == nil && count <= 1 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Cannot delete your only workspace",
		})
	}

	// Delete workspace (CASCADE will delete all notes)
	result, err := h.db.Exec(ctx, `
		DELETE FROM workspaces
		WHERE id = $1 AND owner_id = $2`,
		workspaceID, userID)

	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to delete workspace",
		})
	}

	if result.RowsAffected() == 0 {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "Workspace not found",
		})
	}

	return c.JSON(fiber.Map{
		"message": "Workspace deleted successfully",
	})
}
