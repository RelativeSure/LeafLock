package handlers

import (
	"context"
	"log"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"leaflock/crypto"
	"leaflock/database"
)

// Templates Handler
type TemplatesHandler struct {
	db     database.Database
	crypto *crypto.CryptoService
}

// NewTemplatesHandler constructs a TemplatesHandler instance.
func NewTemplatesHandler(db database.Database, cryptoService *crypto.CryptoService) *TemplatesHandler {
	return &TemplatesHandler{db: db, crypto: cryptoService}
}

type CreateTemplateRequest struct {
	Name        string   `json:"name" validate:"required"`
	Description string   `json:"description,omitempty"`
	Content     string   `json:"content" validate:"required"`
	Tags        []string `json:"tags,omitempty"`
	Icon        string   `json:"icon,omitempty"`
	IsPublic    bool     `json:"is_public,omitempty"`
}

type UpdateTemplateRequest struct {
	Name        string   `json:"name" validate:"required"`
	Description string   `json:"description,omitempty"`
	Content     string   `json:"content" validate:"required"`
	Tags        []string `json:"tags,omitempty"`
	Icon        string   `json:"icon,omitempty"`
	IsPublic    bool     `json:"is_public,omitempty"`
}

type UseTemplateRequest struct {
	Title    string  `json:"title,omitempty"`
	FolderID *string `json:"folder_id,omitempty"`
}

func (h *TemplatesHandler) GetTemplates(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	ctx := context.Background()

	rows, err := h.db.Query(ctx, `
		SELECT id, name_encrypted, description_encrypted, content_encrypted, tags, icon, is_public, usage_count, created_at, updated_at
		FROM templates
		WHERE user_id = $1 OR is_public = true
		ORDER BY created_at DESC
	`, userID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to fetch templates"})
	}
	defer rows.Close()

	var templates []map[string]interface{}
	for rows.Next() {
		var id uuid.UUID
		var nameEncrypted, descriptionEncrypted, contentEncrypted []byte
		var tags []string
		var icon string
		var isPublic bool
		var usageCount int
		var createdAt, updatedAt time.Time

		err := rows.Scan(&id, &nameEncrypted, &descriptionEncrypted, &contentEncrypted, &tags, &icon, &isPublic, &usageCount, &createdAt, &updatedAt)
		if err != nil {
			continue
		}

		// Decrypt template data
		nameBytes, err := h.crypto.Decrypt(nameEncrypted)
		if err != nil {
			continue
		}
		name := string(nameBytes)

		var description string
		if len(descriptionEncrypted) > 0 {
			descBytes, err := h.crypto.Decrypt(descriptionEncrypted)
			if err == nil {
				description = string(descBytes)
			}
		}

		// Don't decrypt content for listing (performance)
		template := map[string]interface{}{
			"id":          id,
			"name":        name,
			"description": description,
			"tags":        tags,
			"icon":        icon,
			"is_public":   isPublic,
			"usage_count": usageCount,
			"created_at":  createdAt,
			"updated_at":  updatedAt,
		}

		templates = append(templates, template)
	}

	return c.JSON(fiber.Map{"templates": templates})
}

func (h *TemplatesHandler) GetTemplate(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	templateID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid template ID"})
	}

	ctx := context.Background()
	var nameEncrypted, descriptionEncrypted, contentEncrypted []byte
	var tags []string
	var icon string
	var isPublic bool
	var usageCount int
	var createdAt, updatedAt time.Time

	err = h.db.QueryRow(ctx, `
		SELECT name_encrypted, description_encrypted, content_encrypted, tags, icon, is_public, usage_count, created_at, updated_at
		FROM templates
		WHERE id = $1 AND (user_id = $2 OR is_public = true)
	`, templateID, userID).Scan(&nameEncrypted, &descriptionEncrypted, &contentEncrypted, &tags, &icon, &isPublic, &usageCount, &createdAt, &updatedAt)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Template not found"})
	}

	// Decrypt template data
	nameBytes, err := h.crypto.Decrypt(nameEncrypted)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to decrypt template name"})
	}
	name := string(nameBytes)

	var description string
	if len(descriptionEncrypted) > 0 {
		descBytes, err := h.crypto.Decrypt(descriptionEncrypted)
		if err == nil {
			description = string(descBytes)
		}
	}

	contentBytes, err := h.crypto.Decrypt(contentEncrypted)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to decrypt template content"})
	}
	content := string(contentBytes)

	template := map[string]interface{}{
		"id":          templateID,
		"name":        name,
		"description": description,
		"content":     content,
		"tags":        tags,
		"icon":        icon,
		"is_public":   isPublic,
		"usage_count": usageCount,
		"created_at":  createdAt,
		"updated_at":  updatedAt,
	}

	return c.JSON(template)
}

func (h *TemplatesHandler) CreateTemplate(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	var req CreateTemplateRequest

	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request format"})
	}

	// Encrypt template data
	nameEncrypted, err := h.crypto.Encrypt([]byte(req.Name))
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to encrypt template name"})
	}

	var descriptionEncrypted []byte
	if req.Description != "" {
		descriptionEncrypted, err = h.crypto.Encrypt([]byte(req.Description))
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "Failed to encrypt template description"})
		}
	}

	contentEncrypted, err := h.crypto.Encrypt([]byte(req.Content))
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to encrypt template content"})
	}

	// Default icon if not provided
	icon := req.Icon
	if icon == "" {
		icon = "📝"
	}

	ctx := context.Background()
	var templateID uuid.UUID
	err = h.db.QueryRow(ctx, `
		INSERT INTO templates (user_id, name_encrypted, description_encrypted, content_encrypted, tags, icon, is_public)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id
	`, userID, nameEncrypted, descriptionEncrypted, contentEncrypted, req.Tags, icon, req.IsPublic).Scan(&templateID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to create template"})
	}

	return c.Status(201).JSON(fiber.Map{
		"id":      templateID,
		"message": "Template created successfully",
	})
}

func (h *TemplatesHandler) UpdateTemplate(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	templateID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid template ID"})
	}

	var req UpdateTemplateRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request format"})
	}

	// Encrypt template data
	nameEncrypted, err := h.crypto.Encrypt([]byte(req.Name))
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to encrypt template name"})
	}

	var descriptionEncrypted []byte
	if req.Description != "" {
		descriptionEncrypted, err = h.crypto.Encrypt([]byte(req.Description))
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "Failed to encrypt template description"})
		}
	}

	contentEncrypted, err := h.crypto.Encrypt([]byte(req.Content))
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to encrypt template content"})
	}

	// Default icon if not provided
	icon := req.Icon
	if icon == "" {
		icon = "📝"
	}

	ctx := context.Background()
	result, err := h.db.Exec(ctx, `
		UPDATE templates
		SET name_encrypted = $3, description_encrypted = $4, content_encrypted = $5, tags = $6, icon = $7, is_public = $8, updated_at = NOW()
		WHERE id = $1 AND user_id = $2
	`, templateID, userID, nameEncrypted, descriptionEncrypted, contentEncrypted, req.Tags, icon, req.IsPublic)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to update template"})
	}

	if result.RowsAffected() == 0 {
		return c.Status(404).JSON(fiber.Map{"error": "Template not found or access denied"})
	}

	return c.JSON(fiber.Map{"message": "Template updated successfully"})
}

func (h *TemplatesHandler) DeleteTemplate(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	templateID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid template ID"})
	}

	ctx := context.Background()
	result, err := h.db.Exec(ctx, `DELETE FROM templates WHERE id = $1 AND user_id = $2`, templateID, userID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to delete template"})
	}

	if result.RowsAffected() == 0 {
		return c.Status(404).JSON(fiber.Map{"error": "Template not found or access denied"})
	}

	return c.JSON(fiber.Map{"message": "Template deleted successfully"})
}

func (h *TemplatesHandler) UseTemplate(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	templateID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid template ID"})
	}

	var req UseTemplateRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request format"})
	}

	ctx := context.Background()

	// Get template content
	var contentEncrypted []byte
	var nameEncrypted []byte
	err = h.db.QueryRow(ctx, `
		SELECT name_encrypted, content_encrypted
		FROM templates
		WHERE id = $1 AND (user_id = $2 OR is_public = true)
	`, templateID, userID).Scan(&nameEncrypted, &contentEncrypted)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Template not found"})
	}

	// Decrypt template data
	templateNameBytes, err := h.crypto.Decrypt(nameEncrypted)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to decrypt template name"})
	}
	templateName := string(templateNameBytes)

	contentBytes, err := h.crypto.Decrypt(contentEncrypted)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to decrypt template content"})
	}
	content := string(contentBytes)

	// Use provided title or template name
	title := req.Title
	if title == "" {
		title = templateName
	}

	// Encrypt note data
	titleEncrypted, err := h.crypto.Encrypt([]byte(title))
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to encrypt note title"})
	}

	contentEncryptedForNote, err := h.crypto.Encrypt([]byte(content))
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to encrypt note content"})
	}

	// Parse folder ID if provided
	var folderID *uuid.UUID
	if req.FolderID != nil && *req.FolderID != "" {
		parsed, err := uuid.Parse(*req.FolderID)
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "Invalid folder ID"})
		}
		folderID = &parsed

		// Verify folder exists and belongs to user
		var exists bool
		err = h.db.QueryRow(ctx, `SELECT true FROM folders WHERE id = $1 AND user_id = $2`, *folderID, userID).Scan(&exists)
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "Folder not found"})
		}
	}

	// Create new note from template
	var noteID uuid.UUID
	err = h.db.QueryRow(ctx, `
		INSERT INTO notes (user_id, title_encrypted, content_encrypted, template_id, folder_id)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id
	`, userID, titleEncrypted, contentEncryptedForNote, templateID, folderID).Scan(&noteID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to create note from template"})
	}

	// Increment template usage count
	_, err = h.db.Exec(ctx, `
		UPDATE templates SET usage_count = usage_count + 1 WHERE id = $1
	`, templateID)
	if err != nil {
		// Log error but don't fail the request
		log.Printf("Failed to increment template usage count: %v", err)
	}

	return c.Status(201).JSON(fiber.Map{
		"id":      noteID,
		"message": "Note created from template successfully",
	})
}
