package handlers

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"leaflock/crypto"
	"leaflock/database"
	"leaflock/metrics"
	"leaflock/services"
	"leaflock/utils"
)

// ShareLinksHandler handles share link operations
type ShareLinksHandler struct {
	db               database.Database
	crypto           *crypto.CryptoService
	shareLinkService *services.ShareLinkService
}

// NewShareLinksHandler creates a new share links handler
func NewShareLinksHandler(db database.Database, cryptoService *crypto.CryptoService, rdb *redis.Client) *ShareLinksHandler {
	return &ShareLinksHandler{
		db:               db,
		crypto:           cryptoService,
		shareLinkService: services.NewShareLinkService(rdb),
	}
}

// CreateShareLinkRequest represents the request to create a share link
type CreateShareLinkRequest struct {
	Permission string  `json:"permission" validate:"required,oneof=read write"`
	ExpiresIn  *string `json:"expires_in,omitempty"` // "1h", "24h", "7d", "30d", or null for never
	MaxUses    *int    `json:"max_uses,omitempty"`   // null for unlimited
	Password   *string `json:"password,omitempty"`   // Optional password protection
}

// ShareLinkResponse represents a share link
type ShareLinkResponse struct {
	ID            string    `json:"id"`
	Token         string    `json:"token"`
	NoteID        string    `json:"note_id"`
	Permission    string    `json:"permission"`
	ExpiresAt     *string   `json:"expires_at,omitempty"`
	MaxUses       *int      `json:"max_uses,omitempty"`
	UseCount      int       `json:"use_count"`
	IsActive      bool      `json:"is_active"`
	HasPassword   bool      `json:"has_password"`
	CreatedAt     string    `json:"created_at"`
	LastAccessedAt *string  `json:"last_accessed_at,omitempty"`
	ShareURL      string    `json:"share_url"`
}

// CreateShareLink godoc
// @Summary Create a shareable link for a note
// @Description Create a public shareable link with read or write permissions
// @Tags ShareLinks
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "Note ID"
// @Param request body CreateShareLinkRequest true "Share link configuration"
// @Success 201 {object} ShareLinkResponse
// @Failure 400 {object} map[string]interface{} "Invalid request"
// @Failure 404 {object} map[string]interface{} "Note not found"
// @Router /notes/{id}/share-links [post]
func (h *ShareLinksHandler) CreateShareLink(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	noteID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid note ID"})
	}

	ctx := context.Background()

	var req CreateShareLinkRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
	}

	// Verify user owns the note
	var ownerCheck bool
	err = h.db.QueryRow(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM notes n
			JOIN workspaces w ON n.workspace_id = w.id
			WHERE n.id = $1 AND w.owner_id = $2 AND n.deleted_at IS NULL
		)`, noteID, userID).Scan(&ownerCheck)

	if err != nil || !ownerCheck {
		return c.Status(404).JSON(fiber.Map{"error": "Note not found"})
	}

	// Generate unique token
	token, err := services.GenerateToken()
	if err != nil {
		utils.LogRequestError(c, "CreateShareLink: failed to generate token", err)
		return c.Status(500).JSON(fiber.Map{"error": "Failed to generate share link"})
	}

	// Calculate expiration
	var expiresAt *time.Time
	if req.ExpiresIn != nil {
		duration, err := parseDuration(*req.ExpiresIn)
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "Invalid expires_in value"})
		}
		expiry := time.Now().Add(duration)
		expiresAt = &expiry
	}

	// Hash password if provided
	var passwordHash *string
	if req.Password != nil && *req.Password != "" {
		salt := make([]byte, 32)
		if _, err := rand.Read(salt); err != nil {
			utils.LogRequestError(c, "CreateShareLink: failed to generate salt", err)
			return c.Status(500).JSON(fiber.Map{"error": "Failed to process password"})
		}
		hash := crypto.HashPassword(*req.Password, salt)
		passwordHash = &hash
	}

	// Create share link in database
	var linkID uuid.UUID
	var createdAt time.Time
	err = h.db.QueryRow(ctx, `
		INSERT INTO share_links (note_id, token, permission, password_hash, expires_at, max_uses, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, created_at`,
		noteID, token, req.Permission, passwordHash, expiresAt, req.MaxUses, userID).
		Scan(&linkID, &createdAt)

	if err != nil {
		utils.LogRequestError(c, "CreateShareLink: failed to create share link", err)
		return c.Status(500).JSON(fiber.Map{"error": "Failed to create share link"})
	}

	// Cache in Redis
	cacheData := services.ShareLinkCache{
		NoteID:      noteID.String(),
		Permission:  req.Permission,
		MaxUses:     0,
		UseCount:    0,
		HasPassword: passwordHash != nil,
	}
	if expiresAt != nil {
		cacheData.ExpiresAt = *expiresAt
	}
	if req.MaxUses != nil {
		cacheData.MaxUses = *req.MaxUses
	}

	if err := h.shareLinkService.CacheShareLink(ctx, token, cacheData); err != nil {
		// Log warning but don't fail the request
		utils.LogRequestError(c, "CreateShareLink: failed to cache share link", err)
	}

	// Log the action
	h.auditLog(userID, "create_share_link", fiber.Map{
		"link_id":    linkID,
		"note_id":    noteID,
		"permission": req.Permission,
	})

	// Build response
	response := ShareLinkResponse{
		ID:          linkID.String(),
		Token:       token,
		NoteID:      noteID.String(),
		Permission:  req.Permission,
		MaxUses:     req.MaxUses,
		UseCount:    0,
		IsActive:    true,
		HasPassword: passwordHash != nil,
		CreatedAt:   createdAt.Format(time.RFC3339),
		ShareURL:    buildShareURL(c, token),
	}
	if expiresAt != nil {
		expiryStr := expiresAt.Format(time.RFC3339)
		response.ExpiresAt = &expiryStr
	}

	return c.Status(201).JSON(response)
}

// GetNoteShareLinks godoc
// @Summary Get share links for a note
// @Description Get all share links for a specific note
// @Tags ShareLinks
// @Produce json
// @Security BearerAuth
// @Param id path string true "Note ID"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{} "Invalid note ID"
// @Failure 404 {object} map[string]interface{} "Note not found"
// @Router /notes/{id}/share-links [get]
func (h *ShareLinksHandler) GetNoteShareLinks(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	noteID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid note ID"})
	}

	ctx := context.Background()

	// Verify user owns the note
	var ownerCheck bool
	err = h.db.QueryRow(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM notes n
			JOIN workspaces w ON n.workspace_id = w.id
			WHERE n.id = $1 AND w.owner_id = $2 AND n.deleted_at IS NULL
		)`, noteID, userID).Scan(&ownerCheck)

	if err != nil || !ownerCheck {
		return c.Status(404).JSON(fiber.Map{"error": "Note not found"})
	}

	// Get share links
	rows, err := h.db.Query(ctx, `
		SELECT id, token, permission, expires_at, max_uses, use_count, is_active,
			   password_hash IS NOT NULL as has_password, created_at, last_accessed_at
		FROM share_links
		WHERE note_id = $1
		ORDER BY created_at DESC`, noteID)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to fetch share links"})
	}
	defer rows.Close()

	links := []ShareLinkResponse{}
	for rows.Next() {
		var link ShareLinkResponse
		var linkID uuid.UUID
		var expiresAt, lastAccessedAt *time.Time
		var createdAt time.Time

		if err := rows.Scan(&linkID, &link.Token, &link.Permission, &expiresAt, &link.MaxUses,
			&link.UseCount, &link.IsActive, &link.HasPassword, &createdAt, &lastAccessedAt); err != nil {
			continue
		}

		link.ID = linkID.String()
		link.NoteID = noteID.String()
		link.CreatedAt = createdAt.Format(time.RFC3339)
		link.ShareURL = buildShareURL(c, link.Token)

		if expiresAt != nil {
			expiryStr := expiresAt.Format(time.RFC3339)
			link.ExpiresAt = &expiryStr
		}
		if lastAccessedAt != nil {
			accessedStr := lastAccessedAt.Format(time.RFC3339)
			link.LastAccessedAt = &accessedStr
		}

		links = append(links, link)
	}

	return c.JSON(fiber.Map{"share_links": links})
}

// GetAllUserShareLinks godoc
// @Summary Get all user's share links
// @Description Get all share links created by the current user across all notes
// @Tags ShareLinks
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{}
// @Router /share-links [get]
func (h *ShareLinksHandler) GetAllUserShareLinks(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	ctx := context.Background()

	// Get all user's share links with note titles
	rows, err := h.db.Query(ctx, `
		SELECT sl.id, sl.token, sl.note_id, n.title_encrypted, sl.permission,
			   sl.expires_at, sl.max_uses, sl.use_count, sl.is_active,
			   sl.password_hash IS NOT NULL as has_password,
			   sl.created_at, sl.last_accessed_at
		FROM share_links sl
		JOIN notes n ON sl.note_id = n.id
		WHERE sl.created_by = $1 AND n.deleted_at IS NULL
		ORDER BY sl.created_at DESC`, userID)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to fetch share links"})
	}
	defer rows.Close()

	links := []fiber.Map{}
	for rows.Next() {
		var linkID, noteID uuid.UUID
		var token, permission string
		var titleEncrypted []byte
		var expiresAt, lastAccessedAt *time.Time
		var maxUses *int
		var useCount int
		var isActive, hasPassword bool
		var createdAt time.Time

		if err := rows.Scan(&linkID, &token, &noteID, &titleEncrypted, &permission,
			&expiresAt, &maxUses, &useCount, &isActive, &hasPassword,
			&createdAt, &lastAccessedAt); err != nil {
			continue
		}

		// Decrypt note title
		title, err := h.crypto.Decrypt(titleEncrypted)
		if err != nil {
			title = []byte("(Encrypted)")
		}

		linkData := fiber.Map{
			"id":           linkID.String(),
			"token":        token,
			"note_id":      noteID.String(),
			"note_title":   string(title),
			"permission":   permission,
			"use_count":    useCount,
			"is_active":    isActive,
			"has_password": hasPassword,
			"created_at":   createdAt.Format(time.RFC3339),
			"share_url":    buildShareURL(c, token),
		}

		if expiresAt != nil {
			linkData["expires_at"] = expiresAt.Format(time.RFC3339)
		}
		if maxUses != nil {
			linkData["max_uses"] = *maxUses
		}
		if lastAccessedAt != nil {
			linkData["last_accessed_at"] = lastAccessedAt.Format(time.RFC3339)
		}

		links = append(links, linkData)
	}

	return c.JSON(fiber.Map{"share_links": links})
}

// RevokeShareLink godoc
// @Summary Revoke a share link
// @Description Revoke (deactivate) a share link by token
// @Tags ShareLinks
// @Security BearerAuth
// @Param token path string true "Share link token"
// @Success 200 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{} "Share link not found"
// @Router /share-links/{token} [delete]
func (h *ShareLinksHandler) RevokeShareLink(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	token := c.Params("token")
	ctx := context.Background()

	// Update link to inactive
	result, err := h.db.Exec(ctx, `
		UPDATE share_links
		SET is_active = false
		WHERE token = $1 AND created_by = $2`,
		token, userID)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to revoke share link"})
	}

	if result.RowsAffected() == 0 {
		return c.Status(404).JSON(fiber.Map{"error": "Share link not found"})
	}

	// Invalidate cache
	if err := h.shareLinkService.InvalidateShareLink(ctx, token); err != nil {
		utils.LogRequestError(c, "RevokeShareLink: failed to invalidate cache", err)
	}

	// Log the action
	h.auditLog(userID, "revoke_share_link", fiber.Map{"token": token})

	return c.JSON(fiber.Map{"message": "Share link revoked successfully"})
}

// UpdateShareLink godoc
// @Summary Update a share link
// @Description Update share link properties (extend expiry, change permission, etc.)
// @Tags ShareLinks
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param token path string true "Share link token"
// @Param request body map[string]interface{} true "Update fields"
// @Success 200 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{} "Share link not found"
// @Router /share-links/{token} [put]
func (h *ShareLinksHandler) UpdateShareLink(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	token := c.Params("token")
	ctx := context.Background()

	var req map[string]interface{}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
	}

	// Build update query dynamically based on provided fields
	updates := []string{}
	args := []interface{}{token, userID}
	argPos := 3

	if expiresIn, ok := req["expires_in"].(string); ok {
		duration, err := parseDuration(expiresIn)
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "Invalid expires_in value"})
		}
		expiry := time.Now().Add(duration)
		updates = append(updates, fmt.Sprintf("expires_at = $%d", argPos))
		args = append(args, expiry)
		argPos++
	}

	if permission, ok := req["permission"].(string); ok {
		if permission != "read" && permission != "write" {
			return c.Status(400).JSON(fiber.Map{"error": "Invalid permission"})
		}
		updates = append(updates, fmt.Sprintf("permission = $%d", argPos))
		args = append(args, permission)
	}

	if len(updates) == 0 {
		return c.Status(400).JSON(fiber.Map{"error": "No fields to update"})
	}

	// Execute update
	query := fmt.Sprintf(`
		UPDATE share_links
		SET %s
		WHERE token = $1 AND created_by = $2
	`, strings.Join(updates, ", "))

	result, err := h.db.Exec(ctx, query, args...)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to update share link"})
	}

	if result.RowsAffected() == 0 {
		return c.Status(404).JSON(fiber.Map{"error": "Share link not found"})
	}

	// Invalidate cache to force refresh
	if err := h.shareLinkService.InvalidateShareLink(ctx, token); err != nil {
		utils.LogRequestError(c, "UpdateShareLink: failed to invalidate cache", err)
	}

	// Log the action
	h.auditLog(userID, "update_share_link", fiber.Map{"token": token})

	return c.JSON(fiber.Map{"message": "Share link updated successfully"})
}

// Helper functions

func parseDuration(str string) (time.Duration, error) {
	switch str {
	case "1h":
		return time.Hour, nil
	case "24h", "1d":
		return 24 * time.Hour, nil
	case "7d":
		return 7 * 24 * time.Hour, nil
	case "30d":
		return 30 * 24 * time.Hour, nil
	default:
		return 0, fmt.Errorf("invalid duration: %s", str)
	}
}

func buildShareURL(c *fiber.Ctx, token string) string {
	scheme := "https"
	if c.Protocol() == "http" {
		scheme = "http"
	}
	host := c.Hostname()
	return fmt.Sprintf("%s://%s/share/%s", scheme, host, token)
}

// GetSharedNote godoc
// @Summary Access a note via share link (public endpoint)
// @Description Get note content via share link token
// @Tags ShareLinks
// @Produce json
// @Param token path string true "Share link token"
// @Success 200 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{} "Link expired or revoked"
// @Failure 404 {object} map[string]interface{} "Share link not found"
// @Router /share/{token} [get]
func (h *ShareLinksHandler) GetSharedNote(c *fiber.Ctx) error {
	// Share link validation is handled by middleware
	noteID := c.Locals("share_link_note_id").(uuid.UUID)
	permission := c.Locals("share_link_permission").(string)

	ctx := context.Background()

	// Get note content
	var titleEnc, contentEnc []byte
	var createdAt, updatedAt time.Time
	var createdBy uuid.UUID

	err := h.db.QueryRow(ctx, `
		SELECT title_encrypted, content_encrypted, created_at, updated_at, created_by
		FROM notes
		WHERE id = $1 AND deleted_at IS NULL`, noteID).
		Scan(&titleEnc, &contentEnc, &createdAt, &updatedAt, &createdBy)

	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Note not found"})
	}

	// Get creator email
	var creatorEmail string
	_ = h.db.QueryRow(ctx, `SELECT email FROM users WHERE id = $1`, createdBy).Scan(&creatorEmail)

	// Return note data with permission level
	return c.JSON(fiber.Map{
		"id":                noteID.String(),
		"title_encrypted":   titleEnc,
		"content_encrypted": contentEnc,
		"created_at":        createdAt.Format(time.RFC3339),
		"updated_at":        updatedAt.Format(time.RFC3339),
		"permission":        permission,
		"shared_by":         creatorEmail,
		"is_shared_access":  true,
	})
}

func (h *ShareLinksHandler) auditLog(userID uuid.UUID, action string, metadata fiber.Map) {
	ctx := context.Background()

	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return
	}

	if _, err := h.db.Exec(ctx, `
		INSERT INTO audit_log (user_id, action, resource_type, metadata_encrypted)
		VALUES ($1, $2, $3, $4)`,
		userID, action, "share_link", metadataJSON,
	); err != nil {
		metrics.IncrementError("audit_log", "share_link")
	}
}
