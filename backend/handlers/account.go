package handlers

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"leaflock/config"
	"leaflock/crypto"
	"leaflock/database"
)

// AccountHandler handles account management requests
type AccountHandler struct {
	db     database.Database
	redis  *redis.Client
	crypto *crypto.CryptoService
	config *config.Config
}

// NewAccountHandler creates a new account handler
func NewAccountHandler(db database.Database, redis *redis.Client, cryptoService *crypto.CryptoService, cfg *config.Config) *AccountHandler {
	return &AccountHandler{
		db:     db,
		redis:  redis,
		crypto: cryptoService,
		config: cfg,
	}
}

// DeleteAccountRequest represents a delete account request
type DeleteAccountRequest struct {
	Password string `json:"password" validate:"required"`
}

// ExportDataResponse represents the exported user data
type ExportDataResponse struct {
	ExportVersion string                   `json:"export_version"`
	ExportedAt    string                   `json:"exported_at"`
	UserID        string                   `json:"user_id"`
	Notes         []map[string]interface{} `json:"notes"`
	Tags          []map[string]interface{} `json:"tags"`
	Folders       []map[string]interface{} `json:"folders"`
	Templates     []map[string]interface{} `json:"templates"`
	Workspace     map[string]interface{}   `json:"workspace"`
}

// DeleteAccount godoc
// @Summary Delete user account
// @Description Permanently delete user account and all associated data
// @Tags Account
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body DeleteAccountRequest true "Password confirmation"
// @Success 200 {object} map[string]interface{} "Account deleted successfully"
// @Failure 400 {object} map[string]interface{} "Invalid request"
// @Failure 401 {object} map[string]interface{} "Invalid password"
// @Failure 500 {object} map[string]interface{} "Server error"
// @Router /account [delete]
func (h *AccountHandler) DeleteAccount(c *fiber.Ctx) error {
	// Get user ID from middleware
	v := c.Locals("user_id")
	userID, ok := v.(uuid.UUID)
	if !ok {
		return c.Status(401).JSON(fiber.Map{"error": "Unauthorized"})
	}

	var req DeleteAccountRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
	}

	if req.Password == "" {
		return c.Status(400).JSON(fiber.Map{"error": "Password is required"})
	}

	ctx := context.Background()

	// Verify password
	var passwordHash string
	var emailHash []byte
	err := h.db.QueryRow(ctx, `
		SELECT password_hash, email_hash FROM users WHERE id = $1
	`, userID).Scan(&passwordHash, &emailHash)

	if err != nil {
		log.Printf("Failed to get user for account deletion: %v", err)
		return c.Status(500).JSON(fiber.Map{"error": "Failed to verify user"})
	}

	if !crypto.VerifyPassword(req.Password, passwordHash) {
		h.logAudit(ctx, userID, "account.delete_failed", "user", userID, c)
		return c.Status(401).JSON(fiber.Map{"error": "Invalid password"})
	}

	// Start transaction
	tx, err := h.db.Begin(ctx)
	if err != nil {
		log.Printf("Failed to start transaction for account deletion: %v", err)
		return c.Status(500).JSON(fiber.Map{"error": "Failed to delete account"})
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	cleanupStatements := []struct {
		query string
		args  []interface{}
	}{
		{"DELETE FROM collaborations WHERE user_id = $1", []interface{}{userID}},
		{"DELETE FROM share_links WHERE created_by = $1", []interface{}{userID}},
		{"DELETE FROM tags WHERE user_id = $1", []interface{}{userID}},
		{"DELETE FROM folders WHERE user_id = $1", []interface{}{userID}},
		{"DELETE FROM templates WHERE user_id = $1", []interface{}{userID}},
		{"DELETE FROM user_sessions WHERE user_id = $1", []interface{}{userID}},
		{"DELETE FROM audit_log WHERE user_id = $1", []interface{}{userID}},
		{"DELETE FROM password_reset_tokens WHERE user_id = $1", []interface{}{userID}},
		{"DELETE FROM user_roles WHERE user_id = $1", []interface{}{userID}},
	}

	for _, stmt := range cleanupStatements {
		if _, err := tx.Exec(ctx, stmt.query, stmt.args...); err != nil {
			log.Printf("Error executing cleanup statement (%s): %v", stmt.query, err)
		}
	}

	// Remove any shared content owned by the user
	_, err = tx.Exec(ctx, `DELETE FROM collaborations WHERE note_id IN (
		SELECT n.id
		FROM notes n
		JOIN workspaces w ON n.workspace_id = w.id
		WHERE w.owner_id = $1
	)`, userID)
	if err != nil {
		log.Printf("Error deleting note collaborations: %v", err)
	}

	// Delete workspaces owned by the user (cascades to notes, note_versions, attachments, share links, etc.)
	_, err = tx.Exec(ctx, "DELETE FROM workspaces WHERE owner_id = $1", userID)
	if err != nil {
		log.Printf("Error deleting workspaces: %v", err)
	}

	// Delete personal tags/folders/templates that may not be owned by cascade (already handled above)

	// Delete GDPR keys for this email hash
	_, err = tx.Exec(ctx, "DELETE FROM gdpr_keys WHERE email_hash = $1", emailHash)
	if err != nil {
		log.Printf("Error deleting GDPR keys: %v", err)
	}

	// Finally, delete the user record
	_, err = tx.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)
	if err != nil {
		log.Printf("Error deleting user: %v", err)
		return c.Status(500).JSON(fiber.Map{"error": "Failed to delete account"})
	}

	// Commit transaction
	if err = tx.Commit(ctx); err != nil {
		log.Printf("Failed to commit account deletion: %v", err)
		return c.Status(500).JSON(fiber.Map{"error": "Failed to delete account"})
	}

	// Clear all Redis sessions for this user
	sessionPattern := "session:*"
	iter := h.redis.Scan(ctx, 0, sessionPattern, 0).Iterator()
	for iter.Next(ctx) {
		key := iter.Val()
		// Get session data and check if it belongs to this user
		encryptedData, err := h.redis.Get(ctx, key).Bytes()
		if err != nil {
			continue
		}

		decryptedData, err := h.crypto.Decrypt(encryptedData)
		if err != nil {
			continue
		}

		var sessionData map[string]interface{}
		if err := json.Unmarshal(decryptedData, &sessionData); err != nil {
			continue
		}

		if sessionUserID, ok := sessionData["user_id"].(string); ok && sessionUserID == userID.String() {
			h.redis.Del(ctx, key)
		}
	}

	// Log audit event (will be deleted but good for debugging)
	h.logAudit(ctx, userID, "account.deleted", "user", userID, c)

	log.Printf("✅ Account deleted successfully: %s", userID)

	return c.JSON(fiber.Map{
		"success": true,
		"message": "Account deleted successfully",
	})
}

// ExportData godoc
// @Summary Export user data
// @Description Export all user data in JSON format
// @Tags Account
// @Security BearerAuth
// @Produce json
// @Success 200 {object} ExportDataResponse "Exported data"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 500 {object} map[string]interface{} "Server error"
// @Router /account/export [get]
func (h *AccountHandler) ExportData(c *fiber.Ctx) error {
	// Get user ID from middleware
	v := c.Locals("user_id")
	userID, ok := v.(uuid.UUID)
	if !ok {
		return c.Status(401).JSON(fiber.Map{"error": "Unauthorized"})
	}

	ctx := context.Background()

	// Fetch all notes owned by the user
	notes := []map[string]interface{}{}
	notesRows, err := h.db.Query(ctx, `
		SELECT n.id, n.title_encrypted, n.content_encrypted, n.folder_id, n.created_at, n.updated_at
		FROM notes n
		JOIN workspaces w ON n.workspace_id = w.id
		WHERE w.owner_id = $1 AND n.deleted_at IS NULL
		ORDER BY n.created_at DESC
	`, userID)
	if err != nil {
		log.Printf("Failed to fetch notes for export: %v", err)
		return c.Status(500).JSON(fiber.Map{"error": "Failed to export data"})
	}
	defer notesRows.Close()

	for notesRows.Next() {
		var id uuid.UUID
		var titleEnc, contentEnc []byte
		var folderID *uuid.UUID
		var createdAt, updatedAt time.Time

		if err := notesRows.Scan(&id, &titleEnc, &contentEnc, &folderID, &createdAt, &updatedAt); err != nil {
			continue
		}

		note := map[string]interface{}{
			"id":                id.String(),
			"title_encrypted":   titleEnc,
			"content_encrypted": contentEnc,
			"created_at":        createdAt.Format(time.RFC3339),
			"updated_at":        updatedAt.Format(time.RFC3339),
		}
		if folderID != nil {
			note["folder_id"] = folderID.String()
		}
		notes = append(notes, note)
	}

	// Fetch all tags
	tags := []map[string]interface{}{}
	tagsRows, err := h.db.Query(ctx, `
		SELECT id, name_encrypted, color, created_at
		FROM tags WHERE user_id = $1
		ORDER BY created_at DESC
	`, userID)
	if err != nil {
		log.Printf("Failed to fetch tags for export: %v", err)
	} else {
		defer tagsRows.Close()
		for tagsRows.Next() {
			var id uuid.UUID
			var nameEnc []byte
			var color string
			var createdAt time.Time

			if err := tagsRows.Scan(&id, &nameEnc, &color, &createdAt); err != nil {
				continue
			}

			tags = append(tags, map[string]interface{}{
				"id":             id.String(),
				"name_encrypted": nameEnc,
				"color":          color,
				"created_at":     createdAt.Format(time.RFC3339),
			})
		}
	}

	// Fetch all folders
	folders := []map[string]interface{}{}
	foldersRows, err := h.db.Query(ctx, `
		SELECT id, name_encrypted, parent_id, created_at
		FROM folders WHERE user_id = $1
		ORDER BY created_at ASC
	`, userID)
	if err != nil {
		log.Printf("Failed to fetch folders for export: %v", err)
	} else {
		defer foldersRows.Close()
		for foldersRows.Next() {
			var id uuid.UUID
			var nameEnc []byte
			var parentID *uuid.UUID
			var createdAt time.Time

			if err := foldersRows.Scan(&id, &nameEnc, &parentID, &createdAt); err != nil {
				continue
			}

			folder := map[string]interface{}{
				"id":             id.String(),
				"name_encrypted": nameEnc,
				"created_at":     createdAt.Format(time.RFC3339),
			}
			if parentID != nil {
				folder["parent_id"] = parentID.String()
			}
			folders = append(folders, folder)
		}
	}

	// Fetch all templates
	templates := []map[string]interface{}{}
	templatesRows, err := h.db.Query(ctx, `
		SELECT id, name_encrypted, content_encrypted, created_at
		FROM templates WHERE user_id = $1
		ORDER BY created_at DESC
	`, userID)
	if err != nil {
		log.Printf("Failed to fetch templates for export: %v", err)
	} else {
		defer templatesRows.Close()
		for templatesRows.Next() {
			var id uuid.UUID
			var nameEnc, contentEnc []byte
			var createdAt time.Time

			if err := templatesRows.Scan(&id, &nameEnc, &contentEnc, &createdAt); err != nil {
				continue
			}

			templates = append(templates, map[string]interface{}{
				"id":                id.String(),
				"name_encrypted":    nameEnc,
				"content_encrypted": contentEnc,
				"created_at":        createdAt.Format(time.RFC3339),
			})
		}
	}

	// Fetch workspace
	workspace := map[string]interface{}{}
	var workspaceID uuid.UUID
	var workspaceNameEnc []byte
	var workspaceCreatedAt time.Time
	err = h.db.QueryRow(ctx, `
		SELECT id, name_encrypted, created_at
		FROM workspaces WHERE owner_id = $1 LIMIT 1
	`, userID).Scan(&workspaceID, &workspaceNameEnc, &workspaceCreatedAt)
	if err == nil {
		workspace["id"] = workspaceID.String()
		workspace["name_encrypted"] = workspaceNameEnc
		workspace["created_at"] = workspaceCreatedAt.Format(time.RFC3339)
	}

	// Log audit event
	h.logAudit(ctx, userID, "account.exported", "user", userID, c)

	response := ExportDataResponse{
		ExportVersion: "1.0",
		ExportedAt:    time.Now().Format(time.RFC3339),
		UserID:        userID.String(),
		Notes:         notes,
		Tags:          tags,
		Folders:       folders,
		Templates:     templates,
		Workspace:     workspace,
	}

	return c.JSON(response)
}

func (h *AccountHandler) logAudit(ctx context.Context, userID uuid.UUID, action, resourceType string, resourceID uuid.UUID, c *fiber.Ctx) {
	encryptedIP, err := h.crypto.Encrypt([]byte(c.IP()))
	if err != nil {
		log.Printf("failed to encrypt audit log IP: %v", err)
		encryptedIP = nil
	}
	encryptedUA, err := h.crypto.Encrypt([]byte(c.Get("User-Agent")))
	if err != nil {
		log.Printf("failed to encrypt audit log user agent: %v", err)
		encryptedUA = nil
	}

	if _, err := h.db.Exec(ctx, `
        INSERT INTO audit_log (user_id, action, resource_type, resource_id, ip_address_encrypted, user_agent_encrypted)
        VALUES ($1, $2, $3, $4, $5, $6)`,
		userID, action, resourceType, resourceID, encryptedIP, encryptedUA,
	); err != nil {
		log.Printf("failed to write audit log entry: %v", err)
	}
}
