package handlers

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"regexp"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"leaflock/crypto"
	"leaflock/database"
	"leaflock/metrics"
	"leaflock/services"
	"leaflock/utils"
)

// Collaboration Handler
type CollaborationHandler struct {
	db                  database.Database
	crypto              *crypto.CryptoService
	notificationService *services.NotificationService
}

// NewCollaborationHandler creates a new collaboration handler.
func NewCollaborationHandler(db database.Database, cryptoService *crypto.CryptoService, notificationService *services.NotificationService) *CollaborationHandler {
	return &CollaborationHandler{
		db:                  db,
		crypto:              cryptoService,
		notificationService: notificationService,
	}
}

type ShareNoteRequest struct {
	UserEmail  string  `json:"user_email" validate:"required,email"`
	Permission string  `json:"permission" validate:"required,oneof=read write admin"`
	CanEdit    *bool   `json:"can_edit,omitempty"`
	CanDelete  *bool   `json:"can_delete,omitempty"`
	CanShare   *bool   `json:"can_share,omitempty"`
	CanComment *bool   `json:"can_comment,omitempty"`
	ExpiresAt  *string `json:"expires_at,omitempty"` // ISO 8601 format
}

type CollaborationResponse struct {
	ID         string  `json:"id"`
	NoteID     string  `json:"note_id"`
	UserID     string  `json:"user_id"`
	UserEmail  string  `json:"user_email"`
	Permission string  `json:"permission"`
	CanEdit    bool    `json:"can_edit"`
	CanDelete  bool    `json:"can_delete"`
	CanShare   bool    `json:"can_share"`
	CanComment bool    `json:"can_comment"`
	ExpiresAt  *string `json:"expires_at,omitempty"`
	CreatedAt  string  `json:"created_at"`
}

// ShareNote godoc
// @Summary Share a note with another user
// @Description Share a note with another user by email and set permission level
// @Tags Collaboration
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "Note ID"
// @Param request body ShareNoteRequest true "Share request data"
// @Success 201 {object} map[string]interface{} "Note shared successfully"
// @Failure 400 {object} map[string]interface{} "Invalid request"
// @Failure 404 {object} map[string]interface{} "Note or user not found"
// @Failure 409 {object} map[string]interface{} "Note already shared with user"
// @Router /notes/{id}/share [post]
func (h *CollaborationHandler) ShareNote(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	noteID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid note ID"})
	}

	ctx := context.Background()

	var req ShareNoteRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
	}

	// Validate email format
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	if !emailRegex.MatchString(req.UserEmail) {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid email format"})
	}

	// Validate permission
	validPermissions := map[string]bool{"read": true, "write": true, "admin": true}
	if !validPermissions[req.Permission] {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid permission"})
	}

	// Prevent self-sharing
	var userEmail string
	err = h.db.QueryRow(ctx, `SELECT email FROM users WHERE id = $1`, userID).Scan(&userEmail)
	if err == nil && userEmail == req.UserEmail {
		return c.Status(400).JSON(fiber.Map{"error": "Cannot share note with yourself"})
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

	// Find the user to share with
	var targetUserID uuid.UUID
	err = h.db.QueryRow(ctx, `SELECT id FROM users WHERE email = $1`, req.UserEmail).Scan(&targetUserID)
	if err != nil {
		utils.LogRequestError(c, "ShareNote: user not found", err, "target_email", req.UserEmail)
		return c.Status(404).JSON(fiber.Map{"error": "User not found"})
	}

	// Check if already shared
	var existingID uuid.UUID
	err = h.db.QueryRow(ctx, `
		SELECT id FROM collaborations
		WHERE note_id = $1 AND user_id = $2`, noteID, targetUserID).Scan(&existingID)

	if err == nil {
		return c.Status(409).JSON(fiber.Map{"error": "Note already shared with this user"})
	}

	// Generate a note encryption key for the collaboration
	noteKey := make([]byte, 32)
	if _, err := rand.Read(noteKey); err != nil {
		utils.LogRequestError(c, "ShareNote: failed to generate encryption key", err)
		return c.Status(500).JSON(fiber.Map{"error": "Failed to generate encryption key"})
	}

	// In a real implementation, we would encrypt the note key with the target user's public key
	// For now, we'll store it encrypted with server's key as a placeholder
	encryptedKey, err := h.crypto.Encrypt(noteKey)
	if err != nil {
		utils.LogRequestError(c, "ShareNote: failed to encrypt key", err)
		return c.Status(500).JSON(fiber.Map{"error": "Failed to encrypt key"})
	}

	// Set defaults based on permission level if not explicitly provided
	canEdit := true
	if req.CanEdit != nil {
		canEdit = *req.CanEdit
	}
	canDelete := false
	if req.CanDelete != nil {
		canDelete = *req.CanDelete
	} else if req.Permission == "admin" {
		canDelete = true
	}
	canShare := false
	if req.CanShare != nil {
		canShare = *req.CanShare
	} else if req.Permission == "admin" {
		canShare = true
	}
	canComment := true
	if req.CanComment != nil {
		canComment = *req.CanComment
	}

	var expiresAt *time.Time
	if req.ExpiresAt != nil {
		parsed, err := time.Parse(time.RFC3339, *req.ExpiresAt)
		if err == nil {
			expiresAt = &parsed
		}
	}

	// Create collaboration record
	var collaborationID uuid.UUID
	err = h.db.QueryRow(ctx, `
		INSERT INTO collaborations (note_id, user_id, permission, key_encrypted, can_edit, can_delete, can_share, can_comment, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id`, noteID, targetUserID, req.Permission, encryptedKey, canEdit, canDelete, canShare, canComment, expiresAt).Scan(&collaborationID)

	if err != nil {
		utils.LogRequestError(c, "ShareNote: failed to create collaboration record", err, "target_user_id", targetUserID)
		return c.Status(500).JSON(fiber.Map{"error": "Failed to share note"})
	}

	// Log the action
	h.auditLog(userID, "share_note", fiber.Map{
		"note_id":     noteID,
		"target_user": targetUserID,
		"permission":  req.Permission,
	})

	// Send email notification if user has it enabled
	if h.notificationService != nil {
		go func() {
			// Check if recipient wants email notifications
			enabled, err := h.notificationService.CheckUserEmailPreference(context.Background(), targetUserID.String(), "note_shared")
			if err == nil && enabled {
				// Get sender name
				var senderName string
				h.db.QueryRow(context.Background(), `SELECT COALESCE(display_name, email_plaintext) FROM users WHERE id = $1`, userID).Scan(&senderName)

				// Get note title (decrypt it)
				var titleEncrypted []byte
				h.db.QueryRow(context.Background(), `SELECT title_encrypted FROM notes WHERE id = $1`, noteID).Scan(&titleEncrypted)
				noteTitle := "Untitled Note"
				if titleEncrypted != nil {
					if titleBytes, err := h.crypto.Decrypt(titleEncrypted); err == nil {
						noteTitle = string(titleBytes)
					}
				}

				// Get recipient name
				var recipientName string
				h.db.QueryRow(context.Background(), `SELECT COALESCE(display_name, email_plaintext) FROM users WHERE id = $1`, targetUserID).Scan(&recipientName)

				// Send email
				h.notificationService.SendNoteSharedNotification(
					context.Background(),
					req.UserEmail,
					recipientName,
					senderName,
					noteTitle,
					req.Permission,
					"", // noteURL - can be constructed from app config
				)
			}
		}()
	}

	return c.Status(201).JSON(fiber.Map{
		"message":          "Note shared successfully",
		"collaboration_id": collaborationID,
	})
}

// GetCollaborators godoc
// @Summary Get note collaborators
// @Description Get list of users who have access to a note
// @Tags Collaboration
// @Produce json
// @Security BearerAuth
// @Param id path string true "Note ID"
// @Success 200 {object} map[string]interface{} "List of collaborators"
// @Failure 400 {object} map[string]interface{} "Invalid note ID"
// @Failure 404 {object} map[string]interface{} "Note not found"
// @Router /notes/{id}/collaborators [get]
func (h *CollaborationHandler) GetCollaborators(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	noteID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid note ID"})
	}

	ctx := context.Background()

	// Verify user has access to the note (owner or collaborator)
	var hasAccess bool
	err = h.db.QueryRow(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM notes n
			JOIN workspaces w ON n.workspace_id = w.id
			WHERE n.id = $1 AND w.owner_id = $2 AND n.deleted_at IS NULL
		) OR EXISTS(
			SELECT 1 FROM collaborations c
			WHERE c.note_id = $1 AND c.user_id = $2
		)`, noteID, userID).Scan(&hasAccess)

	if err != nil || !hasAccess {
		return c.Status(404).JSON(fiber.Map{"error": "Note not found"})
	}

	// Get collaborators
	rows, err := h.db.Query(ctx, `
		SELECT c.id, c.user_id, u.email, c.permission, c.can_edit, c.can_delete, c.can_share, c.can_comment, c.expires_at, c.created_at
		FROM collaborations c
		JOIN users u ON c.user_id = u.id
		WHERE c.note_id = $1
		ORDER BY c.created_at ASC`, noteID)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to fetch collaborators"})
	}
	defer rows.Close()

	collaborators := []CollaborationResponse{}
	for rows.Next() {
		var collab CollaborationResponse
		var collaborationID, collaboratorUserID uuid.UUID
		var createdAt time.Time
		var expiresAt *time.Time

		if err := rows.Scan(&collaborationID, &collaboratorUserID, &collab.UserEmail, &collab.Permission,
			&collab.CanEdit, &collab.CanDelete, &collab.CanShare, &collab.CanComment, &expiresAt, &createdAt); err != nil {
			continue
		}

		collab.ID = collaborationID.String()
		collab.NoteID = noteID.String()
		collab.UserID = collaboratorUserID.String()
		collab.CreatedAt = createdAt.Format(time.RFC3339)
		if expiresAt != nil {
			expiresAtStr := expiresAt.Format(time.RFC3339)
			collab.ExpiresAt = &expiresAtStr
		}

		collaborators = append(collaborators, collab)
	}

	return c.JSON(fiber.Map{"collaborators": collaborators})
}

// RemoveCollaborator godoc
// @Summary Remove collaborator from note
// @Description Remove a user's access to a shared note
// @Tags Collaboration
// @Produce json
// @Security BearerAuth
// @Param id path string true "Note ID"
// @Param userId path string true "User ID to remove"
// @Success 200 {object} map[string]interface{} "Collaborator removed successfully"
// @Failure 400 {object} map[string]interface{} "Invalid note ID or user ID"
// @Failure 404 {object} map[string]interface{} "Note not found or collaboration not found"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /notes/{id}/collaborators/{userId} [delete]
func (h *CollaborationHandler) RemoveCollaborator(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	noteID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid note ID"})
	}

	collaboratorUserID, err := uuid.Parse(c.Params("userId"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid user ID"})
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

	// Remove collaboration
	result, err := h.db.Exec(ctx, `
		DELETE FROM collaborations
		WHERE note_id = $1 AND user_id = $2`, noteID, collaboratorUserID)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to remove collaborator"})
	}

	if result.RowsAffected() == 0 {
		return c.Status(404).JSON(fiber.Map{"error": "Collaboration not found"})
	}

	// Log the action
	h.auditLog(userID, "remove_collaborator", fiber.Map{
		"note_id":     noteID,
		"target_user": collaboratorUserID,
	})

	return c.JSON(fiber.Map{"message": "Collaborator removed successfully"})
}

// GetSharedNotes godoc
// @Summary Get shared notes
// @Description Get all notes shared with the authenticated user
// @Tags Collaboration
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "List of shared notes"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /notes/shared [get]
func (h *CollaborationHandler) GetSharedNotes(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	ctx := context.Background()

	// Get notes shared with the user
	rows, err := h.db.Query(ctx, `
		SELECT n.id, n.title_encrypted, n.content_encrypted, n.created_at, n.updated_at,
			   c.permission, u.email as owner_email
		FROM notes n
		JOIN collaborations c ON n.id = c.note_id
		JOIN workspaces w ON n.workspace_id = w.id
		JOIN users u ON w.owner_id = u.id
		WHERE c.user_id = $1 AND n.deleted_at IS NULL
		ORDER BY n.updated_at DESC`, userID)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to fetch shared notes"})
	}
	defer rows.Close()

	notes := []fiber.Map{}
	for rows.Next() {
		var id uuid.UUID
		var titleEnc, contentEnc []byte
		var createdAt, updatedAt time.Time
		var permission, ownerEmail string

		if err := rows.Scan(&id, &titleEnc, &contentEnc, &createdAt, &updatedAt, &permission, &ownerEmail); err != nil {
			continue
		}

		notes = append(notes, fiber.Map{
			"id":                id,
			"title_encrypted":   base64.StdEncoding.EncodeToString(titleEnc),
			"content_encrypted": base64.StdEncoding.EncodeToString(contentEnc),
			"created_at":        createdAt,
			"updated_at":        updatedAt,
			"permission":        permission,
			"owner_email":       ownerEmail,
			"is_shared":         true,
		})
	}

	return c.JSON(fiber.Map{"notes": notes})
}

func (h *CollaborationHandler) auditLog(userID uuid.UUID, action string, metadata fiber.Map) {
	ctx := context.Background()

	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return
	}

	if _, err := h.db.Exec(ctx, `
		INSERT INTO audit_log (user_id, action, resource_type, metadata_encrypted)
		VALUES ($1, $2, $3, $4)`,
		userID, action, "collaboration", metadataJSON,
	); err != nil {
		metrics.IncrementError("audit_log", "collaboration")
	}
}
