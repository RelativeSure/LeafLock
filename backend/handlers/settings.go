package handlers

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"leaflock/database"
)

// SettingsHandler handles user settings requests
type SettingsHandler struct {
	db database.Database
}

// NewSettingsHandler creates a new settings handler
func NewSettingsHandler(db database.Database) *SettingsHandler {
	return &SettingsHandler{db: db}
}

// UserSettings represents user preferences
type UserSettings struct {
	Theme                string `json:"theme"`
	AutoSave             bool   `json:"autoSave"`
	AutoSaveInterval     int    `json:"autoSaveInterval"`
	DefaultView          string `json:"defaultView"`
	NotificationsEnabled bool   `json:"notificationsEnabled"`
	EmailNotifications   bool   `json:"emailNotifications"`
	EncryptionEnabled    bool   `json:"encryptionEnabled"`
	Language             string `json:"language"`
	DefaultNoteBehavior  string `json:"defaultNoteBehavior"`
	ProfilePicture       struct {
		Type      string  `json:"type"`
		CustomURL *string `json:"customUrl,omitempty"`
	} `json:"profilePicture"`
}

// UpdateSettingsRequest represents a settings update request
type UpdateSettingsRequest struct {
	Theme                *string `json:"theme,omitempty"`
	AutoSave             *bool   `json:"autoSave,omitempty"`
	AutoSaveInterval     *int    `json:"autoSaveInterval,omitempty"`
	DefaultView          *string `json:"defaultView,omitempty"`
	NotificationsEnabled *bool   `json:"notificationsEnabled,omitempty"`
	EmailNotifications   *bool   `json:"emailNotifications,omitempty"`
	EncryptionEnabled    *bool   `json:"encryptionEnabled,omitempty"`
	Language             *string `json:"language,omitempty"`
	DefaultNoteBehavior  *string `json:"defaultNoteBehavior,omitempty"`
	ProfilePicture       *struct {
		Type      string  `json:"type"`
		CustomURL *string `json:"customUrl,omitempty"`
	} `json:"profilePicture,omitempty"`
}

// GetSettings godoc
// @Summary Get user settings
// @Description Get authenticated user's preferences including theme
// @Tags Settings
// @Security BearerAuth
// @Produce json
// @Success 200 {object} UserSettings "User settings"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /settings [get]
func (h *SettingsHandler) GetSettings(c *fiber.Ctx) error {
	userIDVal := c.Locals("user_id")
	if userIDVal == nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
	}

	userID, ok := userIDVal.(uuid.UUID)
	if !ok {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid user ID"})
	}

	ctx := context.Background()
	var settings UserSettings

	err := h.db.QueryRow(ctx, `
		SELECT
			COALESCE(theme_preference, 'system'),
			COALESCE(auto_save, true),
			COALESCE(auto_save_interval, 30),
			COALESCE(default_view, 'list'),
			COALESCE(notifications_enabled, true),
			COALESCE(email_notifications, false),
			COALESCE(encryption_enabled, true),
			COALESCE(language, 'en'),
			COALESCE(default_note_behavior, 'last-seen'),
			COALESCE(profile_picture_type, 'gravatar'),
			profile_picture_custom_url
		FROM users
		WHERE id = $1 AND deleted_at IS NULL
	`, userID).Scan(
		&settings.Theme,
		&settings.AutoSave,
		&settings.AutoSaveInterval,
		&settings.DefaultView,
		&settings.NotificationsEnabled,
		&settings.EmailNotifications,
		&settings.EncryptionEnabled,
		&settings.Language,
		&settings.DefaultNoteBehavior,
		&settings.ProfilePicture.Type,
		&settings.ProfilePicture.CustomURL,
	)

	if err == sql.ErrNoRows {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "User not found"})
	}
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to fetch settings"})
	}

	return c.JSON(settings)
}

// UpdateSettings godoc
// @Summary Update user settings
// @Description Update authenticated user's preferences including theme
// @Tags Settings
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body UpdateSettingsRequest true "Settings to update"
// @Success 200 {object} UserSettings "Updated settings"
// @Failure 400 {object} map[string]interface{} "Invalid request"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /settings [put]
func (h *SettingsHandler) UpdateSettings(c *fiber.Ctx) error {
	userIDVal := c.Locals("user_id")
	if userIDVal == nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
	}

	userID, ok := userIDVal.(uuid.UUID)
	if !ok {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid user ID"})
	}

	var req UpdateSettingsRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request body"})
	}

	// Build dynamic update query
	var setParts []string
	var args []interface{}
	argIndex := 1

	if req.Theme != nil {
		// Validate theme value
		validThemes := map[string]bool{
			"light":  true,
			"dark":   true,
			"system": true,
		}
		if !validThemes[*req.Theme] {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid theme. Must be one of: light, dark, system",
			})
		}
		setParts = append(setParts, fmt.Sprintf("theme_preference = $%d", argIndex))
		args = append(args, *req.Theme)
		argIndex++
	}

	if req.AutoSave != nil {
		setParts = append(setParts, fmt.Sprintf("auto_save = $%d", argIndex))
		args = append(args, *req.AutoSave)
		argIndex++
	}

	if req.AutoSaveInterval != nil {
		if *req.AutoSaveInterval < 5 || *req.AutoSaveInterval > 300 {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Auto save interval must be between 5 and 300 seconds",
			})
		}
		setParts = append(setParts, fmt.Sprintf("auto_save_interval = $%d", argIndex))
		args = append(args, *req.AutoSaveInterval)
		argIndex++
	}

	if req.DefaultView != nil {
		validViews := map[string]bool{"list": true, "grid": true}
		if !validViews[*req.DefaultView] {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid default view. Must be one of: list, grid",
			})
		}
		setParts = append(setParts, fmt.Sprintf("default_view = $%d", argIndex))
		args = append(args, *req.DefaultView)
		argIndex++
	}

	if req.NotificationsEnabled != nil {
		setParts = append(setParts, fmt.Sprintf("notifications_enabled = $%d", argIndex))
		args = append(args, *req.NotificationsEnabled)
		argIndex++
	}

	if req.EmailNotifications != nil {
		setParts = append(setParts, fmt.Sprintf("email_notifications = $%d", argIndex))
		args = append(args, *req.EmailNotifications)
		argIndex++
	}

	if req.EncryptionEnabled != nil {
		setParts = append(setParts, fmt.Sprintf("encryption_enabled = $%d", argIndex))
		args = append(args, *req.EncryptionEnabled)
		argIndex++
	}

	if req.Language != nil {
		validLanguages := map[string]bool{"en": true, "es": true, "fr": true, "de": true, "it": true, "pt": true, "ru": true, "zh": true, "ja": true, "ko": true}
		if !validLanguages[*req.Language] {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid language code",
			})
		}
		setParts = append(setParts, fmt.Sprintf("language = $%d", argIndex))
		args = append(args, *req.Language)
		argIndex++
	}

	if req.DefaultNoteBehavior != nil {
		validBehaviors := map[string]bool{"last-seen": true, "new-note": true}
		if !validBehaviors[*req.DefaultNoteBehavior] {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid default note behavior. Must be one of: last-seen, new-note",
			})
		}
		setParts = append(setParts, fmt.Sprintf("default_note_behavior = $%d", argIndex))
		args = append(args, *req.DefaultNoteBehavior)
		argIndex++
	}

	if req.ProfilePicture != nil {
		validTypes := map[string]bool{"gravatar": true, "initials": true, "custom": true}
		if !validTypes[req.ProfilePicture.Type] {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid profile picture type. Must be one of: gravatar, initials, custom",
			})
		}
		setParts = append(setParts, fmt.Sprintf("profile_picture_type = $%d", argIndex))
		args = append(args, req.ProfilePicture.Type)
		argIndex++

		setParts = append(setParts, fmt.Sprintf("profile_picture_custom_url = $%d", argIndex))
		args = append(args, req.ProfilePicture.CustomURL)
		argIndex++
	}

	if len(setParts) == 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "No settings provided to update"})
	}

	// Add updated_at and user_id
	setParts = append(setParts, "updated_at = NOW()")
	args = append(args, userID)

	query := fmt.Sprintf(`
		UPDATE users
		SET %s
		WHERE id = $%d AND deleted_at IS NULL
	`, strings.Join(setParts, ", "), argIndex)

	ctx := context.Background()
	_, err := h.db.Exec(ctx, query, args...)

	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update settings"})
	}

	// Return updated settings
	return h.GetSettings(c)
}
