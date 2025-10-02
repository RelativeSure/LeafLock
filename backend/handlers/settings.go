package handlers

import (
	"context"
	"database/sql"

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
	Theme string `json:"theme"`
}

// UpdateSettingsRequest represents a settings update request
type UpdateSettingsRequest struct {
	Theme string `json:"theme"`
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

	userID, err := uuid.Parse(userIDVal.(string))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid user ID"})
	}

	ctx := context.Background()
	var theme string

	err = h.db.QueryRow(ctx, `
		SELECT COALESCE(theme_preference, 'system')
		FROM users
		WHERE id = $1 AND deleted_at IS NULL
	`, userID).Scan(&theme)

	if err == sql.ErrNoRows {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "User not found"})
	}
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to fetch settings"})
	}

	return c.JSON(UserSettings{Theme: theme})
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

	userID, err := uuid.Parse(userIDVal.(string))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid user ID"})
	}

	var req UpdateSettingsRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request body"})
	}

	// Validate theme value
	validThemes := map[string]bool{
		"light":  true,
		"blue":   true,
		"dark":   true,
		"system": true,
	}

	if !validThemes[req.Theme] {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid theme. Must be one of: light, blue, dark, system",
		})
	}

	ctx := context.Background()
	_, err = h.db.Exec(ctx, `
		UPDATE users
		SET theme_preference = $1, updated_at = NOW()
		WHERE id = $2 AND deleted_at IS NULL
	`, req.Theme, userID)

	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update settings"})
	}

	return c.JSON(UserSettings{Theme: req.Theme})
}
