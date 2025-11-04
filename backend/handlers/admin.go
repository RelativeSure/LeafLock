package handlers

import (
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"leaflock/database"
)

// AdminHandler handles admin-related operations
type AdminHandler struct {
	db database.Database
}

// NewAdminHandler creates a new admin handler
func NewAdminHandler(db database.Database) *AdminHandler {
	return &AdminHandler{db: db}
}

// SystemStats represents system statistics
type SystemStats struct {
	TotalUsers     int    `json:"totalUsers"`
	ActiveUsers    int    `json:"activeUsers"`
	TotalNotes     int    `json:"totalNotes"`
	TotalTemplates int    `json:"totalTemplates"`
	TotalTags      int    `json:"totalTags"`
	SystemUptime   string `json:"systemUptime"`
}

// UserDetails represents detailed user information for admin
type UserDetails struct {
	ID         string    `json:"id"`
	Email      string    `json:"email"`
	IsAdmin    bool      `json:"isAdmin"`
	CreatedAt  time.Time `json:"createdAt"`
	LastLogin  time.Time `json:"lastLogin"`
	NotesCount int       `json:"notesCount"`
	IsLocked   bool      `json:"isLocked"`
	LockedUntil *time.Time `json:"lockedUntil,omitempty"`
}

// GetSystemStats returns system-wide statistics
// @Summary Get system statistics
// @Description Get overall system statistics (admin only)
// @Tags Admin
// @Produce json
// @Success 200 {object} SystemStats
// @Failure 403 {object} ErrorResponse
// @Router /api/v1/admin/stats [get]
func (h *AdminHandler) GetSystemStats(c *fiber.Ctx) error {
	ctx := c.Context()

	// Count users
	var totalUsers, activeUsers int
	err := h.db.QueryRow(ctx, `
		SELECT COUNT(*), COUNT(CASE WHEN last_login > NOW() - INTERVAL '30 days' THEN 1 END)
		FROM users WHERE deleted_at IS NULL
	`).Scan(&totalUsers, &activeUsers)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to fetch user statistics",
		})
	}

	// Count notes
	var totalNotes int
	err = h.db.QueryRow(ctx, `SELECT COUNT(*) FROM notes WHERE deleted_at IS NULL`).Scan(&totalNotes)
	if err != nil {
		totalNotes = 0
	}

	// Count templates
	var totalTemplates int
	err = h.db.QueryRow(ctx, `SELECT COUNT(*) FROM templates WHERE deleted_at IS NULL`).Scan(&totalTemplates)
	if err != nil {
		totalTemplates = 0
	}

	// Count tags
	var totalTags int
	err = h.db.QueryRow(ctx, `SELECT COUNT(DISTINCT name) FROM tags WHERE deleted_at IS NULL`).Scan(&totalTags)
	if err != nil {
		totalTags = 0
	}

	stats := SystemStats{
		TotalUsers:     totalUsers,
		ActiveUsers:    activeUsers,
		TotalNotes:     totalNotes,
		TotalTemplates: totalTemplates,
		TotalTags:      totalTags,
		SystemUptime:   "N/A", // Would need server start time tracking
	}

	return c.JSON(stats)
}

// GetAllUsers returns all users for admin management
// @Summary Get all users
// @Description Get list of all users (admin only)
// @Tags Admin
// @Produce json
// @Success 200 {array} UserDetails
// @Failure 403 {object} ErrorResponse
// @Router /api/v1/admin/users [get]
func (h *AdminHandler) GetAllUsers(c *fiber.Ctx) error {
	ctx := c.Context()

	query := `
		SELECT u.id, u.email_encrypted, u.is_admin, u.created_at, u.last_login,
		       u.failed_attempts, u.locked_until,
		       COALESCE((SELECT COUNT(*) FROM notes WHERE user_id = u.id AND deleted_at IS NULL), 0) as notes_count
		FROM users u
		WHERE u.deleted_at IS NULL
		ORDER BY u.created_at DESC
	`

	rows, err := h.db.Query(ctx, query)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to fetch users",
		})
	}
	defer rows.Close()

	users := make([]UserDetails, 0)
	for rows.Next() {
		var user UserDetails
		var emailEncrypted []byte
		var failedAttempts int
		var lockedUntil *time.Time
		var lastLogin *time.Time

		err := rows.Scan(
			&user.ID,
			&emailEncrypted,
			&user.IsAdmin,
			&user.CreatedAt,
			&lastLogin,
			&failedAttempts,
			&lockedUntil,
			&user.NotesCount,
		)
		if err != nil {
			continue
		}

		// Decrypt email (just show hash for privacy in admin panel)
		user.Email = "user-" + user.ID[:8] + "@hidden" // Privacy: don't expose real emails
		if lastLogin != nil {
			user.LastLogin = *lastLogin
		}
		user.IsLocked = lockedUntil != nil && lockedUntil.After(time.Now())
		user.LockedUntil = lockedUntil

		users = append(users, user)
	}

	return c.JSON(users)
}

// UpdateUserRole updates a user's admin status
// @Summary Update user role
// @Description Update user's admin role (admin only)
// @Tags Admin
// @Accept json
// @Produce json
// @Param id path string true "User ID"
// @Param request body object true "Role update"
// @Success 200 {object} map[string]string
// @Failure 400 {object} ErrorResponse
// @Failure 403 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Router /api/v1/admin/users/{id}/role [patch]
func (h *AdminHandler) UpdateUserRole(c *fiber.Ctx) error {
	userID := c.Params("id")
	if userID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "User ID is required",
		})
	}

	// Parse UUID
	uid, err := uuid.Parse(userID)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid user ID",
		})
	}

	// Parse request body
	var req struct {
		IsAdmin bool `json:"isAdmin"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	ctx := c.Context()

	// Update user role
	query := `UPDATE users SET is_admin = $1, updated_at = NOW() WHERE id = $2 AND deleted_at IS NULL`
	result, err := h.db.Exec(ctx, query, req.IsAdmin, uid)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to update user role",
		})
	}

	if result.RowsAffected() == 0 {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "User not found",
		})
	}

	return c.JSON(fiber.Map{
		"message": "User role updated successfully",
	})
}

// DeleteUser soft-deletes a user
// @Summary Delete user
// @Description Soft delete a user (admin only)
// @Tags Admin
// @Param id path string true "User ID"
// @Success 200 {object} map[string]string
// @Failure 400 {object} ErrorResponse
// @Failure 403 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Router /api/v1/admin/users/{id} [delete]
func (h *AdminHandler) DeleteUser(c *fiber.Ctx) error {
	userID := c.Params("id")
	if userID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "User ID is required",
		})
	}

	// Parse UUID
	uid, err := uuid.Parse(userID)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid user ID",
		})
	}

	ctx := c.Context()

	// Prevent self-deletion
	currentUserID, ok := c.Locals("user_id").(uuid.UUID)
	if ok && currentUserID == uid {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Cannot delete your own account",
		})
	}

	// Soft delete user
	query := `UPDATE users SET deleted_at = NOW() WHERE id = $1 AND deleted_at IS NULL`
	result, err := h.db.Exec(ctx, query, uid)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to delete user",
		})
	}

	if result.RowsAffected() == 0 {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "User not found",
		})
	}

	return c.JSON(fiber.Map{
		"message": "User deleted successfully",
	})
}

// UnlockUser unlocks a locked user account
// @Summary Unlock user
// @Description Unlock a locked user account (admin only)
// @Tags Admin
// @Param id path string true "User ID"
// @Success 200 {object} map[string]string
// @Failure 400 {object} ErrorResponse
// @Failure 403 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Router /api/v1/admin/users/{id}/unlock [post]
func (h *AdminHandler) UnlockUser(c *fiber.Ctx) error {
	userID := c.Params("id")
	if userID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "User ID is required",
		})
	}

	uid, err := uuid.Parse(userID)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid user ID",
		})
	}

	ctx := c.Context()

	// Reset failed attempts and clear lock
	query := `
		UPDATE users 
		SET failed_attempts = 0, locked_until = NULL, updated_at = NOW()
		WHERE id = $1 AND deleted_at IS NULL
	`
	result, err := h.db.Exec(ctx, query, uid)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to unlock user",
		})
	}

	if result.RowsAffected() == 0 {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "User not found",
		})
	}

	return c.JSON(fiber.Map{
		"message": "User unlocked successfully",
	})
}

// GetRegistrationSetting returns the current registration setting
// @Summary Get registration setting
// @Description Get the current registration enabled/disabled setting (admin only)
// @Tags Admin
// @Produce json
// @Success 200 {object} map[string]bool
// @Failure 403 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/v1/admin/settings/registration [get]
func (h *AdminHandler) GetRegistrationSetting(c *fiber.Ctx) error {
	ctx := c.Context()

	// Check database setting
	var enabled bool
	query := `
		SELECT COALESCE(
			(SELECT value::boolean FROM app_settings WHERE key = 'registration_enabled'),
			true
		) as enabled
	`
	err := h.db.QueryRow(ctx, query).Scan(&enabled)
	if err != nil {
		// Default to true if error
		enabled = true
	}

	return c.JSON(fiber.Map{
		"enabled": enabled,
	})
}

// UpdateRegistrationSetting updates the registration setting
// @Summary Update registration setting
// @Description Enable or disable user registration (admin only)
// @Tags Admin
// @Accept json
// @Produce json
// @Param request body object true "Registration setting"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} ErrorResponse
// @Failure 403 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/v1/admin/settings/registration [put]
func (h *AdminHandler) UpdateRegistrationSetting(c *fiber.Ctx) error {
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	ctx := c.Context()

	// Upsert the registration_enabled setting in app_settings
	query := `
		INSERT INTO app_settings (key, value, updated_at)
		VALUES ('registration_enabled', $1, NOW())
		ON CONFLICT (key)
		DO UPDATE SET value = $1, updated_at = NOW()
	`
	_, err := h.db.Exec(ctx, query, req.Enabled)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to update registration setting",
		})
	}

	return c.JSON(fiber.Map{
		"message": "Registration setting updated successfully",
		"enabled": req.Enabled,
	})
}
