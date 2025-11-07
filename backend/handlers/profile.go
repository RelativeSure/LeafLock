package handlers

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"strings"

	"leaflock/database"

	"github.com/gofiber/fiber/v2"
)

// ProfileHandler handles user profile operations
type ProfileHandler struct {
	db database.Database
}

// NewProfileHandler creates a new profile handler
func NewProfileHandler(db database.Database) *ProfileHandler {
	return &ProfileHandler{db: db}
}

// Profile represents a user's profile information
type Profile struct {
	ID                 string  `json:"id"`
	Email              string  `json:"email"`
	DisplayName        *string `json:"display_name"`
	Bio                *string `json:"bio"`
	AvatarURL          *string `json:"avatar_url"`
	ProfilePictureType string  `json:"profile_picture_type"`
	GravatarURL        string  `json:"gravatar_url"` // Computed Gravatar URL
	CreatedAt          string  `json:"created_at"`
	LastLogin          *string `json:"last_login,omitempty"`
}

// UpdateProfileRequest represents the request body for updating profile
type UpdateProfileRequest struct {
	DisplayName *string `json:"display_name"`
	Bio         *string `json:"bio"`
	AvatarURL   *string `json:"avatar_url"`
}

// GetProfile returns the current user's profile
// @Summary Get user profile
// @Description Retrieve the authenticated user's profile information
// @Tags Profile
// @Accept json
// @Produce json
// @Success 200 {object} Profile
// @Failure 401 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/v1/profile [get]
func (h *ProfileHandler) GetProfile(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(string)
	ctx := context.Background()

	query := `
		SELECT
			id,
			email_plaintext,
			display_name,
			bio,
			avatar_url,
			profile_picture_type,
			created_at,
			last_login
		FROM users
		WHERE id = $1 AND deleted_at IS NULL
	`

	var profile Profile
	var displayName, bio, avatarURL, lastLogin *string
	err := h.db.QueryRow(ctx, query, userID).Scan(
		&profile.ID,
		&profile.Email,
		&displayName,
		&bio,
		&avatarURL,
		&profile.ProfilePictureType,
		&profile.CreatedAt,
		&lastLogin,
	)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to fetch profile",
		})
	}

	profile.DisplayName = displayName
	profile.Bio = bio
	profile.AvatarURL = avatarURL
	profile.LastLogin = lastLogin

	// Generate Gravatar URL
	profile.GravatarURL = generateGravatarURL(profile.Email)

	return c.JSON(profile)
}

// UpdateProfile updates the current user's profile
// @Summary Update user profile
// @Description Update the authenticated user's profile information
// @Tags Profile
// @Accept json
// @Produce json
// @Param profile body UpdateProfileRequest true "Profile data"
// @Success 200 {object} Profile
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/v1/profile [put]
func (h *ProfileHandler) UpdateProfile(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(string)
	ctx := context.Background()

	var req UpdateProfileRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	// Validate display name length
	if req.DisplayName != nil && len(*req.DisplayName) > 100 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Display name must be 100 characters or less",
		})
	}

	// Validate bio length
	if req.Bio != nil && len(*req.Bio) > 500 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Bio must be 500 characters or less",
		})
	}

	// Validate avatar URL format
	if req.AvatarURL != nil && *req.AvatarURL != "" {
		url := strings.TrimSpace(*req.AvatarURL)
		if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Avatar URL must be a valid HTTP/HTTPS URL",
			})
		}
	}

	// Update profile
	query := `
		UPDATE users
		SET
			display_name = COALESCE($2, display_name),
			bio = COALESCE($3, bio),
			avatar_url = COALESCE($4, avatar_url),
			updated_at = NOW()
		WHERE id = $1 AND deleted_at IS NULL
		RETURNING
			id,
			email_plaintext,
			display_name,
			bio,
			avatar_url,
			profile_picture_type,
			created_at,
			last_login
	`

	var profile Profile
	var displayName, bio, avatarURL, lastLogin *string
	err := h.db.QueryRow(ctx, query, userID, req.DisplayName, req.Bio, req.AvatarURL).Scan(
		&profile.ID,
		&profile.Email,
		&displayName,
		&bio,
		&avatarURL,
		&profile.ProfilePictureType,
		&profile.CreatedAt,
		&lastLogin,
	)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to update profile",
		})
	}

	profile.DisplayName = displayName
	profile.Bio = bio
	profile.AvatarURL = avatarURL
	profile.LastLogin = lastLogin
	profile.GravatarURL = generateGravatarURL(profile.Email)

	return c.JSON(profile)
}

// SetAvatarType sets the user's avatar type preference
// @Summary Set avatar type
// @Description Set whether to use Gravatar or custom avatar
// @Tags Profile
// @Accept json
// @Produce json
// @Param type body map[string]string true "Avatar type: gravatar or custom"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/v1/profile/avatar-type [post]
func (h *ProfileHandler) SetAvatarType(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(string)
	ctx := context.Background()

	var req struct {
		Type string `json:"type"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	// Validate avatar type
	if req.Type != "gravatar" && req.Type != "custom" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Avatar type must be 'gravatar' or 'custom'",
		})
	}

	// Update avatar type
	query := `
		UPDATE users
		SET profile_picture_type = $2, updated_at = NOW()
		WHERE id = $1 AND deleted_at IS NULL
	`

	_, err := h.db.Exec(ctx, query, userID, req.Type)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to update avatar type",
		})
	}

	return c.JSON(fiber.Map{
		"message": "Avatar type updated successfully",
		"type":    req.Type,
	})
}

// generateGravatarURL generates a Gravatar URL from an email address
func generateGravatarURL(email string) string {
	// Trim whitespace and convert to lowercase
	email = strings.TrimSpace(strings.ToLower(email))

	// Generate MD5 hash
	hash := md5.Sum([]byte(email))
	hashStr := hex.EncodeToString(hash[:])

	// Return Gravatar URL with default identicon and size 200
	return "https://www.gravatar.com/avatar/" + hashStr + "?d=identicon&s=200"
}
