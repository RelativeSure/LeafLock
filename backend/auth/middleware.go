package auth

import (
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

// RequireAuthMiddleware ensures user is authenticated
func (h *Handler) RequireAuthMiddleware(c *fiber.Ctx) error {
	userID := c.Locals("user_id")
	if userID == nil {
		return c.Status(fiber.StatusUnauthorized).JSON(ErrorResponse{
			Error: "Authentication required",
			Code:  ErrCodeInvalidToken,
		})
	}

	return c.Next()
}

// RequireAdminMiddleware ensures user is an admin
func (h *Handler) RequireAdminMiddleware(c *fiber.Ctx) error {
	isAdmin, ok := c.Locals("is_admin").(bool)
	if !ok || !isAdmin {
		return c.Status(fiber.StatusForbidden).JSON(ErrorResponse{
			Error: "Admin access required",
			Code:  "FORBIDDEN",
		})
	}

	return c.Next()
}

// GetUserID extracts user ID from context
func GetUserID(c *fiber.Ctx) (uuid.UUID, error) {
	userID, ok := c.Locals("user_id").(uuid.UUID)
	if !ok {
		return uuid.Nil, fiber.NewError(fiber.StatusUnauthorized, "User not authenticated")
	}
	return userID, nil
}

// IsAdmin checks if current user is an admin
func IsAdmin(c *fiber.Ctx) bool {
	isAdmin, ok := c.Locals("is_admin").(bool)
	return ok && isAdmin
}