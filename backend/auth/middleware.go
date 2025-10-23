package auth

import (
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

// JWTMiddleware validates JWT tokens and sets user context
func (h *Handler) JWTMiddleware(c *fiber.Ctx) error {
	// Get Authorization header
	authHeader := c.Get("Authorization")
	if authHeader == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(ErrorResponse{
			Error: "No authorization token provided",
			Code:  ErrCodeInvalidToken,
		})
	}

	// Extract token (format: "Bearer <token>")
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return c.Status(fiber.StatusUnauthorized).JSON(ErrorResponse{
			Error: "Invalid authorization format",
			Code:  ErrCodeInvalidToken,
		})
	}

	token := parts[1]

	// Validate JWT
	userID, isAdmin, err := h.service.ValidateJWT(token)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(ErrorResponse{
			Error: "Invalid or expired token",
			Code:  ErrCodeInvalidToken,
		})
	}

	// Set user context
	c.Locals("user_id", userID)
	c.Locals("is_admin", isAdmin)
	c.Locals("token", token)

	return c.Next()
}

// OptionalJWTMiddleware validates JWT if present, but doesn't require it
func (h *Handler) OptionalJWTMiddleware(c *fiber.Ctx) error {
	authHeader := c.Get("Authorization")
	if authHeader == "" {
		return c.Next() // No token, continue without auth
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return c.Next() // Invalid format, continue without auth
	}

	token := parts[1]

	// Try to validate JWT
	userID, isAdmin, err := h.service.ValidateJWT(token)
	if err != nil {
		return c.Next() // Invalid token, continue without auth
	}

	// Set user context
	c.Locals("user_id", userID)
	c.Locals("is_admin", isAdmin)
	c.Locals("token", token)

	return c.Next()
}

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
