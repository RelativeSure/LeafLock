package auth

import (
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

// DualAuthMiddleware supports both JWT and Clerk authentication during migration
func (h *Handler) DualAuthMiddleware(c *fiber.Ctx) error {
	authHeader := c.Get("Authorization")
	if authHeader == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(ErrorResponse{
			Error: "No authorization token provided",
			Code:  ErrCodeInvalidToken,
		})
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return c.Status(fiber.StatusUnauthorized).JSON(ErrorResponse{
			Error: "Invalid authorization format",
			Code:  ErrCodeInvalidToken,
		})
	}

	token := parts[1]

	// Try Clerk authentication first (new system)
	if h.config.ClerkSecretKey != "" {
		claims, err := h.validateClerkToken(c.Context(), token)
		if err == nil {
			// Clerk token is valid
			userID, err := h.extractUserIDFromClerkClaims(claims)
			if err == nil {
				isAdmin := h.extractAdminStatusFromClerkClaims(claims)
				
				// Set user context for Clerk auth
				c.Locals("user_id", userID)
				c.Locals("is_admin", isAdmin)
				c.Locals("clerk_user_id", claims.Subject)
				c.Locals("auth_type", "clerk")
				c.Locals("token", token)
				
				return c.Next()
			}
		}
	}

	// Clerk auth failed or not configured, try JWT authentication (legacy)
	if h.config.JWTSecret != nil {
		// Check if token is blacklisted
		blacklisted, err := h.service.session.IsJWTBlacklisted(c.Context(), token)
		if err == nil && blacklisted {
			return c.Status(fiber.StatusUnauthorized).JSON(ErrorResponse{
				Error: "Token has been revoked",
				Code:  ErrCodeInvalidToken,
			})
		}

		// Validate JWT
		userID, isAdmin, err := h.service.ValidateJWT(token)
		if err == nil {
			// JWT is valid
			c.Locals("user_id", userID)
			c.Locals("is_admin", isAdmin)
			c.Locals("auth_type", "jwt")
			c.Locals("token", token)
			
			return c.Next()
		}
	}

	// Both authentication methods failed
	return c.Status(fiber.StatusUnauthorized).JSON(ErrorResponse{
		Error: "Invalid or expired token",
		Code:  ErrCodeInvalidToken,
	})
}

// OptionalDualAuthMiddleware validates either JWT or Clerk token if present
func (h *Handler) OptionalDualAuthMiddleware(c *fiber.Ctx) error {
	authHeader := c.Get("Authorization")
	if authHeader == "" {
		return c.Next() // No token, continue without auth
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return c.Next() // Invalid format, continue without auth
	}

	token := parts[1]

	// Try Clerk authentication first
	if h.config.ClerkSecretKey != "" {
		claims, err := h.validateClerkToken(c.Context(), token)
		if err == nil {
			userID, err := h.extractUserIDFromClerkClaims(claims)
			if err == nil {
				isAdmin := h.extractAdminStatusFromClerkClaims(claims)
				
				c.Locals("user_id", userID)
				c.Locals("is_admin", isAdmin)
				c.Locals("clerk_user_id", claims.Subject)
				c.Locals("auth_type", "clerk")
				c.Locals("token", token)
				
				return c.Next()
			}
		}
	}

	// Clerk failed, try JWT authentication
	if h.config.JWTSecret != nil {
		// Check if token is blacklisted
		blacklisted, err := h.service.session.IsJWTBlacklisted(c.Context(), token)
		if err == nil && blacklisted {
			return c.Next() // Blacklisted token, continue without auth
		}

		// Try to validate JWT
		userID, isAdmin, err := h.service.ValidateJWT(token)
		if err == nil {
			c.Locals("user_id", userID)
			c.Locals("is_admin", isAdmin)
			c.Locals("auth_type", "jwt")
			c.Locals("token", token)
			
			return c.Next()
		}
	}

	// Both authentication methods failed, continue without auth
	return c.Next()
}

// GetAuthType returns the authentication type used for the current request
func GetAuthType(c *fiber.Ctx) string {
	authType, ok := c.Locals("auth_type").(string)
	if !ok {
		return "none"
	}
	return authType
}

// GetClerkUserID returns the Clerk user ID if available
func GetClerkUserID(c *fiber.Ctx) string {
	clerkUserID, ok := c.Locals("clerk_user_id").(string)
	if !ok {
		return ""
	}
	return clerkUserID
}