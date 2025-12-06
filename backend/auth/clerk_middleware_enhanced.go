package auth

import (
	"strings"

	"github.com/gofiber/fiber/v2"
)

// ClerkAuthMiddleware validates Clerk session tokens and sets user context
func (h *Handler) ClerkAuthMiddleware(c *fiber.Ctx) error {
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

	// Use enhanced session management with timing attack protection
	sessionManager := NewClerkSessionManager(h)

	// Add timing attack protection
	h.TimingAttackProtection()

	// Validate token with enhanced security
	claims, err := sessionManager.ValidateAndRefreshSession(c, token)
	if err != nil {
		// Check if it's a token expiration issue
		if isTokenExpired(err) {
			return c.Status(fiber.StatusUnauthorized).JSON(ErrorResponse{
				Error: "Session expired. Please sign in again.",
				Code:  "SESSION_EXPIRED",
			})
		}

		return c.Status(fiber.StatusUnauthorized).JSON(ErrorResponse{
			Error: "Invalid or expired Clerk session token",
			Code:  ErrCodeInvalidToken,
		})
	}

	// Extract user information from Clerk claims
	userID, err := h.extractUserIDFromClerkClaims(claims)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(ErrorResponse{
			Error: "Invalid user identification",
			Code:  ErrCodeInvalidToken,
		})
	}

	isAdmin := h.extractAdminStatusFromClerkClaims(claims)

	// Set user context with enhanced information
	c.Locals("user_id", userID)
	c.Locals("is_admin", isAdmin)
	c.Locals("clerk_user_id", claims.Subject) // Store original Clerk user ID
	c.Locals("auth_type", "clerk")
	c.Locals("token", token)
	c.Locals("clerk_claims", claims) // Store full claims for advanced usage

	return c.Next()
}

// OptionalClerkAuthMiddleware validates Clerk token if present, but doesn't require it
func (h *Handler) OptionalClerkAuthMiddleware(c *fiber.Ctx) error {
	authHeader := c.Get("Authorization")
	if authHeader == "" {
		return c.Next() // No token, continue without auth
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return c.Next() // Invalid format, continue without auth
	}

	token := parts[1]

	// Try to validate Clerk token
	claims, err := h.validateClerkToken(c.Context(), token)
	if err != nil {
		return c.Next() // Invalid token, continue without auth
	}

	// Extract user information from Clerk claims
	userID, err := h.extractUserIDFromClerkClaims(claims)
	if err != nil {
		return c.Next() // Invalid user identification, continue without auth
	}

	isAdmin := h.extractAdminStatusFromClerkClaims(claims)

	// Set user context
	c.Locals("user_id", userID)
	c.Locals("is_admin", isAdmin)
	c.Locals("clerk_user_id", claims.Subject)
	c.Locals("clerk_token", token)

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
