package auth

import (
	"context"
	"fmt"
	"strings"

	"github.com/clerk/clerk-sdk-go/v2"
	"github.com/clerk/clerk-sdk-go/v2/jwt"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

// ClerkMiddleware validates Clerk session tokens and sets user context with enhanced functionality
func (h *Handler) ClerkMiddleware(c *fiber.Ctx) error {
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

// OptionalClerkMiddleware validates Clerk token if present, but doesn't require it
func (h *Handler) OptionalClerkMiddleware(c *fiber.Ctx) error {
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

// validateClerkToken validates a Clerk session token
func (h *Handler) validateClerkToken(ctx context.Context, token string) (*clerk.SessionClaims, error) {
	// Use Clerk SDK to verify the session token
	claims, err := jwt.Verify(ctx, &jwt.VerifyParams{
		Token: token,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to verify Clerk token: %w", err)
	}

	return claims, nil
}

// extractUserIDFromClerkClaims extracts the internal user ID from Clerk claims
func (h *Handler) extractUserIDFromClerkClaims(claims *jwt.Claims) (uuid.UUID, error) {
	// The Subject claim contains the Clerk user ID
	clerkUserID := claims.Subject
	if clerkUserID == "" {
		return uuid.Nil, fmt.Errorf("missing subject claim")
	}

	// For now, we'll use the Clerk user ID directly
	// In a full migration, you might want to map Clerk user IDs to internal user IDs
	// This would require a database table to maintain the mapping
	
	// Convert Clerk user ID string to UUID
	// Clerk user IDs are already in UUID format
	userID, err := uuid.Parse(clerkUserID)
	if err != nil {
		return uuid.Nil, fmt.Errorf("invalid user ID format: %w", err)
	}

	return userID, nil
}

// extractAdminStatusFromClerkClaims determines if user is admin from Clerk claims
func (h *Handler) extractAdminStatusFromClerkClaims(claims *jwt.Claims) bool {
	// Check for admin role in Clerk's public metadata
	if claims.PublicMetaData != nil {
		// Check for isAdmin flag
		if isAdmin, ok := claims.PublicMetaData["isAdmin"].(bool); ok && isAdmin {
			return true
		}
		// Check for role field
		if role, ok := claims.PublicMetaData["role"].(string); ok && role == "admin" {
			return true
		}
	}
	
	// Check for admin role in Clerk's private metadata (if available)
	if claims.PrivateMetaData != nil {
		if isAdmin, ok := claims.PrivateMetaData["isAdmin"].(bool); ok && isAdmin {
			return true
		}
		if role, ok := claims.PrivateMetaData["role"].(string); ok && role == "admin" {
			return true
		}
	}

	return false
}

// InitializeClerk initializes the Clerk SDK with the secret key
func InitializeClerk(secretKey string) error {
	if secretKey == "" {
		return fmt.Errorf("Clerk secret key is required")
	}

	// Initialize Clerk client
	clerk.SetKey(secretKey)
	
	return nil
}