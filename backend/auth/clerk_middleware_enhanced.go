package auth

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/clerk/clerk-sdk-go/v2"
	"github.com/clerk/clerk-sdk-go/v2/jwt"
	"github.com/gofiber/fiber/v2"
)

// EnhancedClerkMiddleware provides comprehensive logging and error handling for Clerk authentication
type ClerkMiddlewareConfig struct {
	EnableDebugLogging bool
	SkipRedirectLoop   bool
}

// EnhancedClerkMiddleware validates Clerk session tokens with enhanced debugging and error handling
func (h *Handler) EnhancedClerkMiddleware(c *fiber.Ctx) error {
	ctx := c.Context()

	// Debug logging
	if h.config.EnableDebugLogging {
		log.Printf("🔍 EnhancedClerkMiddleware: Processing %s %s", c.Method(), c.Path())
		log.Printf("🔍 Headers: Authorization present=%t", c.Get("Authorization") != "")
		log.Printf("🔍 Origin: %s", c.Get("Origin"))
		log.Printf("🔍 Content-Type: %s", c.Get("Content-Type"))
	}

	// Get Authorization header
	authHeader := c.Get("Authorization")
	if authHeader == "" {
		log.Printf("⚠️  No authorization token provided for %s", c.Path())
		return c.Status(fiber.StatusUnauthorized).JSON(ErrorResponse{
			Error: "No authorization token provided",
			Code:  ErrCodeInvalidToken,
		})
	}

	// Extract token (format: "Bearer <token>")
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		log.Printf("⚠️  Invalid authorization format: %s", authHeader[:min(20, len(authHeader))])
		return c.Status(fiber.StatusUnauthorized).JSON(ErrorResponse{
			Error: "Invalid authorization format. Expected 'Bearer <token>'",
			Code:  ErrCodeInvalidToken,
		})
	}

	token := parts[1]

	if h.config.EnableDebugLogging {
		log.Printf("🔍 Token received: %s...", token[:min(20, len(token))])
	}

	// Validate token with enhanced error handling
	claims, err := h.validateClerkTokenEnhancedWithDebug(ctx, token)
	if err != nil {
		log.Printf("❌ Token validation failed: %v", err)

		// Check if it's a token expiration issue
		if isTokenExpired(err) {
			return c.Status(fiber.StatusUnauthorized).JSON(ErrorResponse{
				Error:   "Session expired. Please sign in again.",
				Code:    "SESSION_EXPIRED",
				Details: h.getDebugInfo(err, token),
			})
		}

		return c.Status(fiber.StatusUnauthorized).JSON(ErrorResponse{
			Error:   "Invalid or expired Clerk session token",
			Code:    ErrCodeInvalidToken,
			Details: h.getDebugInfo(err, token),
		})
	}

	if h.config.EnableDebugLogging {
		log.Printf("✅ Token validated successfully for user: %s", claims.Subject)
		log.Printf("✅ Token issued at: %v, expires at: %v",
			claims.IssuedAt, claims.Expiry)
	}

	// Extract user information from Clerk claims
	userID, err := h.extractUserIDFromClerkClaims(claims)
	if err != nil {
		log.Printf("❌ Invalid user identification: %v", err)
		return c.Status(fiber.StatusUnauthorized).JSON(ErrorResponse{
			Error:   "Invalid user identification",
			Code:    ErrCodeInvalidToken,
			Details: h.getDebugInfo(err, token),
		})
	}

	isAdmin := h.extractAdminStatusFromClerkClaims(claims)

	// Set user context with enhanced information
	c.Locals("user_id", userID)
	c.Locals("is_admin", isAdmin)
	c.Locals("clerk_user_id", claims.Subject)
	c.Locals("auth_type", "clerk")
	c.Locals("token", token)
	c.Locals("clerk_claims", claims)

	if h.config.EnableDebugLogging {
		log.Printf("✅ User authenticated: %s (admin: %v)", userID, isAdmin)
	}

	return c.Next()
}

// validateClerkTokenEnhancedWithDebug validates a Clerk token with enhanced debugging
func (h *Handler) validateClerkTokenEnhancedWithDebug(ctx context.Context, token string) (*clerk.SessionClaims, error) {
	start := time.Now()
	defer func() {
		if h.config.EnableDebugLogging {
			duration := time.Since(start)
			log.Printf("🔍 Token validation took: %v", duration)
		}
	}()

	// Check if Clerk SDK is initialized
	if !h.isClerkInitialized() {
		return nil, fmt.Errorf("Clerk SDK not initialized. Check CLERK_SECRET_KEY configuration")
	}

	// Use Clerk SDK to verify the session token
	claims, err := jwt.Verify(ctx, &jwt.VerifyParams{
		Token: token,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to verify Clerk token: %w", err)
	}

	if claims == nil {
		return nil, fmt.Errorf("token validation returned nil claims")
	}

	// Validate required claims
	if claims.Subject == "" {
		return nil, fmt.Errorf("missing subject claim (user ID)")
	}

	if claims.IssuedAt == nil {
		return nil, fmt.Errorf("missing issued at claim")
	}

	if claims.Expiry == nil {
		return nil, fmt.Errorf("missing expiry claim")
	}

	// Check if token is expired
	now := time.Now().Unix()
	if *claims.Expiry < now {
		return nil, fmt.Errorf("token expired at %d (current time: %d)", *claims.Expiry, now)
	}

	return claims, nil
}

// getDebugInfo returns debug information for troubleshooting
func (h *Handler) getDebugInfo(err error, token string) map[string]interface{} {
	if !h.config.EnableDebugLogging {
		return nil
	}

	// Extract token parts for debugging (without sensitive data)
	tokenParts := strings.Split(token, ".")
	hasValidStructure := len(tokenParts) == 3

	return map[string]interface{}{
		"error":            err.Error(),
		"token_structure":  hasValidStructure,
		"token_length":     len(token),
		"timestamp":        time.Now().Unix(),
		"clerk_configured": h.isClerkInitialized(),
	}
}

// isClerkInitialized checks if Clerk SDK is properly initialized
func (h *Handler) isClerkInitialized() bool {
	// In a real implementation, check if Clerk client is configured
	// For now, we'll check if we have a secret key
	return h.config != nil && h.config.ClerkSecretKey != ""
}

// SafeClerkMiddleware prevents redirect loops by implementing debouncing
func (h *Handler) SafeClerkMiddleware(c *fiber.Ctx) error {
	// Check if this request is part of a redirect loop
	if h.isRedirectLoopDetected(c) {
		log.Printf("⚠️  Redirect loop detected for %s %s", c.Method(), c.Path())
		return c.Status(fiber.StatusTooManyRequests).JSON(ErrorResponse{
			Error: "Too many authentication attempts. Please wait a moment and try again.",
			Code:  "RATE_LIMITED",
		})
	}

	return h.EnhancedClerkMiddleware(c)
}

// isRedirectLoopDetected checks if we're in a redirect loop
func (h *Handler) isRedirectLoopDetected(c *fiber.Ctx) bool {
	// Check for repeated failed authentication attempts from the same client
	// This is a simplified implementation - in production, use Redis or similar
	clientIP := c.IP()
	userAgent := c.Get("User-Agent")

	// Store attempt count in context (in production, store in Redis with TTL)
	attemptKey := fmt.Sprintf("auth_attempt_%s_%s", clientIP, userAgent)
	attempts := c.Locals(attemptKey)

	if attempts == nil {
		c.Locals(attemptKey, 1)
		return false
	}

	count := attempts.(int)
	if count > 5 { // More than 5 attempts in one request cycle
		return true
	}

	c.Locals(attemptKey, count+1)
	return false
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
