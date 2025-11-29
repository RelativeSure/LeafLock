package auth

import (
	"errors"
	"fmt"
	"strings"

	"github.com/clerk/clerk-sdk-go/v2"
	"github.com/gofiber/fiber/v2"
	"leaflock/utils"
)

// ClerkErrorHandler provides secure error handling for Clerk operations
type ClerkErrorHandler struct {
	logger *utils.SecurityLogger
}

// NewClerkErrorHandler creates a new error handler
func NewClerkErrorHandler() *ClerkErrorHandler {
	return &ClerkErrorHandler{
		logger: utils.NewSecurityLogger(),
	}
}

// HandleClerkError processes Clerk errors securely
func (h *ClerkErrorHandler) HandleClerkError(c *fiber.Ctx, err error, operation string) error {
	// Extract user ID if available
	var userID string
	if uid, ok := c.Locals("user_id").(string); ok {
		userID = uid
	}

	// Categorize and log the error
	errorType, severity, publicMessage := h.categorizeClerkError(err)
	
	// Log error securely (without sensitive details)
	h.logger.LogError(operation, errors.New(errorType), map[string]interface{}{
		"user_id":      utils.SanitizeValue(userID),
		"error_type":   errorType,
		"severity":     severity,
		"ip":           c.IP(),
		"user_agent":   c.Get("User-Agent"),
	})

	// Return safe error message to client
	return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
		"error": publicMessage,
		"code":  "CLERK_ERROR",
	})
}

// categorizeClerkError categorizes Clerk errors and returns safe information
func (h *ClerkErrorHandler) categorizeClerkError(err error) (errorType string, severity string, publicMessage string) {
	errMsg := err.Error()
	
	switch {
	case strings.Contains(errMsg, "expired"):
		return "token_expired", "info", "Your session has expired. Please sign in again."
		
	case strings.Contains(errMsg, "invalid"):
		return "invalid_token", "info", "Invalid authentication. Please try again."
		
	case strings.Contains(errMsg, "rate limit"):
		return "rate_limited", "warning", "Too many requests. Please try again later."
		
	case strings.Contains(errMsg, "unauthorized"):
		return "unauthorized", "info", "You don't have permission to perform this action."
		
	case strings.Contains(errMsg, "not found"):
		return "not_found", "info", "The requested resource was not found."
		
	case strings.Contains(errMsg, "already exists"):
		return "already_exists", "info", "This resource already exists."
		
	case strings.Contains(errMsg, "network") || strings.Contains(errMsg, "connection"):
		return "network_error", "error", "Network error. Please try again."
		
	case strings.Contains(errMsg, "timeout"):
		return "timeout", "error", "Request timed out. Please try again."
		
	default:
		return "unknown_error", "error", "An error occurred. Please try again."
	}
}

// SecureClerkError creates a secure error response
func SecureClerkError(err error, operation string) error {
	if err == nil {
		return nil
	}
	
	// Never expose internal error details
	return fmt.Errorf("%s: authentication failed", operation)
}

// ValidateClerkConfiguration validates Clerk configuration
func ValidateClerkConfiguration(clerkSecretKey string) error {
	if clerkSecretKey == "" {
		return errors.New("CLERK_SECRET_KEY is required")
	}
	
	if len(clerkSecretKey) < 20 {
		return errors.New("CLERK_SECRET_KEY must be at least 20 characters")
	}
	
	// Check for common weak patterns
	weakPatterns := []string{"test", "example", "123456", "password", "secret"}
	for _, pattern := range weakPatterns {
		if strings.Contains(strings.ToLower(clerkSecretKey), pattern) {
			return fmt.Errorf("CLERK_SECRET_KEY contains weak pattern: %s", pattern)
		}
	}
	
	return nil
}

// SanitizeClerkError sanitizes Clerk error messages for logging
func SanitizeClerkError(err error) string {
	if err == nil {
		return ""
	}
	
	errMsg := err.Error()
	
	// Remove sensitive information
	sanitized := errMsg
	
	// Remove email addresses
	sanitized = removeEmails(sanitized)
	
	// Remove tokens/secrets
	sanitized = removeTokens(sanitized)
	
	// Remove phone numbers
	sanitized = removePhoneNumbers(sanitized)
	
	// Remove IP addresses
	sanitized = removeIPAddresses(sanitized)
	
	return sanitized
}

// removeEmails removes email addresses from strings
func removeEmails(s string) string {
	// Simple email removal - in production, use proper regex
	parts := strings.Split(s, "@")
	if len(parts) == 2 {
		return "[email]"
	}
	return s
}

// removeTokens removes tokens/secrets from strings
func removeTokens(s string) string {
	// Remove long alphanumeric strings that look like tokens
	// This is a simplified version - in production, use proper regex
	words := strings.Fields(s)
	result := make([]string, 0, len(words))
	
	for _, word := range words {
		if len(word) > 20 && strings.ContainsAny(word, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") {
			result = append(result, "[token]")
		} else {
			result = append(result, word)
		}
	}
	
	return strings.Join(result, " ")
}

// removePhoneNumbers removes phone numbers from strings
func removePhoneNumbers(s string) string {
	// Simple phone number removal
	if strings.ContainsAny(s, "0123456789") && len(s) >= 10 {
		return "[phone]"
	}
	return s
}

// removeIPAddresses removes IP addresses from strings
func removeIPAddresses(s string) bool {
	// Simple IP detection
	if strings.Count(s, ".") == 3 && strings.ContainsAny(s, "0123456789") {
		return true
	}
	return false
}

// CreateSecureError creates a secure error for logging
func CreateSecureError(operation string, originalError error, context map[string]interface{}) error {
	// Sanitize the original error
	sanitizedError := SanitizeClerkError(originalError)
	
	// Create secure context
	secureContext := make(map[string]interface{})
	for key, value := range context {
		secureContext[key] = utils.SanitizeValue(value)
	}
	
	// Return generic error message
	return fmt.Errorf("%s: %s", operation, sanitizedError)
}

// LogSecurityIncident logs security incidents securely
func LogSecurityIncident(operation string, incidentType string, details map[string]interface{}) {
	logger := utils.NewSecurityLogger()
	
	// Sanitize details
	safeDetails := make(map[string]interface{})
	for key, value := range details {
		safeDetails[key] = utils.SanitizeValue(value)
	}
	
	logger.LogSecurityEvent(incidentType, "high", safeDetails)
}

// RateLimitSecurityEvents prevents abuse of security logging
var securityEventLimiter = make(map[string]time.Time)

// ShouldLogSecurityEvent checks if we should log a security event (rate limiting)
func ShouldLogSecurityEvent(eventType string, userID string) bool {
	key := eventType + ":" + userID
	
	now := time.Now()
	if lastTime, exists := securityEventLimiter[key]; exists {
		if now.Sub(lastTime) < 1*time.Minute {
			return false // Rate limited
		}
	}
	
	securityEventLimiter[key] = now
	return true
}