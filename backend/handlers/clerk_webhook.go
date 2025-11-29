package handlers

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"leaflock/utils"
)

// ClerkWebhookHandler handles Clerk webhook events securely
type ClerkWebhookHandler struct {
	webhookSecret string
	logger        *utils.SecurityLogger
}

// NewClerkWebhookHandler creates a new webhook handler
func NewClerkWebhookHandler(webhookSecret string) *ClerkWebhookHandler {
	return &ClerkWebhookHandler{
		webhookSecret: webhookSecret,
		logger:        utils.NewSecurityLogger(),
	}
}

// HandleClerkWebhook processes Clerk webhook events with security validation
func (h *ClerkWebhookHandler) HandleClerkWebhook(c *fiber.Ctx) error {
	// Verify webhook signature
	if err := h.verifyWebhookSignature(c); err != nil {
		h.logger.LogSecurityEvent("webhook_signature_failed", "high", map[string]interface{}{
			"error": err.Error(),
			"ip":    c.IP(),
		})
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Invalid webhook signature",
		})
	}

	// Parse webhook payload
	var payload map[string]interface{}
	if err := c.BodyParser(&payload); err != nil {
		h.logger.LogError("webhook_parse_error", err, map[string]interface{}{
			"ip": c.IP(),
		})
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid webhook payload",
		})
	}

	// Extract and validate event type
	eventType, ok := payload["type"].(string)
	if !ok {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Missing event type",
		})
	}

	// Process webhook event based on type
	switch eventType {
	case "user.created":
		return h.handleUserCreated(c, payload)
	case "user.updated":
		return h.handleUserUpdated(c, payload)
	case "user.deleted":
		return h.handleUserDeleted(c, payload)
	case "session.created":
		return h.handleSessionCreated(c, payload)
	case "session.revoked":
		return h.handleSessionRevoked(c, payload)
	case "email.created":
		return h.handleEmailCreated(c, payload)
	case "email.updated":
		return h.handleEmailUpdated(c, payload)
	case "email.deleted":
		return h.handleEmailDeleted(c, payload)
	default:
		h.logger.LogSecurityEvent("unknown_webhook_event", "medium", map[string]interface{}{
			"event_type": eventType,
		})
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Unknown webhook event type",
		})
	}
}

// verifyWebhookSignature verifies the Clerk webhook signature
func (h *ClerkWebhookHandler) verifyWebhookSignature(c *fiber.Ctx) error {
	// Get signature from headers
	signature := c.Get("Clerk-Signature")
	if signature == "" {
		return fmt.Errorf("missing Clerk-Signature header")
	}

	// Get timestamp from headers
	timestamp := c.Get("Clerk-Timestamp")
	if timestamp == "" {
		return fmt.Errorf("missing Clerk-Timestamp header")
	}

	// Verify timestamp to prevent replay attacks
	if err := h.verifyTimestamp(timestamp); err != nil {
		return fmt.Errorf("invalid timestamp: %w", err)
	}

	// Get request body
	body, err := io.ReadAll(c.Request().Body)
	if err != nil {
		return fmt.Errorf("failed to read request body: %w", err)
	}

	// Reconstruct the signed payload
	signedPayload := timestamp + "." + string(body)

	// Calculate expected signature
	expectedSignature := h.calculateSignature(signedPayload)

	// Compare signatures using constant-time comparison
	if !hmac.Equal([]byte(expectedSignature), []byte(signature)) {
		return fmt.Errorf("signature mismatch")
	}

	return nil
}

// verifyTimestamp checks if the timestamp is recent enough to prevent replay attacks
func (h *ClerkWebhookHandler) verifyTimestamp(timestamp string) error {
	timestampTime, err := time.Parse(time.RFC3339, timestamp)
	if err != nil {
		return fmt.Errorf("invalid timestamp format: %w", err)
	}

	// Check if timestamp is within 5 minutes (adjust as needed)
	now := time.Now()
	if timestampTime.Before(now.Add(-5 * time.Minute)) || timestampTime.After(now.Add(5 * time.Minute)) {
		return fmt.Errorf("timestamp too old or too new")
	}

	return nil
}

// calculateSignature calculates the expected webhook signature
func (h *ClerkWebhookHandler) calculateSignature(payload string) string {
	mac := hmac.New(sha256.New, []byte(h.webhookSecret))
	mac.Write([]byte(payload))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// Webhook event handlers

func (h *ClerkWebhookHandler) handleUserCreated(c *fiber.Ctx, payload map[string]interface{}) error {
	userID, ok := payload["data"].(map[string]interface{})["id"].(string)
	if !ok {
		return fmt.Errorf("missing user ID")
	}

	h.logger.LogAuthEvent("user_created", uuid.MustParse(userID), true, map[string]interface{}{
		"source": "webhook",
	})

	// Update local database with new user information
	// This would integrate with your database layer
	
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status": "processed",
		"event": "user.created",
	})
}

func (h *ClerkWebhookHandler) handleUserUpdated(c *fiber.Ctx, payload map[string]interface{}) error {
	userID, ok := payload["data"].(map[string]interface{})["id"].(string)
	if !ok {
		return fmt.Errorf("missing user ID")
	}

	h.logger.LogAuthEvent("user_updated", uuid.MustParse(userID), true, map[string]interface{}{
		"source": "webhook",
	})

	// Update local database with user changes
	// This would integrate with your database layer
	
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status": "processed",
		"event": "user.updated",
	})
}

func (h *ClerkWebhookHandler) handleUserDeleted(c *fiber.Ctx, payload map[string]interface{}) error {
	userID, ok := payload["data"].(map[string]interface{})["id"].(string)
	if !ok {
		return fmt.Errorf("missing user ID")
	}

	h.logger.LogAuthEvent("user_deleted", uuid.MustParse(userID), true, map[string]interface{}{
		"source": "webhook",
	})

	// Handle user deletion (soft delete, data cleanup, etc.)
	// This would integrate with your database layer
	
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status": "processed",
		"event": "user.deleted",
	})
}

func (h *ClerkWebhookHandler) handleSessionCreated(c *fiber.Ctx, payload map[string]interface{}) error {
	sessionID, ok := payload["data"].(map[string]interface{})["id"].(string)
	if !ok {
		return fmt.Errorf("missing session ID")
	}

	h.logger.LogSecurityEvent("session_created", "info", map[string]interface{}{
		"session_id": sessionID,
		"source": "webhook",
	})

	// Handle new session (could be used for analytics, notifications, etc.)
	
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status": "processed",
		"event": "session.created",
	})
}

func (h *ClerkWebhookHandler) handleSessionRevoked(c *fiber.Ctx, payload map[string]interface{}) error {
	sessionID, ok := payload["data"].(map[string]interface{})["id"].(string)
	if !ok {
		return fmt.Errorf("missing session ID")
	}

	h.logger.LogSecurityEvent("session_revoked", "warning", map[string]interface{}{
		"session_id": sessionID,
		"source": "webhook",
	})

	// Handle session revocation (could be used for security monitoring)
	
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status": "processed",
		"event": "session.revoked",
	})
}

func (h *ClerkWebhookHandler) handleEmailCreated(c *fiber.Ctx, payload map[string]interface{}) error {
	emailAddress, ok := payload["data"].(map[string]interface{})["email_address"].(string)
	if !ok {
		return fmt.Errorf("missing email address")
	}

	h.logger.LogSecurityEvent("email_created", "info", map[string]interface{}{
		"email": "[email]", // Don't log actual email
		"source": "webhook",
	})

	// Handle email creation (verification workflows, etc.)
	
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status": "processed",
		"event": "email.created",
	})
}

// SetupClerkWebhookRoutes sets up the webhook routes
func SetupClerkWebhookRoutes(app *fiber.App, webhookSecret string) {
	handler := NewClerkWebhookHandler(webhookSecret)
	
	// Webhook endpoint with security headers
	app.Post("/api/webhooks/clerk", func(c *fiber.Ctx) error {
		// Add security headers
		c.Set("X-Content-Type-Options", "nosniff")
		c.Set("X-Frame-Options", "DENY")
		c.Set("X-XSS-Protection", "1; mode=block")
		c.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		
		return handler.HandleClerkWebhook(c)
	})
}