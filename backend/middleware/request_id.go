package middleware

import (
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

// RequestIDMiddleware adds a unique request ID to each request
// The request ID is stored in locals and can be used for logging and tracing
func RequestIDMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Check if request ID already exists in header (from load balancer/proxy)
		requestID := c.Get("X-Request-ID")
		if requestID == "" {
			// Generate new UUID for request tracking
			requestID = uuid.New().String()
		}

		// Store in locals for use in handlers and logging
		c.Locals("request_id", requestID)

		// Add to response headers for client-side tracking
		c.Set("X-Request-ID", requestID)

		return c.Next()
	}
}
