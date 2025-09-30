package middleware

import (
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

// CryptoService interface for encryption operations
type CryptoService interface {
	Encrypt(plaintext []byte) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
}

// JWTMiddleware creates a Fiber middleware for JWT token validation
// It validates JWT tokens, checks Redis session validity, and sets user context
func JWTMiddleware(secret []byte, redis *redis.Client, crypto CryptoService) fiber.Handler {
	return func(c *fiber.Ctx) error {
		token := c.Get("Authorization")
		if token == "" {
			return c.Status(401).JSON(fiber.Map{"error": "Missing authorization"})
		}

		token = strings.TrimPrefix(token, "Bearer ")

		parsed, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
			return secret, nil
		})

		if err != nil || !parsed.Valid {
			return c.Status(401).JSON(fiber.Map{"error": "Invalid token"})
		}

		claims := parsed.Claims.(jwt.MapClaims)

		// Safely extract user_id claim
		userIDClaim, exists := claims["user_id"]
		if !exists {
			return c.Status(401).JSON(fiber.Map{"error": "Missing user_id claim"})
		}

		userIDStr, ok := userIDClaim.(string)
		if !ok {
			return c.Status(401).JSON(fiber.Map{"error": "Invalid user_id claim type"})
		}

		userID, err := uuid.Parse(userIDStr)
		if err != nil {
			return c.Status(401).JSON(fiber.Map{"error": "Invalid user_id format"})
		}

		// Set user ID in context for subsequent middleware
		c.Locals("user_id", userID)

		return c.Next()
	}
}