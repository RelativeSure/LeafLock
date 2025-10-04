package middleware

import (
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	redisstorage "github.com/gofiber/storage/redis/v3"
	"github.com/redis/go-redis/v9"

	"leaflock/utils"
)

// RateLimitConfig holds all rate limiter instances
type RateLimitConfig struct {
	AuthLimiter       fiber.Handler
	RegisterLimiter   fiber.Handler
	MFAVerifyLimiter  fiber.Handler
	AdminRecoveryLimiter fiber.Handler
	ShareLinkPublicLimiter fiber.Handler
	ShareLinkCreateLimiter fiber.Handler
	SearchLimiter     fiber.Handler
	ImportExportLimiter fiber.Handler
	BulkImportLimiter fiber.Handler
	AttachmentUploadLimiter fiber.Handler
	StandardCRUDLimiter fiber.Handler
	CollaborationLimiter fiber.Handler
	LightweightLimiter fiber.Handler
}

// NewRateLimitConfig creates all rate limiters using Redis storage
func NewRateLimitConfig(rdb *redis.Client) *RateLimitConfig {
	// Create Redis storage instance for distributed rate limiting from existing client
	storage := redisstorage.NewFromConnection(rdb)

	// Tier 1: Auth Endpoints (Strictest - Prevent brute force)
	authLimiter := limiter.New(limiter.Config{
		Max:        10,
		Expiration: 5 * time.Minute,
		KeyGenerator: func(c *fiber.Ctx) string {
			return utils.ClientIP(c)
		},
		Storage: storage,
		LimitReached: func(c *fiber.Ctx) error {
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"error": "Too many authentication attempts. Please try again later.",
			})
		},
	})

	registerLimiter := limiter.New(limiter.Config{
		Max:        5,
		Expiration: 15 * time.Minute,
		KeyGenerator: func(c *fiber.Ctx) string {
			return utils.ClientIP(c)
		},
		Storage: storage,
		LimitReached: func(c *fiber.Ctx) error {
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"error": "Too many registration attempts. Please try again later.",
			})
		},
	})

	mfaVerifyLimiter := limiter.New(limiter.Config{
		Max:        10,
		Expiration: 5 * time.Minute,
		KeyGenerator: func(c *fiber.Ctx) string {
			return utils.ClientIP(c)
		},
		Storage: storage,
		LimitReached: func(c *fiber.Ctx) error {
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"error": "Too many MFA verification attempts. Please try again later.",
			})
		},
	})

	adminRecoveryLimiter := limiter.New(limiter.Config{
		Max:        3,
		Expiration: 15 * time.Minute,
		KeyGenerator: func(c *fiber.Ctx) string {
			return utils.ClientIP(c)
		},
		Storage: storage,
		LimitReached: func(c *fiber.Ctx) error {
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"error": "Too many admin recovery attempts. Please try again later.",
			})
		},
	})

	// Tier 2: Public Share Links (Aggressive - Prevent abuse)
	shareLinkPublicLimiter := limiter.New(limiter.Config{
		Max:        20,
		Expiration: 5 * time.Minute,
		KeyGenerator: func(c *fiber.Ctx) string {
			return utils.ClientIP(c)
		},
		Storage: storage,
		LimitReached: func(c *fiber.Ctx) error {
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"error": "Too many share link requests. Please try again later.",
			})
		},
	})

	shareLinkCreateLimiter := limiter.New(limiter.Config{
		Max:        10,
		Expiration: 15 * time.Minute,
		KeyGenerator: func(c *fiber.Ctx) string {
			return utils.ClientIP(c)
		},
		Storage: storage,
		LimitReached: func(c *fiber.Ctx) error {
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"error": "Too many share link creation requests. Please try again later.",
			})
		},
	})

	// Tier 3: Heavy Operations (Resource intensive)
	searchLimiter := limiter.New(limiter.Config{
		Max:        30,
		Expiration: time.Minute,
		KeyGenerator: func(c *fiber.Ctx) string {
			return utils.ClientIP(c)
		},
		Storage: storage,
		LimitReached: func(c *fiber.Ctx) error {
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"error": "Too many search requests. Please try again later.",
			})
		},
	})

	importExportLimiter := limiter.New(limiter.Config{
		Max:        10,
		Expiration: 5 * time.Minute,
		KeyGenerator: func(c *fiber.Ctx) string {
			return utils.ClientIP(c)
		},
		Storage: storage,
		LimitReached: func(c *fiber.Ctx) error {
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"error": "Too many import/export requests. Please try again later.",
			})
		},
	})

	bulkImportLimiter := limiter.New(limiter.Config{
		Max:        5,
		Expiration: 15 * time.Minute,
		KeyGenerator: func(c *fiber.Ctx) string {
			return utils.ClientIP(c)
		},
		Storage: storage,
		LimitReached: func(c *fiber.Ctx) error {
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"error": "Too many bulk import requests. Please try again later.",
			})
		},
	})

	attachmentUploadLimiter := limiter.New(limiter.Config{
		Max:        20,
		Expiration: 5 * time.Minute,
		KeyGenerator: func(c *fiber.Ctx) string {
			return utils.ClientIP(c)
		},
		Storage: storage,
		LimitReached: func(c *fiber.Ctx) error {
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"error": "Too many attachment upload requests. Please try again later.",
			})
		},
	})

	// Tier 4: Standard CRUD (Normal usage)
	standardCRUDLimiter := limiter.New(limiter.Config{
		Max:        100,
		Expiration: time.Minute,
		KeyGenerator: func(c *fiber.Ctx) string {
			return utils.ClientIP(c)
		},
		Storage: storage,
		LimitReached: func(c *fiber.Ctx) error {
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"error": "Too many requests. Please try again later.",
			})
		},
	})

	collaborationLimiter := limiter.New(limiter.Config{
		Max:        50,
		Expiration: time.Minute,
		KeyGenerator: func(c *fiber.Ctx) string {
			return utils.ClientIP(c)
		},
		Storage: storage,
		LimitReached: func(c *fiber.Ctx) error {
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"error": "Too many collaboration requests. Please try again later.",
			})
		},
	})

	// Tier 5: Read-Only/Lightweight (Liberal)
	lightweightLimiter := limiter.New(limiter.Config{
		Max:        200,
		Expiration: time.Minute,
		KeyGenerator: func(c *fiber.Ctx) string {
			return utils.ClientIP(c)
		},
		Storage: storage,
		LimitReached: func(c *fiber.Ctx) error {
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"error": "Too many requests. Please try again later.",
			})
		},
	})

	return &RateLimitConfig{
		AuthLimiter:             authLimiter,
		RegisterLimiter:         registerLimiter,
		MFAVerifyLimiter:        mfaVerifyLimiter,
		AdminRecoveryLimiter:    adminRecoveryLimiter,
		ShareLinkPublicLimiter:  shareLinkPublicLimiter,
		ShareLinkCreateLimiter:  shareLinkCreateLimiter,
		SearchLimiter:           searchLimiter,
		ImportExportLimiter:     importExportLimiter,
		BulkImportLimiter:       bulkImportLimiter,
		AttachmentUploadLimiter: attachmentUploadLimiter,
		StandardCRUDLimiter:     standardCRUDLimiter,
		CollaborationLimiter:    collaborationLimiter,
		LightweightLimiter:      lightweightLimiter,
	}
}
