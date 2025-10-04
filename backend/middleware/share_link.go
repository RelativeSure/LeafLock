package middleware

import (
	"context"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	appcrypto "leaflock/crypto"
	"leaflock/database"
	"leaflock/services"
	"leaflock/utils"
)

// ShareLinkMiddleware validates share link tokens and grants access
func ShareLinkMiddleware(db database.Database, crypto *appcrypto.CryptoService, rdb *redis.Client) fiber.Handler {
	shareLinkService := services.NewShareLinkService(rdb)

	return func(c *fiber.Ctx) error {
		token := c.Params("token")
		if token == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Share link token is required",
			})
		}

		ctx := context.Background()

		// Try to get from Redis cache first
		cachedLink, err := shareLinkService.GetShareLink(ctx, token)
		if err != nil {
			utils.LogRequestError(c, "ShareLinkMiddleware: cache lookup failed", err)
		}

		// If not in cache or cache miss, query database
		var noteID uuid.UUID
		var permission string
		var expiresAt *time.Time
		var maxUses *int
		var useCount int
		var isActive bool
		var passwordHash *string

		if cachedLink != nil {
			// Use cached data
			noteID, _ = uuid.Parse(cachedLink.NoteID)
			permission = cachedLink.Permission
			if !cachedLink.ExpiresAt.IsZero() {
				expiresAt = &cachedLink.ExpiresAt
			}
			if cachedLink.MaxUses > 0 {
				maxUses = &cachedLink.MaxUses
			}
			useCount = cachedLink.UseCount

			// Still need to check database for password and active status
			err = db.QueryRow(ctx, `
				SELECT is_active, password_hash
				FROM share_links
				WHERE token = $1`, token).Scan(&isActive, &passwordHash)

			if err != nil {
				return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
					"error": "Share link not found",
				})
			}
		} else {
			// Query database
			err = db.QueryRow(ctx, `
				SELECT note_id, permission, expires_at, max_uses, use_count, is_active, password_hash
				FROM share_links
				WHERE token = $1`, token).
				Scan(&noteID, &permission, &expiresAt, &maxUses, &useCount, &isActive, &passwordHash)

			if err != nil {
				return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
					"error": "Share link not found",
				})
			}

			// Cache for future requests
			cacheData := services.ShareLinkCache{
				NoteID:      noteID.String(),
				Permission:  permission,
				UseCount:    useCount,
				HasPassword: passwordHash != nil,
			}
			if expiresAt != nil {
				cacheData.ExpiresAt = *expiresAt
			}
			if maxUses != nil {
				cacheData.MaxUses = *maxUses
			}

			_ = shareLinkService.CacheShareLink(ctx, token, cacheData)
		}

		// Validate link is active
		if !isActive {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": "This share link has been revoked",
			})
		}

		// Check expiration
		if expiresAt != nil && time.Now().After(*expiresAt) {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": "This share link has expired",
			})
		}

		// Check usage limits
		if maxUses != nil && useCount >= *maxUses {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": "This share link has reached its usage limit",
			})
		}

		// Check password if required
		if passwordHash != nil {
			// Password should be sent in request body or header
			var password string
			if c.Method() == "POST" {
				body := struct {
					Password string `json:"password"`
				}{}
				if err := c.BodyParser(&body); err == nil {
					password = body.Password
				}
			}
			if password == "" {
				password = c.Get("X-Share-Password")
			}

			if password == "" {
				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
					"error":          "This share link is password protected",
					"requires_password": true,
				})
			}

			// Verify password
			if !appcrypto.VerifyPassword(password, *passwordHash) {
				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
					"error": "Incorrect password",
				})
			}
		}

		// Increment use count in database
		_, err = db.Exec(ctx, `
			UPDATE share_links
			SET use_count = use_count + 1,
			    last_accessed_at = NOW(),
			    last_accessed_ip = $2
			WHERE token = $1`,
			token, encryptIP(c, crypto))

		if err != nil {
			utils.LogRequestError(c, "ShareLinkMiddleware: failed to update use count", err)
		}

		// Refresh cache TTL for never-expiring links
		if expiresAt == nil {
			_ = shareLinkService.RefreshTTL(ctx, token)
		}

		// Store share link context for handlers
		c.Locals("share_link_token", token)
		c.Locals("share_link_note_id", noteID)
		c.Locals("share_link_permission", permission)
		c.Locals("is_share_link_access", true)

		return c.Next()
	}
}

// encryptIP encrypts the client IP address
func encryptIP(c *fiber.Ctx, crypto *appcrypto.CryptoService) []byte {
	ip := utils.ClientIP(c)
	encrypted, err := crypto.Encrypt([]byte(ip))
	if err != nil {
		return nil
	}
	return encrypted
}
