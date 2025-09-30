package server

import (
	"context"
	"fmt"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/compress"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/google/uuid"
	"leaflock/utils"
)

// CreateFiberApp creates and configures the Fiber application with optimized settings
func CreateFiberApp(startTime time.Time, readyState *ReadyState) *fiber.App {
	app := fiber.New(fiber.Config{
		DisableStartupMessage: false,
		BodyLimit:             512 * 1024, // 512KB body size limit
		// Enable proxy header trust for Railway/Cloudflare/nginx reverse proxies
		EnableTrustedProxyCheck: utils.TrustProxyHeaders.Load(),
		ProxyHeader:             fiber.HeaderXForwardedFor,
		// Trust Railway's IPv6 private network ranges and common proxy IPs
		TrustedProxies: []string{
			"10.0.0.0/8",      // Private IPv4
			"172.16.0.0/12",   // Private IPv4
			"192.168.0.0/16",  // Private IPv4
			"fd00::/8",        // Private IPv6 (Railway uses this)
			"::1",             // IPv6 localhost
			"127.0.0.1",       // IPv4 localhost
		},
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			code := fiber.StatusInternalServerError
			message := "Internal Server Error"

			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
				message = e.Message
			} else if code < 500 {
				// Only show actual error for client errors (4xx)
				message = err.Error()
			} else {
				// Log server errors but don't expose details
				utils.LogError("HTTP_ERROR", err,
					"method", c.Method(),
					"path", c.Path(),
					"ip", c.IP(),
				)
			}

			return c.Status(code).JSON(fiber.Map{"error": message})
		},
	})

	// Enhanced panic recovery middleware with error logging
	app.Use(recover.New(recover.Config{
		EnableStackTrace: true,
		StackTraceHandler: func(c *fiber.Ctx, e interface{}) {
			utils.LogError("PANIC RECOVERED", fmt.Errorf("%v", e),
				"method", c.Method(),
				"path", c.Path(),
				"ip", c.IP(),
				"user_agent", c.Get("User-Agent"),
			)
		},
	}))

	// Request ID middleware for error correlation
	app.Use(func(c *fiber.Ctx) error {
		requestID := uuid.New().String()
		c.Locals("request_id", requestID)
		c.Set("X-Request-ID", requestID)
		return c.Next()
	})

	// Enhanced request logging
	app.Use(logger.New(logger.Config{
		Output: utils.InfoLogger.Writer(),
		Format: "[${time}] ${locals:request_id} ${status} - ${method} ${path} - ${ip} - ${latency}\n",
	}))

	// Compression middleware for API responses
	app.Use(compress.New(compress.Config{
		Level: compress.LevelBestSpeed, // Balance between speed and compression ratio
		Next: func(c *fiber.Ctx) bool {
			// Skip compression for WebSocket upgrades
			return c.Get("Upgrade") == "websocket"
		},
	}))

	// Basic health endpoints available immediately
	api := app.Group("/api/v1")

	// Live endpoint - just checks if server is running
	api.Get("/health/live", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"status":    "live",
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"uptime":    time.Since(startTime).String(),
		})
	})

	// Ready endpoint - checks if all initialization is complete
	api.Get("/health/ready", func(c *fiber.Ctx) error {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		health := fiber.Map{
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"uptime":    time.Since(startTime).String(),
		}

		// Check if fully ready
		if readyState.IsFullyReady() {
			// Quick database health check
			var userCount int
			if err := readyState.GetDB().QueryRow(ctx, "SELECT COUNT(*) FROM users").Scan(&userCount); err != nil {
				health["status"] = "unhealthy"
				health["error"] = "database check failed"
				return c.Status(503).JSON(health)
			}

			// Quick Redis health check
			if err := readyState.GetRedis().Ping(ctx).Err(); err != nil {
				health["status"] = "unhealthy"
				health["error"] = "redis check failed"
				return c.Status(503).JSON(health)
			}

			health["status"] = "ready"
			return c.JSON(health)
		} else {
			// Still initializing
			health["status"] = "initializing"
			health["admin_ready"] = readyState.IsAdminReady()
			health["templates_ready"] = readyState.IsTemplatesReady()
			health["allowlist_ready"] = readyState.IsAllowlistReady()
			health["redis_ready"] = readyState.IsRedisReady()
			return c.Status(503).JSON(health)
		}
	})

	return app
}