package main

import (
	"context"
	"strings"
	"time"

	fiberws "github.com/gofiber/contrib/websocket"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/csrf"
	"github.com/gofiber/fiber/v2/middleware/helmet"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	appconfig "leaflock/config"
	appcrypto "leaflock/crypto"
	"leaflock/handlers"
	"leaflock/metrics"
	"leaflock/middleware"
	appserver "leaflock/server"
	websocketpkg "leaflock/websocket"
)

// setupRoutes configures all API routes and middleware for the application
func setupRoutes(app *fiber.App, db *pgxpool.Pool, rdb *redis.Client, crypto *appcrypto.CryptoService, config *appconfig.Config, startTime time.Time, readyState *appserver.ReadyState) {
	// Security middleware
	app.Use(helmet.New(helmet.Config{
		XSSProtection:      "1; mode=block",
		ContentTypeNosniff: "nosniff",
		XFrameOptions:      "DENY",
		HSTSMaxAge: func() int {
			if appconfig.GetEnvOrDefault("APP_ENV", "development") == "production" {
				return 31536000
			}
			return 0
		}(),
		HSTSPreloadEnabled: appconfig.GetEnvOrDefault("APP_ENV", "development") == "production",
		ContentSecurityPolicy: "default-src 'self'; " +
			"script-src 'self' 'strict-dynamic' 'nonce-{random}'; " +
			"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
			"font-src 'self' https://fonts.gstatic.com data:; " +
			"img-src 'self' data: https: blob:; " +
			"connect-src 'self' ws: wss:; " +
			"media-src 'self' blob:; " +
			"worker-src 'self' blob:; " +
			"child-src 'self' blob:; " +
			"object-src 'none'; " +
			"frame-ancestors 'none'; " +
			"base-uri 'self'; " +
			"form-action 'self'; " +
			"upgrade-insecure-requests; " +
			"block-all-mixed-content",
		ReferrerPolicy: "strict-origin-when-cross-origin",
	}))

	// CSRF protection
	app.Use(csrf.New(csrf.Config{
		KeyLookup:      "header:X-CSRF-Token",
		CookieName:     "csrf_token",
		CookieSameSite: "Strict",
		CookieSecure:   true,
		CookieHTTPOnly: true,
		Expiration:     time.Hour,
		KeyGenerator:   uuid.NewString,
		ContextKey:     "csrf",
		Next: func(c *fiber.Ctx) bool {
			method := c.Method()
			path := c.Path()
			return method == fiber.MethodGet || method == fiber.MethodHead || method == fiber.MethodOptions ||
				strings.HasPrefix(path, "/api/v1/health") ||
				strings.HasPrefix(path, "/api/v1/ready") ||
				strings.HasPrefix(path, "/api/v1/auth/")
		},
	}))

	// CORS configuration
	app.Use(cors.New(cors.Config{
		AllowOrigins:     strings.Join(config.AllowedOrigins, ","),
		AllowCredentials: true,
		AllowHeaders:     "Origin, Content-Type, Accept, Authorization, X-CSRF-Token",
		AllowMethods:     "GET, POST, PUT, DELETE, OPTIONS",
		ExposeHeaders:    "X-CSRF-Token",
	}))

	// Optional Prometheus metrics
	if appconfig.GetEnvAsBool("ENABLE_METRICS", false) {
		app.Use(metrics.PrometheusMiddleware())
	}

	// Initialize rate limiters
	rateLimits := middleware.NewRateLimitConfig(rdb)

	// Initialize handlers
	authHandler := handlers.NewAuthHandler(db, rdb, crypto, config)
	accountHandler := handlers.NewAccountHandler(db, rdb, crypto, config)
	notesHandler := handlers.NewNotesHandler(db, crypto)
	tagsHandler := handlers.NewTagsHandler(db, crypto)
	foldersHandler := handlers.NewFoldersHandler(db, crypto)
	templatesHandler := handlers.NewTemplatesHandler(db, crypto)
	settingsHandler := handlers.NewSettingsHandler(db)
	collabHandler := handlers.NewCollaborationHandler(db, crypto)
	attachmentsHandler := handlers.NewAttachmentsHandler(db, crypto)
	searchHandler := handlers.NewSearchHandler(db, crypto)
	importExportHandler := handlers.NewImportExportHandler(db, crypto)
	shareLinksHandler := handlers.NewShareLinksHandler(db, crypto, rdb)

	// API group
	api := app.Group("/api/v1")

	// Health check endpoints
	api.Get("/health/live", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"status":    "live",
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"uptime":    time.Since(startTime).String(),
		})
	})

	api.Get("/health/ready", func(c *fiber.Ctx) error {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		health := fiber.Map{
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"uptime":    time.Since(startTime).String(),
		}

		if readyState.IsFullyReady() {
			var userCount int
			if err := readyState.GetDB().QueryRow(ctx, "SELECT COUNT(*) FROM users").Scan(&userCount); err != nil {
				health["status"] = "unhealthy"
				health["error"] = "database check failed"
				return c.Status(fiber.StatusServiceUnavailable).JSON(health)
			}

			if err := readyState.GetRedis().Ping(ctx).Err(); err != nil {
				health["status"] = "unhealthy"
				health["error"] = "redis check failed"
				return c.Status(fiber.StatusServiceUnavailable).JSON(health)
			}

			health["status"] = "ready"
			health["user_count"] = userCount
			return c.JSON(health)
		}

		health["status"] = "initializing"
		health["admin_ready"] = readyState.IsAdminReady()
		health["templates_ready"] = readyState.IsTemplatesReady()
		health["allowlist_ready"] = readyState.IsAllowlistReady()
		health["redis_ready"] = readyState.IsRedisReady()
		return c.Status(fiber.StatusServiceUnavailable).JSON(health)
	})

	api.Get("/health", func(c *fiber.Ctx) error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		health := fiber.Map{
			"status":    "healthy",
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"version":   "1.0.0",
			"uptime":    time.Since(startTime).String(),
		}

		var userCount int
		dbHealthy := true
		if err := db.QueryRow(ctx, "SELECT COUNT(*) FROM users").Scan(&userCount); err != nil {
			dbHealthy = false
			health["database"] = "unhealthy"
			health["database_error"] = err.Error()
		} else {
			health["database"] = "healthy"
			health["user_count"] = userCount
		}

		redisHealthy := true
		if err := rdb.Ping(ctx).Err(); err != nil {
			redisHealthy = false
			health["redis"] = "unhealthy"
			health["redis_error"] = err.Error()
		} else {
			health["redis"] = "healthy"
		}

		if !dbHealthy || !redisHealthy {
			health["status"] = "unhealthy"
			return c.Status(fiber.StatusServiceUnavailable).JSON(health)
		}

		return c.JSON(health)
	})

	// Swagger documentation endpoints
	api.Get("/docs", swaggerUIHandler)
	api.Get("/docs/openapi.json", swaggerJSONHandler)
	app.Get("/swagger", swaggerUIHandler)
	app.Get("/swagger/openapi.json", swaggerJSONHandler)

	// Authentication routes (public) - Tier 1: Strictest rate limiting
	api.Post("/auth/register", rateLimits.RegisterLimiter, authHandler.Register)
	api.Post("/auth/login", rateLimits.AuthLimiter, authHandler.Login)
	api.Post("/auth/admin-recovery", rateLimits.AdminRecoveryLimiter, authHandler.AdminRecovery)
	api.Get("/auth/registration", func(c *fiber.Ctx) error {
		var dbVal string
		if err := db.QueryRow(c.Context(), `SELECT value FROM app_settings WHERE key='registration_enabled'`).Scan(&dbVal); err == nil {
			if strings.ToLower(strings.TrimSpace(dbVal)) == "true" {
				appconfig.RegEnabled.Store(1)
			} else {
				appconfig.RegEnabled.Store(0)
			}
		}
		return c.JSON(fiber.Map{"enabled": appconfig.RegEnabled.Load() == 1})
	})

	// Protected routes (require JWT)
	protected := api.Group("", middleware.JWTMiddleware(config.JWTSecret, rdb, crypto))

	// MFA routes - Tier 5: Lightweight for status checks, Tier 1 for verification
	protected.Get("/auth/mfa/status", rateLimits.LightweightLimiter, authHandler.GetMFAStatus)
	protected.Post("/auth/mfa/begin", rateLimits.AuthLimiter, authHandler.BeginMFASetup)
	protected.Post("/auth/mfa/enable", rateLimits.AuthLimiter, authHandler.EnableMFA)
	protected.Post("/auth/mfa/disable", rateLimits.AuthLimiter, authHandler.DisableMFA)
	protected.Get("/auth/mfa/backup-codes", rateLimits.LightweightLimiter, authHandler.GetBackupCodes)
	protected.Post("/auth/mfa/backup-codes/regenerate", rateLimits.AuthLimiter, authHandler.RegenerateBackupCodes)
	api.Post("/auth/mfa/verify", rateLimits.MFAVerifyLimiter, authHandler.VerifyMFACode) // Public endpoint

	// Notes routes - Tier 4: Standard CRUD
	protected.Get("/notes", rateLimits.StandardCRUDLimiter, notesHandler.GetNotes)
	protected.Get("/notes/:id", rateLimits.StandardCRUDLimiter, notesHandler.GetNote)
	protected.Post("/notes", rateLimits.StandardCRUDLimiter, notesHandler.CreateNote)
	protected.Put("/notes/:id", rateLimits.StandardCRUDLimiter, notesHandler.UpdateNote)
	protected.Delete("/notes/:id", rateLimits.StandardCRUDLimiter, notesHandler.DeleteNote)
	protected.Get("/notes/trash", rateLimits.StandardCRUDLimiter, notesHandler.GetTrash)
	protected.Post("/notes/:id/restore", rateLimits.StandardCRUDLimiter, notesHandler.RestoreNote)
	protected.Get("/notes/:id/versions", rateLimits.StandardCRUDLimiter, notesHandler.GetNoteVersions)
	protected.Post("/notes/:id/versions/:version", rateLimits.StandardCRUDLimiter, notesHandler.RestoreNoteVersion)
	protected.Delete("/notes/:id/permanent", rateLimits.StandardCRUDLimiter, notesHandler.PermanentlyDeleteNote)

	// Tags routes - Tier 4: Standard CRUD
	protected.Get("/tags", rateLimits.StandardCRUDLimiter, tagsHandler.GetTags)
	protected.Post("/tags", rateLimits.StandardCRUDLimiter, tagsHandler.CreateTag)
	protected.Delete("/tags/:id", rateLimits.StandardCRUDLimiter, tagsHandler.DeleteTag)
	protected.Post("/notes/:id/tags", rateLimits.StandardCRUDLimiter, tagsHandler.AssignTagToNote)
	protected.Delete("/notes/:id/tags/:tag_id", rateLimits.StandardCRUDLimiter, tagsHandler.RemoveTagFromNote)
	protected.Get("/tags/:id/notes", rateLimits.StandardCRUDLimiter, tagsHandler.GetNotesByTag)

	// Folders routes - Tier 4: Standard CRUD
	protected.Get("/folders", rateLimits.StandardCRUDLimiter, foldersHandler.GetFolders)
	protected.Post("/folders", rateLimits.StandardCRUDLimiter, foldersHandler.CreateFolder)
	protected.Delete("/folders/:id", rateLimits.StandardCRUDLimiter, foldersHandler.DeleteFolder)
	protected.Post("/notes/:id/folder", rateLimits.StandardCRUDLimiter, foldersHandler.MoveNoteToFolder)

	// Templates routes - Tier 4: Standard CRUD
	protected.Get("/templates", rateLimits.StandardCRUDLimiter, templatesHandler.GetTemplates)
	protected.Get("/templates/:id", rateLimits.StandardCRUDLimiter, templatesHandler.GetTemplate)
	protected.Post("/templates", rateLimits.StandardCRUDLimiter, templatesHandler.CreateTemplate)
	protected.Put("/templates/:id", rateLimits.StandardCRUDLimiter, templatesHandler.UpdateTemplate)
	protected.Delete("/templates/:id", rateLimits.StandardCRUDLimiter, templatesHandler.DeleteTemplate)
	protected.Post("/templates/:id/use", rateLimits.StandardCRUDLimiter, templatesHandler.UseTemplate)

	// Collaboration routes - Tier 4: Collaboration limits
	protected.Post("/notes/:id/share", rateLimits.CollaborationLimiter, collabHandler.ShareNote)
	protected.Get("/notes/:id/collaborators", rateLimits.CollaborationLimiter, collabHandler.GetCollaborators)
	protected.Delete("/notes/:id/collaborators/:userId", rateLimits.CollaborationLimiter, collabHandler.RemoveCollaborator)
	protected.Get("/collaborations", rateLimits.CollaborationLimiter, collabHandler.GetSharedNotes)

	// Share link routes (protected) - Tier 2: Aggressive limiting for share link creation
	protected.Post("/notes/:id/share-links", rateLimits.ShareLinkCreateLimiter, shareLinksHandler.CreateShareLink)
	protected.Get("/notes/:id/share-links", rateLimits.StandardCRUDLimiter, shareLinksHandler.GetNoteShareLinks)
	protected.Get("/share-links", rateLimits.StandardCRUDLimiter, shareLinksHandler.GetAllUserShareLinks)
	protected.Delete("/share-links/:token", rateLimits.StandardCRUDLimiter, shareLinksHandler.RevokeShareLink)
	protected.Put("/share-links/:token", rateLimits.StandardCRUDLimiter, shareLinksHandler.UpdateShareLink)

	// Public share link route (no authentication required) - Tier 2: Aggressive limiting
	api.Get("/share/:token", rateLimits.ShareLinkPublicLimiter, middleware.ShareLinkMiddleware(db, crypto, rdb), shareLinksHandler.GetSharedNote)

	// Attachments routes - Tier 3: Heavy operations
	protected.Post("/notes/:noteId/attachments", rateLimits.AttachmentUploadLimiter, attachmentsHandler.UploadAttachment)
	protected.Get("/notes/:noteId/attachments", rateLimits.StandardCRUDLimiter, attachmentsHandler.GetAttachments)
	protected.Get("/notes/:noteId/attachments/:attachmentId", rateLimits.StandardCRUDLimiter, attachmentsHandler.DownloadAttachment)
	protected.Delete("/notes/:noteId/attachments/:attachmentId", rateLimits.StandardCRUDLimiter, attachmentsHandler.DeleteAttachment)

	// Search and Import/Export routes - Tier 3: Heavy operations
	protected.Post("/search", rateLimits.SearchLimiter, searchHandler.SearchNotes)
	protected.Get("/storage", rateLimits.LightweightLimiter, importExportHandler.GetStorageInfo)
	protected.Post("/notes/import", rateLimits.ImportExportLimiter, importExportHandler.ImportNote)
	protected.Post("/notes/:id/export", rateLimits.ImportExportLimiter, importExportHandler.ExportNote)
	protected.Post("/notes/bulk-import", rateLimits.BulkImportLimiter, importExportHandler.BulkImport)

	// Settings routes - Tier 5: Lightweight
	protected.Get("/settings", rateLimits.LightweightLimiter, settingsHandler.GetSettings)
	protected.Put("/settings", rateLimits.StandardCRUDLimiter, settingsHandler.UpdateSettings)

	// Account management routes - Tier 3: Heavy operations
	protected.Delete("/account", rateLimits.ImportExportLimiter, accountHandler.DeleteAccount)
	protected.Get("/account/export", rateLimits.ImportExportLimiter, accountHandler.ExportData)

	// WebSocket setup
	hub := websocketpkg.NewHub()
	go hub.Run()

	app.Use("/ws", func(c *fiber.Ctx) error {
		if fiberws.IsWebSocketUpgrade(c) {
			return c.Next()
		}
		return fiber.ErrUpgradeRequired
	})

	app.Get("/ws", fiberws.New(func(conn *fiberws.Conn) {
		websocketpkg.HandleWebSocket(conn, hub, db)
	}))
}
