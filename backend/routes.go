package main

import (
	"crypto/sha256"
	"os"
	"regexp"
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

	"leaflock/auth"
	appconfig "leaflock/config"
	appcrypto "leaflock/crypto"
	"leaflock/handlers"
	"leaflock/metrics"
	"leaflock/middleware"
	appserver "leaflock/server"
	"leaflock/services"
	websocketpkg "leaflock/websocket"
)

// setupRoutes configures all API routes and middleware for the application
// Zero-knowledge: crypto removed, handlers derive encryption from JWT_SECRET internally
func setupRoutes(app *fiber.App, db *pgxpool.Pool, rdb *redis.Client, config *appconfig.Config, startTime time.Time, readyState *appserver.ReadyState) {
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
			"script-src 'self'; " +
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
		KeyLookup:  "header:X-CSRF-Token",
		CookieName: "csrf_token",
		CookieSameSite: func() string {
			if appconfig.GetEnvOrDefault("APP_ENV", "development") == "production" {
				return "Strict"
			}
			return "Lax"
		}(),
		CookieSecure:   appconfig.GetEnvOrDefault("APP_ENV", "development") != "development",
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
				strings.HasPrefix(path, "/api/v1/auth/") ||
				strings.HasPrefix(path, "/api/v1/") // Skip CSRF for all API routes (JWT-authenticated, CSRF-safe)
		},
	}))

	// CORS configuration with development/production mode support
	app.Use(cors.New(cors.Config{
		AllowOriginsFunc: func(origin string) bool {
			// Development mode: allow all origins
			if len(config.AllowedOrigins) == 1 && config.AllowedOrigins[0] == "*" {
				return true
			}

			// Production mode: check each configured origin
			for _, allowedOrigin := range config.AllowedOrigins {
				// Exact match
				if allowedOrigin == origin {
					return true
				}
				// Wildcard pattern matching (e.g., https://*.leaflock.app)
				if strings.Contains(allowedOrigin, "*") {
					pattern := strings.ReplaceAll(allowedOrigin, "*", ".*")
					matched, err := regexp.MatchString("^"+pattern+"$", origin)
					if err == nil && matched {
						return true
					}
				}
			}
			return false
		},
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

	// Initialize email service
	emailService := services.NewEmailService(config)

	// Zero-knowledge: Derive handler encryption key from JWT secret
	// Used for share links, attachments, and other server-managed encrypted data
	// Note: User notes remain E2E encrypted with password-derived keys
	handlerKey := sha256.Sum256(append([]byte(config.JWTSecret), []byte("-handler-encryption")...))
	handlerCrypto := appcrypto.NewCryptoService(handlerKey[:])

	// Initialize modern auth package
	authService := auth.NewService(db, rdb, string(config.JWTSecret))
	authHandler := auth.NewHandler(authService, emailService)

	// Initialize other handlers
	accountHandler := handlers.NewAccountHandler(db, rdb, handlerCrypto, config)
	notesHandler := handlers.NewNotesHandler(db, handlerCrypto)
	tagsHandler := handlers.NewTagsHandler(db, handlerCrypto)
	foldersHandler := handlers.NewFoldersHandler(db, handlerCrypto)
	templatesHandler := handlers.NewTemplatesHandler(db, handlerCrypto)
	settingsHandler := handlers.NewSettingsHandler(db)
	collabHandler := handlers.NewCollaborationHandler(db, handlerCrypto)
	attachmentsHandler := handlers.NewAttachmentsHandler(db, handlerCrypto)
	searchHandler := handlers.NewSearchHandler()
	importExportHandler := handlers.NewImportExportHandler(db, handlerCrypto)
	shareLinksHandler := handlers.NewShareLinksHandler(db, handlerCrypto, rdb)
	announcementsHandler := handlers.NewAnnouncementsHandler(db)
	noteLinksHandler := handlers.NewNoteLinksHandler(db)
	adminHandler := handlers.NewAdminHandler(db)
	auditLogHandler := handlers.NewAuditLogHandler(db)

	// API group
	api := app.Group("/api/v1")

	// Swagger documentation endpoints
	api.Get("/docs", swaggerUIHandler)
	api.Get("/docs/openapi.json", swaggerJSONHandler)
	app.Get("/swagger", swaggerUIHandler)
	app.Get("/swagger/openapi.json", swaggerJSONHandler)

	// Authentication routes (public) - Tier 1: Strictest rate limiting - MODERN AUTH PACKAGE
	api.Post("/auth/register", rateLimits.RegisterLimiter, authHandler.Register)
	api.Post("/auth/login", rateLimits.AuthLimiter, authHandler.Login)
	api.Post("/auth/logout", authHandler.JWTMiddleware, authHandler.Logout)
	api.Get("/auth/registration", rateLimits.LightweightLimiter, authHandler.GetRegistrationStatus)

	// Debug routes (development only) - double check for security
	if config.Environment != "production" && os.Getenv("ENABLE_DEBUG_ENDPOINTS") == "true" {
		api.Post("/auth/debug-login", authHandler.DebugLogin)
		api.Get("/auth/debug-admin", authHandler.DebugAdminInfo)
		api.Get("/auth/debug-encryption", authHandler.DebugEncryptionKey)
		api.Post("/auth/reset-admin", authHandler.ResetAdminUser)
	}

	// Password reset routes (public) - Tier 1: Strictest rate limiting
	api.Post("/auth/password/reset-request", rateLimits.AuthLimiter, authHandler.RequestPasswordReset)
	api.Get("/auth/password/reset-verify", rateLimits.AuthLimiter, authHandler.VerifyResetToken)
	api.Post("/auth/password/reset-confirm", rateLimits.AuthLimiter, authHandler.ConfirmPasswordReset)

	// Announcements (public with optional auth) - Tier 5: Lightweight
	// Returns announcements based on auth status: 'all' for everyone, 'logged_in' only for authenticated users
	api.Get("/announcements", rateLimits.LightweightLimiter, authHandler.OptionalJWTMiddleware, announcementsHandler.GetAnnouncements)

	// Protected routes (require JWT) - USING MODERN AUTH MIDDLEWARE
	protected := api.Group("", authHandler.JWTMiddleware)

	// MFA routes - Tier 5: Lightweight for status checks, Tier 1 for verification - MODERN AUTH PACKAGE
	protected.Get("/auth/mfa/status", rateLimits.LightweightLimiter, authHandler.GetMFAStatus)
	protected.Post("/auth/mfa/setup", rateLimits.AuthLimiter, authHandler.BeginMFASetup)
	protected.Post("/auth/mfa/enable", rateLimits.AuthLimiter, authHandler.EnableMFA)
	protected.Post("/auth/mfa/disable", rateLimits.AuthLimiter, authHandler.DisableMFA)
	protected.Post("/auth/mfa/backup-codes/regenerate", rateLimits.AuthLimiter, authHandler.RegenerateBackupCodes)
	api.Post("/auth/mfa/verify", rateLimits.MFAVerifyLimiter, authHandler.VerifyMFA) // Public endpoint

	// Notes routes - Tier 4: Standard CRUD
	// Note: Specific routes MUST come before generic /:id routes to avoid route shadowing
	protected.Get("/notes", rateLimits.StandardCRUDLimiter, notesHandler.GetNotes)
	protected.Get("/notes/trash", rateLimits.StandardCRUDLimiter, notesHandler.GetTrash)
	protected.Get("/notes/search-for-linking", rateLimits.StandardCRUDLimiter, noteLinksHandler.GetAllNotesForLinking)
	protected.Post("/notes/bulk/delete", rateLimits.StandardCRUDLimiter, notesHandler.BulkDeleteNotes)
	protected.Post("/notes/bulk/restore", rateLimits.StandardCRUDLimiter, notesHandler.BulkRestoreNotes)
	protected.Post("/notes/bulk/permanent-delete", rateLimits.StandardCRUDLimiter, notesHandler.BulkPermanentlyDeleteNotes)
	protected.Post("/notes", rateLimits.StandardCRUDLimiter, notesHandler.CreateNote)
	protected.Get("/notes/:id", rateLimits.StandardCRUDLimiter, notesHandler.GetNote)
	protected.Put("/notes/:id", rateLimits.StandardCRUDLimiter, notesHandler.UpdateNote)
	protected.Delete("/notes/:id", rateLimits.StandardCRUDLimiter, notesHandler.DeleteNote)
	protected.Post("/notes/:id/restore", rateLimits.StandardCRUDLimiter, notesHandler.RestoreNote)
	protected.Get("/notes/:id/versions", rateLimits.StandardCRUDLimiter, notesHandler.GetNoteVersions)
	protected.Get("/notes/:id/versions/compare", rateLimits.StandardCRUDLimiter, notesHandler.CompareNoteVersions)
	protected.Delete("/notes/:id/versions/:versionId", rateLimits.StandardCRUDLimiter, notesHandler.DeleteNoteVersion)
	protected.Post("/notes/:id/versions/:version", rateLimits.StandardCRUDLimiter, notesHandler.RestoreNoteVersion)
	protected.Put("/notes/:id/retention", rateLimits.StandardCRUDLimiter, notesHandler.UpdateRetentionPolicy)
	protected.Delete("/notes/:id/permanent", rateLimits.StandardCRUDLimiter, notesHandler.PermanentlyDeleteNote)
	protected.Post("/notes/:id/pin", rateLimits.StandardCRUDLimiter, notesHandler.TogglePin)
	protected.Post("/notes/:id/lock", rateLimits.StandardCRUDLimiter, notesHandler.ToggleLock)
	protected.Post("/notes/:id/links", rateLimits.StandardCRUDLimiter, noteLinksHandler.CreateNoteLink)
	protected.Get("/notes/:id/links", rateLimits.StandardCRUDLimiter, noteLinksHandler.GetNoteLinks)
	protected.Get("/notes/:id/backlinks", rateLimits.StandardCRUDLimiter, noteLinksHandler.GetNoteBacklinks)
	protected.Delete("/notes/:id/links/:linkId", rateLimits.StandardCRUDLimiter, noteLinksHandler.DeleteNoteLink)

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
	api.Get("/share/:token", rateLimits.ShareLinkPublicLimiter, middleware.ShareLinkMiddleware(db, handlerCrypto, rdb), shareLinksHandler.GetSharedNote)

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

	// Audit log routes - Tier 5: Lightweight (user's own logs)
	protected.Get("/audit-logs", rateLimits.LightweightLimiter, auditLogHandler.GetUserAuditLogs)

	// Admin routes - Tier 4: Standard CRUD (admin only)
	admin := protected.Group("/admin", authHandler.RequireAdminMiddleware)
	// Announcements
	admin.Get("/announcements", rateLimits.StandardCRUDLimiter, announcementsHandler.GetAllAnnouncements)
	admin.Post("/announcements", rateLimits.StandardCRUDLimiter, announcementsHandler.CreateAnnouncement)
	admin.Put("/announcements/:id", rateLimits.StandardCRUDLimiter, announcementsHandler.UpdateAnnouncement)
	admin.Delete("/announcements/:id", rateLimits.StandardCRUDLimiter, announcementsHandler.DeleteAnnouncement)
	// User management
	admin.Get("/stats", rateLimits.StandardCRUDLimiter, adminHandler.GetSystemStats)
	admin.Get("/users", rateLimits.StandardCRUDLimiter, adminHandler.GetAllUsers)
	admin.Patch("/users/:id/role", rateLimits.StandardCRUDLimiter, adminHandler.UpdateUserRole)
	admin.Delete("/users/:id", rateLimits.StandardCRUDLimiter, adminHandler.DeleteUser)
	admin.Post("/users/:id/unlock", rateLimits.StandardCRUDLimiter, adminHandler.UnlockUser)
	// Registration settings
	admin.Get("/settings/registration", rateLimits.StandardCRUDLimiter, adminHandler.GetRegistrationSetting)
	admin.Put("/settings/registration", rateLimits.StandardCRUDLimiter, adminHandler.UpdateRegistrationSetting)
	// Audit logs (admin view - all users)
	admin.Get("/audit-logs", rateLimits.StandardCRUDLimiter, auditLogHandler.GetAuditLogs)

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
