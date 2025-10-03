// LeafLock API
//
// LeafLock is a secure notes application with end-to-end encryption and real-time collaboration features.
//
// @title LeafLock API
// @description A secure notes application with end-to-end encryption and collaboration features
// @version 1.0
// @host localhost:8080
// @BasePath /api/v1
// @schemes http https
//
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Type "Bearer" followed by a space and JWT token.
//
// main.go - Complete secure backend with automatic PostgreSQL setup
package main

import (
	"context"
	"log"
	"os"
	"strings"
	"time"

	fiberws "github.com/gofiber/contrib/websocket"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/csrf"
	"github.com/gofiber/fiber/v2/middleware/helmet"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/redis/go-redis/v9"
	appconfig "leaflock/config"
	appcrypto "leaflock/crypto"
	appdb "leaflock/database"
	"leaflock/handlers"
	"leaflock/metrics"
	"leaflock/middleware"
	appserver "leaflock/server"
	"leaflock/services"
	"leaflock/utils"
	websocketpkg "leaflock/websocket"
)

// AUTOMATIC DATABASE SETUP - Runs migrations on startup
// Database is an alias for the shared database interface
type Database = appdb.Database

func setupRoutes(app *fiber.App, db *pgxpool.Pool, rdb *redis.Client, crypto *appcrypto.CryptoService, config *appconfig.Config, startTime time.Time, readyState *appserver.ReadyState) {
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

	app.Use(cors.New(cors.Config{
		AllowOrigins:     strings.Join(config.AllowedOrigins, ","),
		AllowCredentials: true,
		AllowHeaders:     "Origin, Content-Type, Accept, Authorization, X-CSRF-Token",
		AllowMethods:     "GET, POST, PUT, DELETE, OPTIONS",
		ExposeHeaders:    "X-CSRF-Token",
	}))

	if appconfig.GetEnvAsBool("ENABLE_METRICS", false) {
		app.Use(metrics.PrometheusMiddleware())
	}

	app.Use(limiter.New(limiter.Config{
		Max:        100,
		Expiration: time.Minute,
		KeyGenerator: func(c *fiber.Ctx) string {
			return utils.ClientIP(c)
		},
	}))

	authHandler := handlers.NewAuthHandler(db, rdb, crypto, config)
	notesHandler := handlers.NewNotesHandler(db, crypto)
	tagsHandler := handlers.NewTagsHandler(db, crypto)
	foldersHandler := handlers.NewFoldersHandler(db, crypto)
	templatesHandler := handlers.NewTemplatesHandler(db, crypto)
	settingsHandler := handlers.NewSettingsHandler(db)
	collabHandler := handlers.NewCollaborationHandler(db, crypto)
	attachmentsHandler := handlers.NewAttachmentsHandler(db, crypto)
	searchHandler := handlers.NewSearchHandler(db, crypto)
	importExportHandler := handlers.NewImportExportHandler(db, crypto)

	api := app.Group("/api/v1")

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

	// Public swagger access (outside /api/v1 prefix)
	app.Get("/swagger", swaggerUIHandler)
	app.Get("/swagger/openapi.json", swaggerJSONHandler)

	if env := strings.ToLower(strings.TrimSpace(config.Environment)); env != "development" && env != "local" {
		regLimiter := limiter.New(limiter.Config{
			Max:        5,
			Expiration: time.Minute,
			KeyGenerator: func(c *fiber.Ctx) string {
				return utils.ClientIP(c)
			},
		})
		api.Post("/auth/register", regLimiter, authHandler.Register)
	} else {
		api.Post("/auth/register", authHandler.Register)
	}

	api.Post("/auth/login", authHandler.Login)
	api.Post("/auth/admin-recovery", authHandler.AdminRecovery)
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

	protected := api.Group("", middleware.JWTMiddleware(config.JWTSecret, rdb, crypto))

	protected.Get("/auth/mfa/status", authHandler.GetMFAStatus)
	protected.Post("/auth/mfa/begin", authHandler.BeginMFASetup)
	protected.Post("/auth/mfa/enable", authHandler.EnableMFA)
	protected.Post("/auth/mfa/disable", authHandler.DisableMFA)
	protected.Get("/auth/mfa/backup-codes", authHandler.GetBackupCodes)
	protected.Post("/auth/mfa/backup-codes/regenerate", authHandler.RegenerateBackupCodes)

	// Public MFA verification endpoint (doesn't require JWT)
	api.Post("/auth/mfa/verify", authHandler.VerifyMFACode)

	protected.Get("/notes", notesHandler.GetNotes)
	protected.Get("/notes/:id", notesHandler.GetNote)
	protected.Post("/notes", notesHandler.CreateNote)
	protected.Put("/notes/:id", notesHandler.UpdateNote)
	protected.Delete("/notes/:id", notesHandler.DeleteNote)
	protected.Get("/notes/trash", notesHandler.GetTrash)
	protected.Post("/notes/:id/restore", notesHandler.RestoreNote)
	protected.Get("/notes/:id/versions", notesHandler.GetNoteVersions)
	protected.Post("/notes/:id/versions/:version", notesHandler.RestoreNoteVersion)
	protected.Delete("/notes/:id/permanent", notesHandler.PermanentlyDeleteNote)

	protected.Get("/tags", tagsHandler.GetTags)
	protected.Post("/tags", tagsHandler.CreateTag)
	protected.Delete("/tags/:id", tagsHandler.DeleteTag)
	protected.Post("/notes/:id/tags", tagsHandler.AssignTagToNote)
	protected.Delete("/notes/:id/tags/:tag_id", tagsHandler.RemoveTagFromNote)
	protected.Get("/tags/:id/notes", tagsHandler.GetNotesByTag)

	protected.Get("/folders", foldersHandler.GetFolders)
	protected.Post("/folders", foldersHandler.CreateFolder)
	protected.Delete("/folders/:id", foldersHandler.DeleteFolder)
	protected.Post("/notes/:id/folder", foldersHandler.MoveNoteToFolder)

	protected.Get("/templates", templatesHandler.GetTemplates)
	protected.Get("/templates/:id", templatesHandler.GetTemplate)
	protected.Post("/templates", templatesHandler.CreateTemplate)
	protected.Put("/templates/:id", templatesHandler.UpdateTemplate)
	protected.Delete("/templates/:id", templatesHandler.DeleteTemplate)
	protected.Post("/templates/:id/use", templatesHandler.UseTemplate)

	protected.Post("/notes/:id/share", collabHandler.ShareNote)
	protected.Get("/notes/:id/collaborators", collabHandler.GetCollaborators)
	protected.Delete("/notes/:id/collaborators/:userId", collabHandler.RemoveCollaborator)
	protected.Get("/collaborations", collabHandler.GetSharedNotes)

	protected.Post("/notes/:noteId/attachments", attachmentsHandler.UploadAttachment)
	protected.Get("/notes/:noteId/attachments", attachmentsHandler.GetAttachments)
	protected.Get("/notes/:noteId/attachments/:attachmentId", attachmentsHandler.DownloadAttachment)
	protected.Delete("/notes/:noteId/attachments/:attachmentId", attachmentsHandler.DeleteAttachment)

	protected.Post("/search", searchHandler.SearchNotes)
	protected.Get("/storage", importExportHandler.GetStorageInfo)
	protected.Post("/notes/import", importExportHandler.ImportNote)
	protected.Post("/notes/:id/export", importExportHandler.ExportNote)
	protected.Post("/notes/bulk-import", importExportHandler.BulkImport)

	// User settings endpoints
	protected.Get("/settings", settingsHandler.GetSettings)
	protected.Put("/settings", settingsHandler.UpdateSettings)

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

func main() {
	// Track startup timing
	startupStart := time.Now()
	log.Printf("🚀 Starting LeafLock backend (PID: %d)...", os.Getpid())

	// Initialize logging
	utils.InitLogging()
	log.Printf("⏱️  Logging initialized in %v", time.Since(startupStart))

	// Load configuration
	configStart := time.Now()
	config := appconfig.LoadConfig()
	utils.TrustProxyHeaders.Store(config.TrustProxyHeaders)
	log.Printf("⏱️  Configuration loaded in %v", time.Since(configStart))

	// Track application start time for uptime calculation
	startTime := time.Now()

	// Initialize runtime toggle from env (default false for security)
	envRegRaw, envRegExplicit := os.LookupEnv("ENABLE_REGISTRATION")
	envRegValue := strings.ToLower(strings.TrimSpace(envRegRaw))
	if !envRegExplicit || envRegValue == "" {
		envRegValue = "false"
	}
	if envRegValue == "true" {
		appconfig.RegEnabled.Store(1)
	} else {
		appconfig.RegEnabled.Store(0)
	}

	// Parse startup optimization flags
	skipMigrationCheck := os.Getenv("SKIP_MIGRATION_CHECK") == "true" // Default: false (always run migrations)

	// Setup database with conditional migrations
	dbStart := time.Now()
	var db *pgxpool.Pool
	var err error
	if skipMigrationCheck {
		log.Println("⚡ Skipping migration check for faster startup")
		db, err = appdb.SetupDatabaseFast(config.DatabaseURL)
	} else {
		db, err = appdb.SetupDatabase(config.DatabaseURL)
	}
	if err != nil {
		log.Fatal("Database setup failed:", err)
	}
	defer db.Close()
	log.Printf("⏱️  Database setup completed in %v", time.Since(dbStart))

	// Setup Redis with connection pool pre-warming
	redisStart := time.Now()
	rdb := redis.NewClient(&redis.Options{
		Addr:     config.RedisURL,
		Password: config.RedisPassword,
		DB:       0, // use default DB
		// Optimize connection pool for faster startup
		PoolSize:     10,
		MinIdleConns: 2,
		MaxRetries:   3,
		PoolTimeout:  5 * time.Second,
	})
	defer func() {
		_ = rdb.Close() // Best effort cleanup
	}()
	log.Printf("⏱️  Redis client initialized in %v", time.Since(redisStart))

	// Initialize crypto service
	cryptoStart := time.Now()
	crypto := appcrypto.NewCryptoService(config.EncryptionKey)
	log.Printf("⏱️  Crypto service initialized in %v", time.Since(cryptoStart))

	// Initialize readiness state
	readyState := appserver.NewReadyState(db, crypto, config, rdb)

	// Create Fiber app first to enable health endpoints
	appStart := time.Now()
	app := appserver.CreateFiberApp(startTime, readyState)
	log.Printf("⏱️  Fiber app created in %v", time.Since(appStart))

	// Setup routes
	routeStart := time.Now()
	setupRoutes(app, db, rdb, crypto, config, startTime, readyState)
	log.Printf("⏱️  Routes setup completed in %v", time.Since(routeStart))

	// Start server in background to handle health checks immediately
	port := config.Port
	go func() {
		if err := appserver.ListenWithIPv6Fallback(app, port, startupStart); err != nil {
			log.Fatal("Server failed to start:", err)
		}
	}()

	// Wait a moment for server to start accepting connections
	time.Sleep(100 * time.Millisecond)
	log.Printf("✅ Server is live and accepting health checks")

	// Begin async initialization of non-critical components
	initStart := time.Now()

	// Validate encryption key (non-blocking warning, skip in dev mode)
	go func() {
		if os.Getenv("SKIP_ADMIN_VALIDATION") != "true" {
			if err := services.ValidateEncryptionKeyAndAdminAccess(db, crypto, config.DefaultAdminEmail); err != nil {
				log.Printf("⚠️  ENCRYPTION KEY WARNING: %v", err)
			}
		} else {
			log.Println("⏭️ Skipping admin validation (SKIP_ADMIN_VALIDATION=true)")
		}
	}()

	// Initialize admin user
	adminStart := time.Now()
	adminService := services.NewAdminService(db, crypto)
	if err := adminService.CreateDefaultAdminUser(); err != nil {
		log.Printf("Warning: Failed to create default admin user: %v", err)
	}
	log.Printf("⏱️  Admin user initialization completed in %v", time.Since(adminStart))
	readyState.MarkAdminReady()

	// Initialize templates
	templateStart := time.Now()
	if err := services.SeedDefaultTemplates(db, crypto); err != nil {
		log.Printf("Warning: Failed to seed default templates: %v", err)
	}
	log.Printf("⏱️  Template seeding completed in %v", time.Since(templateStart))
	readyState.MarkTemplatesReady()

	// Start admin allowlist refresher
	services.StartAdminAllowlistRefresher()
	log.Printf("✅ Admin allowlist refresher started")
	readyState.MarkAllowlistReady()

	// Pre-warm Redis connection pool in background
	go func() {
		prewarmStart := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := rdb.Ping(ctx).Err(); err != nil {
			log.Printf("⚠️  Redis prewarm ping failed: %v", err)
		} else {
			log.Printf("✅ Redis connection pool pre-warmed in %v", time.Since(prewarmStart))
		}
		readyState.MarkRedisReady()
	}()

	services.StartCleanupService(db)

	log.Printf("⏱️  Async initialization tasks started in %v", time.Since(initStart))
	log.Printf("🎯 Basic startup completed in %v - server is live!", time.Since(startupStart))

	// Wait for server to exit (blocks here)
	select {}
}
