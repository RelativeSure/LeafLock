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
// @description Type "Bearer" followed by a space and Clerk session token.
//
// main.go - Complete secure backend with automatic PostgreSQL setup
package main

import (
	"context"
	"crypto/sha256"
	"log"
	"os"
	"strings"
	"time"

	"leaflock/auth"
	appconfig "leaflock/config"
	appcrypto "leaflock/crypto"
	appdb "leaflock/database"
	_ "leaflock/docs"     // Import docs for Swagger
	_ "leaflock/handlers" // Import handlers for Swagger
	appserver "leaflock/server"
	"leaflock/services"
	"leaflock/utils"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/redis/go-redis/v9"
)

// AUTOMATIC DATABASE SETUP - Runs migrations on startup
// Database is an alias for the shared database interface
type Database = appdb.Database

// setupRoutes is defined in routes.go
// This keeps main.go focused on initialization and startup logic

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

	// Crypto service removed - zero-knowledge architecture
	// MFA and session encryption derived from Clerk secret internally in auth.NewService
	// Handler crypto for templates and other server-managed encrypted data
	handlerKey := sha256.Sum256(append([]byte(config.ClerkSecretKey), []byte("-handler-encryption")...))
	handlerCrypto := appcrypto.NewCryptoService(handlerKey[:])

	// Initialize Clerk if configured
	if config.ClerkSecretKey != "" {
		clerkStart := time.Now()
		if err := auth.InitializeClerk(config.ClerkSecretKey); err != nil {
			log.Printf("⚠️  Clerk initialization failed: %v", err)
			log.Printf("⚠️  Clerk authentication not available")
		} else {
			log.Printf("⏱️  Clerk SDK initialized in %v", time.Since(clerkStart))
		}
	} else {
		log.Println("⚠️  CLERK_SECRET_KEY not configured - Clerk authentication disabled")
	}

	// Initialize readiness state
	readyState := appserver.NewReadyState(db, config, rdb)

	// Create Fiber app first to enable health endpoints
	appStart := time.Now()
	app := appserver.CreateFiberApp(startTime, readyState)
	log.Printf("⏱️  Fiber app created in %v", time.Since(appStart))

	// Setup routes
	routeStart := time.Now()
	setupRoutes(app, db, rdb, config, startTime, readyState)
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

	// Ensure default admin user from environment variables (idempotent)
	adminStart := time.Now()
	authService := auth.NewService(db, rdb, config.ClerkSecretKey)
	if err := authService.EnsureDefaultAdminFromEnv(context.Background()); err != nil {
		log.Printf("⚠️  Failed to ensure default admin user: %v", err)
	} else {
		log.Printf("⏱️  Admin initialization completed in %v", time.Since(adminStart))
	}
	readyState.MarkAdminReady()

	// Initialize templates
	templateStart := time.Now()
	if err := services.SeedDefaultTemplates(db, handlerCrypto); err != nil {
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
