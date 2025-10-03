package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	neturl "net/url"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
)

// MigrationSchemaVersion tracks the current schema version
const MigrationSchemaVersion = "2024.12.25.003" // Updated for theme_preference column

// Database interface for dependency injection and testing
type Database interface {
	QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row
	Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error)
	Exec(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error)
	Begin(ctx context.Context) (pgx.Tx, error)
}

var identRe = regexp.MustCompile(`^[a-zA-Z0-9_]+$`)

// SetupDatabase creates and configures the database connection pool with migrations
func SetupDatabase(dbURL string) (*pgxpool.Pool, error) {
	// Parse URL to detect DB name and construct an admin URL pointing to 'postgres'
	adminURL, dbName := adminURLAndDBName(dbURL)

	// Create database if not exists (skip if dbName is empty or 'postgres')
	if dbName != "" && dbName != "postgres" {
		adminDB, err := sql.Open("pgx", adminURL)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to postgres: %w", err)
		}
		// Best effort ensure DB exists
		if safe, ok := safePgIdent(dbName); ok {
			if _, err := adminDB.Exec("CREATE DATABASE " + safe); err != nil && !strings.Contains(strings.ToLower(err.Error()), "already exists") {
				log.Printf("Note: CREATE DATABASE may have failed (continuing if it exists): %v", err)
			}
		} else {
			log.Printf("Warning: Database name '%s' contains unsupported characters; skipping CREATE DATABASE step", dbName)
		}
		_ = adminDB.Close()
	}

	// Connect to the actual database with optimized connection pool settings for fast startup
	ctx := context.Background()

	// Parse the database URL into a config
	config, err := pgxpool.ParseConfig(dbURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse database URL: %w", err)
	}

	// Configure connection pool optimized for Railway managed PostgreSQL
	config.MaxConns = 25                       // Railway can handle higher concurrency
	config.MinConns = 5                        // Better connection pool warmup
	config.MaxConnLifetime = 1 * time.Hour     // Railway connections should refresh hourly
	config.MaxConnIdleTime = 15 * time.Minute  // Railway's idle timeout consideration
	config.HealthCheckPeriod = 1 * time.Minute // Regular health checks for Railway

	// Optimize connection parameters for performance
	config.ConnConfig.ConnectTimeout = 5 * time.Second // Faster timeout for startup
	config.ConnConfig.RuntimeParams["jit"] = "off"     // Disable JIT for faster startup

	// Configure faster health check query
	config.ConnConfig.RuntimeParams["application_name"] = "leaflock_backend"

	// Create the connection pool with the configured settings
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Run optimized migrations with caching
	if err := runOptimizedMigrations(ctx, pool); err != nil {
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	// Validate database connectivity with fast health check
	if err := validateDatabaseConnectivity(pool); err != nil {
		return nil, fmt.Errorf("database connectivity validation failed: %w", err)
	}

	log.Println("Database setup completed successfully")
	return pool, nil
}

// SetupDatabaseFast creates database connection pool without running migrations
// Used for faster startup when SKIP_MIGRATION_CHECK=true
func SetupDatabaseFast(dbURL string) (*pgxpool.Pool, error) {
	log.Println("Setting up database connection (fast mode - skipping migrations)")

	// Parse URL to detect DB name and construct an admin URL pointing to 'postgres'
	adminURL, dbName := adminURLAndDBName(dbURL)

	// Create database if not exists (skip if dbName is empty or 'postgres')
	if dbName != "" && dbName != "postgres" {
		adminDB, err := sql.Open("pgx", adminURL)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to postgres: %w", err)
		}
		// Best effort ensure DB exists
		if safe, ok := safePgIdent(dbName); ok {
			if _, err := adminDB.Exec("CREATE DATABASE " + safe); err != nil && !strings.Contains(strings.ToLower(err.Error()), "already exists") {
				log.Printf("Note: CREATE DATABASE may have failed (continuing if it exists): %v", err)
			}
		} else {
			log.Printf("Warning: Database name '%s' contains unsupported characters; skipping CREATE DATABASE step", dbName)
		}
		_ = adminDB.Close()
	}

	// Connect to the actual database with minimal connection pool settings for fast startup
	ctx := context.Background()

	// Parse the database URL into a config
	config, err := pgxpool.ParseConfig(dbURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse database URL: %w", err)
	}

	// Configure connection pool optimized for fastest possible startup
	config.MaxConns = 10 // Balanced for fast startup and safety
	config.MinConns = 2  // Minimum viable pool
	config.MaxConnLifetime = 1 * time.Hour
	config.MaxConnIdleTime = 15 * time.Minute
	config.HealthCheckPeriod = 2 * time.Minute

	// Optimize connection parameters for fastest startup
	config.ConnConfig.ConnectTimeout = 3 * time.Second
	config.ConnConfig.RuntimeParams["jit"] = "off" // Disable JIT for faster startup

	// Create the connection pool with minimal settings
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Test connection but don't run migrations
	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("database ping failed: %w", err)
	}

	log.Println("Database connection established (fast mode)")
	return pool, nil
}

// runOptimizedMigrations checks if migrations are needed before running them
func runOptimizedMigrations(ctx context.Context, pool *pgxpool.Pool) error {
	// Check if migration tracking table exists and get current version
	currentVersion, needsMigration := checkMigrationStatus(ctx, pool)

	if !needsMigration {
		log.Printf("Database schema is up to date (version: %s), skipping migrations", currentVersion)
		return nil
	}

	log.Printf("Running database migrations (current: %s, target: %s)...", currentVersion, MigrationSchemaVersion)
	start := time.Now()

	// Run migrations in a transaction for atomicity
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin migration transaction: %w", err)
	}
	defer func() {
		_ = tx.Rollback(ctx) // Rollback is safe to call even if tx was committed
	}()

	// Execute the schema
	if _, err := tx.Exec(ctx, DatabaseSchema); err != nil {
		return fmt.Errorf("failed to execute migrations: %w", err)
	}

	// Update migration version
	if err := updateMigrationVersion(ctx, tx, MigrationSchemaVersion); err != nil {
		return fmt.Errorf("failed to update migration version: %w", err)
	}

	// Commit the transaction
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit migration transaction: %w", err)
	}

	log.Printf("Database migrations completed in %v", time.Since(start))
	return nil
}

// checkMigrationStatus returns current version and whether migration is needed
func checkMigrationStatus(ctx context.Context, pool *pgxpool.Pool) (string, bool) {
	// Create migration tracking table if it doesn't exist
	_, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS _migrations (
			id SERIAL PRIMARY KEY,
			version TEXT UNIQUE NOT NULL,
			applied_at TIMESTAMPTZ DEFAULT NOW(),
			checksum TEXT
		)
	`)
	if err != nil {
		log.Printf("Warning: Could not create migration table, running full migrations: %v", err)
		return "", true
	}

	// Check current version
	var currentVersion string
	err = pool.QueryRow(ctx, "SELECT version FROM _migrations ORDER BY applied_at DESC LIMIT 1").Scan(&currentVersion)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// No migrations applied yet
			return "", true
		}
		log.Printf("Warning: Could not check migration version, running full migrations: %v", err)
		return "", true
	}

	// Check if current version matches target
	if currentVersion == MigrationSchemaVersion {
		return currentVersion, false
	}

	// Additional quick check: verify key tables exist to avoid unnecessary migrations
	var tableCount int
	err = pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM information_schema.tables
		WHERE table_schema = 'public'
		AND table_name IN ('users', 'notes', 'workspaces', 'audit_log')
	`).Scan(&tableCount)
	if err == nil && tableCount >= 4 && currentVersion != "" {
		// Core tables exist and we have a version - likely a minor schema update
		return currentVersion, true
	}

	return currentVersion, true
}

// updateMigrationVersion records the successful migration
func updateMigrationVersion(ctx context.Context, tx pgx.Tx, version string) error {
	_, err := tx.Exec(ctx, "INSERT INTO _migrations (version) VALUES ($1) ON CONFLICT (version) DO NOTHING", version)
	return err
}

// fastHealthCheck performs a lightweight database connectivity check
func fastHealthCheck(ctx context.Context, pool *pgxpool.Pool) error {
	// Use a simple SELECT 1 query for fast health checking
	var result int
	err := pool.QueryRow(ctx, "SELECT 1").Scan(&result)
	if err != nil {
		return fmt.Errorf("database health check failed: %w", err)
	}
	return nil
}

// validateDatabaseConnectivity performs an optimized database connectivity check
func validateDatabaseConnectivity(pool *pgxpool.Pool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Fast health check first
	if err := fastHealthCheck(ctx, pool); err != nil {
		return fmt.Errorf("database connectivity check failed: %w", err)
	}

	log.Println("✅ Database connectivity verified")
	return nil
}

// adminURLAndDBName builds an admin URL pointing to the 'postgres' database and returns the target db name
func adminURLAndDBName(dbURL string) (string, string) {
	u, err := neturl.Parse(dbURL)
	if err != nil {
		return dbURL, ""
	}
	// Extract db name from path
	dbName := strings.TrimPrefix(u.Path, "/")
	// Point to 'postgres' db for admin tasks
	u.Path = "/postgres"
	return u.String(), dbName
}

// safePgIdent validates and quotes identifier safely for CREATE DATABASE
func safePgIdent(name string) (string, bool) {
	if identRe.MatchString(name) {
		return name, true
	}
	return "", false
}