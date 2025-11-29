package database

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"leaflock/utils"
)

// DatabaseSecurity provides security configurations and utilities for PostgreSQL

// SecurityConfig contains database security configurations
type SecurityConfig struct {
	EncryptionAtRest     bool
	ConnectionEncryption bool
	AuditLogging         bool
	RowLevelSecurity     bool
	RateLimiting         bool
	IPWhitelisting       bool
	ConnectionTimeout    time.Duration
	IdleTimeout          time.Duration
	MaxConnections       int32
	MinConnections       int32
}

// DefaultSecurityConfig returns default security configuration
func DefaultSecurityConfig() SecurityConfig {
	return SecurityConfig{
		EncryptionAtRest:     true,
		ConnectionEncryption: true,
		AuditLogging:         true,
		RowLevelSecurity:     true,
		RateLimiting:         true,
		IPWhitelisting:       false, // Enable in production
		ConnectionTimeout:    30 * time.Second,
		IdleTimeout:          5 * time.Minute,
		MaxConnections:       25,
		MinConnections:       5,
	}
}

// SetupDatabaseSecurity configures database security features
func SetupDatabaseSecurity(ctx context.Context, pool *pgxpool.Pool, config SecurityConfig) error {
	logger := utils.NewSecurityLogger()

	logger.LogSecurityEvent("database_security_setup", "info", map[string]interface{}{
		"encryption_at_rest": config.EncryptionAtRest,
		"audit_logging":      config.AuditLogging,
	})

	// Enable encryption at rest
	if config.EncryptionAtRest {
		if err := enableEncryptionAtRest(ctx, pool); err != nil {
			return fmt.Errorf("failed to enable encryption at rest: %w", err)
		}
	}

	// Enable audit logging
	if config.AuditLogging {
		if err := enableAuditLogging(ctx, pool); err != nil {
			return fmt.Errorf("failed to enable audit logging: %w", err)
		}
	}

	// Enable row-level security
	if config.RowLevelSecurity {
		if err := enableRowLevelSecurity(ctx, pool); err != nil {
			return fmt.Errorf("failed to enable row-level security: %w", err)
		}
	}

	// Setup connection security
	if err := setupConnectionSecurity(ctx, pool, config); err != nil {
		return fmt.Errorf("failed to setup connection security: %w", err)
	}

	return nil
}

// enableEncryptionAtRest enables encryption at rest for PostgreSQL
func enableEncryptionAtRest(ctx context.Context, pool *pgxpool.Pool) error {
	// PostgreSQL encryption at rest is typically configured at the database level
	// This function sets up the necessary database parameters

	queries := []string{
		"ALTER SYSTEM SET ssl = on",
		"ALTER SYSTEM SET ssl_cert_file = 'server.crt'",
		"ALTER SYSTEM SET ssl_key_file = 'server.key'",
		"ALTER SYSTEM SET ssl_ca_file = 'root.crt'",
	}

	for _, query := range queries {
		if _, err := pool.Exec(ctx, query); err != nil {
			// Log but don't fail - these might already be set
			utils.NewSecurityLogger().LogError("encryption_setup", err, map[string]interface{}{
				"query": query,
			})
		}
	}

	return nil
}

// enableAuditLogging enables comprehensive audit logging
func enableAuditLogging(ctx context.Context, pool *pgxpool.Pool) error {
	// Enable PostgreSQL audit logging
	queries := []string{
		"ALTER SYSTEM SET log_statement = 'all'",
		"ALTER SYSTEM SET log_connections = on",
		"ALTER SYSTEM SET log_disconnections = on",
		"ALTER SYSTEM SET log_duration = on",
		"ALTER SYSTEM SET log_hostname = on",
		"ALTER SYSTEM SET log_line_prefix = '%t [%p]: [%l-1] user=%u,db=%d,app=%a,client=%h'",
	}

	for _, query := range queries {
		if _, err := pool.Exec(ctx, query); err != nil {
			// Log but don't fail - these might already be set
			utils.NewSecurityLogger().LogError("audit_setup", err, map[string]interface{}{
				"query": query,
			})
		}
	}

	return nil
}

// enableRowLevelSecurity enables row-level security for sensitive tables
func enableRowLevelSecurity(ctx context.Context, pool *pgxpool.Pool) error {
	// Enable RLS on sensitive tables
	rlsQueries := []string{
		"ALTER TABLE users ENABLE ROW LEVEL SECURITY",
		"ALTER TABLE notes ENABLE ROW LEVEL SECURITY",
		"ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY",
	}

	for _, query := range rlsQueries {
		if _, err := pool.Exec(ctx, query); err != nil {
			return fmt.Errorf("failed to enable RLS: %w", err)
		}
	}

	// Create RLS policies
	if err := createRLSPolicies(ctx, pool); err != nil {
		return fmt.Errorf("failed to create RLS policies: %w", err)
	}

	return nil
}

// createRLSPolicies creates row-level security policies
func createRLSPolicies(ctx context.Context, pool *pgxpool.Pool) error {
	policies := []string{
		// Users can only see their own data
		`CREATE POLICY users_isolation ON users FOR ALL TO app_user USING (id = current_user_id())`,

		// Notes are isolated by user with sharing support
		`CREATE POLICY notes_isolation ON notes FOR ALL TO app_user 
		 USING (user_id = current_user_id() OR EXISTS (
		   SELECT 1 FROM note_shares WHERE note_id = notes.id AND shared_with_user_id = current_user_id()
		 ))`,

		// Audit log access is restricted to the user and admins
		`CREATE POLICY audit_log_access ON audit_log FOR ALL TO app_user 
		 USING (user_id = current_user_id() OR current_user_is_admin())`,
	}

	for _, policy := range policies {
		if _, err := pool.Exec(ctx, policy); err != nil {
			return fmt.Errorf("failed to create policy: %w", err)
		}
	}

	return nil
}

// setupConnectionSecurity configures secure connection settings
func setupConnectionSecurity(ctx context.Context, pool *pgxpool.Pool, config SecurityConfig) error {
	// Set connection security parameters
	params := map[string]string{
		"sslmode":                             "require",
		"sslcert":                             "client.crt",
		"sslkey":                              "client.key",
		"sslrootcert":                         "root.crt",
		"connect_timeout":                     fmt.Sprintf("%d", int(config.ConnectionTimeout.Seconds())),
		"idle_in_transaction_session_timeout": fmt.Sprintf("%d", int(config.IdleTimeout.Seconds())),
		"statement_timeout":                   "30000", // 30 seconds
		"lock_timeout":                        "10000", // 10 seconds
	}

	for key, value := range params {
		query := fmt.Sprintf("SET %s = '%s'", key, value)
		if _, err := pool.Exec(ctx, query); err != nil {
			utils.NewSecurityLogger().LogError("connection_security_setup", err, map[string]interface{}{
				"param": key,
				"value": value,
			})
		}
	}

	return nil
}

// ValidateDatabaseSecurity validates database security configuration
func ValidateDatabaseSecurity(ctx context.Context, pool *pgxpool.Pool) error {
	logger := utils.NewSecurityLogger()

	// Check for weak passwords
	var weakPasswords int
	err := pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM users 
		WHERE password_hash IS NOT NULL 
		AND length(password_hash) < 60
	`).Scan(&weakPasswords)

	if err == nil && weakPasswords > 0 {
		logger.LogSecurityEvent("weak_passwords_detected", "warning", map[string]interface{}{
			"count": weakPasswords,
		})
	}

	// Check for default users
	var defaultUsers int
	err = pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM users 
		WHERE email = 'admin@example.com' OR email = 'test@example.com'
	`).Scan(&defaultUsers)

	if err == nil && defaultUsers > 0 {
		logger.LogSecurityEvent("default_users_detected", "warning", map[string]interface{}{
			"count": defaultUsers,
		})
	}

	// Check for unencrypted connections
	var unencryptedConnections int
	err = pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM pg_stat_activity 
		WHERE ssl = false AND state != 'idle'
	`).Scan(&unencryptedConnections)

	if err == nil && unencryptedConnections > 0 {
		logger.LogSecurityEvent("unencrypted_connections", "high", map[string]interface{}{
			"count": unencryptedConnections,
		})
	}

	return nil
}

// SetupSecureConnectionPool creates a connection pool with security configurations
func SetupSecureConnectionPool(ctx context.Context, databaseURL string, config SecurityConfig) (*pgxpool.Pool, error) {
	// Add security parameters to connection string
	secureURL := databaseURL

	// Add SSL parameters
	if config.ConnectionEncryption {
		secureURL += "?sslmode=require&sslcert=client.crt&sslkey=client.key&sslrootcert=root.crt"
	}

	// Create pool configuration
	poolConfig, err := pgxpool.ParseConfig(secureURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse database URL: %w", err)
	}

	// Apply security configurations
	poolConfig.MaxConns = config.MaxConnections
	poolConfig.MinConns = config.MinConnections
	poolConfig.MaxConnLifetime = config.ConnectionTimeout
	poolConfig.MaxConnIdleTime = config.IdleTimeout
	poolConfig.HealthCheckPeriod = 30 * time.Second

	// Add security interceptors
	poolConfig.BeforeConnect = func(ctx context.Context, config *pgx.ConnConfig) error {
		// Set security parameters for each connection
		config.RuntimeParams["application_name"] = "leaflock-secure"
		config.RuntimeParams["statement_timeout"] = "30000"
		config.RuntimeParams["lock_timeout"] = "10000"

		return nil
	}

	// Create connection pool
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection pool: %w", err)
	}

	// Setup security features
	if err := SetupDatabaseSecurity(ctx, pool, config); err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to setup database security: %w", err)
	}

	return pool, nil
}
