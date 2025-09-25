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
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	neturl "net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gofiber/contrib/websocket"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/compress"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/csrf"
	"github.com/gofiber/fiber/v2/middleware/helmet"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"net/http"
)

// ReadyState tracks initialization state for health checks
type ReadyState struct {
	db         *pgxpool.Pool
	crypto     *CryptoService
	config     *Config
	rdb        *redis.Client
	adminReady atomic.Bool
	templatesReady atomic.Bool
	allowlistReady atomic.Bool
	redisReady atomic.Bool
}

func (r *ReadyState) markAdminReady()     { r.adminReady.Store(true) }
func (r *ReadyState) markTemplatesReady() { r.templatesReady.Store(true) }
func (r *ReadyState) markAllowlistReady() { r.allowlistReady.Store(true) }
func (r *ReadyState) markRedisReady()     { r.redisReady.Store(true) }

func (r *ReadyState) IsFullyReady() bool {
	return r.adminReady.Load() && 
		   r.templatesReady.Load() && 
		   r.allowlistReady.Load() && 
		   r.redisReady.Load()
}

// AUTOMATIC DATABASE SETUP - Runs migrations on startup
const DatabaseSchema = `
-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- Users table with encrypted fields
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email_hash BYTEA UNIQUE NOT NULL, -- SHA-256 hash for unique constraint and GDPR lookups
    email_encrypted BYTEA NOT NULL, -- Encrypted email for privacy
    email_search_hash BYTEA UNIQUE, -- Deterministic encryption for login lookups
    password_hash TEXT NOT NULL, -- Argon2id hash
    salt BYTEA NOT NULL,
    master_key_encrypted BYTEA NOT NULL, -- User's encrypted master key
    public_key BYTEA, -- For sharing encrypted notes
    private_key_encrypted BYTEA, -- Encrypted with user's derived key
    mfa_secret_encrypted BYTEA, -- Encrypted TOTP secret
    mfa_enabled BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    last_login TIMESTAMPTZ,
    failed_attempts INT DEFAULT 0,
    locked_until TIMESTAMPTZ,
    deleted_at TIMESTAMPTZ
);

-- Ensure admin flag exists
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin BOOLEAN DEFAULT false;

-- Add new encryption columns for enhanced security
ALTER TABLE users ADD COLUMN IF NOT EXISTS email_hash BYTEA UNIQUE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS email_search_hash BYTEA UNIQUE;

-- Add storage tracking columns for file import limits
ALTER TABLE users ADD COLUMN IF NOT EXISTS storage_used BIGINT DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS storage_limit BIGINT DEFAULT 5242880; -- 5MB default limit

-- Add soft delete column for users table (required for idx_users_count_fast index)
ALTER TABLE users ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;


-- GDPR compliance: Add table to store GDPR deletion keys for email recovery
CREATE TABLE IF NOT EXISTS gdpr_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email_hash BYTEA UNIQUE NOT NULL,
    deletion_key BYTEA NOT NULL, -- Key to decrypt email for GDPR requests
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Remove plaintext email column (after data migration)
-- ALTER TABLE users DROP COLUMN IF EXISTS email;

-- RBAC roles
CREATE TABLE IF NOT EXISTS roles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS user_roles (
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

-- Seed default roles
INSERT INTO roles (name)
SELECT r FROM (VALUES ('admin'), ('user'), ('moderator'), ('auditor')) AS v(r)
ON CONFLICT (name) DO NOTHING;

-- Announcements table for system-wide messages
CREATE TABLE IF NOT EXISTS announcements (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    title TEXT NOT NULL,
    content TEXT NOT NULL, -- Markdown content
    visibility TEXT CHECK (visibility IN ('all', 'logged_in')) DEFAULT 'logged_in',
    style JSONB DEFAULT '{}', -- Style configuration (colors, icons, etc.)
    active BOOLEAN DEFAULT true,
    dismissible BOOLEAN DEFAULT true,
    priority INT DEFAULT 0, -- For ordering (higher = more important)
    start_date TIMESTAMPTZ,
    end_date TIMESTAMPTZ,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Index for active announcements query
CREATE INDEX IF NOT EXISTS idx_announcements_active ON announcements(active, priority DESC, created_at DESC);

-- Workspace table
CREATE TABLE IF NOT EXISTS workspaces (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name_encrypted BYTEA NOT NULL, -- Encrypted workspace name
    owner_id UUID REFERENCES users(id) ON DELETE CASCADE,
    encryption_key_encrypted BYTEA NOT NULL, -- Workspace key encrypted with owner's key
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Notes table with full encryption
CREATE TABLE IF NOT EXISTS notes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    workspace_id UUID REFERENCES workspaces(id) ON DELETE CASCADE,
    title_encrypted BYTEA NOT NULL, -- Encrypted title
    content_encrypted BYTEA NOT NULL, -- Encrypted content
    content_hash BYTEA NOT NULL, -- For integrity verification
    parent_id UUID REFERENCES notes(id) ON DELETE CASCADE,
    position INT DEFAULT 0,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    deleted_at TIMESTAMPTZ,
    version INT DEFAULT 1
);

-- Note versions for history tracking
CREATE TABLE IF NOT EXISTS note_versions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    note_id UUID REFERENCES notes(id) ON DELETE CASCADE,
    version_number INT NOT NULL,
    title_encrypted BYTEA NOT NULL, -- Encrypted title at this version
    content_encrypted BYTEA NOT NULL, -- Encrypted content at this version
    content_hash BYTEA NOT NULL, -- For integrity verification
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(note_id, version_number)
);

-- Encrypted search index (searchable encryption)
CREATE TABLE IF NOT EXISTS search_index (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    note_id UUID REFERENCES notes(id) ON DELETE CASCADE,
    keyword_hash BYTEA NOT NULL, -- HMAC of keyword
    position INT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Collaboration table for shared notes
CREATE TABLE IF NOT EXISTS collaborations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    note_id UUID REFERENCES notes(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    permission TEXT CHECK (permission IN ('read', 'write', 'admin')),
    key_encrypted BYTEA NOT NULL, -- Note key encrypted with user's public key
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(note_id, user_id)
);

-- Audit log for security
CREATE TABLE IF NOT EXISTS audit_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id),
    action TEXT NOT NULL,
    resource_type TEXT,
    resource_id UUID,
    ip_address_encrypted BYTEA,
    user_agent_encrypted BYTEA,
    metadata JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Encrypt audit log metadata field
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS metadata_encrypted BYTEA;

-- File attachments with encryption
CREATE TABLE IF NOT EXISTS attachments (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    note_id UUID REFERENCES notes(id) ON DELETE CASCADE,
    filename_encrypted BYTEA NOT NULL,
    content_encrypted BYTEA NOT NULL, -- Store encrypted files in DB for simplicity
    mime_type TEXT,
    size_bytes BIGINT,
    checksum BYTEA NOT NULL, -- SHA-256 of encrypted content
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Encryption keys rotation table
CREATE TABLE IF NOT EXISTS key_rotations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    old_key_hash BYTEA NOT NULL,
    new_key_hash BYTEA NOT NULL,
    items_rotated INT DEFAULT 0,
    completed BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

-- Folders table for organizing notes
CREATE TABLE IF NOT EXISTS folders (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    parent_id UUID REFERENCES folders(id) ON DELETE CASCADE, -- NULL for root folders
    name_encrypted BYTEA NOT NULL, -- Encrypted folder name
    color VARCHAR(7) DEFAULT '#3b82f6', -- Hex color code
    position INT DEFAULT 0, -- For custom ordering
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Add folder_id to notes table for folder organization
ALTER TABLE notes ADD COLUMN IF NOT EXISTS folder_id UUID REFERENCES folders(id) ON DELETE SET NULL;



-- Tags table for organizing notes
CREATE TABLE IF NOT EXISTS tags (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    name_encrypted BYTEA NOT NULL, -- Encrypted tag name
    color VARCHAR(7) DEFAULT '#3b82f6', -- Hex color code
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(user_id, name_encrypted) -- Prevent duplicate tag names per user
);

-- Junction table for note-tag relationships
CREATE TABLE IF NOT EXISTS note_tags (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    note_id UUID REFERENCES notes(id) ON DELETE CASCADE,
    tag_id UUID REFERENCES tags(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(note_id, tag_id) -- Prevent duplicate assignments
);

-- Templates table for reusable note templates
CREATE TABLE IF NOT EXISTS templates (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    name_encrypted BYTEA NOT NULL, -- Encrypted template name
    description_encrypted BYTEA, -- Encrypted template description
    content_encrypted BYTEA NOT NULL, -- Encrypted template content
    tags TEXT[], -- Array of tag names for categorization
    icon VARCHAR(50) DEFAULT '📝', -- Emoji icon for template
    is_public BOOLEAN DEFAULT false, -- Whether template is shared publicly
    usage_count INT DEFAULT 0, -- Track how often template is used
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Add template_id to notes table for tracking template origin
ALTER TABLE notes ADD COLUMN IF NOT EXISTS template_id UUID REFERENCES templates(id) ON DELETE SET NULL;

-- Functions for automatic updated_at
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Apply updated_at triggers
DO $$ 
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'update_users_updated_at') THEN
        CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users 
            FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'update_workspaces_updated_at') THEN
        CREATE TRIGGER update_workspaces_updated_at BEFORE UPDATE ON workspaces 
            FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'update_notes_updated_at') THEN
        CREATE TRIGGER update_notes_updated_at BEFORE UPDATE ON notes 
            FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'update_tags_updated_at') THEN
        CREATE TRIGGER update_tags_updated_at BEFORE UPDATE ON tags
            FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'update_folders_updated_at') THEN
        CREATE TRIGGER update_folders_updated_at BEFORE UPDATE ON folders
            FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'update_templates_updated_at') THEN
        CREATE TRIGGER update_templates_updated_at BEFORE UPDATE ON templates
            FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
    END IF;
END $$;


-- Cleanup old deleted notes function (30 days)
CREATE OR REPLACE FUNCTION cleanup_old_deleted_notes()
RETURNS void AS $$
BEGIN
    DELETE FROM notes WHERE deleted_at IS NOT NULL AND deleted_at < NOW() - INTERVAL '30 days';
END;
$$ LANGUAGE plpgsql;

-- Create indexes for better performance (optimized for startup and common queries)
CREATE INDEX IF NOT EXISTS idx_notes_workspace ON notes(workspace_id) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_notes_parent ON notes(parent_id);
CREATE INDEX IF NOT EXISTS idx_notes_created ON notes(created_by, created_at DESC);

-- Critical index for admin validation queries (optimized for fast lookup)
CREATE INDEX IF NOT EXISTS idx_users_email_search_hash ON users(email_search_hash) WHERE email_search_hash IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_users_count_fast ON users(id) WHERE deleted_at IS NULL; -- For fast COUNT(*) queries

-- Partial indexes for performance-critical startup queries
CREATE INDEX IF NOT EXISTS idx_users_admin_flag ON users(is_admin) WHERE is_admin = true;
CREATE INDEX IF NOT EXISTS idx_users_email_hash ON users(email_hash) WHERE email_hash IS NOT NULL;

-- Search index optimization
CREATE INDEX IF NOT EXISTS idx_search_keyword ON search_index(keyword_hash);

-- Migration tracking index for fast version checks
CREATE INDEX IF NOT EXISTS idx_migrations_version ON _migrations(version, applied_at DESC);


-- App settings key-value store
CREATE TABLE IF NOT EXISTS app_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE OR REPLACE FUNCTION update_settings_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END; $$ LANGUAGE plpgsql;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'update_app_settings_updated_at') THEN
        CREATE TRIGGER update_app_settings_updated_at BEFORE UPDATE ON app_settings
        FOR EACH ROW EXECUTE FUNCTION update_settings_updated_at();
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action, created_at DESC);

-- Tags indexes
CREATE INDEX IF NOT EXISTS idx_tags_user ON tags(user_id);
CREATE INDEX IF NOT EXISTS idx_note_tags_note ON note_tags(note_id);
CREATE INDEX IF NOT EXISTS idx_note_tags_tag ON note_tags(tag_id);

-- Folders indexes
CREATE INDEX IF NOT EXISTS idx_folders_user ON folders(user_id);
CREATE INDEX IF NOT EXISTS idx_folders_parent ON folders(parent_id);
CREATE INDEX IF NOT EXISTS idx_folders_position ON folders(user_id, position);
CREATE INDEX IF NOT EXISTS idx_notes_folder ON notes(folder_id);

-- Note: Cleanup jobs run automatically via background service every 24 hours
`

// Configuration with secure defaults
type Config struct {
	DatabaseURL        string
	RedisURL           string
	RedisPassword      string
	JWTSecret          []byte
	EncryptionKey      []byte
	Port               string
	AllowedOrigins     []string
	MaxLoginAttempts   int
	LockoutDuration    time.Duration
	IPLockoutDuration  time.Duration
	MaxIPLoginAttempts int
	SessionDuration    time.Duration
	Environment        string
	TrustProxyHeaders  bool
	// Progressive rate limiting options
	RateLimitMode         string   // "progressive", "lockout", or "disabled"
	IPRateLimitEnabled    bool     // Enable/disable IP-based rate limiting
	RateLimitDecayMinutes int      // Minutes between attempt count reductions
	RateLimitUseSubnet    bool     // Group by subnet instead of individual IP
	MaxDelaySeconds       int      // Maximum delay to apply in seconds
	TrustedIPRanges       []string // IP ranges that bypass rate limiting
	// Default admin settings
	DefaultAdminEnabled  bool
	DefaultAdminEmail    string
	DefaultAdminPassword string
}

// fiberResponseWriter adapts Fiber's context to http.ResponseWriter interface
type fiberResponseWriter struct {
	ctx    *fiber.Ctx
	status int
	header http.Header
}

func (w *fiberResponseWriter) Header() http.Header {
	return w.header
}

func (w *fiberResponseWriter) Write(data []byte) (int, error) {
	// Copy headers to Fiber context
	for key, values := range w.header {
		for _, value := range values {
			w.ctx.Set(key, value)
		}
	}

	// Set status code if it was set
	if w.status != 200 {
		w.ctx.Status(w.status)
	}

	return w.ctx.Write(data)
}

func (w *fiberResponseWriter) WriteHeader(statusCode int) {
	w.status = statusCode
}

// Runtime feature toggles (in-memory; initialized from env at startup)
var regEnabled atomic.Int32
var trustProxyHeaders atomic.Bool

func LoadConfig() *Config {
	// Generate secure random keys if not provided
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		key := make([]byte, 64)
		if _, err := rand.Read(key); err != nil {
			log.Fatalf("failed to generate JWT secret: %v", err)
		}
		jwtSecret = base64.StdEncoding.EncodeToString(key)
		log.Println("Generated new JWT secret")
	}

	encKey := os.Getenv("SERVER_ENCRYPTION_KEY")
	if encKey == "" {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			log.Fatalf("failed to generate server encryption key: %v", err)
		}
		encKey = base64.StdEncoding.EncodeToString(key)
		log.Println("Generated new server encryption key")
	}

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		// Try Coolify-provided Postgres envs first
		if built := buildDatabaseURLFromEnv(); built != "" {
			dbURL = built
		} else {
			// Safe local default for dev
			dbURL = "postgres://postgres:postgres@localhost:5432/leaflock?sslmode=prefer"
		}
	}

	return &Config{
		DatabaseURL:        dbURL,
		RedisURL:           getEnvOrDefault("REDIS_URL", "localhost:6379"),
		RedisPassword:      os.Getenv("REDIS_PASSWORD"),
		JWTSecret:          []byte(jwtSecret),
		EncryptionKey:      []byte(encKey),
		Port:               getEnvOrDefault("PORT", "8080"),
		AllowedOrigins:     strings.Split(getEnvOrDefault("CORS_ORIGINS", "https://localhost:3000"), ","),
		MaxLoginAttempts:   getEnvAsInt("MAX_LOGIN_ATTEMPTS", 5),
		LockoutDuration:    time.Duration(getEnvAsInt("LOCKOUT_MINUTES", 15)) * time.Minute,
		MaxIPLoginAttempts: getEnvAsInt("MAX_IP_LOGIN_ATTEMPTS", 15),
		IPLockoutDuration:  time.Duration(getEnvAsInt("IP_LOCKOUT_MINUTES", 15)) * time.Minute,
		SessionDuration:    24 * time.Hour,
		Environment:        getEnvOrDefault("APP_ENV", "development"),
		TrustProxyHeaders:  getEnvAsBool("TRUST_PROXY_HEADERS", false),
		// Progressive rate limiting configuration
		RateLimitMode:         getEnvOrDefault("RATE_LIMIT_MODE", "progressive"),
		IPRateLimitEnabled:    getEnvAsBool("IP_RATE_LIMIT_ENABLED", true),
		RateLimitDecayMinutes: getEnvAsInt("RATE_LIMIT_DECAY_MINUTES", 5),
		RateLimitUseSubnet:    getEnvAsBool("RATE_LIMIT_USE_SUBNET", false),
		MaxDelaySeconds:       getEnvAsInt("MAX_DELAY_SECONDS", 60),
		TrustedIPRanges:       getEnvAsStringSlice("TRUSTED_IP_RANGES", []string{}),
		// Default admin configuration
		DefaultAdminEnabled:  getEnvAsBool("ENABLE_DEFAULT_ADMIN", true),
		DefaultAdminEmail:    getEnvOrDefault("DEFAULT_ADMIN_EMAIL", "admin@leaflock.app"),
		DefaultAdminPassword: getEnvOrDefault("DEFAULT_ADMIN_PASSWORD", "AdminPass123!"),
	}
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvAsBool(key string, defaultValue bool) bool {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		value = strings.ToLower(value)
		if value == "true" || value == "1" || value == "yes" {
			return true
		}
		if value == "false" || value == "0" || value == "no" {
			return false
		}
	}
	return defaultValue
}

func getEnvAsStringSlice(key string, defaultValue []string) []string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		parts := strings.Split(value, ",")
		result := make([]string, 0, len(parts))
		for _, part := range parts {
			if trimmed := strings.TrimSpace(part); trimmed != "" {
				result = append(result, trimmed)
			}
		}
		return result
	}
	return defaultValue
}

func getEnvAsInt(key string, defaultValue int) int {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

// Build a postgres URL from common env vars (Coolify/Postgres add-on style)
// Recognized: POSTGRESQL_HOST, POSTGRESQL_PORT, POSTGRESQL_USER, POSTGRESQL_PASSWORD, POSTGRESQL_DATABASE, POSTGRESQL_SSLMODE
func buildDatabaseURLFromEnv() string {
	host := strings.TrimSpace(os.Getenv("POSTGRESQL_HOST"))
	user := strings.TrimSpace(os.Getenv("POSTGRESQL_USER"))
	pass := os.Getenv("POSTGRESQL_PASSWORD") // may contain spaces/specials
	db := strings.TrimSpace(os.Getenv("POSTGRESQL_DATABASE"))
	if host == "" || user == "" || db == "" {
		return ""
	}
	port := getEnvOrDefault("POSTGRESQL_PORT", "5432")
	sslmode := getEnvOrDefault("POSTGRESQL_SSLMODE", "require")
	u := &neturl.URL{
		Scheme: "postgres",
		User:   neturl.UserPassword(user, pass),
		Host:   net.JoinHostPort(host, port),
		Path:   "/" + db,
	}
	q := neturl.Values{}
	q.Set("sslmode", sslmode)
	u.RawQuery = q.Encode()
	return u.String()
}

// Crypto Service for server-side encryption
type CryptoService struct {
	serverKey []byte
}

// RBAC helpers
func HasRole(ctx context.Context, db Database, userID uuid.UUID, role string) bool {
	// Admins always pass
	var isAdmin bool
	if err := db.QueryRow(ctx, "SELECT is_admin FROM users WHERE id = $1", userID).Scan(&isAdmin); err == nil && isAdmin {
		return true
	}
	if strings.ToLower(role) == "admin" {
		if isUserInAdminAllowlist(userID.String()) {
			return true
		}
	}
	// Check user_roles
	var exists bool
	_ = db.QueryRow(ctx, `
        SELECT EXISTS (
            SELECT 1 FROM user_roles ur
            JOIN roles r ON ur.role_id = r.id
            WHERE ur.user_id = $1 AND r.name = $2
        )`, userID, role).Scan(&exists)
	return exists
}

// --- Dynamic admin allowlist with hot-reload support ---
var adminAllowlist atomic.Value // holds map[string]struct{}
var privateIPBlocks []*net.IPNet

func init() {
	adminAllowlist.Store(make(map[string]struct{}))
	blocks := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	}
	for _, cidr := range blocks {
		if _, block, err := net.ParseCIDR(cidr); err == nil {
			privateIPBlocks = append(privateIPBlocks, block)
		}
	}
}

func currentAllowlist() map[string]struct{} {
	v := adminAllowlist.Load()
	if v == nil {
		return map[string]struct{}{}
	}
	return v.(map[string]struct{})
}

func isUserInAdminAllowlist(userID string) bool {
	if _, ok := currentAllowlist()[strings.TrimSpace(userID)]; ok {
		return true
	}
	// Backward-compat: also check process env in case watcher not configured
	envAdmins := strings.Split(os.Getenv("ADMIN_USER_IDS"), ",")
	for _, a := range envAdmins {
		if strings.TrimSpace(a) == strings.TrimSpace(userID) {
			return true
		}
	}
	return false
}

func loadAllowlistFromSources(envList string, filePath string) (map[string]struct{}, string) {
	m := make(map[string]struct{})
	var buf bytes.Buffer
	// include env first
	if envList != "" {
		buf.WriteString("ENV:")
		buf.WriteString(envList)
		buf.WriteString("\n")
		for _, a := range strings.Split(envList, ",") {
			a = strings.TrimSpace(a)
			if a != "" {
				m[a] = struct{}{}
			}
		}
	}
	// include file if present
	if filePath != "" {
		if f, err := os.Open(filePath); err == nil {
			defer f.Close()
			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				if strings.HasPrefix(line, "ADMIN_USER_IDS=") {
					val := strings.TrimSpace(strings.TrimPrefix(line, "ADMIN_USER_IDS="))
					// strip quotes if present
					val = strings.Trim(val, "\"'")
					buf.WriteString("FILE:")
					buf.WriteString(val)
					buf.WriteString("\n")
					for _, a := range strings.Split(val, ",") {
						a = strings.TrimSpace(a)
						if a != "" {
							m[a] = struct{}{}
						}
					}
				}
			}
		}
	}
	return m, buf.String()
}

func startAdminAllowlistRefresher() {
	filePath := strings.TrimSpace(os.Getenv("ADMIN_USER_IDS_FILE"))
	// initial load
	m, _ := loadAllowlistFromSources(os.Getenv("ADMIN_USER_IDS"), filePath)
	adminAllowlist.Store(m)
	go func() {
		var lastSig string
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			m, sig := loadAllowlistFromSources(os.Getenv("ADMIN_USER_IDS"), filePath)
			if sig != lastSig {
				adminAllowlist.Store(m)
				lastSig = sig
				log.Printf("🔄 Admin allowlist reloaded (%d entries)", len(m))
			}
		}
	}()
}

// Helper function to get user ID from JWT token stored in context
func getUserIDFromToken(c *fiber.Ctx) (uuid.UUID, error) {
	userID, ok := c.Locals("user_id").(uuid.UUID)
	if !ok {
		return uuid.Nil, fmt.Errorf("user ID not found in context")
	}
	return userID, nil
}

func RequireRole(db Database, role string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		v := c.Locals("user_id")
		if v == nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
		}
		var uid uuid.UUID
		switch t := v.(type) {
		case uuid.UUID:
			uid = t
		case string:
			parsed, err := uuid.Parse(t)
			if err != nil {
				return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Forbidden"})
			}
			uid = parsed
		default:
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Forbidden"})
		}
		if !HasRole(c.Context(), db, uid, role) {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Forbidden"})
		}
		return c.Next()
	}
}

// helper: return nil if sql.NullTime is invalid
func nilIfInvalid(t sql.NullTime) any {
	if t.Valid {
		return t.Time
	}
	return nil
}

// min returns the smaller of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// max returns the larger of two integers
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// clientIP returns the best-effort client address, honoring common proxy headers.
func clientIP(c *fiber.Ctx) string {
	if !trustProxyHeaders.Load() {
		return c.IP()
	}
	if cf := strings.TrimSpace(c.Get("CF-Connecting-IP")); cf != "" {
		if ip := net.ParseIP(cf); ip != nil {
			return cf
		}
	}
	if forwarded := c.Get("X-Forwarded-For"); forwarded != "" {
		var fallback string
		for _, part := range strings.Split(forwarded, ",") {
			ip := strings.TrimSpace(part)
			if ip == "" || strings.ToLower(ip) == "unknown" {
				continue
			}
			parsed := net.ParseIP(ip)
			if parsed == nil {
				continue
			}
			if isPublicIP(parsed) {
				return ip
			}
			if fallback == "" {
				fallback = ip
			}
		}
		if fallback != "" {
			return fallback
		}
	}
	if realIP := strings.TrimSpace(c.Get("X-Real-IP")); realIP != "" {
		if ip := net.ParseIP(realIP); ip != nil {
			return realIP
		}
	}
	if clientIPHeader := strings.TrimSpace(c.Get("X-Client-IP")); clientIPHeader != "" {
		if ip := net.ParseIP(clientIPHeader); ip != nil {
			return clientIPHeader
		}
	}
	return c.IP()
}

func isPublicIP(ip net.IP) bool {
	if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
		return false
	}
	for _, block := range privateIPBlocks {
		if block.Contains(ip) {
			return false
		}
	}
	return true
}

// normalizeIPForRateLimit normalizes IP addresses for rate limiting
// If using subnet mode, converts to network address. Also handles trusted IPs.
func (h *AuthHandler) normalizeIPForRateLimit(ipAddr string) (string, bool) {
	// Check if IP is in trusted ranges first
	if h.isIPTrusted(ipAddr) {
		return "", true // Return empty string to bypass rate limiting
	}

	if !h.config.RateLimitUseSubnet {
		return ipAddr, false
	}

	// Parse IP address
	ip := net.ParseIP(ipAddr)
	if ip == nil {
		return ipAddr, false // Fallback to original IP if parsing fails
	}

	// For IPv4, use /24 subnet (class C network)
	if ip4 := ip.To4(); ip4 != nil {
		mask := net.CIDRMask(24, 32)
		network := ip4.Mask(mask)
		return network.String(), false
	}

	// For IPv6, use /48 subnet (typical provider allocation)
	if ip.To16() != nil {
		mask := net.CIDRMask(48, 128)
		network := ip.Mask(mask)
		return network.String(), false
	}

	return ipAddr, false
}

// isIPTrusted checks if an IP address is in the trusted ranges
func (h *AuthHandler) isIPTrusted(ipAddr string) bool {
	if len(h.config.TrustedIPRanges) == 0 {
		return false
	}

	ip := net.ParseIP(ipAddr)
	if ip == nil {
		return false
	}

	for _, cidr := range h.config.TrustedIPRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// calculateProgressiveDelay calculates delay based on attempt count
func (h *AuthHandler) calculateProgressiveDelay(attempts int) time.Duration {
	if attempts <= 3 {
		return 0 // No delay for first 3 attempts
	}

	var delaySeconds int
	switch {
	case attempts <= 5:
		delaySeconds = 1
	case attempts <= 7:
		delaySeconds = 2
	case attempts <= 9:
		delaySeconds = 5
	case attempts <= 12:
		delaySeconds = 10
	case attempts <= 15:
		delaySeconds = 30
	default:
		delaySeconds = h.config.MaxDelaySeconds
	}

	// Cap at max delay
	if delaySeconds > h.config.MaxDelaySeconds {
		delaySeconds = h.config.MaxDelaySeconds
	}

	return time.Duration(delaySeconds) * time.Second
}

// getProgressiveDelay gets the current progressive delay for an IP
func (h *AuthHandler) getProgressiveDelay(ctx context.Context, ipAddr string) (time.Duration, error) {
	if h.config.RateLimitMode == "disabled" || !h.config.IPRateLimitEnabled {
		return 0, nil
	}

	normalizedIP, isTrusted := h.normalizeIPForRateLimit(ipAddr)
	if isTrusted {
		return 0, nil // Trusted IPs bypass rate limiting
	}

	key := "rate_limit:attempts:" + normalizedIP
	count, err := h.redis.Get(ctx, key).Int()
	if err != nil && err.Error() != "redis: nil" {
		return 0, err
	}

	return h.calculateProgressiveDelay(count), nil
}

// incrementProgressiveAttempts increments the attempt count for progressive rate limiting
func (h *AuthHandler) incrementProgressiveAttempts(ctx context.Context, ipAddr string) error {
	if h.config.RateLimitMode == "disabled" || !h.config.IPRateLimitEnabled {
		return nil
	}

	normalizedIP, isTrusted := h.normalizeIPForRateLimit(ipAddr)
	if isTrusted {
		return nil // Trusted IPs bypass rate limiting
	}

	key := "rate_limit:attempts:" + normalizedIP
	count, err := h.redis.Incr(ctx, key).Result()
	if err != nil {
		return err
	}

	// Set expiration on first attempt (will be extended by decay process)
	if count == 1 {
		decayTime := time.Duration(h.config.RateLimitDecayMinutes) * time.Minute
		expireTime := decayTime * 20 // Give enough time for multiple decay cycles
		h.redis.Expire(ctx, key, expireTime)
	}

	return nil
}

// resetProgressiveAttempts resets the attempt count for an IP
func (h *AuthHandler) resetProgressiveAttempts(ctx context.Context, ipAddr string) error {
	if h.config.RateLimitMode == "disabled" || !h.config.IPRateLimitEnabled {
		return nil
	}

	normalizedIP, isTrusted := h.normalizeIPForRateLimit(ipAddr)
	if isTrusted {
		return nil
	}

	key := "rate_limit:attempts:" + normalizedIP
	return h.redis.Del(ctx, key).Err()
}

// startRateLimitDecayProcess starts a background process to decay rate limit attempts
func (h *AuthHandler) startRateLimitDecayProcess() {
	if h.config.RateLimitMode == "disabled" || !h.config.IPRateLimitEnabled {
		return
	}

	go func() {
		ticker := time.NewTicker(time.Duration(h.config.RateLimitDecayMinutes) * time.Minute)
		defer ticker.Stop()

		for range ticker.C {
			h.decayRateLimitAttempts()
		}
	}()
}

// decayRateLimitAttempts reduces attempt counts for all IPs by 1 (minimum 0)
func (h *AuthHandler) decayRateLimitAttempts() {
	ctx := context.Background()
	pattern := "rate_limit:attempts:*"

	// Use SCAN to iterate through all rate limit keys
	iter := h.redis.Scan(ctx, 0, pattern, 100).Iterator()
	for iter.Next(ctx) {
		key := iter.Val()

		// Get current count
		count, err := h.redis.Get(ctx, key).Int()
		if err != nil {
			continue // Key might have expired or been deleted
		}

		// Decay the count by 1, minimum 0
		newCount := count - 1
		if newCount <= 0 {
			// Remove key entirely if count reaches 0
			h.redis.Del(ctx, key)
		} else {
			// Update with decayed count and refresh expiration
			h.redis.Set(ctx, key, newCount, time.Duration(h.config.RateLimitDecayMinutes)*time.Minute*20)
		}
	}

	if err := iter.Err(); err != nil {
		log.Printf("Error during rate limit decay process: %v", err)
	}
}

func csvEscape(s string) string {
	// Escape quotes and wrap in quotes if needed
	if strings.ContainsAny(s, ",\n\r\"") {
		s = strings.ReplaceAll(s, "\"", "\"\"")
		return "\"" + s + "\""
	}
	return s
}

func formatNullTime(t sql.NullTime) string {
	if t.Valid {
		return t.Time.Format(time.RFC3339)
	}
	return ""
}

func NewCryptoService(key []byte) *CryptoService {
	return &CryptoService{serverKey: key}
}

// prewarmRedisPool pre-warms the Redis connection pool
func prewarmRedisPool(rdb *redis.Client) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	// Ping Redis to establish connections
	if err := rdb.Ping(ctx).Err(); err != nil {
		log.Printf("Warning: Redis pool pre-warm failed: %v", err)
		return
	}
	
	// Do a simple operation to warm up the connection
	rdb.Set(ctx, "startup:prewarm", time.Now().Unix(), time.Second)
	rdb.Del(ctx, "startup:prewarm")
}

// createFiberApp creates and configures the Fiber application
func createFiberApp(startTime time.Time, readyState *ReadyState) *fiber.App {
	app := fiber.New(fiber.Config{
		DisableStartupMessage: false,
		BodyLimit:             512 * 1024, // 512KB body size limit
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
				logError("HTTP_ERROR", err,
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
			logError("PANIC RECOVERED", fmt.Errorf("%v", e),
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
		Output: InfoLogger.Writer(),
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
			if err := readyState.db.QueryRow(ctx, "SELECT COUNT(*) FROM users").Scan(&userCount); err != nil {
				health["status"] = "unhealthy"
				health["error"] = "database check failed"
				return c.Status(503).JSON(health)
			}

			// Quick Redis health check
			if err := readyState.rdb.Ping(ctx).Err(); err != nil {
				health["status"] = "unhealthy"
				health["error"] = "redis check failed"
				return c.Status(503).JSON(health)
			}

			health["status"] = "ready"
			return c.JSON(health)
		} else {
			// Still initializing
			health["status"] = "initializing"
			health["admin_ready"] = readyState.adminReady.Load()
			health["templates_ready"] = readyState.templatesReady.Load()
			health["allowlist_ready"] = readyState.allowlistReady.Load()
			health["redis_ready"] = readyState.redisReady.Load()
			return c.Status(503).JSON(health)
		}
	})

	return app
}

// setupRoutes configures all middleware and routes for the Fiber app
func setupRoutes(app *fiber.App, db *pgxpool.Pool, rdb *redis.Client, crypto *CryptoService, config *Config, startTime time.Time, readyState *ReadyState) {
	// Security headers
	app.Use(helmet.New(helmet.Config{
		XSSProtection:      "1; mode=block",
		ContentTypeNosniff: "nosniff",
		XFrameOptions:      "DENY",
		HSTSMaxAge:         31536000,
		HSTSPreloadEnabled: true,
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

	// CSRF Protection
	app.Use(csrf.New(csrf.Config{
		KeyLookup:      "header:X-CSRF-Token",
		CookieName:     "csrf_token",
		CookieSameSite: "Strict",
		CookieSecure:   true,
		CookieHTTPOnly: true,
		Expiration:     1 * time.Hour,
		KeyGenerator:   uuid.NewString,
		ContextKey:     "csrf",
		Next: func(c *fiber.Ctx) bool {
			// Skip CSRF for safe methods, health endpoints, and auth endpoints
			method := c.Method()
			path := c.Path()
			return method == "GET" || method == "HEAD" || method == "OPTIONS" ||
				strings.HasPrefix(path, "/api/v1/health") ||
				strings.HasPrefix(path, "/api/v1/ready") ||
				strings.HasPrefix(path, "/api/v1/auth/")
		},
	}))

	// CORS
	app.Use(cors.New(cors.Config{
		AllowOrigins:     strings.Join(config.AllowedOrigins, ","),
		AllowCredentials: true,
		AllowHeaders:     "Origin, Content-Type, Accept, Authorization, X-CSRF-Token",
		AllowMethods:     "GET, POST, PUT, DELETE, OPTIONS",
		ExposeHeaders:    "X-CSRF-Token",
	}))

	// Prometheus metrics (if enabled)
	if os.Getenv("ENABLE_METRICS") != "false" {
		app.Use(PrometheusMiddleware())
	}

	// Rate limiting
	app.Use(limiter.New(limiter.Config{
		Max:        100,
		Expiration: 1 * time.Minute,
		KeyGenerator: func(c *fiber.Ctx) string {
			return clientIP(c)
		},
	}))

	// Initialize handlers
	authHandler := &AuthHandler{
		db:     db,
		redis:  rdb,
		crypto: crypto,
		config: config,
	}

	// Start background rate limit decay process
	authHandler.startRateLimitDecayProcess()

	// API routes
	api := app.Group("/api/v1")

	// Registration rate limiting when not running locally
	if env := strings.ToLower(strings.TrimSpace(config.Environment)); env != "development" && env != "local" {
		regLimiter := limiter.New(limiter.Config{
			Max:        5,
			Expiration: 1 * time.Minute,
			KeyGenerator: func(c *fiber.Ctx) string {
				return clientIP(c)
			},
		})
		api.Post("/auth/register", regLimiter, authHandler.Register)
	} else {
		api.Post("/auth/register", authHandler.Register)
	}

	// Public authentication routes
	api.Post("/auth/login", authHandler.Login)
	api.Post("/auth/admin-recovery", authHandler.AdminRecovery)

	// Public registration status endpoint
	api.Get("/auth/registration", func(c *fiber.Ctx) error {
		// Refresh runtime toggle from DB if present
		var dbVal string
		if err := db.QueryRow(c.Context(), `SELECT value FROM app_settings WHERE key='registration_enabled'`).Scan(&dbVal); err == nil {
			if strings.ToLower(strings.TrimSpace(dbVal)) == "true" {
				regEnabled.Store(1)
			} else {
				regEnabled.Store(0)
			}
		}
		return c.JSON(fiber.Map{"enabled": regEnabled.Load() == 1})
	})

	// Enhanced health check endpoint (original endpoint for backwards compatibility)
	api.Get("/health", func(c *fiber.Ctx) error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		health := fiber.Map{
			"status":    "healthy",
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"version":   "1.0.0",
			"uptime":    time.Since(startTime).String(),
		}

		// Database health check
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

		// Redis health check
		redisHealthy := true
		if err := rdb.Ping(ctx).Err(); err != nil {
			redisHealthy = false
			health["redis"] = "unhealthy"
			health["redis_error"] = err.Error()
		} else {
			health["redis"] = "healthy"
		}

		// Overall status
		if !dbHealthy || !redisHealthy {
			health["status"] = "unhealthy"
			return c.Status(503).JSON(health)
		}

		return c.JSON(health)
	})

	// Continue with all other route setup...
	// This would include all the remaining routes from the original main function
}

func (c *CryptoService) Encrypt(plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(c.serverKey[:32])
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := aead.Seal(nil, nonce, plaintext, nil)
	return append(nonce, ciphertext...), nil
}

func (c *CryptoService) Decrypt(ciphertext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(c.serverKey[:32])
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aead.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce := ciphertext[:aead.NonceSize()]
	ciphertext = ciphertext[aead.NonceSize():]

	return aead.Open(nil, nonce, ciphertext, nil)
}

func (c *CryptoService) EncryptDeterministic(plaintext []byte, context string) ([]byte, error) {
	h := sha256.New()
	h.Write(c.serverKey[:32])
	h.Write([]byte(context))
	h.Write(plaintext)
	deterministicKey := h.Sum(nil)[:32]

	aead, err := chacha20poly1305.NewX(deterministicKey)
	if err != nil {
		return nil, err
	}

	h2 := sha256.New()
	h2.Write(deterministicKey)
	h2.Write(plaintext)
	nonce := h2.Sum(nil)[:aead.NonceSize()]

	return aead.Seal(nil, nonce, plaintext, nil), nil
}

func (c *CryptoService) DecryptDeterministic(ciphertext []byte, context string, expectedPlaintext []byte) ([]byte, error) {
	h := sha256.New()
	h.Write(c.serverKey[:32])
	h.Write([]byte(context))
	h.Write(expectedPlaintext)
	deterministicKey := h.Sum(nil)[:32]

	aead, err := chacha20poly1305.NewX(deterministicKey)
	if err != nil {
		return nil, err
	}

	h2 := sha256.New()
	h2.Write(deterministicKey)
	h2.Write(expectedPlaintext)
	nonce := h2.Sum(nil)[:aead.NonceSize()]

	return aead.Open(nil, nonce, ciphertext, nil)
}

func (c *CryptoService) EncryptWithKeyDerivation(plaintext []byte, keyType string) ([]byte, error) {
	h := sha256.New()
	h.Write(c.serverKey[:32])
	h.Write([]byte("field:" + keyType))
	fieldKey := h.Sum(nil)[:32]

	aead, err := chacha20poly1305.NewX(fieldKey)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, nil)
	return append(nonce, ciphertext...), nil
}

func (c *CryptoService) DecryptWithKeyDerivation(ciphertext []byte, keyType string) ([]byte, error) {
	h := sha256.New()
	h.Write(c.serverKey[:32])
	h.Write([]byte("field:" + keyType))
	fieldKey := h.Sum(nil)[:32]

	aead, err := chacha20poly1305.NewX(fieldKey)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < aead.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce := ciphertext[:aead.NonceSize()]
	ciphertext = ciphertext[aead.NonceSize():]
	return aead.Open(nil, nonce, ciphertext, nil)
}

func (c *CryptoService) EncryptWithGDPRKey(plaintext []byte, deletionKey []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(deletionKey)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, nil)
	return append(nonce, ciphertext...), nil
}

func (c *CryptoService) DecryptWithGDPRKey(ciphertext []byte, deletionKey []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(deletionKey)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < aead.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce := ciphertext[:aead.NonceSize()]
	ciphertext = ciphertext[aead.NonceSize():]
	return aead.Open(nil, nonce, ciphertext, nil)
}

func (c *CryptoService) HashEmail(email string) []byte {
	h := sha256.New()
	h.Write([]byte(strings.ToLower(email)))
	return h.Sum(nil)
}

// Secure password hashing with Argon2id
func HashPassword(password string, salt []byte) string {
	hash := argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, 32)
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, 64*1024, 3, 4, b64Salt, b64Hash)
}

func VerifyPassword(password, encodedHash string) bool {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return false
	}

	salt, _ := base64.RawStdEncoding.DecodeString(parts[4])
	hash, _ := base64.RawStdEncoding.DecodeString(parts[5])

	comparisonHash := argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, 32)
	return subtle.ConstantTimeCompare(hash, comparisonHash) == 1
}

// Database setup and migration runner with caching and optimization
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

	// Configure connection pool optimized for fast startup and production workloads
	config.MaxConns = 15                       // Reduced max connections for faster startup
	config.MinConns = 2                        // Reduced min connections for faster startup
	config.MaxConnLifetime = 2 * time.Hour     // Longer lifetime to reduce churn
	config.MaxConnIdleTime = 45 * time.Minute  // Longer idle time to reduce connection recycling
	config.HealthCheckPeriod = 2 * time.Minute // Less frequent health checks for startup performance

	// Optimize connection parameters for performance
	config.ConnConfig.ConnectTimeout = 5 * time.Second  // Faster timeout for startup
	config.ConnConfig.RuntimeParams["jit"] = "off" // Disable JIT for faster startup
	
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
	config.MaxConns = 5                        // Minimal connections for startup
	config.MinConns = 1                        // Single connection to start
	config.MaxConnLifetime = 1 * time.Hour     
	config.MaxConnIdleTime = 30 * time.Minute  
	config.HealthCheckPeriod = 5 * time.Minute 

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

// Migration tracking and optimization functions
const MigrationSchemaVersion = "2024.12.25.002" // Updated for performance optimizations

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
	defer tx.Rollback(ctx)

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

// Build an admin URL pointing to the 'postgres' database and return the target db name.
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

var identRe = regexp.MustCompile(`^[a-zA-Z0-9_]+$`)

// Quote/validate identifier safely for CREATE DATABASE
func safePgIdent(name string) (string, bool) {
	if identRe.MatchString(name) {
		return name, true
	}
	return "", false
}

// Database interface for dependency injection and testing
type Database interface {
	QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row
	Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error)
	Exec(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error)
	Begin(ctx context.Context) (pgx.Tx, error)
}

// Auth handlers
type AuthHandler struct {
	db     Database
	redis  *redis.Client
	crypto *CryptoService
	config *Config
}

// Session data structure for Redis storage
type SessionData struct {
	UserID    string    `json:"user_id"`
	IPAddress string    `json:"ip_address"`
	UserAgent string    `json:"user_agent"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Store session in Redis with encrypted metadata
func (h *AuthHandler) storeSessionInRedis(ctx context.Context, tokenHash []byte, userID uuid.UUID, ipAddr, userAgent string, expiresAt time.Time) error {
	sessionData := SessionData{
		UserID:    userID.String(),
		IPAddress: ipAddr,
		UserAgent: userAgent,
		CreatedAt: time.Now(),
		ExpiresAt: expiresAt,
	}

	// Serialize session data
	data, err := json.Marshal(sessionData)
	if err != nil {
		return fmt.Errorf("failed to marshal session data: %w", err)
	}

	// Encrypt session data
	encryptedData, err := h.crypto.Encrypt(data)
	if err != nil {
		return fmt.Errorf("failed to encrypt session data: %w", err)
	}

	// Store in Redis with expiration
	sessionKey := fmt.Sprintf("session:%x", tokenHash)
	duration := time.Until(expiresAt)

	return h.redis.Set(ctx, sessionKey, encryptedData, duration).Err()
}

// Validate session from Redis
func (h *AuthHandler) validateSessionInRedis(ctx context.Context, tokenHash []byte) (*SessionData, error) {
	sessionKey := fmt.Sprintf("session:%x", tokenHash)

	// Get encrypted session data from Redis
	encryptedData, err := h.redis.Get(ctx, sessionKey).Bytes()
	if err != nil {
		if err.Error() == "redis: nil" {
			return nil, fmt.Errorf("session not found")
		}
		return nil, fmt.Errorf("failed to get session from Redis: %w", err)
	}

	// Decrypt session data
	data, err := h.crypto.Decrypt(encryptedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt session data: %w", err)
	}

	// Deserialize session data
	var sessionData SessionData
	if err := json.Unmarshal(data, &sessionData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal session data: %w", err)
	}

	// Check if session is expired
	if time.Now().After(sessionData.ExpiresAt) {
		// Delete expired session
		h.redis.Del(ctx, sessionKey)
		return nil, fmt.Errorf("session expired")
	}

	return &sessionData, nil
}

// Delete session from Redis
func (h *AuthHandler) deleteSessionFromRedis(ctx context.Context, tokenHash []byte) error {
	sessionKey := fmt.Sprintf("session:%x", tokenHash)
	return h.redis.Del(ctx, sessionKey).Err()
}

type RegisterRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=12"`
}

type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
	MFACode  string `json:"mfa_code,omitempty"`
}

type AdminRecoveryRequest struct {
	Email           string `json:"email" validate:"required,email"`
	Password        string `json:"password" validate:"required,min=12"`
	RecoveryToken   string `json:"recovery_token" validate:"required"`
	ConfirmDeletion bool   `json:"confirm_deletion"`
}

// Register godoc
// @Summary Register a new user
// @Description Register a new user with email and password
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body RegisterRequest true "Registration data"
// @Success 201 {object} map[string]interface{} "User registered successfully"
// @Failure 400 {object} map[string]interface{} "Invalid request"
// @Failure 409 {object} map[string]interface{} "Email already exists"
// @Failure 503 {object} map[string]interface{} "Registration disabled"
// @Router /auth/register [post]
func (h *AuthHandler) Register(c *fiber.Ctx) error {
	// Check if registration is enabled (runtime toggle)
	if regEnabled.Load() != 1 {
		return c.Status(403).JSON(fiber.Map{"error": "Registration is currently disabled"})
	}

	var req RegisterRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
	}

	// Validate password requirements
	if len(req.Password) < 12 {
		return c.Status(400).JSON(fiber.Map{"error": "Password must be at least 12 characters long"})
	}

	// Generate salt and hash password
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to generate credentials"})
	}
	passwordHash := HashPassword(req.Password, salt)

	// Generate user's master encryption key
	masterKey := make([]byte, 32)
	if _, err := rand.Read(masterKey); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to generate credentials"})
	}

	// Derive key from password to encrypt master key
	userKey := argon2.IDKey([]byte(req.Password), salt, 1, 64*1024, 4, 32)

	// Encrypt master key with user's derived key
	aead, err := chacha20poly1305.NewX(userKey)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to initialize encryption"})
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to initialize encryption"})
	}
	encryptedMasterKey := aead.Seal(nonce, nonce, masterKey, nil)

	// Generate GDPR deletion key for email encryption
	deletionKey := make([]byte, 32)
	if _, err := rand.Read(deletionKey); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to generate credentials"})
	}

	// Create email hash for uniqueness and GDPR lookups
	emailHash := h.crypto.HashEmail(req.Email)

	// Encrypt email with GDPR key (allows recovery for deletion requests)
	encryptedEmail, err := h.crypto.EncryptWithGDPRKey([]byte(req.Email), deletionKey)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to protect account data"})
	}

	// Create deterministic email hash for secure login lookups
	emailSearchHash, err := h.crypto.EncryptDeterministic([]byte(strings.ToLower(req.Email)), "email_search")
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to protect account data"})
	}

	// Start transaction
	ctx := context.Background()
	tx, err := h.db.Begin(ctx)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Database error"})
	}
	defer tx.Rollback(ctx)

	// Store GDPR deletion key
	_, err = tx.Exec(ctx, `
        INSERT INTO gdpr_keys (email_hash, deletion_key)
        VALUES ($1, $2)`,
		emailHash, deletionKey,
	)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to setup account security"})
	}

	// Create user
	var userID uuid.UUID
	err = tx.QueryRow(ctx, `
        INSERT INTO users (email_hash, email_encrypted, email_search_hash, password_hash, salt, master_key_encrypted)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING id`,
		emailHash, encryptedEmail, emailSearchHash, passwordHash, salt, encryptedMasterKey,
	).Scan(&userID)

	if err != nil {
		if strings.Contains(err.Error(), "duplicate") {
			return c.Status(409).JSON(fiber.Map{"error": "Email already registered"})
		}
		return c.Status(500).JSON(fiber.Map{"error": "Registration failed"})
	}

	// Create default workspace
	workspaceName, err := h.crypto.Encrypt([]byte("My Workspace"))
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to set up workspace"})
	}
	workspaceKey := make([]byte, 32)
	if _, err := rand.Read(workspaceKey); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to set up workspace"})
	}

	// Encrypt workspace key with user's master key
	encryptedWorkspaceKey, err := h.crypto.Encrypt(workspaceKey)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to set up workspace"})
	}

	var workspaceID uuid.UUID
	err = tx.QueryRow(ctx, `
        INSERT INTO workspaces (name_encrypted, owner_id, encryption_key_encrypted)
        VALUES ($1, $2, $3)
        RETURNING id`,
		workspaceName, userID, encryptedWorkspaceKey,
	).Scan(&workspaceID)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to create workspace"})
	}

	// Commit transaction
	if err = tx.Commit(ctx); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Registration failed"})
	}

	// Log audit event
	h.logAudit(ctx, userID, "user.registered", "user", userID, c)

	// Generate session token
	token, err := h.generateToken(userID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Token generation failed"})
	}

	return c.Status(201).JSON(fiber.Map{
		"message":      "Registration successful",
		"token":        token,
		"user_id":      userID,
		"workspace_id": workspaceID,
	})
}

// Login godoc
// @Summary User login
// @Description Authenticate user with email and password
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body LoginRequest true "Login credentials"
// @Success 200 {object} map[string]interface{} "Login successful"
// @Failure 400 {object} map[string]interface{} "Invalid request"
// @Failure 401 {object} map[string]interface{} "Invalid credentials"
// @Failure 423 {object} map[string]interface{} "MFA required"
// @Router /auth/login [post]
func (h *AuthHandler) Login(c *fiber.Ctx) error {
	// Enhanced debug logging for troubleshooting CORS/request issues
	log.Printf("🔍 Login Request Debug Info:")
	log.Printf("   - Method: %s", c.Method())
	log.Printf("   - Origin: %s", c.Get("Origin"))
	log.Printf("   - Content-Type: %s", c.Get("Content-Type"))
	log.Printf("   - User-Agent: %s", c.Get("User-Agent"))
	log.Printf("   - Content-Length: %s", c.Get("Content-Length"))

	var req LoginRequest
	if err := c.BodyParser(&req); err != nil {
		log.Printf("❌ Body parsing failed: %v", err)
		log.Printf("   - Raw body: %s", c.Body())
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
	}

	// Log parsed request details (without logging full password for security)
	log.Printf("✅ Request parsed successfully:")
	log.Printf("   - Email: %s", req.Email)
	log.Printf("   - Password length: %d", len(req.Password))
	if len(req.Password) > 0 {
		log.Printf("   - Password first char: %c", req.Password[0])
		log.Printf("   - Password last char: %c", req.Password[len(req.Password)-1])
	}
	log.Printf("   - MFA Code present: %t", req.MFACode != "")

	clientIPAddr := clientIP(c)

	// Apply progressive delay based on failed attempts
	delay, err := h.getProgressiveDelay(c.Context(), clientIPAddr)
	if err != nil {
		log.Printf("Error getting progressive delay: %v", err)
		// Continue with login attempt even if rate limiting check fails
	} else if delay > 0 {
		log.Printf("Applying progressive delay of %v for IP %s", delay, clientIPAddr)
		time.Sleep(delay)
	}

	ctx := context.Background()

	// Create deterministic hash for secure email lookup
	emailSearchHash, err := h.crypto.EncryptDeterministic([]byte(strings.ToLower(req.Email)), "email_search")
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Authentication failed"})
	}

	// Get user using deterministic hash
	var userID uuid.UUID
	var passwordHash string
	var failedAttempts int
	var lockedUntil *time.Time
	var mfaEnabled bool
	var mfaSecret []byte

	err = h.db.QueryRow(ctx, `
        SELECT id, password_hash, failed_attempts, locked_until, mfa_enabled, mfa_secret_encrypted
        FROM users WHERE email_search_hash = $1`,
		emailSearchHash,
	).Scan(&userID, &passwordHash, &failedAttempts, &lockedUntil, &mfaEnabled, &mfaSecret)

	if err != nil {
		// Increment progressive IP attempts on invalid email
		if ipErr := h.incrementProgressiveAttempts(ctx, clientIPAddr); ipErr != nil {
			log.Printf("Error incrementing progressive attempts: %v", ipErr)
		}
		return c.Status(401).JSON(fiber.Map{"error": "Invalid credentials"})
	}

	// Check if account is locked with detailed time remaining
	if lockedUntil != nil && lockedUntil.After(time.Now()) {
		timeRemaining := time.Until(*lockedUntil)
		minutes := int(timeRemaining.Minutes())
		seconds := int(timeRemaining.Seconds()) % 60

		var timeMessage string
		if minutes > 0 {
			timeMessage = fmt.Sprintf("%d minutes and %d seconds", minutes, seconds)
		} else {
			timeMessage = fmt.Sprintf("%d seconds", seconds)
		}

		return c.Status(423).JSON(fiber.Map{
			"error":               fmt.Sprintf("Account locked due to too many failed login attempts. Please try again in %s.", timeMessage),
			"locked_until":        lockedUntil.Format(time.RFC3339),
			"retry_after_seconds": int(timeRemaining.Seconds()),
		})
	}

	// Debug logging for password verification
	log.Printf("🔍 Login attempt for email: %s", req.Email)
	log.Printf("🔍 Received password length: %d characters", len(req.Password))
	if len(req.Password) > 0 {
		log.Printf("🔍 Password starts with: %c", req.Password[0])
	}

	// Verify password
	if !VerifyPassword(req.Password, passwordHash) {
		// Also increment progressive IP attempts
		if err := h.incrementProgressiveAttempts(ctx, clientIPAddr); err != nil {
			log.Printf("Error incrementing progressive attempts: %v", err)
		}

		// Increment failed attempts
		failedAttempts++

		var lockDuration time.Duration
		if failedAttempts >= 7 {
			lockDuration = 15 * time.Minute
		} else if failedAttempts >= 6 {
			lockDuration = 5 * time.Minute
		} else if failedAttempts >= h.config.MaxLoginAttempts {
			lockDuration = 1 * time.Minute
		}

		if lockDuration > 0 {
			lockUntil := time.Now().Add(lockDuration)
			h.db.Exec(ctx, `
                UPDATE users SET failed_attempts = $1, locked_until = $2 
                WHERE id = $3`,
				failedAttempts, lockUntil, userID,
			)
			h.logAudit(ctx, userID, "login.locked", "user", userID, c)

			// Calculate time remaining for the lockout message
			timeRemaining := time.Until(lockUntil)
			minutes := int(timeRemaining.Minutes())
			seconds := int(timeRemaining.Seconds()) % 60

			var timeMessage string
			if minutes > 0 {
				timeMessage = fmt.Sprintf("%d minutes and %d seconds", minutes, seconds)
			} else {
				timeMessage = fmt.Sprintf("%d seconds", seconds)
			}

			return c.Status(423).JSON(fiber.Map{
				"error":               fmt.Sprintf("Account locked due to too many failed login attempts. Please try again in %s.", timeMessage),
				"locked_until":        lockUntil.Format(time.RFC3339),
				"retry_after_seconds": int(timeRemaining.Seconds()),
			})
		}

		h.db.Exec(ctx, `UPDATE users SET failed_attempts = $1 WHERE id = $2`, failedAttempts, userID)
		h.logAudit(ctx, userID, "login.failed", "user", userID, c)

		return c.Status(401).JSON(fiber.Map{"error": "Invalid credentials"})
	}

	// Verify MFA if enabled
	if mfaEnabled {
		if strings.TrimSpace(req.MFACode) == "" {
			return c.Status(200).JSON(fiber.Map{"mfa_required": true})
		}
		if len(mfaSecret) == 0 {
			log.Printf("mfa secret missing for user %s", userID)
			return c.Status(500).JSON(fiber.Map{"error": "MFA validation failed"})
		}
		secretBytes, err := h.crypto.Decrypt(mfaSecret)
		if err != nil {
			log.Printf("failed to decrypt mfa secret for user %s: %v", userID, err)
			return c.Status(500).JSON(fiber.Map{"error": "MFA validation failed"})
		}
		secret := strings.TrimSpace(string(secretBytes))
		code := strings.TrimSpace(req.MFACode)
		if secret == "" {
			log.Printf("empty mfa secret for user %s", userID)
			return c.Status(500).JSON(fiber.Map{"error": "MFA validation failed"})
		}
		if !totp.Validate(code, secret) {
			h.logAudit(ctx, userID, "login.mfa_failed", "user", userID, c)

			// Also increment progressive IP attempts on failed MFA
			if ipErr := h.incrementProgressiveAttempts(ctx, clientIPAddr); ipErr != nil {
				log.Printf("Error incrementing progressive attempts: %v", ipErr)
			}

			return c.Status(401).JSON(fiber.Map{"error": "Invalid MFA code"})
		}
	}

	// Reset failed attempts and update last login
	h.db.Exec(ctx, `
        UPDATE users SET failed_attempts = 0, locked_until = NULL, last_login = NOW()
        WHERE id = $1`,
		userID,
	)

	// Reset progressive IP attempts on successful login
	if err := h.resetProgressiveAttempts(ctx, clientIPAddr); err != nil {
		log.Printf("Error resetting progressive attempts: %v", err)
	}

	// Generate session
	sessionToken := make([]byte, 32)
	if _, err := rand.Read(sessionToken); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Session creation failed"})
	}
	sessionTokenStr := hex.EncodeToString(sessionToken)

	// Hash token for storage
	tokenHash := argon2.IDKey(sessionToken, []byte("session"), 1, 64*1024, 4, 32)

	// Store session in Redis
	expiresAt := time.Now().Add(h.config.SessionDuration)
	err = h.storeSessionInRedis(ctx, tokenHash, userID, clientIP(c), c.Get("User-Agent"), expiresAt)
	if err != nil {
		log.Printf("Failed to store session in Redis: %v", err)
		return c.Status(500).JSON(fiber.Map{"error": "Session creation failed"})
	}

	// Log successful login
	h.logAudit(ctx, userID, "login.success", "user", userID, c)

	// Generate JWT token
	token, err := h.generateToken(userID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Token generation failed"})
	}

	// Get workspace
	var workspaceID uuid.UUID
	h.db.QueryRow(ctx, `SELECT id FROM workspaces WHERE owner_id = $1 LIMIT 1`, userID).Scan(&workspaceID)

	return c.JSON(fiber.Map{
		"token":        token,
		"session":      sessionTokenStr,
		"user_id":      userID,
		"workspace_id": workspaceID,
	})
}

func (h *AuthHandler) AdminRecovery(c *fiber.Ctx) error {
	log.Println("🚨 Admin Recovery Request - Starting emergency admin recovery process")

	var req AdminRecoveryRequest
	if err := c.BodyParser(&req); err != nil {
		log.Printf("❌ Admin recovery body parsing failed: %v", err)
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
	}

	// Validate request
	if req.Email == "" {
		return c.Status(400).JSON(fiber.Map{"error": "Email is required"})
	}
	if len(req.Password) < 12 {
		return c.Status(400).JSON(fiber.Map{"error": "Password must be at least 12 characters long"})
	}
	if req.RecoveryToken == "" {
		return c.Status(400).JSON(fiber.Map{"error": "Recovery token is required"})
	}

	log.Printf("📧 Admin recovery for email: %s", req.Email)

	// Generate and validate recovery token
	expectedToken := h.generateRecoveryToken(req.Email)
	if req.RecoveryToken != expectedToken {
		log.Printf("❌ Invalid recovery token provided")
		return c.Status(401).JSON(fiber.Map{"error": "Invalid recovery token"})
	}

	// Only allow recovery for admin email
	if req.Email != h.config.DefaultAdminEmail {
		log.Printf("❌ Recovery attempted for non-admin email: %s", req.Email)
		return c.Status(403).JSON(fiber.Map{"error": "Recovery only allowed for default admin account"})
	}

	ctx := context.Background()

	// Check if this is a key mismatch situation
	oldEmailSearchHash, err := h.findExistingUserWithDifferentKey(ctx, req.Email)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		log.Printf("❌ Error checking for existing user: %v", err)
		return c.Status(500).JSON(fiber.Map{"error": "Recovery check failed"})
	}

	var userFound bool
	var existingUserID uuid.UUID

	if oldEmailSearchHash != "" {
		userFound = true
		log.Printf("🔍 Found existing admin user with old encryption key")

		// Get the user ID
		err = h.db.QueryRow(ctx, `SELECT id FROM users WHERE email_search_hash = $1`, oldEmailSearchHash).Scan(&existingUserID)
		if err != nil {
			log.Printf("❌ Error getting user ID: %v", err)
			return c.Status(500).JSON(fiber.Map{"error": "Recovery failed"})
		}
	}

	if userFound && !req.ConfirmDeletion {
		return c.JSON(fiber.Map{
			"status":          "confirmation_required",
			"message":         "An admin user exists but is unreachable due to encryption key mismatch. Continuing will delete the old user and create a new one.",
			"user_id":         existingUserID,
			"action_required": "Set confirm_deletion to true to proceed",
		})
	}

	// Begin transaction
	tx, err := h.db.Begin(ctx)
	if err != nil {
		log.Printf("❌ Failed to start recovery transaction: %v", err)
		return c.Status(500).JSON(fiber.Map{"error": "Recovery failed"})
	}
	defer tx.Rollback(ctx)

	// If user exists, delete them and all related data
	if userFound {
		log.Printf("🗑️ Deleting existing admin user and related data...")

		// Delete related data first (to avoid foreign key constraints)
		tables := []string{
			"notes", "tags", "folders", "templates", "note_tags", "attachments",
			"shared_notes", "user_sessions", "audit_logs", "password_reset_tokens",
			"gdpr_keys",
		}

		for _, table := range tables {
			_, err = tx.Exec(ctx, fmt.Sprintf("DELETE FROM %s WHERE user_id = $1", table), existingUserID)
			if err != nil {
				log.Printf("⚠️ Error deleting from %s: %v", table, err)
				// Continue with other tables
			}
		}

		// Delete the user
		_, err = tx.Exec(ctx, "DELETE FROM users WHERE id = $1", existingUserID)
		if err != nil {
			log.Printf("❌ Error deleting user: %v", err)
			return c.Status(500).JSON(fiber.Map{"error": "Failed to delete existing user"})
		}

		log.Printf("✅ Deleted existing admin user and all related data")
	}

	// Create new admin user with current encryption key
	log.Printf("👤 Creating new admin user with current encryption key...")

	// Generate salt for password hashing
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		log.Printf("❌ Failed to generate salt: %v", err)
		return c.Status(500).JSON(fiber.Map{"error": "Recovery failed"})
	}

	// Hash password with Argon2id
	passwordHash := HashPassword(req.Password, salt)

	// Generate user's master encryption key
	masterKey := make([]byte, 32)
	if _, err := rand.Read(masterKey); err != nil {
		log.Printf("❌ Failed to generate master key: %v", err)
		return c.Status(500).JSON(fiber.Map{"error": "Recovery failed"})
	}

	// Derive key from password to encrypt master key
	userKey := argon2.IDKey([]byte(req.Password), salt, 1, 64*1024, 4, 32)

	// Encrypt master key with user's derived key
	aead, err := chacha20poly1305.NewX(userKey)
	if err != nil {
		log.Printf("❌ Failed to initialize encryption: %v", err)
		return c.Status(500).JSON(fiber.Map{"error": "Recovery failed"})
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		log.Printf("❌ Failed to generate nonce: %v", err)
		return c.Status(500).JSON(fiber.Map{"error": "Recovery failed"})
	}

	masterKeyEncrypted := aead.Seal(nonce, nonce, masterKey, nil)

	// Generate GDPR deletion key for email encryption
	deletionKey := make([]byte, 32)
	if _, err := rand.Read(deletionKey); err != nil {
		log.Printf("❌ Failed to generate GDPR deletion key: %v", err)
		return c.Status(500).JSON(fiber.Map{"error": "Recovery failed"})
	}

	// Create email hash for uniqueness and GDPR lookups
	emailHash := h.crypto.HashEmail(req.Email)

	// Encrypt email with GDPR key
	emailEncrypted, err := h.crypto.EncryptWithGDPRKey([]byte(req.Email), deletionKey)
	if err != nil {
		log.Printf("❌ Failed to encrypt email: %v", err)
		return c.Status(500).JSON(fiber.Map{"error": "Recovery failed"})
	}

	// Create deterministic email hash for secure login lookups (with CURRENT key)
	emailSearchHash, err := h.crypto.EncryptDeterministic([]byte(strings.ToLower(req.Email)), "email_search")
	if err != nil {
		log.Printf("❌ Failed to create email search hash: %v", err)
		return c.Status(500).JSON(fiber.Map{"error": "Recovery failed"})
	}

	// Store GDPR deletion key
	_, err = tx.Exec(ctx, `
		INSERT INTO gdpr_keys (email_hash, deletion_key)
		VALUES ($1, $2)`,
		emailHash, deletionKey,
	)
	if err != nil {
		log.Printf("❌ Failed to store GDPR key: %v", err)
		return c.Status(500).JSON(fiber.Map{"error": "Recovery failed"})
	}

	// Create new user
	newUserID := uuid.New()
	workspaceID := uuid.New()

	_, err = tx.Exec(ctx, `
		INSERT INTO users (
			id, email_encrypted, email_search_hash, password_hash,
			master_key_encrypted, workspace_id, created_at, updated_at,
			failed_attempts, locked_until, mfa_enabled
		) VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW(), 0, NULL, false)`,
		newUserID, emailEncrypted, emailSearchHash, passwordHash,
		masterKeyEncrypted, workspaceID,
	)
	if err != nil {
		log.Printf("❌ Failed to create new admin user: %v", err)
		return c.Status(500).JSON(fiber.Map{"error": "Recovery failed"})
	}

	// Commit transaction
	if err = tx.Commit(ctx); err != nil {
		log.Printf("❌ Failed to commit recovery transaction: %v", err)
		return c.Status(500).JSON(fiber.Map{"error": "Recovery failed"})
	}

	log.Printf("✅ Admin recovery completed successfully")
	log.Printf("   - New User ID: %s", newUserID)
	log.Printf("   - Workspace ID: %s", workspaceID)
	log.Printf("   - Email: %s", req.Email)

	return c.JSON(fiber.Map{
		"status":       "success",
		"message":      "Admin user recovered successfully",
		"user_id":      newUserID,
		"workspace_id": workspaceID,
		"instructions": "You can now login with the provided credentials",
	})
}

func (h *AuthHandler) generateRecoveryToken(email string) string {
	// Generate recovery token based on current server encryption key and email
	// This ensures only someone with access to the server config can generate valid tokens
	data := fmt.Sprintf("%s:%s:%s", email, h.config.EncryptionKey, "admin_recovery")
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("recovery_%x", hash[:16]) // First 16 bytes as hex
}

func (h *AuthHandler) findExistingUserWithDifferentKey(ctx context.Context, email string) (string, error) {
	// Try to find users with the same email but different email_search_hash
	// This indicates they were created with a different encryption key

	log.Printf("🔍 Searching for existing admin users that may have key mismatch...")

	var foundHashes [][]byte
	rows, err := h.db.Query(ctx, `
		SELECT DISTINCT email_search_hash
		FROM users
		WHERE LENGTH(email_search_hash) > 0
	`)
	if err != nil {
		return "", err
	}
	defer rows.Close()

	for rows.Next() {
		var hash []byte
		if err := rows.Scan(&hash); err != nil {
			continue
		}
		foundHashes = append(foundHashes, hash)
	}

	log.Printf("🔍 Found %d existing users in database", len(foundHashes))

	// Since we can't decrypt the stored emails to check if they match,
	// we'll assume any existing user might be the admin if there's exactly one user
	// and the current email search hash doesn't match
	currentEmailSearchHash, err := h.crypto.EncryptDeterministic([]byte(strings.ToLower(email)), "email_search")
	if err != nil {
		return "", err
	}

	// Check if current hash exists
	for _, hash := range foundHashes {
		if bytes.Equal(hash, currentEmailSearchHash) {
			log.Printf("🔍 Current email search hash found - no key mismatch")
			return "", sql.ErrNoRows // No mismatch
		}
	}

	// If we have exactly one user and it's not matching current hash, likely key mismatch
	if len(foundHashes) == 1 {
		log.Printf("🔍 Found potential key mismatch - one user exists with different hash")
		return string(foundHashes[0]), nil
	}

	log.Printf("🔍 No clear key mismatch detected")
	return "", sql.ErrNoRows
}

type mfaCodeRequest struct {
	Code string `json:"code"`
}

func (h *AuthHandler) GetMFAStatus(c *fiber.Ctx) error {
	v := c.Locals("user_id")
	uid, ok := v.(uuid.UUID)
	if !ok {
		return c.Status(401).JSON(fiber.Map{"error": "Unauthorized"})
	}
	var enabled bool
	var hasSecret sql.NullBool
	if err := h.db.QueryRow(c.Context(), `SELECT mfa_enabled, mfa_secret_encrypted IS NOT NULL FROM users WHERE id = $1`, uid).
		Scan(&enabled, &hasSecret); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to load MFA status"})
	}
	return c.JSON(fiber.Map{
		"enabled":    enabled,
		"has_secret": hasSecret.Valid && hasSecret.Bool,
	})
}

func (h *AuthHandler) BeginMFASetup(c *fiber.Ctx) error {
	v := c.Locals("user_id")
	uid, ok := v.(uuid.UUID)
	if !ok {
		return c.Status(401).JSON(fiber.Map{"error": "Unauthorized"})
	}
	ctx := c.Context()
	var emailEnc []byte
	var emailHash []byte
	if err := h.db.QueryRow(ctx, `SELECT email_encrypted, email_hash FROM users WHERE id=$1`, uid).Scan(&emailEnc, &emailHash); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Unable to start MFA setup"})
	}

	// Get GDPR key to decrypt email for MFA setup
	var deletionKey []byte
	if err := h.db.QueryRow(ctx, `SELECT deletion_key FROM gdpr_keys WHERE email_hash = $1`, emailHash).Scan(&deletionKey); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Unable to start MFA setup"})
	}

	// Decrypt email for MFA setup
	emailBytes, err := h.crypto.DecryptWithGDPRKey(emailEnc, deletionKey)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Unable to start MFA setup"})
	}
	email := string(emailBytes)
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "LeafLock",
		AccountName: email,
		Period:      30,
		Digits:      otp.DigitsSix,
	})
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to generate MFA secret"})
	}
	secret := key.Secret()
	encryptedSecret, err := h.crypto.Encrypt([]byte(secret))
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to secure MFA secret"})
	}
	if _, err := h.db.Exec(ctx, `UPDATE users SET mfa_secret_encrypted = $1, mfa_enabled = FALSE WHERE id = $2`, encryptedSecret, uid); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to persist MFA secret"})
	}
	h.logAudit(ctx, uid, "mfa.setup_started", "user", uid, c)
	return c.JSON(fiber.Map{
		"secret":      secret,
		"otpauth_url": key.URL(),
		"issuer":      key.Issuer(),
		"account":     key.AccountName(),
	})
}

func (h *AuthHandler) EnableMFA(c *fiber.Ctx) error {
	v := c.Locals("user_id")
	uid, ok := v.(uuid.UUID)
	if !ok {
		return c.Status(401).JSON(fiber.Map{"error": "Unauthorized"})
	}
	var req mfaCodeRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
	}
	code := strings.TrimSpace(req.Code)
	if code == "" {
		return c.Status(400).JSON(fiber.Map{"error": "MFA code required"})
	}
	ctx := c.Context()
	var secretEnc []byte
	if err := h.db.QueryRow(ctx, `SELECT mfa_secret_encrypted FROM users WHERE id = $1`, uid).Scan(&secretEnc); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "MFA secret not initialized"})
	}
	if len(secretEnc) == 0 {
		return c.Status(400).JSON(fiber.Map{"error": "MFA secret not initialized"})
	}
	secretBytes, err := h.crypto.Decrypt(secretEnc)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to access MFA secret"})
	}
	secret := strings.TrimSpace(string(secretBytes))
	if secret == "" {
		return c.Status(500).JSON(fiber.Map{"error": "MFA secret invalid"})
	}
	if !totp.Validate(code, secret) {
		h.logAudit(ctx, uid, "mfa.enable_failed", "user", uid, c)
		return c.Status(401).JSON(fiber.Map{"error": "Invalid MFA code"})
	}
	if _, err := h.db.Exec(ctx, `UPDATE users SET mfa_enabled = TRUE WHERE id = $1`, uid); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to enable MFA"})
	}
	h.logAudit(ctx, uid, "mfa.enabled", "user", uid, c)
	return c.JSON(fiber.Map{"enabled": true})
}

func (h *AuthHandler) DisableMFA(c *fiber.Ctx) error {
	v := c.Locals("user_id")
	uid, ok := v.(uuid.UUID)
	if !ok {
		return c.Status(401).JSON(fiber.Map{"error": "Unauthorized"})
	}
	var req mfaCodeRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
	}
	code := strings.TrimSpace(req.Code)
	if code == "" {
		return c.Status(400).JSON(fiber.Map{"error": "MFA code required"})
	}
	ctx := c.Context()
	var secretEnc []byte
	if err := h.db.QueryRow(ctx, `SELECT mfa_secret_encrypted FROM users WHERE id = $1`, uid).Scan(&secretEnc); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "MFA not enabled"})
	}
	if len(secretEnc) == 0 {
		return c.Status(400).JSON(fiber.Map{"error": "MFA not enabled"})
	}
	secretBytes, err := h.crypto.Decrypt(secretEnc)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to access MFA secret"})
	}
	secret := strings.TrimSpace(string(secretBytes))
	if secret == "" {
		return c.Status(500).JSON(fiber.Map{"error": "MFA secret invalid"})
	}
	if !totp.Validate(code, secret) {
		h.logAudit(ctx, uid, "mfa.disable_failed", "user", uid, c)
		return c.Status(401).JSON(fiber.Map{"error": "Invalid MFA code"})
	}
	if _, err := h.db.Exec(ctx, `UPDATE users SET mfa_enabled = FALSE, mfa_secret_encrypted = NULL WHERE id = $1`, uid); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to disable MFA"})
	}
	h.logAudit(ctx, uid, "mfa.disabled", "user", uid, c)
	return c.JSON(fiber.Map{"enabled": false})
}

func (h *AuthHandler) generateToken(userID uuid.UUID) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID.String(),
		"exp":     time.Now().Add(24 * time.Hour).Unix(),
		"iat":     time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	return token.SignedString(h.config.JWTSecret)
}

func (h *AuthHandler) logAudit(ctx context.Context, userID uuid.UUID, action, resourceType string, resourceID uuid.UUID, c *fiber.Ctx) {
	encryptedIP, err := h.crypto.Encrypt([]byte(clientIP(c)))
	if err != nil {
		log.Printf("failed to encrypt audit log IP: %v", err)
		encryptedIP = nil
	}
	encryptedUA, err := h.crypto.Encrypt([]byte(c.Get("User-Agent")))
	if err != nil {
		log.Printf("failed to encrypt audit log user agent: %v", err)
		encryptedUA = nil
	}

	if _, err := h.db.Exec(ctx, `
        INSERT INTO audit_log (user_id, action, resource_type, resource_id, ip_address_encrypted, user_agent_encrypted)
        VALUES ($1, $2, $3, $4, $5, $6)`,
		userID, action, resourceType, resourceID, encryptedIP, encryptedUA,
	); err != nil {
		log.Printf("failed to write audit log entry: %v", err)
	}
}

// Helper function for audit logging from collaboration handlers
func auditLog(db Database, userID uuid.UUID, action string, metadata fiber.Map) {
	ctx := context.Background()

	// Convert metadata to JSON for storage
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		log.Printf("failed to marshal audit log metadata: %v", err)
		metadataJSON = []byte("{}")
	}

	// Create a simple audit log entry without IP/UA since we don't have the request context
	if _, err := db.Exec(ctx, `
        INSERT INTO audit_log (user_id, action, resource_type, metadata_encrypted)
        VALUES ($1, $2, $3, $4)`,
		userID, action, "collaboration", metadataJSON,
	); err != nil {
		log.Printf("failed to write audit log entry: %v", err)
	}
}

// Notes Handler
type NotesHandler struct {
	db     Database
	crypto *CryptoService
}

type CreateNoteRequest struct {
	TitleEncrypted   string `json:"title_encrypted" validate:"required"`
	ContentEncrypted string `json:"content_encrypted" validate:"required"`
}

type UpdateNoteRequest struct {
	TitleEncrypted   string `json:"title_encrypted" validate:"required"`
	ContentEncrypted string `json:"content_encrypted" validate:"required"`
}

// GetNotes godoc
// @Summary List all notes
// @Description Get all notes for the authenticated user
// @Tags Notes
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "List of notes"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /notes [get]
func (h *NotesHandler) GetNotes(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	ctx := context.Background()

	// Get user's default workspace
	var workspaceID uuid.UUID
	err := h.db.QueryRow(ctx, `SELECT id FROM workspaces WHERE owner_id = $1 LIMIT 1`, userID).Scan(&workspaceID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to get workspace"})
	}

	// Get notes from workspace
	rows, err := h.db.Query(ctx, `
		SELECT id, title_encrypted, content_encrypted, created_at, updated_at
		FROM notes 
		WHERE workspace_id = $1 AND deleted_at IS NULL
		ORDER BY updated_at DESC`,
		workspaceID)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to fetch notes"})
	}
	defer rows.Close()

	notes := []fiber.Map{}
	for rows.Next() {
		var id uuid.UUID
		var titleEnc, contentEnc []byte
		var createdAt, updatedAt time.Time

		if err := rows.Scan(&id, &titleEnc, &contentEnc, &createdAt, &updatedAt); err != nil {
			continue
		}

		notes = append(notes, fiber.Map{
			"id":                id,
			"title_encrypted":   base64.StdEncoding.EncodeToString(titleEnc),
			"content_encrypted": base64.StdEncoding.EncodeToString(contentEnc),
			"created_at":        createdAt,
			"updated_at":        updatedAt,
		})
	}

	return c.JSON(fiber.Map{"notes": notes})
}

func (h *NotesHandler) GetNote(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	noteID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid note ID"})
	}

	ctx := context.Background()
	var id uuid.UUID
	var titleEnc, contentEnc []byte
	var createdAt, updatedAt time.Time

	err = h.db.QueryRow(ctx, `
		SELECT n.id, n.title_encrypted, n.content_encrypted, n.created_at, n.updated_at
		FROM notes n
		JOIN workspaces w ON n.workspace_id = w.id
		WHERE n.id = $1 AND w.owner_id = $2 AND n.deleted_at IS NULL`,
		noteID, userID).Scan(&id, &titleEnc, &contentEnc, &createdAt, &updatedAt)

	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Note not found"})
	}

	return c.JSON(fiber.Map{
		"id":                id,
		"title_encrypted":   base64.StdEncoding.EncodeToString(titleEnc),
		"content_encrypted": base64.StdEncoding.EncodeToString(contentEnc),
		"created_at":        createdAt,
		"updated_at":        updatedAt,
	})
}

func (h *NotesHandler) CreateNote(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	var req CreateNoteRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
	}

	ctx := context.Background()

	// Get user's default workspace
	var workspaceID uuid.UUID
	err := h.db.QueryRow(ctx, `SELECT id FROM workspaces WHERE owner_id = $1 LIMIT 1`, userID).Scan(&workspaceID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to get workspace"})
	}

	// Decode encrypted data
	titleEnc, err := base64.StdEncoding.DecodeString(req.TitleEncrypted)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid title encryption"})
	}

	contentEnc, err := base64.StdEncoding.DecodeString(req.ContentEncrypted)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid content encryption"})
	}

	// Create content hash for integrity
	contentHash := argon2.IDKey(contentEnc, []byte("integrity"), 1, 64*1024, 4, 32)

	// Create note
	var noteID uuid.UUID
	err = h.db.QueryRow(ctx, `
		INSERT INTO notes (workspace_id, title_encrypted, content_encrypted, content_hash, created_by)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id`,
		workspaceID, titleEnc, contentEnc, contentHash, userID).Scan(&noteID)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to create note"})
	}

	// Record metrics
	IncrementNoteOperation("create")
	IncrementDatabaseQuery("insert")

	return c.Status(201).JSON(fiber.Map{
		"id":      noteID,
		"message": "Note created successfully",
	})
}

func (h *NotesHandler) UpdateNote(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	noteID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid note ID"})
	}

	var req UpdateNoteRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
	}

	ctx := context.Background()

	// Decode encrypted data
	titleEnc, err := base64.StdEncoding.DecodeString(req.TitleEncrypted)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid title encryption"})
	}

	contentEnc, err := base64.StdEncoding.DecodeString(req.ContentEncrypted)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid content encryption"})
	}

	// Create content hash for integrity
	contentHash := argon2.IDKey(contentEnc, []byte("integrity"), 1, 64*1024, 4, 32)

	// Start transaction for version history
	tx, err := h.db.Begin(ctx)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Database transaction failed"})
	}
	defer tx.Rollback(ctx)

	// Get current version and content to save as history
	var currentVersion int
	var currentTitle, currentContent, currentHash []byte
	err = tx.QueryRow(ctx, `
		SELECT version, title_encrypted, content_encrypted, content_hash
		FROM notes n
		JOIN workspaces w ON n.workspace_id = w.id
		WHERE n.id = $1 AND w.owner_id = $2 AND n.deleted_at IS NULL`,
		noteID, userID).Scan(&currentVersion, &currentTitle, &currentContent, &currentHash)

	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Note not found"})
	}

	// Save current version to history before updating
	_, err = tx.Exec(ctx, `
		INSERT INTO note_versions (note_id, version_number, title_encrypted, content_encrypted, content_hash, created_by)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		noteID, currentVersion, currentTitle, currentContent, currentHash, userID)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to save version history"})
	}

	// Update note with new content and increment version
	result, err := tx.Exec(ctx, `
		UPDATE notes
		SET title_encrypted = $1, content_encrypted = $2, content_hash = $3, version = version + 1, updated_at = NOW()
		FROM workspaces w
		WHERE notes.id = $4 AND notes.workspace_id = w.id AND w.owner_id = $5 AND notes.deleted_at IS NULL`,
		titleEnc, contentEnc, contentHash, noteID, userID)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to update note"})
	}

	if result.RowsAffected() == 0 {
		return c.Status(404).JSON(fiber.Map{"error": "Note not found"})
	}

	// Commit transaction
	err = tx.Commit(ctx)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to commit version history"})
	}

	// Record metrics
	IncrementNoteOperation("update")
	IncrementDatabaseQuery("update")

	return c.JSON(fiber.Map{"message": "Note updated successfully"})
}

func (h *NotesHandler) DeleteNote(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	noteID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid note ID"})
	}

	ctx := context.Background()

	// Soft delete the note
	result, err := h.db.Exec(ctx, `
		UPDATE notes 
		SET deleted_at = NOW()
		FROM workspaces w
		WHERE notes.id = $1 AND notes.workspace_id = w.id AND w.owner_id = $2 AND notes.deleted_at IS NULL`,
		noteID, userID)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to delete note"})
	}

	if result.RowsAffected() == 0 {
		return c.Status(404).JSON(fiber.Map{"error": "Note not found"})
	}

	// Record metrics
	IncrementNoteOperation("delete")
	IncrementDatabaseQuery("update")

	return c.JSON(fiber.Map{"message": "Note moved to trash successfully"})
}

func (h *NotesHandler) GetTrash(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	ctx := context.Background()

	// Get user's default workspace
	var workspaceID uuid.UUID
	err := h.db.QueryRow(ctx, `SELECT id FROM workspaces WHERE owner_id = $1 LIMIT 1`, userID).Scan(&workspaceID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to get workspace"})
	}

	// Get deleted notes from workspace
	rows, err := h.db.Query(ctx, `
		SELECT id, title_encrypted, content_encrypted, deleted_at, updated_at
		FROM notes 
		WHERE workspace_id = $1 AND deleted_at IS NOT NULL
		ORDER BY deleted_at DESC`,
		workspaceID)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to fetch trash"})
	}
	defer rows.Close()

	trashedNotes := []fiber.Map{}
	for rows.Next() {
		var id uuid.UUID
		var titleEnc, contentEnc []byte
		var deletedAt, updatedAt time.Time

		if err := rows.Scan(&id, &titleEnc, &contentEnc, &deletedAt, &updatedAt); err != nil {
			continue
		}

		trashedNotes = append(trashedNotes, fiber.Map{
			"id":                id,
			"title_encrypted":   base64.StdEncoding.EncodeToString(titleEnc),
			"content_encrypted": base64.StdEncoding.EncodeToString(contentEnc),
			"deleted_at":        deletedAt,
			"updated_at":        updatedAt,
		})
	}

	return c.JSON(fiber.Map{"notes": trashedNotes})
}

func (h *NotesHandler) RestoreNote(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	noteID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid note ID"})
	}

	ctx := context.Background()

	// Restore the note (set deleted_at to NULL)
	result, err := h.db.Exec(ctx, `
		UPDATE notes 
		SET deleted_at = NULL, updated_at = NOW()
		FROM workspaces w
		WHERE notes.id = $1 AND notes.workspace_id = w.id AND w.owner_id = $2 AND notes.deleted_at IS NOT NULL`,
		noteID, userID)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to restore note"})
	}

	if result.RowsAffected() == 0 {
		return c.Status(404).JSON(fiber.Map{"error": "Note not found in trash"})
	}

	return c.JSON(fiber.Map{"message": "Note restored successfully"})
}

// GetNoteVersions returns version history for a note
func (h *NotesHandler) GetNoteVersions(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	noteID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid note ID"})
	}

	ctx := context.Background()

	// Get all versions for the note
	rows, err := h.db.Query(ctx, `
		SELECT nv.id, nv.version_number, nv.created_at, u.email as created_by_email
		FROM note_versions nv
		JOIN notes n ON nv.note_id = n.id
		JOIN workspaces w ON n.workspace_id = w.id
		JOIN users u ON nv.created_by = u.id
		WHERE n.id = $1 AND w.owner_id = $2 AND n.deleted_at IS NULL
		ORDER BY nv.version_number DESC`,
		noteID, userID)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to fetch version history"})
	}
	defer rows.Close()

	var versions []map[string]interface{}
	for rows.Next() {
		var versionID uuid.UUID
		var versionNumber int
		var createdAt time.Time
		var createdByEmail string

		err := rows.Scan(&versionID, &versionNumber, &createdAt, &createdByEmail)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "Failed to read version data"})
		}

		versions = append(versions, map[string]interface{}{
			"id":             versionID.String(),
			"version_number": versionNumber,
			"created_at":     createdAt.Format(time.RFC3339),
			"created_by":     createdByEmail,
		})
	}

	return c.JSON(fiber.Map{"versions": versions})
}

// RestoreNoteVersion restores a note to a specific version
func (h *NotesHandler) RestoreNoteVersion(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	noteID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid note ID"})
	}

	versionNumber, err := strconv.Atoi(c.Params("version"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid version number"})
	}

	ctx := context.Background()

	// Start transaction
	tx, err := h.db.Begin(ctx)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Database transaction failed"})
	}
	defer tx.Rollback(ctx)

	// Get the version to restore
	var titleEnc, contentEnc, contentHash []byte
	err = tx.QueryRow(ctx, `
		SELECT nv.title_encrypted, nv.content_encrypted, nv.content_hash
		FROM note_versions nv
		JOIN notes n ON nv.note_id = n.id
		JOIN workspaces w ON n.workspace_id = w.id
		WHERE n.id = $1 AND nv.version_number = $2 AND w.owner_id = $3 AND n.deleted_at IS NULL`,
		noteID, versionNumber, userID).Scan(&titleEnc, &contentEnc, &contentHash)

	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Version not found"})
	}

	// Save current version before restoring
	var currentVersion int
	var currentTitle, currentContent, currentContentHash []byte
	err = tx.QueryRow(ctx, `
		SELECT version, title_encrypted, content_encrypted, content_hash
		FROM notes n
		JOIN workspaces w ON n.workspace_id = w.id
		WHERE n.id = $1 AND w.owner_id = $2 AND n.deleted_at IS NULL`,
		noteID, userID).Scan(&currentVersion, &currentTitle, &currentContent, &currentContentHash)

	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Note not found"})
	}

	// Save current version to history
	_, err = tx.Exec(ctx, `
		INSERT INTO note_versions (note_id, version_number, title_encrypted, content_encrypted, content_hash, created_by)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		noteID, currentVersion, currentTitle, currentContent, currentContentHash, userID)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to save current version"})
	}

	// Restore to the selected version
	result, err := tx.Exec(ctx, `
		UPDATE notes
		SET title_encrypted = $1, content_encrypted = $2, content_hash = $3, version = version + 1, updated_at = NOW()
		FROM workspaces w
		WHERE notes.id = $4 AND notes.workspace_id = w.id AND w.owner_id = $5 AND notes.deleted_at IS NULL`,
		titleEnc, contentEnc, contentHash, noteID, userID)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to restore version"})
	}

	if result.RowsAffected() == 0 {
		return c.Status(404).JSON(fiber.Map{"error": "Note not found"})
	}

	// Commit transaction
	err = tx.Commit(ctx)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to commit version restore"})
	}

	return c.JSON(fiber.Map{"message": "Note restored to version " + strconv.Itoa(versionNumber)})
}

func (h *NotesHandler) PermanentlyDeleteNote(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	noteID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid note ID"})
	}

	ctx := context.Background()

	// Permanently delete the note
	result, err := h.db.Exec(ctx, `
		DELETE FROM notes 
		USING workspaces w
		WHERE notes.id = $1 AND notes.workspace_id = w.id AND w.owner_id = $2 AND notes.deleted_at IS NOT NULL`,
		noteID, userID)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to permanently delete note"})
	}

	if result.RowsAffected() == 0 {
		return c.Status(404).JSON(fiber.Map{"error": "Note not found in trash"})
	}

	return c.JSON(fiber.Map{"message": "Note permanently deleted successfully"})
}

// Tags Handler
type TagsHandler struct {
	db     Database
	crypto *CryptoService
}

type CreateTagRequest struct {
	Name  string `json:"name" validate:"required"`
	Color string `json:"color,omitempty"`
}

type AssignTagRequest struct {
	TagID string `json:"tag_id" validate:"required"`
}

func (h *TagsHandler) GetTags(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	ctx := context.Background()

	// Get user's tags
	rows, err := h.db.Query(ctx, `
		SELECT id, name_encrypted, color, created_at, updated_at
		FROM tags 
		WHERE user_id = $1
		ORDER BY name_encrypted ASC`,
		userID)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to fetch tags"})
	}
	defer rows.Close()

	tags := []fiber.Map{}
	for rows.Next() {
		var id uuid.UUID
		var nameEnc []byte
		var color string
		var createdAt, updatedAt time.Time

		if err := rows.Scan(&id, &nameEnc, &color, &createdAt, &updatedAt); err != nil {
			continue
		}

		// Decrypt tag name
		name, err := h.crypto.Decrypt(nameEnc)
		if err != nil {
			continue
		}

		tags = append(tags, fiber.Map{
			"id":         id,
			"name":       string(name),
			"color":      color,
			"created_at": createdAt,
			"updated_at": updatedAt,
		})
	}

	return c.JSON(fiber.Map{"tags": tags})
}

func (h *TagsHandler) CreateTag(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	var req CreateTagRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
	}

	// Validate color format (if provided)
	if req.Color != "" && !isValidHexColor(req.Color) {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid color format"})
	}

	// Set default color if not provided
	if req.Color == "" {
		req.Color = "#3b82f6"
	}

	// Encrypt tag name
	encryptedName, err := h.crypto.Encrypt([]byte(req.Name))
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to encrypt tag name"})
	}

	ctx := context.Background()

	// Create tag
	var tagID uuid.UUID
	err = h.db.QueryRow(ctx, `
		INSERT INTO tags (user_id, name_encrypted, color)
		VALUES ($1, $2, $3)
		RETURNING id`,
		userID, encryptedName, req.Color).Scan(&tagID)

	if err != nil {
		if strings.Contains(err.Error(), "duplicate") {
			return c.Status(409).JSON(fiber.Map{"error": "Tag with this name already exists"})
		}
		return c.Status(500).JSON(fiber.Map{"error": "Failed to create tag"})
	}

	return c.Status(201).JSON(fiber.Map{
		"id":      tagID,
		"message": "Tag created successfully",
	})
}

func (h *TagsHandler) DeleteTag(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	tagID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid tag ID"})
	}

	ctx := context.Background()

	// Delete tag (this will cascade delete note_tags relationships)
	result, err := h.db.Exec(ctx, `
		DELETE FROM tags 
		WHERE id = $1 AND user_id = $2`,
		tagID, userID)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to delete tag"})
	}

	if result.RowsAffected() == 0 {
		return c.Status(404).JSON(fiber.Map{"error": "Tag not found"})
	}

	return c.JSON(fiber.Map{"message": "Tag deleted successfully"})
}

func (h *TagsHandler) AssignTagToNote(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	noteID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid note ID"})
	}

	var req AssignTagRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
	}

	tagID, err := uuid.Parse(req.TagID)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid tag ID"})
	}

	ctx := context.Background()

	// Verify note belongs to user
	var noteExists bool
	err = h.db.QueryRow(ctx, `
		SELECT true FROM notes n
		JOIN workspaces w ON n.workspace_id = w.id
		WHERE n.id = $1 AND w.owner_id = $2 AND n.deleted_at IS NULL`,
		noteID, userID).Scan(&noteExists)

	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Note not found"})
	}

	// Verify tag belongs to user
	var tagExists bool
	err = h.db.QueryRow(ctx, `
		SELECT true FROM tags WHERE id = $1 AND user_id = $2`,
		tagID, userID).Scan(&tagExists)

	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Tag not found"})
	}

	// Assign tag to note
	_, err = h.db.Exec(ctx, `
		INSERT INTO note_tags (note_id, tag_id)
		VALUES ($1, $2)
		ON CONFLICT (note_id, tag_id) DO NOTHING`,
		noteID, tagID)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to assign tag"})
	}

	return c.JSON(fiber.Map{"message": "Tag assigned successfully"})
}

func (h *TagsHandler) RemoveTagFromNote(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	noteID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid note ID"})
	}

	tagID, err := uuid.Parse(c.Params("tag_id"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid tag ID"})
	}

	ctx := context.Background()

	// Remove tag assignment (with user verification)
	result, err := h.db.Exec(ctx, `
		DELETE FROM note_tags 
		USING notes n, workspaces w, tags t
		WHERE note_tags.note_id = n.id 
		AND note_tags.tag_id = t.id
		AND n.workspace_id = w.id
		AND note_tags.note_id = $1 
		AND note_tags.tag_id = $2
		AND w.owner_id = $3 
		AND t.user_id = $3`,
		noteID, tagID, userID)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to remove tag"})
	}

	if result.RowsAffected() == 0 {
		return c.Status(404).JSON(fiber.Map{"error": "Tag assignment not found"})
	}

	return c.JSON(fiber.Map{"message": "Tag removed successfully"})
}

func (h *TagsHandler) GetNotesByTag(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	tagID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid tag ID"})
	}

	ctx := context.Background()

	// Get notes with this tag
	rows, err := h.db.Query(ctx, `
		SELECT n.id, n.title_encrypted, n.content_encrypted, n.created_at, n.updated_at
		FROM notes n
		JOIN workspaces w ON n.workspace_id = w.id
		JOIN note_tags nt ON n.id = nt.note_id
		JOIN tags t ON nt.tag_id = t.id
		WHERE t.id = $1 AND w.owner_id = $2 AND n.deleted_at IS NULL
		ORDER BY n.updated_at DESC`,
		tagID, userID)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to fetch notes"})
	}
	defer rows.Close()

	notes := []fiber.Map{}
	for rows.Next() {
		var id uuid.UUID
		var titleEnc, contentEnc []byte
		var createdAt, updatedAt time.Time

		if err := rows.Scan(&id, &titleEnc, &contentEnc, &createdAt, &updatedAt); err != nil {
			continue
		}

		notes = append(notes, fiber.Map{
			"id":                id,
			"title_encrypted":   base64.StdEncoding.EncodeToString(titleEnc),
			"content_encrypted": base64.StdEncoding.EncodeToString(contentEnc),
			"created_at":        createdAt,
			"updated_at":        updatedAt,
		})
	}

	return c.JSON(fiber.Map{"notes": notes})
}

func isValidHexColor(color string) bool {
	if len(color) != 7 || color[0] != '#' {
		return false
	}
	for i := 1; i < 7; i++ {
		c := color[i]
		if !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// Folders Handler
type FoldersHandler struct {
	db     Database
	crypto *CryptoService
}

type CreateFolderRequest struct {
	Name     string  `json:"name" validate:"required"`
	ParentID *string `json:"parent_id,omitempty"`
	Color    string  `json:"color,omitempty"`
	Position int     `json:"position,omitempty"`
}

type UpdateFolderRequest struct {
	Name     string  `json:"name" validate:"required"`
	ParentID *string `json:"parent_id,omitempty"`
	Color    string  `json:"color,omitempty"`
	Position int     `json:"position,omitempty"`
}

type MoveNoteToFolderRequest struct {
	FolderID *string `json:"folder_id"`
}

func (h *FoldersHandler) GetFolders(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	ctx := context.Background()

	rows, err := h.db.Query(ctx, `
		SELECT id, parent_id, name_encrypted, color, position, created_at, updated_at
		FROM folders
		WHERE user_id = $1
		ORDER BY position ASC, created_at ASC`,
		userID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to fetch folders"})
	}
	defer rows.Close()

	folders := []fiber.Map{}
	for rows.Next() {
		var id uuid.UUID
		var parentID *uuid.UUID
		var nameEncrypted []byte
		var color string
		var position int
		var createdAt, updatedAt time.Time

		err := rows.Scan(&id, &parentID, &nameEncrypted, &color, &position, &createdAt, &updatedAt)
		if err != nil {
			continue
		}

		nameBytes, err := h.crypto.Decrypt(nameEncrypted)
		if err != nil {
			continue
		}

		var parentIDStr *string
		if parentID != nil {
			str := parentID.String()
			parentIDStr = &str
		}

		folders = append(folders, fiber.Map{
			"id":         id,
			"parent_id":  parentIDStr,
			"name":       string(nameBytes),
			"color":      color,
			"position":   position,
			"created_at": createdAt,
			"updated_at": updatedAt,
		})
	}

	return c.JSON(fiber.Map{"folders": folders})
}

func (h *FoldersHandler) CreateFolder(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	var req CreateFolderRequest

	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request format"})
	}

	if req.Color != "" && !isValidHexColor(req.Color) {
		req.Color = "#3b82f6"
	} else if req.Color == "" {
		req.Color = "#3b82f6"
	}

	encryptedName, err := h.crypto.Encrypt([]byte(req.Name))
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to encrypt folder name"})
	}

	ctx := context.Background()
	var parentID *uuid.UUID
	if req.ParentID != nil && *req.ParentID != "" {
		parsed, err := uuid.Parse(*req.ParentID)
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "Invalid parent ID"})
		}
		parentID = &parsed

		var exists bool
		err = h.db.QueryRow(ctx, `SELECT true FROM folders WHERE id = $1 AND user_id = $2`, *parentID, userID).Scan(&exists)
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "Parent folder not found"})
		}
	}

	var folderID uuid.UUID
	err = h.db.QueryRow(ctx, `
		INSERT INTO folders (user_id, parent_id, name_encrypted, color, position)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id`,
		userID, parentID, encryptedName, req.Color, req.Position).Scan(&folderID)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to create folder"})
	}

	return c.JSON(fiber.Map{
		"id":      folderID,
		"name":    req.Name,
		"color":   req.Color,
		"message": "Folder created successfully",
	})
}

func (h *FoldersHandler) DeleteFolder(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	folderID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid folder ID"})
	}

	ctx := context.Background()

	_, err = h.db.Exec(ctx, `
		UPDATE notes
		SET folder_id = (
			SELECT parent_id FROM folders WHERE id = $1 AND user_id = $2
		)
		WHERE folder_id = $1`,
		folderID, userID)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to move notes from folder"})
	}

	_, err = h.db.Exec(ctx, `
		DELETE FROM folders
		WHERE id = $1 AND user_id = $2`,
		folderID, userID)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to delete folder"})
	}

	return c.JSON(fiber.Map{"message": "Folder deleted successfully"})
}

func (h *FoldersHandler) MoveNoteToFolder(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	noteID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid note ID"})
	}

	var req MoveNoteToFolderRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request format"})
	}

	ctx := context.Background()
	var folderID *uuid.UUID

	if req.FolderID != nil && *req.FolderID != "" {
		parsed, err := uuid.Parse(*req.FolderID)
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "Invalid folder ID"})
		}
		folderID = &parsed

		var exists bool
		err = h.db.QueryRow(ctx, `SELECT true FROM folders WHERE id = $1 AND user_id = $2`, *folderID, userID).Scan(&exists)
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "Folder not found"})
		}
	}

	_, err = h.db.Exec(ctx, `
		UPDATE notes
		SET folder_id = $1, updated_at = NOW()
		FROM workspaces w
		WHERE notes.id = $2
		AND notes.workspace_id = w.id
		AND w.owner_id = $3`,
		folderID, noteID, userID)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to move note"})
	}

	return c.JSON(fiber.Map{"message": "Note moved successfully"})
}

// Templates Handler
type TemplatesHandler struct {
	db     Database
	crypto *CryptoService
}

type CreateTemplateRequest struct {
	Name        string   `json:"name" validate:"required"`
	Description string   `json:"description,omitempty"`
	Content     string   `json:"content" validate:"required"`
	Tags        []string `json:"tags,omitempty"`
	Icon        string   `json:"icon,omitempty"`
	IsPublic    bool     `json:"is_public,omitempty"`
}

type UpdateTemplateRequest struct {
	Name        string   `json:"name" validate:"required"`
	Description string   `json:"description,omitempty"`
	Content     string   `json:"content" validate:"required"`
	Tags        []string `json:"tags,omitempty"`
	Icon        string   `json:"icon,omitempty"`
	IsPublic    bool     `json:"is_public,omitempty"`
}

type UseTemplateRequest struct {
	Title    string  `json:"title,omitempty"`
	FolderID *string `json:"folder_id,omitempty"`
}

func (h *TemplatesHandler) GetTemplates(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	ctx := context.Background()

	rows, err := h.db.Query(ctx, `
		SELECT id, name_encrypted, description_encrypted, content_encrypted, tags, icon, is_public, usage_count, created_at, updated_at
		FROM templates
		WHERE user_id = $1 OR is_public = true
		ORDER BY created_at DESC
	`, userID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to fetch templates"})
	}
	defer rows.Close()

	var templates []map[string]interface{}
	for rows.Next() {
		var id uuid.UUID
		var nameEncrypted, descriptionEncrypted, contentEncrypted []byte
		var tags []string
		var icon string
		var isPublic bool
		var usageCount int
		var createdAt, updatedAt time.Time

		err := rows.Scan(&id, &nameEncrypted, &descriptionEncrypted, &contentEncrypted, &tags, &icon, &isPublic, &usageCount, &createdAt, &updatedAt)
		if err != nil {
			continue
		}

		// Decrypt template data
		nameBytes, err := h.crypto.Decrypt(nameEncrypted)
		if err != nil {
			continue
		}
		name := string(nameBytes)

		var description string
		if len(descriptionEncrypted) > 0 {
			descBytes, err := h.crypto.Decrypt(descriptionEncrypted)
			if err == nil {
				description = string(descBytes)
			}
		}

		// Don't decrypt content for listing (performance)
		template := map[string]interface{}{
			"id":          id,
			"name":        name,
			"description": description,
			"tags":        tags,
			"icon":        icon,
			"is_public":   isPublic,
			"usage_count": usageCount,
			"created_at":  createdAt,
			"updated_at":  updatedAt,
		}

		templates = append(templates, template)
	}

	return c.JSON(fiber.Map{"templates": templates})
}

func (h *TemplatesHandler) GetTemplate(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	templateID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid template ID"})
	}

	ctx := context.Background()
	var nameEncrypted, descriptionEncrypted, contentEncrypted []byte
	var tags []string
	var icon string
	var isPublic bool
	var usageCount int
	var createdAt, updatedAt time.Time

	err = h.db.QueryRow(ctx, `
		SELECT name_encrypted, description_encrypted, content_encrypted, tags, icon, is_public, usage_count, created_at, updated_at
		FROM templates
		WHERE id = $1 AND (user_id = $2 OR is_public = true)
	`, templateID, userID).Scan(&nameEncrypted, &descriptionEncrypted, &contentEncrypted, &tags, &icon, &isPublic, &usageCount, &createdAt, &updatedAt)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Template not found"})
	}

	// Decrypt template data
	nameBytes, err := h.crypto.Decrypt(nameEncrypted)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to decrypt template name"})
	}
	name := string(nameBytes)

	var description string
	if len(descriptionEncrypted) > 0 {
		descBytes, err := h.crypto.Decrypt(descriptionEncrypted)
		if err == nil {
			description = string(descBytes)
		}
	}

	contentBytes, err := h.crypto.Decrypt(contentEncrypted)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to decrypt template content"})
	}
	content := string(contentBytes)

	template := map[string]interface{}{
		"id":          templateID,
		"name":        name,
		"description": description,
		"content":     content,
		"tags":        tags,
		"icon":        icon,
		"is_public":   isPublic,
		"usage_count": usageCount,
		"created_at":  createdAt,
		"updated_at":  updatedAt,
	}

	return c.JSON(template)
}

func (h *TemplatesHandler) CreateTemplate(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	var req CreateTemplateRequest

	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request format"})
	}

	// Encrypt template data
	nameEncrypted, err := h.crypto.Encrypt([]byte(req.Name))
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to encrypt template name"})
	}

	var descriptionEncrypted []byte
	if req.Description != "" {
		descriptionEncrypted, err = h.crypto.Encrypt([]byte(req.Description))
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "Failed to encrypt template description"})
		}
	}

	contentEncrypted, err := h.crypto.Encrypt([]byte(req.Content))
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to encrypt template content"})
	}

	// Default icon if not provided
	icon := req.Icon
	if icon == "" {
		icon = "📝"
	}

	ctx := context.Background()
	var templateID uuid.UUID
	err = h.db.QueryRow(ctx, `
		INSERT INTO templates (user_id, name_encrypted, description_encrypted, content_encrypted, tags, icon, is_public)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id
	`, userID, nameEncrypted, descriptionEncrypted, contentEncrypted, req.Tags, icon, req.IsPublic).Scan(&templateID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to create template"})
	}

	return c.Status(201).JSON(fiber.Map{
		"id":      templateID,
		"message": "Template created successfully",
	})
}

func (h *TemplatesHandler) UpdateTemplate(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	templateID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid template ID"})
	}

	var req UpdateTemplateRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request format"})
	}

	// Encrypt template data
	nameEncrypted, err := h.crypto.Encrypt([]byte(req.Name))
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to encrypt template name"})
	}

	var descriptionEncrypted []byte
	if req.Description != "" {
		descriptionEncrypted, err = h.crypto.Encrypt([]byte(req.Description))
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "Failed to encrypt template description"})
		}
	}

	contentEncrypted, err := h.crypto.Encrypt([]byte(req.Content))
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to encrypt template content"})
	}

	// Default icon if not provided
	icon := req.Icon
	if icon == "" {
		icon = "📝"
	}

	ctx := context.Background()
	result, err := h.db.Exec(ctx, `
		UPDATE templates
		SET name_encrypted = $3, description_encrypted = $4, content_encrypted = $5, tags = $6, icon = $7, is_public = $8, updated_at = NOW()
		WHERE id = $1 AND user_id = $2
	`, templateID, userID, nameEncrypted, descriptionEncrypted, contentEncrypted, req.Tags, icon, req.IsPublic)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to update template"})
	}

	if result.RowsAffected() == 0 {
		return c.Status(404).JSON(fiber.Map{"error": "Template not found or access denied"})
	}

	return c.JSON(fiber.Map{"message": "Template updated successfully"})
}

func (h *TemplatesHandler) DeleteTemplate(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	templateID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid template ID"})
	}

	ctx := context.Background()
	result, err := h.db.Exec(ctx, `DELETE FROM templates WHERE id = $1 AND user_id = $2`, templateID, userID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to delete template"})
	}

	if result.RowsAffected() == 0 {
		return c.Status(404).JSON(fiber.Map{"error": "Template not found or access denied"})
	}

	return c.JSON(fiber.Map{"message": "Template deleted successfully"})
}

func (h *TemplatesHandler) UseTemplate(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	templateID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid template ID"})
	}

	var req UseTemplateRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request format"})
	}

	ctx := context.Background()

	// Get template content
	var contentEncrypted []byte
	var nameEncrypted []byte
	err = h.db.QueryRow(ctx, `
		SELECT name_encrypted, content_encrypted
		FROM templates
		WHERE id = $1 AND (user_id = $2 OR is_public = true)
	`, templateID, userID).Scan(&nameEncrypted, &contentEncrypted)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Template not found"})
	}

	// Decrypt template data
	templateNameBytes, err := h.crypto.Decrypt(nameEncrypted)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to decrypt template name"})
	}
	templateName := string(templateNameBytes)

	contentBytes, err := h.crypto.Decrypt(contentEncrypted)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to decrypt template content"})
	}
	content := string(contentBytes)

	// Use provided title or template name
	title := req.Title
	if title == "" {
		title = templateName
	}

	// Encrypt note data
	titleEncrypted, err := h.crypto.Encrypt([]byte(title))
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to encrypt note title"})
	}

	contentEncryptedForNote, err := h.crypto.Encrypt([]byte(content))
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to encrypt note content"})
	}

	// Parse folder ID if provided
	var folderID *uuid.UUID
	if req.FolderID != nil && *req.FolderID != "" {
		parsed, err := uuid.Parse(*req.FolderID)
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "Invalid folder ID"})
		}
		folderID = &parsed

		// Verify folder exists and belongs to user
		var exists bool
		err = h.db.QueryRow(ctx, `SELECT true FROM folders WHERE id = $1 AND user_id = $2`, *folderID, userID).Scan(&exists)
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "Folder not found"})
		}
	}

	// Create new note from template
	var noteID uuid.UUID
	err = h.db.QueryRow(ctx, `
		INSERT INTO notes (user_id, title_encrypted, content_encrypted, template_id, folder_id)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id
	`, userID, titleEncrypted, contentEncryptedForNote, templateID, folderID).Scan(&noteID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to create note from template"})
	}

	// Increment template usage count
	_, err = h.db.Exec(ctx, `
		UPDATE templates SET usage_count = usage_count + 1 WHERE id = $1
	`, templateID)
	if err != nil {
		// Log error but don't fail the request
		log.Printf("Failed to increment template usage count: %v", err)
	}

	return c.Status(201).JSON(fiber.Map{
		"id":      noteID,
		"message": "Note created from template successfully",
	})
}

// Collaboration Handler
type CollaborationHandler struct {
	db     Database
	crypto *CryptoService
}

type ShareNoteRequest struct {
	UserEmail  string `json:"user_email" validate:"required,email"`
	Permission string `json:"permission" validate:"required,oneof=read write admin"`
}

type CollaborationResponse struct {
	ID         string `json:"id"`
	NoteID     string `json:"note_id"`
	UserID     string `json:"user_id"`
	UserEmail  string `json:"user_email"`
	Permission string `json:"permission"`
	CreatedAt  string `json:"created_at"`
}

// ShareNote godoc
// @Summary Share a note with another user
// @Description Share a note with another user by email and set permission level
// @Tags Collaboration
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "Note ID"
// @Param request body ShareNoteRequest true "Share request data"
// @Success 201 {object} map[string]interface{} "Note shared successfully"
// @Failure 400 {object} map[string]interface{} "Invalid request"
// @Failure 404 {object} map[string]interface{} "Note or user not found"
// @Failure 409 {object} map[string]interface{} "Note already shared with user"
// @Router /notes/{id}/share [post]
func (h *CollaborationHandler) ShareNote(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	noteID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid note ID"})
	}

	ctx := context.Background()

	var req ShareNoteRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
	}

	// Validate email format
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	if !emailRegex.MatchString(req.UserEmail) {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid email format"})
	}

	// Validate permission
	validPermissions := map[string]bool{"read": true, "write": true, "admin": true}
	if !validPermissions[req.Permission] {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid permission"})
	}

	// Prevent self-sharing
	var userEmail string
	err = h.db.QueryRow(ctx, `SELECT email FROM users WHERE id = $1`, userID).Scan(&userEmail)
	if err == nil && userEmail == req.UserEmail {
		return c.Status(400).JSON(fiber.Map{"error": "Cannot share note with yourself"})
	}

	// Verify user owns the note
	var ownerCheck bool
	err = h.db.QueryRow(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM notes n
			JOIN workspaces w ON n.workspace_id = w.id
			WHERE n.id = $1 AND w.owner_id = $2 AND n.deleted_at IS NULL
		)`, noteID, userID).Scan(&ownerCheck)

	if err != nil || !ownerCheck {
		return c.Status(404).JSON(fiber.Map{"error": "Note not found"})
	}

	// Find the user to share with
	var targetUserID uuid.UUID
	err = h.db.QueryRow(ctx, `SELECT id FROM users WHERE email = $1`, req.UserEmail).Scan(&targetUserID)
	if err != nil {
		logRequestError(c, "ShareNote: user not found", err, "target_email", req.UserEmail)
		return c.Status(404).JSON(fiber.Map{"error": "User not found"})
	}

	// Check if already shared
	var existingID uuid.UUID
	err = h.db.QueryRow(ctx, `
		SELECT id FROM collaborations
		WHERE note_id = $1 AND user_id = $2`, noteID, targetUserID).Scan(&existingID)

	if err == nil {
		return c.Status(409).JSON(fiber.Map{"error": "Note already shared with this user"})
	}

	// Generate a note encryption key for the collaboration
	noteKey := make([]byte, 32)
	if _, err := rand.Read(noteKey); err != nil {
		logRequestError(c, "ShareNote: failed to generate encryption key", err)
		return c.Status(500).JSON(fiber.Map{"error": "Failed to generate encryption key"})
	}

	// In a real implementation, we would encrypt the note key with the target user's public key
	// For now, we'll store it encrypted with server's key as a placeholder
	encryptedKey, err := h.crypto.Encrypt(noteKey)
	if err != nil {
		logRequestError(c, "ShareNote: failed to encrypt key", err)
		return c.Status(500).JSON(fiber.Map{"error": "Failed to encrypt key"})
	}

	// Create collaboration record
	var collaborationID uuid.UUID
	err = h.db.QueryRow(ctx, `
		INSERT INTO collaborations (note_id, user_id, permission, key_encrypted)
		VALUES ($1, $2, $3, $4)
		RETURNING id`, noteID, targetUserID, req.Permission, encryptedKey).Scan(&collaborationID)

	if err != nil {
		logRequestError(c, "ShareNote: failed to create collaboration record", err, "target_user_id", targetUserID)
		return c.Status(500).JSON(fiber.Map{"error": "Failed to share note"})
	}

	// Log the action
	auditLog(h.db, userID, "share_note", fiber.Map{
		"note_id":     noteID,
		"target_user": targetUserID,
		"permission":  req.Permission,
	})

	return c.Status(201).JSON(fiber.Map{
		"message":          "Note shared successfully",
		"collaboration_id": collaborationID,
	})
}

// GetCollaborators godoc
// @Summary Get note collaborators
// @Description Get list of users who have access to a note
// @Tags Collaboration
// @Produce json
// @Security BearerAuth
// @Param id path string true "Note ID"
// @Success 200 {object} map[string]interface{} "List of collaborators"
// @Failure 400 {object} map[string]interface{} "Invalid note ID"
// @Failure 404 {object} map[string]interface{} "Note not found"
// @Router /notes/{id}/collaborators [get]
func (h *CollaborationHandler) GetCollaborators(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	noteID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid note ID"})
	}

	ctx := context.Background()

	// Verify user has access to the note (owner or collaborator)
	var hasAccess bool
	err = h.db.QueryRow(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM notes n
			JOIN workspaces w ON n.workspace_id = w.id
			WHERE n.id = $1 AND w.owner_id = $2 AND n.deleted_at IS NULL
		) OR EXISTS(
			SELECT 1 FROM collaborations c
			WHERE c.note_id = $1 AND c.user_id = $2
		)`, noteID, userID).Scan(&hasAccess)

	if err != nil || !hasAccess {
		return c.Status(404).JSON(fiber.Map{"error": "Note not found"})
	}

	// Get collaborators
	rows, err := h.db.Query(ctx, `
		SELECT c.id, c.user_id, u.email, c.permission, c.created_at
		FROM collaborations c
		JOIN users u ON c.user_id = u.id
		WHERE c.note_id = $1
		ORDER BY c.created_at ASC`, noteID)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to fetch collaborators"})
	}
	defer rows.Close()

	collaborators := []CollaborationResponse{}
	for rows.Next() {
		var collab CollaborationResponse
		var collaborationID, collaboratorUserID uuid.UUID
		var createdAt time.Time

		if err := rows.Scan(&collaborationID, &collaboratorUserID, &collab.UserEmail, &collab.Permission, &createdAt); err != nil {
			continue
		}

		collab.ID = collaborationID.String()
		collab.NoteID = noteID.String()
		collab.UserID = collaboratorUserID.String()
		collab.CreatedAt = createdAt.Format(time.RFC3339)

		collaborators = append(collaborators, collab)
	}

	return c.JSON(fiber.Map{"collaborators": collaborators})
}

func (h *CollaborationHandler) RemoveCollaborator(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	noteID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid note ID"})
	}

	collaboratorUserID, err := uuid.Parse(c.Params("userId"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid user ID"})
	}

	ctx := context.Background()

	// Verify user owns the note
	var ownerCheck bool
	err = h.db.QueryRow(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM notes n
			JOIN workspaces w ON n.workspace_id = w.id
			WHERE n.id = $1 AND w.owner_id = $2 AND n.deleted_at IS NULL
		)`, noteID, userID).Scan(&ownerCheck)

	if err != nil || !ownerCheck {
		return c.Status(404).JSON(fiber.Map{"error": "Note not found"})
	}

	// Remove collaboration
	result, err := h.db.Exec(ctx, `
		DELETE FROM collaborations
		WHERE note_id = $1 AND user_id = $2`, noteID, collaboratorUserID)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to remove collaborator"})
	}

	if result.RowsAffected() == 0 {
		return c.Status(404).JSON(fiber.Map{"error": "Collaboration not found"})
	}

	// Log the action
	auditLog(h.db, userID, "remove_collaborator", fiber.Map{
		"note_id":     noteID,
		"target_user": collaboratorUserID,
	})

	return c.JSON(fiber.Map{"message": "Collaborator removed successfully"})
}

func (h *CollaborationHandler) GetSharedNotes(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	ctx := context.Background()

	// Get notes shared with the user
	rows, err := h.db.Query(ctx, `
		SELECT n.id, n.title_encrypted, n.content_encrypted, n.created_at, n.updated_at,
			   c.permission, u.email as owner_email
		FROM notes n
		JOIN collaborations c ON n.id = c.note_id
		JOIN workspaces w ON n.workspace_id = w.id
		JOIN users u ON w.owner_id = u.id
		WHERE c.user_id = $1 AND n.deleted_at IS NULL
		ORDER BY n.updated_at DESC`, userID)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to fetch shared notes"})
	}
	defer rows.Close()

	notes := []fiber.Map{}
	for rows.Next() {
		var id uuid.UUID
		var titleEnc, contentEnc []byte
		var createdAt, updatedAt time.Time
		var permission, ownerEmail string

		if err := rows.Scan(&id, &titleEnc, &contentEnc, &createdAt, &updatedAt, &permission, &ownerEmail); err != nil {
			continue
		}

		notes = append(notes, fiber.Map{
			"id":                id,
			"title_encrypted":   base64.StdEncoding.EncodeToString(titleEnc),
			"content_encrypted": base64.StdEncoding.EncodeToString(contentEnc),
			"created_at":        createdAt,
			"updated_at":        updatedAt,
			"permission":        permission,
			"owner_email":       ownerEmail,
			"is_shared":         true,
		})
	}

	return c.JSON(fiber.Map{"notes": notes})
}

// Attachments Handler
type AttachmentsHandler struct {
	db     Database
	crypto *CryptoService
}

type AttachmentUploadRequest struct {
	NoteID   string `json:"note_id" validate:"required,uuid"`
	Filename string `json:"filename" validate:"required"`
	MimeType string `json:"mime_type"`
}

type AttachmentResponse struct {
	ID          string `json:"id"`
	NoteID      string `json:"note_id"`
	Filename    string `json:"filename"`
	MimeType    string `json:"mime_type"`
	SizeBytes   int64  `json:"size_bytes"`
	CreatedAt   string `json:"created_at"`
	DownloadURL string `json:"download_url"`
}

// Upload attachment to a note
func (h *AttachmentsHandler) UploadAttachment(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	noteID := c.Params("noteId")

	// Validate note ID
	noteUUID, err := uuid.Parse(noteID)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid note ID"})
	}

	// Verify user owns the note
	var noteExists bool
	err = h.db.QueryRow(c.Context(),
		"SELECT EXISTS(SELECT 1 FROM notes WHERE id = $1 AND user_id = $2)",
		noteUUID, userID).Scan(&noteExists)
	if err != nil || !noteExists {
		return c.Status(404).JSON(fiber.Map{"error": "Note not found"})
	}

	// Get uploaded file
	file, err := c.FormFile("file")
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "No file uploaded"})
	}

	// Security: Validate file size (10MB limit)
	const maxFileSize = 10 * 1024 * 1024 // 10MB
	if file.Size > maxFileSize {
		return c.Status(400).JSON(fiber.Map{"error": "File too large. Maximum size is 10MB"})
	}

	// Security: Validate file type
	allowedTypes := map[string]bool{
		"image/jpeg":      true,
		"image/png":       true,
		"image/gif":       true,
		"image/webp":      true,
		"text/plain":      true,
		"application/pdf": true,
		"text/markdown":   true,
	}

	if file.Header.Get("Content-Type") != "" && !allowedTypes[file.Header.Get("Content-Type")] {
		return c.Status(400).JSON(fiber.Map{"error": "File type not allowed"})
	}

	// Read file content
	fileContent, err := file.Open()
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to read file"})
	}
	defer fileContent.Close()

	content, err := io.ReadAll(fileContent)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to read file content"})
	}

	// Calculate checksum
	hash := sha256.Sum256(content)

	// Encrypt filename and content
	encryptedFilename, err := h.crypto.Encrypt([]byte(file.Filename))
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to encrypt filename"})
	}

	encryptedContent, err := h.crypto.Encrypt(content)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to encrypt file content"})
	}

	// Save to database
	attachmentID := uuid.New()
	mimeType := file.Header.Get("Content-Type")
	if mimeType == "" {
		mimeType = "application/octet-stream"
	}

	_, err = h.db.Exec(c.Context(), `
		INSERT INTO attachments (id, note_id, filename_encrypted, content_encrypted, mime_type, size_bytes, checksum, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		attachmentID, noteUUID, encryptedFilename, encryptedContent, mimeType, file.Size, hash[:], userID)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to save attachment"})
	}

	return c.JSON(AttachmentResponse{
		ID:          attachmentID.String(),
		NoteID:      noteID,
		Filename:    file.Filename,
		MimeType:    mimeType,
		SizeBytes:   file.Size,
		CreatedAt:   time.Now().Format(time.RFC3339),
		DownloadURL: "/api/v1/notes/" + noteID + "/attachments/" + attachmentID.String(),
	})
}

// Get attachments for a note
func (h *AttachmentsHandler) GetAttachments(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	noteID := c.Params("noteId")

	noteUUID, err := uuid.Parse(noteID)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid note ID"})
	}

	// Verify user owns the note
	var noteExists bool
	err = h.db.QueryRow(c.Context(),
		"SELECT EXISTS(SELECT 1 FROM notes WHERE id = $1 AND user_id = $2)",
		noteUUID, userID).Scan(&noteExists)
	if err != nil || !noteExists {
		return c.Status(404).JSON(fiber.Map{"error": "Note not found"})
	}

	rows, err := h.db.Query(c.Context(), `
		SELECT id, filename_encrypted, mime_type, size_bytes, created_at
		FROM attachments
		WHERE note_id = $1
		ORDER BY created_at DESC`, noteUUID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to fetch attachments"})
	}
	defer rows.Close()

	var attachments []AttachmentResponse
	for rows.Next() {
		var id uuid.UUID
		var encryptedFilename []byte
		var mimeType string
		var sizeBytes int64
		var createdAt time.Time

		err := rows.Scan(&id, &encryptedFilename, &mimeType, &sizeBytes, &createdAt)
		if err != nil {
			continue
		}

		// Decrypt filename
		filenameBytes, err := h.crypto.Decrypt(encryptedFilename)
		if err != nil {
			continue
		}

		attachments = append(attachments, AttachmentResponse{
			ID:          id.String(),
			NoteID:      noteID,
			Filename:    string(filenameBytes),
			MimeType:    mimeType,
			SizeBytes:   sizeBytes,
			CreatedAt:   createdAt.Format(time.RFC3339),
			DownloadURL: "/api/v1/notes/" + noteID + "/attachments/" + id.String(),
		})
	}

	return c.JSON(attachments)
}

// Download attachment
func (h *AttachmentsHandler) DownloadAttachment(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	noteID := c.Params("noteId")
	attachmentID := c.Params("attachmentId")

	noteUUID, err := uuid.Parse(noteID)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid note ID"})
	}

	attachmentUUID, err := uuid.Parse(attachmentID)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid attachment ID"})
	}

	// Verify user owns the note and attachment exists
	var encryptedFilename, encryptedContent []byte
	var mimeType string
	err = h.db.QueryRow(c.Context(), `
		SELECT a.filename_encrypted, a.content_encrypted, a.mime_type
		FROM attachments a
		JOIN notes n ON a.note_id = n.id
		WHERE a.id = $1 AND a.note_id = $2 AND n.user_id = $3`,
		attachmentUUID, noteUUID, userID).Scan(&encryptedFilename, &encryptedContent, &mimeType)

	if err != nil {
		if err == pgx.ErrNoRows {
			return c.Status(404).JSON(fiber.Map{"error": "Attachment not found"})
		}
		return c.Status(500).JSON(fiber.Map{"error": "Failed to fetch attachment"})
	}

	// Decrypt filename and content
	filenameBytes, err := h.crypto.Decrypt(encryptedFilename)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to decrypt filename"})
	}

	content, err := h.crypto.Decrypt(encryptedContent)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to decrypt file content"})
	}

	filename := string(filenameBytes)

	// Set appropriate headers
	c.Set("Content-Type", mimeType)
	c.Set("Content-Disposition", "attachment; filename=\""+filename+"\"")
	c.Set("Content-Length", strconv.Itoa(len(content)))

	return c.Send(content)
}

// Delete attachment
func (h *AttachmentsHandler) DeleteAttachment(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	noteID := c.Params("noteId")
	attachmentID := c.Params("attachmentId")

	noteUUID, err := uuid.Parse(noteID)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid note ID"})
	}

	attachmentUUID, err := uuid.Parse(attachmentID)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid attachment ID"})
	}

	// Delete attachment (verify ownership through note)
	result, err := h.db.Exec(c.Context(), `
		DELETE FROM attachments a
		USING notes n
		WHERE a.id = $1 AND a.note_id = $2 AND a.note_id = n.id AND n.user_id = $3`,
		attachmentUUID, noteUUID, userID)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to delete attachment"})
	}

	if result.RowsAffected() == 0 {
		return c.Status(404).JSON(fiber.Map{"error": "Attachment not found"})
	}

	return c.JSON(fiber.Map{"message": "Attachment deleted successfully"})
}

// Search Handler
type SearchHandler struct {
	db     Database
	crypto *CryptoService
}

type SearchRequest struct {
	Query string `json:"query" validate:"required,min=1"`
	Limit int    `json:"limit,omitempty"`
}

type SearchResult struct {
	ID        string `json:"id"`
	Title     string `json:"title"`
	Content   string `json:"content"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
	Snippet   string `json:"snippet"`
}

type SearchResponse struct {
	Results []SearchResult `json:"results"`
	Total   int            `json:"total"`
	Query   string         `json:"query"`
}

// Search notes for the authenticated user
func (h *SearchHandler) SearchNotes(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)

	var req SearchRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
	}

	// Validate request
	if req.Query == "" {
		return c.Status(400).JSON(fiber.Map{"error": "Search query is required"})
	}

	if req.Limit <= 0 {
		req.Limit = 20 // Default limit
	}
	if req.Limit > 100 {
		req.Limit = 100 // Max limit
	}

	// Search in notes (decrypt and search - in production you'd want indexed search)
	query := `
		SELECT id, title_encrypted, content_encrypted, created_at, updated_at
		FROM notes
		WHERE created_by = $1 AND deleted_at IS NULL
		ORDER BY updated_at DESC
		LIMIT $2`

	rows, err := h.db.Query(c.Context(), query, userID, req.Limit*2) // Get more to account for filtering
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to search notes"})
	}
	defer rows.Close()

	var results []SearchResult
	searchQuery := strings.ToLower(strings.TrimSpace(req.Query))

	for rows.Next() {
		var id uuid.UUID
		var titleEncrypted, contentEncrypted []byte
		var createdAt, updatedAt time.Time

		err := rows.Scan(&id, &titleEncrypted, &contentEncrypted, &createdAt, &updatedAt)
		if err != nil {
			continue
		}

		// Decrypt title and content
		titleBytes, err := h.crypto.Decrypt(titleEncrypted)
		if err != nil {
			continue
		}

		contentBytes, err := h.crypto.Decrypt(contentEncrypted)
		if err != nil {
			continue
		}

		title := string(titleBytes)
		content := string(contentBytes)

		// Perform case-insensitive search
		titleLower := strings.ToLower(title)
		contentLower := strings.ToLower(content)

		if strings.Contains(titleLower, searchQuery) || strings.Contains(contentLower, searchQuery) {
			// Create snippet showing context around the match
			snippet := createSearchSnippet(content, searchQuery, 150)

			results = append(results, SearchResult{
				ID:        id.String(),
				Title:     title,
				Content:   content,
				CreatedAt: createdAt.Format(time.RFC3339),
				UpdatedAt: updatedAt.Format(time.RFC3339),
				Snippet:   snippet,
			})

			// Stop when we have enough results
			if len(results) >= req.Limit {
				break
			}
		}
	}

	return c.JSON(SearchResponse{
		Results: results,
		Total:   len(results),
		Query:   req.Query,
	})
}

// Create a snippet showing context around the search term
func createSearchSnippet(content, query string, maxLength int) string {
	contentLower := strings.ToLower(content)
	queryLower := strings.ToLower(query)

	index := strings.Index(contentLower, queryLower)
	if index == -1 {
		// If query not found in content, return beginning
		if len(content) <= maxLength {
			return content
		}
		return content[:maxLength] + "..."
	}

	// Calculate snippet bounds
	start := index - 50
	if start < 0 {
		start = 0
	}

	end := index + len(query) + 50
	if end > len(content) {
		end = len(content)
	}

	snippet := content[start:end]

	// Add ellipsis if needed
	if start > 0 {
		snippet = "..." + snippet
	}
	if end < len(content) {
		snippet = snippet + "..."
	}

	return snippet
}

// Import/Export Handler
type ImportExportHandler struct {
	db     Database
	crypto *CryptoService
}

type ImportRequest struct {
	Format   string `json:"format" validate:"required,oneof=markdown text html json"`
	Content  string `json:"content" validate:"required"`
	Title    string `json:"title,omitempty"`
	Filename string `json:"filename,omitempty"`
}

type ExportRequest struct {
	Format string `json:"format" validate:"required,oneof=markdown text html json"`
}

type BulkImportRequest struct {
	Files []ImportRequest `json:"files" validate:"required,min=1,max=50"`
}

// Helper functions for storage management
func (h *ImportExportHandler) checkStorageLimit(userID uuid.UUID, additionalBytes int64) error {
	ctx := context.Background()

	var storageUsed, storageLimit int64
	err := h.db.QueryRow(ctx, `
		SELECT storage_used, storage_limit
		FROM users
		WHERE id = $1
	`, userID).Scan(&storageUsed, &storageLimit)

	if err != nil {
		return fmt.Errorf("failed to check storage: %w", err)
	}

	if storageUsed+additionalBytes > storageLimit {
		return fmt.Errorf("storage limit exceeded: %d bytes used + %d bytes new > %d bytes limit",
			storageUsed, additionalBytes, storageLimit)
	}

	return nil
}

func (h *ImportExportHandler) updateStorageUsage(userID uuid.UUID, additionalBytes int64) error {
	ctx := context.Background()

	_, err := h.db.Exec(ctx, `
		UPDATE users
		SET storage_used = storage_used + $1
		WHERE id = $2
	`, additionalBytes, userID)

	return err
}

func validateFileContent(content, format string) error {
	// Validate file size (max 100KB per file for text content)
	if len(content) > 100*1024 {
		return fmt.Errorf("file too large (max 100KB per file)")
	}

	// Basic content security validation
	lowerContent := strings.ToLower(content)

	// Check for potentially malicious content
	dangerousPatterns := []string{
		"<script", "javascript:", "data:text/html", "data:image/svg+xml",
		"vbscript:", "onload=", "onerror=", "onclick=", "onmouseover=",
		"<iframe", "<object", "<embed", "<applet",
	}

	for _, pattern := range dangerousPatterns {
		if strings.Contains(lowerContent, pattern) {
			return fmt.Errorf("potentially malicious content detected: %s", pattern)
		}
	}

	// Format-specific validation
	switch format {
	case "html":
		// Additional HTML validation
		if strings.Contains(lowerContent, "<meta http-equiv") {
			return fmt.Errorf("meta refresh tags not allowed")
		}
	case "json":
		// Validate JSON structure
		var js interface{}
		if err := json.Unmarshal([]byte(content), &js); err != nil {
			return fmt.Errorf("invalid JSON format: %w", err)
		}
	}

	return nil
}

// GetStorageInfo godoc
// @Summary Get user storage information
// @Description Get current storage usage and limit for the user
// @Tags Import/Export
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "Storage information"
// @Failure 500 {object} map[string]interface{} "Failed to get storage info"
// @Router /user/storage [get]
func (h *ImportExportHandler) GetStorageInfo(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	ctx := context.Background()

	var storageUsed, storageLimit int64
	err := h.db.QueryRow(ctx, `
		SELECT storage_used, storage_limit
		FROM users
		WHERE id = $1
	`, userID).Scan(&storageUsed, &storageLimit)

	if err != nil {
		logRequestError(c, "GetStorageInfo: failed to get storage info", err, "user_id", userID)
		return c.Status(500).JSON(fiber.Map{"error": "Failed to get storage information"})
	}

	return c.JSON(fiber.Map{
		"storage_used":      storageUsed,
		"storage_limit":     storageLimit,
		"storage_remaining": storageLimit - storageUsed,
		"usage_percentage":  float64(storageUsed) / float64(storageLimit) * 100,
	})
}

// ImportNote godoc
// @Summary Import a note from various formats
// @Description Import a note from markdown, text, HTML, or JSON format
// @Tags Import/Export
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body ImportRequest true "Import data"
// @Success 201 {object} map[string]interface{} "Note imported successfully"
// @Failure 400 {object} map[string]interface{} "Invalid request"
// @Failure 500 {object} map[string]interface{} "Import failed"
// @Router /notes/import [post]
func (h *ImportExportHandler) ImportNote(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	ctx := context.Background()

	var req ImportRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
	}

	// Validate file content and security
	if err := validateFileContent(req.Content, req.Format); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": fmt.Sprintf("Invalid file content: %s", err.Error())})
	}

	// Check storage limit before processing
	contentSize := int64(len(req.Content))
	if err := h.checkStorageLimit(userID, contentSize); err != nil {
		return c.Status(413).JSON(fiber.Map{"error": err.Error()})
	}

	// Extract title from content if not provided
	title := req.Title
	if title == "" {
		title = extractTitleFromContent(req.Content, req.Format)
	}
	if title == "" {
		title = req.Filename
	}
	if title == "" {
		title = "Imported Note"
	}

	// Convert content based on format
	content, err := convertToMarkdown(req.Content, req.Format)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": fmt.Sprintf("Failed to convert %s: %s", req.Format, err.Error())})
	}

	// Get user's default workspace
	var workspaceID uuid.UUID
	err = h.db.QueryRow(ctx, `SELECT id FROM workspaces WHERE owner_id = $1 LIMIT 1`, userID).Scan(&workspaceID)
	if err != nil {
		logRequestError(c, "ImportNote: failed to get user workspace", err)
		return c.Status(500).JSON(fiber.Map{"error": "Failed to get workspace"})
	}

	// Encrypt title and content
	titleEncrypted, err := h.crypto.Encrypt([]byte(title))
	if err != nil {
		logRequestError(c, "ImportNote: failed to encrypt title", err, "title_length", len(title))
		return c.Status(500).JSON(fiber.Map{"error": "Failed to encrypt title"})
	}

	contentEncrypted, err := h.crypto.Encrypt([]byte(content))
	if err != nil {
		logRequestError(c, "ImportNote: failed to encrypt content", err, "content_length", len(content))
		return c.Status(500).JSON(fiber.Map{"error": "Failed to encrypt content"})
	}

	// Insert note
	noteID := uuid.New()
	_, err = h.db.Exec(ctx, `
		INSERT INTO notes (id, workspace_id, title_encrypted, content_encrypted)
		VALUES ($1, $2, $3, $4)`,
		noteID, workspaceID, titleEncrypted, contentEncrypted)

	if err != nil {
		logRequestError(c, "ImportNote: failed to create note in database", err, "note_id", noteID)
		return c.Status(500).JSON(fiber.Map{"error": "Failed to create note"})
	}

	// Update storage usage
	if err := h.updateStorageUsage(userID, contentSize); err != nil {
		logRequestError(c, "ImportNote: failed to update storage usage", err, "user_id", userID, "content_size", contentSize)
		// Note: We don't fail the import here as the note was already created
	}

	return c.Status(201).JSON(fiber.Map{
		"message": "Note imported successfully",
		"note_id": noteID,
		"title":   title,
		"format":  req.Format,
	})
}

// ExportNote godoc
// @Summary Export a note in various formats
// @Description Export a note as markdown, text, HTML, or JSON
// @Tags Import/Export
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "Note ID"
// @Param request body ExportRequest true "Export format"
// @Success 200 {object} map[string]interface{} "Note exported successfully"
// @Failure 400 {object} map[string]interface{} "Invalid request"
// @Failure 404 {object} map[string]interface{} "Note not found"
// @Router /notes/{id}/export [post]
func (h *ImportExportHandler) ExportNote(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	noteID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid note ID"})
	}

	ctx := context.Background()

	var req ExportRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
	}

	// Get note with permission check
	var titleEnc, contentEnc []byte
	var createdAt, updatedAt time.Time
	err = h.db.QueryRow(ctx, `
		SELECT n.title_encrypted, n.content_encrypted, n.created_at, n.updated_at
		FROM notes n
		JOIN workspaces w ON n.workspace_id = w.id
		WHERE n.id = $1 AND (w.owner_id = $2 OR EXISTS(
			SELECT 1 FROM collaborations c
			WHERE c.note_id = n.id AND c.user_id = $2
		)) AND n.deleted_at IS NULL`,
		noteID, userID).Scan(&titleEnc, &contentEnc, &createdAt, &updatedAt)

	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Note not found"})
	}

	// Decrypt content
	titleBytes, err := h.crypto.Decrypt(titleEnc)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to decrypt title"})
	}

	contentBytes, err := h.crypto.Decrypt(contentEnc)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to decrypt content"})
	}

	title := string(titleBytes)
	content := string(contentBytes)

	// Convert content to requested format
	exportedContent, contentType, err := convertFromMarkdown(content, req.Format, title, createdAt, updatedAt)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": fmt.Sprintf("Failed to convert to %s: %s", req.Format, err.Error())})
	}

	return c.JSON(fiber.Map{
		"content":      exportedContent,
		"content_type": contentType,
		"title":        title,
		"format":       req.Format,
		"filename":     generateFilename(title, req.Format),
	})
}

// BulkImport godoc
// @Summary Import multiple notes at once
// @Description Import multiple notes from various formats
// @Tags Import/Export
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body BulkImportRequest true "Bulk import data"
// @Success 201 {object} map[string]interface{} "Notes imported successfully"
// @Failure 400 {object} map[string]interface{} "Invalid request"
// @Router /notes/bulk-import [post]
func (h *ImportExportHandler) BulkImport(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	ctx := context.Background()

	var req BulkImportRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
	}

	if len(req.Files) > 50 {
		return c.Status(400).JSON(fiber.Map{"error": "Too many files (max 50)"})
	}

	// Calculate total size and check overall storage limit
	var totalSize int64
	for _, file := range req.Files {
		totalSize += int64(len(file.Content))
	}

	if err := h.checkStorageLimit(userID, totalSize); err != nil {
		return c.Status(413).JSON(fiber.Map{"error": err.Error()})
	}

	// Get user's default workspace
	var workspaceID uuid.UUID
	err := h.db.QueryRow(ctx, `SELECT id FROM workspaces WHERE owner_id = $1 LIMIT 1`, userID).Scan(&workspaceID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to get workspace"})
	}

	var imported []map[string]interface{}
	var failed []map[string]interface{}
	var totalImportedSize int64

	for i, file := range req.Files {
		// Validate file content and security
		if err := validateFileContent(file.Content, file.Format); err != nil {
			failed = append(failed, map[string]interface{}{
				"index": i,
				"title": file.Title,
				"error": fmt.Sprintf("Invalid file content: %s", err.Error()),
			})
			continue
		}

		// Extract title
		title := file.Title
		if title == "" {
			title = extractTitleFromContent(file.Content, file.Format)
		}
		if title == "" {
			title = file.Filename
		}
		if title == "" {
			title = fmt.Sprintf("Imported Note %d", i+1)
		}

		// Convert content
		content, err := convertToMarkdown(file.Content, file.Format)
		if err != nil {
			failed = append(failed, map[string]interface{}{
				"index": i,
				"title": title,
				"error": fmt.Sprintf("Failed to convert %s: %s", file.Format, err.Error()),
			})
			continue
		}

		// Encrypt and save
		titleEncrypted, err := h.crypto.Encrypt([]byte(title))
		if err != nil {
			failed = append(failed, map[string]interface{}{
				"index": i,
				"title": title,
				"error": "Failed to encrypt title",
			})
			continue
		}

		contentEncrypted, err := h.crypto.Encrypt([]byte(content))
		if err != nil {
			failed = append(failed, map[string]interface{}{
				"index": i,
				"title": title,
				"error": "Failed to encrypt content",
			})
			continue
		}

		noteID := uuid.New()
		_, err = h.db.Exec(ctx, `
			INSERT INTO notes (id, workspace_id, title_encrypted, content_encrypted)
			VALUES ($1, $2, $3, $4)`,
			noteID, workspaceID, titleEncrypted, contentEncrypted)

		if err != nil {
			failed = append(failed, map[string]interface{}{
				"index": i,
				"title": title,
				"error": "Failed to save note",
			})
			continue
		}

		// Track successful import size
		totalImportedSize += int64(len(file.Content))

		imported = append(imported, map[string]interface{}{
			"note_id": noteID,
			"title":   title,
			"format":  file.Format,
		})
	}

	// Update storage usage for all successfully imported files
	if totalImportedSize > 0 {
		if err := h.updateStorageUsage(userID, totalImportedSize); err != nil {
			logRequestError(c, "BulkImport: failed to update storage usage", err, "user_id", userID, "imported_size", totalImportedSize)
			// Note: We don't fail the import here as the notes were already created
		}
	}

	return c.Status(201).JSON(fiber.Map{
		"imported_count": len(imported),
		"failed_count":   len(failed),
		"imported":       imported,
		"failed":         failed,
	})
}

// Helper functions for content conversion
func extractTitleFromContent(content, format string) string {
	switch format {
	case "markdown":
		lines := strings.Split(content, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "# ") {
				return strings.TrimSpace(line[2:])
			}
		}
	case "html":
		// Simple regex to extract title from HTML
		re := regexp.MustCompile(`<title[^>]*>([^<]+)</title>`)
		matches := re.FindStringSubmatch(content)
		if len(matches) > 1 {
			return strings.TrimSpace(matches[1])
		}
		// Try h1 tag
		re = regexp.MustCompile(`<h1[^>]*>([^<]+)</h1>`)
		matches = re.FindStringSubmatch(content)
		if len(matches) > 1 {
			return strings.TrimSpace(matches[1])
		}
	case "text":
		lines := strings.Split(content, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" {
				if len(line) > 50 {
					return line[:50] + "..."
				}
				return line
			}
		}
	case "json":
		var data map[string]interface{}
		if err := json.Unmarshal([]byte(content), &data); err == nil {
			if title, ok := data["title"].(string); ok {
				return title
			}
		}
	}
	return ""
}

func convertToMarkdown(content, format string) (string, error) {
	switch format {
	case "markdown":
		return content, nil
	case "text":
		// Convert plain text to markdown by preserving line breaks
		return strings.ReplaceAll(content, "\n", "\n\n"), nil
	case "html":
		// Basic HTML to Markdown conversion
		// In production, you'd use a proper HTML to Markdown converter
		content = regexp.MustCompile(`<h([1-6])[^>]*>([^<]+)</h[1-6]>`).ReplaceAllString(content, "${1} $2\n")
		content = regexp.MustCompile(`<p[^>]*>([^<]*)</p>`).ReplaceAllString(content, "$1\n\n")
		content = regexp.MustCompile(`<strong[^>]*>([^<]*)</strong>`).ReplaceAllString(content, "**$1**")
		content = regexp.MustCompile(`<em[^>]*>([^<]*)</em>`).ReplaceAllString(content, "*$1*")
		content = regexp.MustCompile(`<br[^>]*>`).ReplaceAllString(content, "\n")
		content = regexp.MustCompile(`<[^>]+>`).ReplaceAllString(content, "")
		return strings.TrimSpace(content), nil
	case "json":
		var data map[string]interface{}
		if err := json.Unmarshal([]byte(content), &data); err != nil {
			return "", err
		}

		if markdownContent, ok := data["content"].(string); ok {
			return markdownContent, nil
		}
		if textContent, ok := data["text"].(string); ok {
			return textContent, nil
		}

		// Convert JSON to markdown representation
		formatted, _ := json.MarshalIndent(data, "", "  ")
		return "```json\n" + string(formatted) + "\n```", nil
	default:
		return "", fmt.Errorf("unsupported format: %s", format)
	}
}

func convertFromMarkdown(content, format, title string, createdAt, updatedAt time.Time) (string, string, error) {
	switch format {
	case "markdown":
		return content, "text/markdown", nil
	case "text":
		// Strip markdown formatting for plain text
		text := content
		text = regexp.MustCompile(`\*\*([^*]+)\*\*`).ReplaceAllString(text, "$1")
		text = regexp.MustCompile(`\*([^*]+)\*`).ReplaceAllString(text, "$1")
		text = regexp.MustCompile(`#{1,6}\s*`).ReplaceAllString(text, "")
		text = regexp.MustCompile(`\[([^\]]+)\]\([^)]+\)`).ReplaceAllString(text, "$1")
		return text, "text/plain", nil
	case "html":
		// Basic markdown to HTML conversion
		html := content
		html = regexp.MustCompile(`^#{6}\s*(.+)$`).ReplaceAllString(html, "<h6>$1</h6>")
		html = regexp.MustCompile(`^#{5}\s*(.+)$`).ReplaceAllString(html, "<h5>$1</h5>")
		html = regexp.MustCompile(`^#{4}\s*(.+)$`).ReplaceAllString(html, "<h4>$1</h4>")
		html = regexp.MustCompile(`^#{3}\s*(.+)$`).ReplaceAllString(html, "<h3>$1</h3>")
		html = regexp.MustCompile(`^#{2}\s*(.+)$`).ReplaceAllString(html, "<h2>$1</h2>")
		html = regexp.MustCompile(`^#{1}\s*(.+)$`).ReplaceAllString(html, "<h1>$1</h1>")
		html = regexp.MustCompile(`\*\*([^*]+)\*\*`).ReplaceAllString(html, "<strong>$1</strong>")
		html = regexp.MustCompile(`\*([^*]+)\*`).ReplaceAllString(html, "<em>$1</em>")
		html = strings.ReplaceAll(html, "\n\n", "</p><p>")
		html = "<p>" + html + "</p>"

		fullHTML := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>%s</title>
    <meta charset="UTF-8">
</head>
<body>
    %s
</body>
</html>`, title, html)

		return fullHTML, "text/html", nil
	case "json":
		data := map[string]interface{}{
			"title":      title,
			"content":    content,
			"created_at": createdAt,
			"updated_at": updatedAt,
			"format":     "markdown",
		}
		jsonBytes, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			return "", "", err
		}
		return string(jsonBytes), "application/json", nil
	default:
		return "", "", fmt.Errorf("unsupported format: %s", format)
	}
}

func generateFilename(title, format string) string {
	// Sanitize title for filename
	filename := regexp.MustCompile(`[^a-zA-Z0-9\-_\s]`).ReplaceAllString(title, "")
	filename = regexp.MustCompile(`\s+`).ReplaceAllString(filename, "_")
	filename = strings.Trim(filename, "_")

	if len(filename) > 50 {
		filename = filename[:50]
	}

	if filename == "" {
		filename = "exported_note"
	}

	switch format {
	case "markdown":
		return filename + ".md"
	case "text":
		return filename + ".txt"
	case "html":
		return filename + ".html"
	case "json":
		return filename + ".json"
	default:
		return filename + ".txt"
	}
}

// WebSocket connection management for real-time collaboration
type Connection struct {
	ID     string
	UserID uuid.UUID
	NoteID uuid.UUID
	Conn   *websocket.Conn
	Send   chan []byte
}

type Hub struct {
	connections map[string]*Connection
	noteUsers   map[uuid.UUID]map[uuid.UUID]*Connection // noteID -> userID -> connection
	register    chan *Connection
	unregister  chan *Connection
	broadcast   chan []byte
	mu          sync.RWMutex
}

type WSMessage struct {
	Type    string      `json:"type"`
	NoteID  string      `json:"note_id,omitempty"`
	UserID  string      `json:"user_id,omitempty"`
	Content interface{} `json:"content,omitempty"`
}

type PresenceMessage struct {
	UserID    string `json:"user_id"`
	UserEmail string `json:"user_email"`
	Status    string `json:"status"` // "online", "offline"
}

type EditMessage struct {
	Operation string `json:"operation"` // "insert", "delete", "replace"
	Position  int    `json:"position"`
	Content   string `json:"content"`
	Timestamp int64  `json:"timestamp"`
}

type CursorMessage struct {
	UserID   string `json:"user_id"`
	Position int    `json:"position"`
	Length   int    `json:"length"`
}

func NewHub() *Hub {
	return &Hub{
		connections: make(map[string]*Connection),
		noteUsers:   make(map[uuid.UUID]map[uuid.UUID]*Connection),
		register:    make(chan *Connection),
		unregister:  make(chan *Connection),
		broadcast:   make(chan []byte),
	}
}

func (h *Hub) Run() {
	for {
		select {
		case conn := <-h.register:
			h.mu.Lock()
			h.connections[conn.ID] = conn

			if h.noteUsers[conn.NoteID] == nil {
				h.noteUsers[conn.NoteID] = make(map[uuid.UUID]*Connection)
			}
			h.noteUsers[conn.NoteID][conn.UserID] = conn
			h.mu.Unlock()

			// Notify others about new user joining
			h.broadcastToNote(conn.NoteID, WSMessage{
				Type:   "presence",
				NoteID: conn.NoteID.String(),
				Content: PresenceMessage{
					UserID: conn.UserID.String(),
					Status: "online",
				},
			}, conn.UserID)

		case conn := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.connections[conn.ID]; ok {
				delete(h.connections, conn.ID)
				if noteConns, exists := h.noteUsers[conn.NoteID]; exists {
					delete(noteConns, conn.UserID)
					if len(noteConns) == 0 {
						delete(h.noteUsers, conn.NoteID)
					}
				}
				close(conn.Send)
			}
			h.mu.Unlock()

			// Notify others about user leaving
			h.broadcastToNote(conn.NoteID, WSMessage{
				Type:   "presence",
				NoteID: conn.NoteID.String(),
				Content: PresenceMessage{
					UserID: conn.UserID.String(),
					Status: "offline",
				},
			}, conn.UserID)
		}
	}
}

func (h *Hub) broadcastToNote(noteID uuid.UUID, message WSMessage, excludeUserID uuid.UUID) {
	h.mu.RLock()
	noteConns := h.noteUsers[noteID]
	h.mu.RUnlock()

	if noteConns == nil {
		return
	}

	data, err := json.Marshal(message)
	if err != nil {
		return
	}

	for userID, conn := range noteConns {
		if userID != excludeUserID {
			select {
			case conn.Send <- data:
			default:
				close(conn.Send)
				delete(noteConns, userID)
			}
		}
	}
}

func (h *Hub) GetConnectedUsers(noteID uuid.UUID) []string {
	h.mu.RLock()
	defer h.mu.RUnlock()

	noteConns := h.noteUsers[noteID]
	if noteConns == nil {
		return []string{}
	}

	users := make([]string, 0, len(noteConns))
	for userID := range noteConns {
		users = append(users, userID.String())
	}
	return users
}

// WebSocket handler for note collaboration with dependencies
func handleWebSocketWithDeps(c *websocket.Conn, hub *Hub, db Database) {
	defer c.Close()

	// Extract note ID, user ID, and token from query params
	noteIDStr := c.Query("note_id")
	userIDStr := c.Query("user_id")
	tokenStr := c.Query("token")

	// Validate JWT token
	if tokenStr == "" {
		log.Printf("WebSocket connection rejected: missing token")
		return
	}

	// Parse and validate JWT token
	config := LoadConfig()
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return config.JWTSecret, nil
	})

	if err != nil || !token.Valid {
		log.Printf("WebSocket connection rejected: invalid token")
		return
	}

	// Extract claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		log.Printf("WebSocket connection rejected: invalid token claims")
		return
	}

	// Verify the user ID matches the token
	tokenUserID, ok := claims["user_id"].(string)
	if !ok || tokenUserID != userIDStr {
		log.Printf("WebSocket connection rejected: user ID mismatch")
		return
	}

	noteID, err := uuid.Parse(noteIDStr)
	if err != nil {
		log.Printf("Invalid note ID: %v", err)
		return
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		log.Printf("Invalid user ID: %v", err)
		return
	}

	// Verify user has access to the note
	ctx := context.Background()
	var hasAccess bool
	err = db.QueryRow(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM notes n
			JOIN workspaces w ON n.workspace_id = w.id
			WHERE n.id = $1 AND w.owner_id = $2 AND n.deleted_at IS NULL
		) OR EXISTS(
			SELECT 1 FROM collaborations c
			WHERE c.note_id = $1 AND c.user_id = $2
		)`, noteID, userID).Scan(&hasAccess)

	if err != nil || !hasAccess {
		log.Printf("User %s does not have access to note %s", userID, noteID)
		return
	}

	// Create connection
	conn := &Connection{
		ID:     uuid.New().String(),
		UserID: userID,
		NoteID: noteID,
		Conn:   c,
		Send:   make(chan []byte, 256),
	}

	hub.register <- conn

	// Handle outgoing messages
	go func() {
		defer func() {
			hub.unregister <- conn
		}()

		for {
			select {
			case message, ok := <-conn.Send:
				if !ok {
					c.WriteMessage(websocket.CloseMessage, []byte{})
					return
				}

				if err := c.WriteMessage(websocket.TextMessage, message); err != nil {
					log.Printf("WebSocket write error: %v", err)
					return
				}
			}
		}
	}()

	// Handle incoming messages
	for {
		var msg WSMessage
		err := c.ReadJSON(&msg)
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("WebSocket error: %v", err)
			}
			break
		}

		// Broadcast the message to other users in the same note
		switch msg.Type {
		case "edit":
			// Handle real-time editing
			hub.broadcastToNote(noteID, WSMessage{
				Type:    "edit",
				NoteID:  noteID.String(),
				UserID:  userID.String(),
				Content: msg.Content,
			}, userID)

		case "cursor":
			// Handle cursor position updates
			hub.broadcastToNote(noteID, WSMessage{
				Type:    "cursor",
				NoteID:  noteID.String(),
				UserID:  userID.String(),
				Content: msg.Content,
			}, userID)

		case "presence":
			// Handle presence updates (typing indicators, etc.)
			hub.broadcastToNote(noteID, WSMessage{
				Type:    "presence",
				NoteID:  noteID.String(),
				UserID:  userID.String(),
				Content: msg.Content,
			}, userID)
		}
	}
}

// JWT Middleware
func JWTMiddleware(secret []byte, redis *redis.Client, crypto *CryptoService) fiber.Handler {
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

// Background cleanup service that runs every 24 hours
func startCleanupService(db Database) {
	go func() {
		ctx := context.Background()
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()

		// Run initial cleanup
		runCleanupTasks(ctx, db)

		for {
			select {
			case <-ticker.C:
				runCleanupTasks(ctx, db)
			}
		}
	}()
}

func runCleanupTasks(ctx context.Context, db Database) {
	log.Println("🧹 Running scheduled cleanup tasks...")

	// Note: Session cleanup is now handled by Redis TTL

	// Reset failed login attempts for users who are no longer locked
	result, err := db.Exec(ctx, `
		UPDATE users
		SET failed_attempts = 0
		WHERE locked_until IS NOT NULL AND locked_until < NOW()
	`)
	if err != nil {
		log.Printf("⚠️ Failed to reset failed login attempts: %v", err)
	} else if result.RowsAffected() > 0 {
		log.Printf("✅ Reset failed login attempts for %d users", result.RowsAffected())
	}

	// Clean up old deleted notes (30+ days)
	_, err2 := db.Exec(ctx, "SELECT cleanup_old_deleted_notes()")
	if err2 != nil {
		log.Printf("⚠️ Failed to cleanup old deleted notes: %v", err2)
	} else {
		log.Println("✅ Cleaned up old deleted notes")
	}

	// Get count of deleted notes
	var deletedCount int
	db.QueryRow(ctx, "SELECT COUNT(*) FROM notes WHERE deleted_at < NOW() - INTERVAL '30 days' AND deleted_at IS NOT NULL").Scan(&deletedCount)

	if deletedCount > 0 {
		log.Printf("🗑️ Permanently deleted %d notes older than 30 days", deletedCount)
	}

	log.Println("🎯 Cleanup tasks completed successfully")
}

// Structured logging setup
var (
	InfoLogger  *log.Logger
	ErrorLogger *log.Logger
)

func initLogging() {
	// Info logs go to stdout
	InfoLogger = log.New(os.Stdout, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)

	// Error logs go to stderr
	ErrorLogger = log.New(os.Stderr, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)

	// Configure default log package to use stderr for errors
	log.SetOutput(os.Stderr)
	log.SetPrefix("SYSTEM: ")
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
}

// logError logs errors with context to stderr
func logError(context string, err error, metadata ...interface{}) {
	if err != nil {
		args := []interface{}{context, err}
		args = append(args, metadata...)
		ErrorLogger.Println(args...)
	}
}

// logInfo logs informational messages to stdout
func logInfo(message string, metadata ...interface{}) {
	args := []interface{}{message}
	args = append(args, metadata...)
	InfoLogger.Println(args...)
}

// logRequestError logs errors with request context to stderr
func logRequestError(c *fiber.Ctx, context string, err error, metadata ...interface{}) {
	if err != nil {
		requestID, _ := c.Locals("request_id").(string)
		userID, _ := c.Locals("user_id").(uuid.UUID)

		args := []interface{}{
			"request_id", requestID,
			"user_id", userID.String(),
			"method", c.Method(),
			"path", c.Path(),
			"ip", c.IP(),
			"context", context,
			"error", err,
		}
		args = append(args, metadata...)
		ErrorLogger.Println(args...)
	}
}

// Default template data
type DefaultTemplate struct {
	Name        string
	Description string
	Content     string
	Tags        []string
	Icon        string
}

var defaultTemplates = []DefaultTemplate{
	{
		Name:        "Meeting Notes",
		Description: "Template for recording meeting discussions and action items",
		Content: `# Meeting Notes

**Date:** ${date}
**Attendees:**
**Duration:**

## Agenda
1.
2.
3.

## Discussion Points
### Topic 1
-
-

### Topic 2
-
-

## Action Items
- [ ] Task 1 - Assigned to: ${person} - Due: ${date}
- [ ] Task 2 - Assigned to: ${person} - Due: ${date}

## Next Meeting
**Date:**
**Topics to discuss:**
-
- `,
		Tags: []string{"meeting", "work", "action-items"},
		Icon: "📝",
	},
	{
		Name:        "Project Planning",
		Description: "Template for planning projects with goals, milestones, and resources",
		Content: `# Project: ${project_name}

## Overview
**Start Date:** ${date}
**End Date:** ${date}
**Project Manager:** ${person}
**Budget:** $

## Goals & Objectives
### Primary Goal
-

### Secondary Goals
-
-

## Project Scope
### Included
-
-

### Excluded
-
-

## Timeline & Milestones
- [ ] **Phase 1:** ${milestone} - Due: ${date}
- [ ] **Phase 2:** ${milestone} - Due: ${date}
- [ ] **Phase 3:** ${milestone} - Due: ${date}

## Resources Required
### Team Members
- ${person} - Role:
- ${person} - Role:

### Tools & Technology
-
-

### Budget Breakdown
- Category 1: $
- Category 2: $
- Total: $

## Risk Assessment
### High Priority Risks
- **Risk:** ${risk} - **Mitigation:** ${strategy}

### Medium Priority Risks
- **Risk:** ${risk} - **Mitigation:** ${strategy}

## Success Criteria
-
-
- `,
		Tags: []string{"project", "planning", "work", "goals"},
		Icon: "📊",
	},
	{
		Name:        "Daily Journal",
		Description: "Template for daily reflection and gratitude practice",
		Content: `# Daily Journal - ${date}

## Today's Mood
Scale 1-10: ___
Overall feeling:

## Gratitude
3 things I'm grateful for today:
1.
2.
3.

## Today's Priorities
### Must Do
- [ ]
- [ ]
- [ ]

### Should Do
- [ ]
- [ ]

### Could Do
- [ ]
- [ ]

## Reflections
### What went well today?
-
-

### What could have been better?
-
-

### What did I learn?
-
-

## Tomorrow's Focus
Main priority:
3 key tasks:
1.
2.
3.

## Random Thoughts
${thoughts}

---
*"Every day is a new beginning."*`,
		Tags: []string{"journal", "personal", "gratitude", "reflection"},
		Icon: "🗒️",
	},
	{
		Name:        "Code Review Checklist",
		Description: "Template for thorough code review documentation",
		Content: `# Code Review: ${feature_name}

**Pull Request:** #${pr_number}
**Author:** ${developer}
**Reviewer:** ${reviewer}
**Date:** ${date}

## Summary
Brief description of changes:


## Review Checklist

### Code Quality
- [ ] Code follows project style guidelines
- [ ] Functions are well-named and focused
- [ ] Code is DRY (Don't Repeat Yourself)
- [ ] Comments explain the "why", not the "what"
- [ ] No commented-out code left behind

### Functionality
- [ ] Code does what it's supposed to do
- [ ] Edge cases are handled
- [ ] Error handling is appropriate
- [ ] Input validation is present where needed

### Performance
- [ ] No obvious performance issues
- [ ] Database queries are optimized
- [ ] Caching used where appropriate
- [ ] No memory leaks

### Security
- [ ] No hardcoded secrets
- [ ] Input sanitization implemented
- [ ] Authorization checks in place
- [ ] HTTPS used for sensitive data

### Testing
- [ ] Unit tests cover new functionality
- [ ] Integration tests updated if needed
- [ ] Test coverage is adequate
- [ ] Tests are meaningful and not just for coverage

## Detailed Comments

### Positive Feedback
-
-

### Issues Found
1. **File:** ${file} **Line:** ${line}
   **Issue:**
   **Suggestion:**

2. **File:** ${file} **Line:** ${line}
   **Issue:**
   **Suggestion:**

## Overall Assessment
- [ ] Approve
- [ ] Approve with minor changes
- [ ] Request changes
- [ ] Major revision needed

**Final Comments:**


**Next Steps:**
- `,
		Tags: []string{"code-review", "development", "quality", "checklist"},
		Icon: "🔍",
	},
	{
		Name:        "Bug Report",
		Description: "Template for documenting software bugs with all necessary details",
		Content: `# Bug Report: ${bug_title}

**Reporter:** ${person}
**Date:** ${date}
**Priority:** [ ] Low [ ] Medium [ ] High [ ] Critical
**Status:** Open

## Environment
- **OS:**
- **Browser/App Version:**
- **Device:**
- **Screen Resolution:**

## Description
Brief summary of the issue:


## Steps to Reproduce
1.
2.
3.
4.

## Expected Behavior
What should happen:


## Actual Behavior
What actually happens:


## Screenshots/Videos
[Attach screenshots or screen recordings if applicable]

## Error Messages
` + "```" + `
[Paste any error messages here]
` + "```" + `

## Console Logs
` + "```" + `
[Paste relevant console logs here]
` + "```" + `

## Additional Context
Any other information that might be helpful:


## Workaround
Temporary solution (if any):


## Related Issues
- Issue #
- Related to:

---

## For Developers

### Investigation Notes
-

### Root Cause
-

### Proposed Solution
-

### Testing Requirements
- [ ] Unit tests
- [ ] Integration tests
- [ ] Manual testing scenarios:
  -
  -

### Deployment Notes
- `,
		Tags: []string{"bug-report", "development", "testing", "issue"},
		Icon: "🐛",
	},
}

// validateEncryptionKeyAndAdminAccess checks for potential admin access issues due to encryption key changes
// Optimized version with combined queries and early exits
func validateEncryptionKeyAndAdminAccess(db Database, crypto *CryptoService, config *Config) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	log.Println("🔍 Validating encryption key and admin access...")

	// Pre-generate admin email search hash to avoid redundant work
	adminEmail := config.DefaultAdminEmail
	currentEmailSearchHash, err := crypto.EncryptDeterministic([]byte(strings.ToLower(adminEmail)), "email_search")
	if err != nil {
		return fmt.Errorf("failed to generate current email search hash: %w", err)
	}

	// Combined query: Check user count and admin existence in a single query for efficiency
	var userCount int
	var adminExists bool
	err = db.QueryRow(ctx, `
		SELECT 
			(SELECT COUNT(*) FROM users) as user_count,
			EXISTS(SELECT 1 FROM users WHERE email_search_hash = $1) as admin_exists
	`, currentEmailSearchHash).Scan(&userCount, &adminExists)
	
	if err != nil {
		return fmt.Errorf("failed to check user status: %w", err)
	}

	if userCount == 0 {
		log.Println("✅ No users found - fresh installation, no key validation needed")
		return nil
	}

	if adminExists {
		log.Printf("✅ Admin user accessible with current encryption key (%d users total)", userCount)
		return nil
	}

	// Admin user not found - check if other users exist with encrypted hashes (indicating key mismatch)
	log.Printf("⚠️  ADMIN ACCESS ISSUE DETECTED!")
	log.Printf("   - Admin email: %s", adminEmail)
	log.Printf("   - Admin user not found with current encryption key")

	// Efficient check: just count users with email_search_hash (indicates encrypted users exist)
	var usersWithHashes int
	err = db.QueryRow(ctx, `SELECT COUNT(*) FROM users WHERE email_search_hash IS NOT NULL AND LENGTH(email_search_hash) > 0`).Scan(&usersWithHashes)
	if err != nil {
		log.Printf("Warning: Could not check for encrypted users, assuming key mismatch: %v", err)
		usersWithHashes = userCount // Assume worst case
	}

	if usersWithHashes > 0 {
		log.Printf("🚨 CRITICAL: Admin user unreachable due to encryption key mismatch!")
		log.Printf("   📊 Found %d users with encrypted hashes (out of %d total)", usersWithHashes, userCount)
		log.Printf("   This likely means the SERVER_ENCRYPTION_KEY has changed")
		log.Printf("")
		log.Printf("🔧 RECOVERY OPTIONS:")
		log.Printf("   1. Restore the original SERVER_ENCRYPTION_KEY if you have it")
		log.Printf("   2. Use the emergency admin recovery endpoint:")
		log.Printf("      POST /api/v1/auth/admin-recovery")
		log.Printf("      Body: {\"email\": \"%s\", \"password\": \"your_password\", \"recovery_token\": \"<token>\", \"confirm_deletion\": true}", adminEmail)
		log.Printf("")
		log.Printf("⚠️  WARNING: Recovery will delete the old admin user and create a new one!")

		return fmt.Errorf("admin user unreachable due to encryption key mismatch - see logs for recovery instructions")
	}

	log.Printf("ℹ️  No users with encrypted hashes found - may be legacy installation")
	return nil
}

// seedDefaultAdminUser creates a default admin user using the AdminService
func seedDefaultAdminUser(db Database, crypto *CryptoService, config *Config) error {
	// Import the services package (this will be handled by Go modules)
	// services "./services" - This will be done via proper import at the top

	// Create admin service instance
	adminService := createAdminService(db, crypto)

	// Validate admin configuration first
	if err := adminService.ValidateAdminConfig(); err != nil {
		log.Printf("❌ Admin configuration validation failed: %v", err)
		return fmt.Errorf("admin configuration invalid: %w", err)
	}

	// Create the default admin user
	if err := adminService.CreateDefaultAdminUser(); err != nil {
		log.Printf("❌ Failed to create default admin user: %v", err)
		return fmt.Errorf("failed to create default admin user: %w", err)
	}

	log.Printf("✅ Admin user management completed successfully")
	log.Printf("🔑 Default password from environment: %s", config.DefaultAdminPassword)
	log.Println("⚠️  SECURITY WARNING: Change the default password immediately!")
	log.Println("📖 See USER_MANAGEMENT.md for user management instructions")

	return nil
}

// createAdminService creates an AdminService instance (adapter function)
func createAdminService(db Database, crypto *CryptoService) AdminServiceInterface {
	return &adminServiceImpl{
		db:     db,
		crypto: crypto,
	}
}

// AdminServiceInterface defines the interface for admin service operations
type AdminServiceInterface interface {
	ValidateAdminConfig() error
	CreateDefaultAdminUser() error
}

// adminServiceImpl implements AdminServiceInterface using the services package logic
type adminServiceImpl struct {
	db     Database
	crypto *CryptoService
}

func (a *adminServiceImpl) ValidateAdminConfig() error {
	config := getAdminConfigFromEnv()
	
	if !config.Enabled {
		return nil
	}

	if config.Email == "" {
		return errors.New("admin email cannot be empty")
	}

	if !isValidAdminEmail(config.Email) {
		return fmt.Errorf("invalid admin email format: %s", config.Email)
	}

	if err := validateAdminPassword(config.Password); err != nil {
		return fmt.Errorf("admin password validation failed: %w", err)
	}

	return nil
}

func (a *adminServiceImpl) CreateDefaultAdminUser() error {
	config := getAdminConfigFromEnv()
	
	if !config.Enabled {
		log.Println("⏭️ Default admin user creation is disabled")
		return nil
	}

	log.Printf("🔧 Starting default admin user creation process...")
	log.Printf("   - Email: %s", config.Email)
	log.Printf("   - Password length: %d characters", len(config.Password))
	if len(config.Password) > 0 {
		log.Printf("   - Password starts with: %c", config.Password[0])
		log.Printf("   - Password ends with: %c", config.Password[len(config.Password)-1])
	}

	// Check if admin user already exists
	exists, err := a.adminUserExists(config.Email)
	if err != nil {
		return fmt.Errorf("failed to check admin user existence: %w", err)
	}

	if exists {
		log.Printf("ℹ️ Admin user already exists with email: %s", config.Email)
		return nil
	}

	// Create the admin user using the same logic as the original function
	return a.createAdminUserInDatabase(config)
}

// Helper functions for the admin service implementation

type adminConfigStruct struct {
	Enabled  bool
	Email    string
	Password string
}

func getAdminConfigFromEnv() adminConfigStruct {
	return adminConfigStruct{
		Enabled:  getEnvAsBool("ENABLE_DEFAULT_ADMIN", true),
		Email:    getEnvOrDefault("DEFAULT_ADMIN_EMAIL", "admin@leaflock.app"),
		Password: getEnvOrDefault("DEFAULT_ADMIN_PASSWORD", "AdminPass123!"),
	}
}

func isValidAdminEmail(email string) bool {
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	return emailRegex.MatchString(email)
}

func validateAdminPassword(password string) error {
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters long")
	}

	if len(password) > 128 {
		return errors.New("password must be less than 128 characters long")
	}

	// Check for at least one uppercase, one lowercase, one digit, and one special char
	hasUpper := regexp.MustCompile(`[A-Z]`).MatchString(password)
	hasLower := regexp.MustCompile(`[a-z]`).MatchString(password)
	hasDigit := regexp.MustCompile(`[0-9]`).MatchString(password)
	hasSpecial := regexp.MustCompile(`[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\?]`).MatchString(password)

	if !hasUpper {
		return errors.New("password must contain at least one uppercase letter")
	}
	if !hasLower {
		return errors.New("password must contain at least one lowercase letter")
	}
	if !hasDigit {
		return errors.New("password must contain at least one digit")
	}
	if !hasSpecial {
		return errors.New("password must contain at least one special character")
	}

	return nil
}

func (a *adminServiceImpl) adminUserExists(email string) (bool, error) {
	ctx := context.Background()
	
	// Generate the email search hash using the crypto service (same as original)
	emailSearchHash, err := a.crypto.EncryptDeterministic([]byte(strings.ToLower(email)), "email_search")
	if err != nil {
		return false, fmt.Errorf("failed to generate email search hash: %w", err)
	}

	// Check if admin user exists with current encryption key
	var existingAdminID uuid.UUID
	err = a.db.QueryRow(ctx, `SELECT id FROM users WHERE email_search_hash = $1`, emailSearchHash).Scan(&existingAdminID)
	if err == nil {
		log.Printf("✅ Default admin user already exists and is accessible (ID: %s)", existingAdminID)
		return true, nil
	}

	// Check if this is a "no rows" error (user doesn't exist)
	if err.Error() == "no rows in result set" {
		return false, nil
	}

	// Some other database error occurred
	return false, fmt.Errorf("database query failed: %w", err)
}

func (a *adminServiceImpl) createAdminUserInDatabase(config adminConfigStruct) error {
	ctx := context.Background()

	// Check for any encryption key mismatches first
	var totalUserCount int
	err := a.db.QueryRow(ctx, `SELECT COUNT(*) FROM users`).Scan(&totalUserCount)
	if err != nil {
		return fmt.Errorf("failed to check existing users: %w", err)
	}

	if totalUserCount > 0 {
		log.Printf("⚠️  Admin user not accessible with current encryption key, but %d other users exist", totalUserCount)
		log.Printf("   This indicates a SERVER_ENCRYPTION_KEY mismatch.")
		log.Printf("   Creating new admin user with current key...")
		log.Printf("   Use /api/v1/auth/admin-recovery to clean up old unreachable users if needed.")
	} else {
		log.Println("🔐 No users found - creating default admin user...")
	}

	log.Println("⚠️  WARNING: Default admin credentials are insecure. Please change them immediately after first login!")

	// Generate salt for password hashing (same as main.go)
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	// Hash password with Argon2id (same as main.go)
	passwordHash := HashPassword(config.Password, salt)

	// Generate user's master encryption key (same as main.go)
	masterKey := make([]byte, 32)
	if _, err := rand.Read(masterKey); err != nil {
		return fmt.Errorf("failed to generate master key: %w", err)
	}

	// Derive key from password to encrypt master key (same as main.go)
	userKey := argon2.IDKey([]byte(config.Password), salt, 1, 64*1024, 4, 32)

	// Encrypt master key with user's derived key (same as main.go)
	aead, err := chacha20poly1305.NewX(userKey)
	if err != nil {
		return fmt.Errorf("failed to initialize encryption: %w", err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	masterKeyEncrypted := aead.Seal(nonce, nonce, masterKey, nil)

	// Generate GDPR deletion key for email encryption (same as main.go)
	deletionKey := make([]byte, 32)
	if _, err := rand.Read(deletionKey); err != nil {
		return fmt.Errorf("failed to generate GDPR deletion key: %w", err)
	}

	// Create email hash for uniqueness and GDPR lookups (same as main.go)
	emailHash := a.crypto.HashEmail(config.Email)

	// Encrypt email with GDPR key (same as main.go)
	emailEncrypted, err := a.crypto.EncryptWithGDPRKey([]byte(config.Email), deletionKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt email: %w", err)
	}

	// Generate email search hash (same as main.go)
	emailSearchHash, err := a.crypto.EncryptDeterministic([]byte(strings.ToLower(config.Email)), "email_search")
	if err != nil {
		return fmt.Errorf("failed to generate email search hash: %w", err)
	}

	// Start transaction (same as main.go)
	tx, err := a.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to start transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	// Store GDPR deletion key (same as main.go)
	_, err = tx.Exec(ctx, `
		INSERT INTO gdpr_keys (email_hash, deletion_key)
		VALUES ($1, $2)`,
		emailHash, deletionKey,
	)
	if err != nil {
		return fmt.Errorf("failed to store GDPR deletion key: %w", err)
	}

	// Insert default admin user (same as main.go)
	_, err = tx.Exec(ctx, `
		INSERT INTO users (
			email_hash, email_encrypted, email_search_hash,
			password_hash, salt, master_key_encrypted,
			is_admin, mfa_enabled, failed_attempts
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`, emailHash, emailEncrypted, emailSearchHash, passwordHash, salt, masterKeyEncrypted, true, false, 0)

	if err != nil {
		return fmt.Errorf("failed to create default admin user: %w", err)
	}

	// Commit transaction
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit admin user creation: %w", err)
	}

	log.Printf("✅ Created default admin user: %s", config.Email)
	log.Printf("🔑 Default password: %s", config.Password)
	log.Println("⚠️  SECURITY WARNING: Change the default password immediately!")
	log.Println("📖 See USER_MANAGEMENT.md for user management instructions")

	return nil
}

// seedDefaultTemplates creates default public templates if they don't exist
func seedDefaultTemplates(db Database, crypto *CryptoService) error {
	ctx := context.Background()

	// Check if we already have default templates
	var count int
	err := db.QueryRow(ctx, `SELECT COUNT(*) FROM templates WHERE tags @> ARRAY['system']`).Scan(&count)
	if err != nil {
		return fmt.Errorf("failed to check existing templates: %w", err)
	}

	if count > 0 {
		log.Println("Default templates already exist, skipping seed")
		return nil
	}

	log.Println("Seeding default templates...")

	for _, template := range defaultTemplates {
		// Encrypt template data
		nameEncrypted, err := crypto.Encrypt([]byte(template.Name))
		if err != nil {
			return fmt.Errorf("failed to encrypt template name '%s': %w", template.Name, err)
		}

		descriptionEncrypted, err := crypto.Encrypt([]byte(template.Description))
		if err != nil {
			return fmt.Errorf("failed to encrypt template description '%s': %w", template.Name, err)
		}

		contentEncrypted, err := crypto.Encrypt([]byte(template.Content))
		if err != nil {
			return fmt.Errorf("failed to encrypt template content '%s': %w", template.Name, err)
		}

		// Add 'system' tag to identify default templates
		tags := append(template.Tags, "system")

		// Insert template
		_, err = db.Exec(ctx, `
			INSERT INTO templates (user_id, name_encrypted, description_encrypted, content_encrypted, tags, icon, is_public, usage_count)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		`, nil, nameEncrypted, descriptionEncrypted, contentEncrypted, tags, template.Icon, true, 0)
		if err != nil {
			return fmt.Errorf("failed to insert template '%s': %w", template.Name, err)
		}

		log.Printf("✅ Created default template: %s", template.Name)
	}

	log.Printf("Successfully seeded %d default templates", len(defaultTemplates))
	return nil
}

func main() {
	// Track startup timing
	startupStart := time.Now()
	log.Printf("🚀 Starting LeafLock backend (PID: %d)...", os.Getpid())

	// Initialize logging
	initLogging()
	log.Printf("⏱️  Logging initialized in %v", time.Since(startupStart))

	// Load configuration
	configStart := time.Now()
	config := LoadConfig()
	trustProxyHeaders.Store(config.TrustProxyHeaders)
	log.Printf("⏱️  Configuration loaded in %v", time.Since(configStart))

	// Track application start time for uptime calculation
	startTime := time.Now()

	// Initialize runtime toggle from env (default true)
	envRegRaw, envRegExplicit := os.LookupEnv("ENABLE_REGISTRATION")
	envRegValue := strings.ToLower(strings.TrimSpace(envRegRaw))
	if !envRegExplicit || envRegValue == "" {
		envRegValue = "true"
	}
	if envRegValue == "true" {
		regEnabled.Store(1)
	} else {
		regEnabled.Store(0)
	}

	// Parse startup optimization flags with defaults optimized for Coolify
	skipMigrationCheck := os.Getenv("SKIP_MIGRATION_CHECK") == "true" // Default: false (always run migrations)
	lazyInitAdmin := os.Getenv("LAZY_INIT_ADMIN") != "false" // Default: true (async admin creation)
	asyncTemplateSeed := os.Getenv("ASYNC_TEMPLATE_SEED") != "false" // Default: true (async template seeding)

	// Setup database with conditional migrations
	dbStart := time.Now()
	var db *pgxpool.Pool
	var err error
	if skipMigrationCheck {
		log.Println("⚡ Skipping migration check for faster startup")
		db, err = SetupDatabaseFast(config.DatabaseURL)
	} else {
		db, err = SetupDatabase(config.DatabaseURL)
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
	defer rdb.Close()
	log.Printf("⏱️  Redis client initialized in %v", time.Since(redisStart))

	// Initialize crypto service
	cryptoStart := time.Now()
	crypto := NewCryptoService(config.EncryptionKey)
	log.Printf("⏱️  Crypto service initialized in %v", time.Since(cryptoStart))

	// Initialize readiness state
	readyState := &ReadyState{
		db:     db,
		crypto: crypto,
		config: config,
		rdb:    rdb,
	}

	// Create Fiber app first to enable health endpoints
	appStart := time.Now()
	app := createFiberApp(startTime, readyState)
	log.Printf("⏱️  Fiber app created in %v", time.Since(appStart))

	// Setup routes
	routeStart := time.Now()
	setupRoutes(app, db, rdb, crypto, config, startTime, readyState)
	log.Printf("⏱️  Routes setup completed in %v", time.Since(routeStart))

	// Start server in background to handle health checks immediately
	port := config.Port
	go func() {
		log.Printf("🌐 HTTP server starting on port %s (startup time: %v)", port, time.Since(startupStart))
		if err := app.Listen(":" + port); err != nil {
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
			if err := validateEncryptionKeyAndAdminAccess(db, crypto, config); err != nil {
				log.Printf("⚠️  ENCRYPTION KEY WARNING: %v", err)
			}
		} else {
			log.Println("⏭️ Skipping admin validation (SKIP_ADMIN_VALIDATION=true)")
		}
	}()

	// Initialize admin user (conditional async)
	if lazyInitAdmin {
		log.Println("⚡ Starting admin user initialization asynchronously")
		go func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("❌ PANIC in admin user initialization: %v", r)
				}
				readyState.markAdminReady()
			}()
			if err := seedDefaultAdminUser(db, crypto, config); err != nil {
				log.Printf("Warning: Failed to create default admin user: %v", err)
			} else {
				log.Printf("✅ Admin user initialization completed")
			}
		}()
	} else {
		adminStart := time.Now()
		if err := seedDefaultAdminUser(db, crypto, config); err != nil {
			log.Printf("Warning: Failed to create default admin user: %v", err)
		}
		log.Printf("⏱️  Admin user initialization completed in %v", time.Since(adminStart))
		readyState.markAdminReady()
	}

	// Initialize templates (conditional async)
	if asyncTemplateSeed {
		log.Println("⚡ Starting template seeding asynchronously")
		go func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("❌ PANIC in template seeding: %v", r)
				}
				readyState.markTemplatesReady()
			}()
			if err := seedDefaultTemplates(db, crypto); err != nil {
				log.Printf("Warning: Failed to seed default templates: %v", err)
			} else {
				log.Printf("✅ Template seeding completed")
			}
		}()
	} else {
		templateStart := time.Now()
		if err := seedDefaultTemplates(db, crypto); err != nil {
			log.Printf("Warning: Failed to seed default templates: %v", err)
		}
		log.Printf("⏱️  Template seeding completed in %v", time.Since(templateStart))
		readyState.markTemplatesReady()
	}

	// Start admin allowlist refresher
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("❌ PANIC in admin allowlist refresher: %v", r)
			}
			readyState.markAllowlistReady()
		}()
		startAdminAllowlistRefresher()
		log.Printf("✅ Admin allowlist refresher started")
	}()

	// Pre-warm Redis connection pool in background
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("❌ PANIC in Redis prewarming: %v", r)
			}
			readyState.markRedisReady()
		}()
		prewarmStart := time.Now()
		prewarmRedisPool(rdb)
		log.Printf("✅ Redis connection pool pre-warmed in %v", time.Since(prewarmStart))
	}()

	log.Printf("⏱️  Async initialization tasks started in %v", time.Since(initStart))
	log.Printf("🎯 Basic startup completed in %v - server is live!", time.Since(startupStart))

	// Wait for server to exit (blocks here)
	select {}
}
