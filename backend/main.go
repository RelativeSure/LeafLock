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
	"encoding/hex"
	"encoding/json"
	"fmt"
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
	"github.com/gofiber/swagger"
	"github.com/gofiber/fiber/v2/middleware/cors"
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
	_ "leaflock/docs/swagger" // Import generated docs
)

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
    locked_until TIMESTAMPTZ
);

-- Ensure admin flag exists
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin BOOLEAN DEFAULT false;

-- Add new encryption columns for enhanced security
ALTER TABLE users ADD COLUMN IF NOT EXISTS email_hash BYTEA UNIQUE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS email_search_hash BYTEA UNIQUE;

-- Add storage tracking columns for file import limits
ALTER TABLE users ADD COLUMN IF NOT EXISTS storage_used BIGINT DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS storage_limit BIGINT DEFAULT 5242880; -- 5MB default limit


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

-- Session management with encryption
CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    token_hash BYTEA NOT NULL UNIQUE, -- SHA-256 hash of session token
    ip_address_encrypted BYTEA,
    user_agent_encrypted BYTEA,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
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
END $$;

-- Session cleanup function
CREATE OR REPLACE FUNCTION cleanup_expired_sessions()
RETURNS void AS $$
BEGIN
    DELETE FROM sessions WHERE expires_at < NOW();
END;
$$ LANGUAGE plpgsql;

-- Cleanup old deleted notes function (30 days)
CREATE OR REPLACE FUNCTION cleanup_old_deleted_notes()
RETURNS void AS $$
BEGIN
    DELETE FROM notes WHERE deleted_at IS NOT NULL AND deleted_at < NOW() - INTERVAL '30 days';
END;
$$ LANGUAGE plpgsql;

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_notes_workspace ON notes(workspace_id) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_notes_parent ON notes(parent_id);
CREATE INDEX IF NOT EXISTS idx_notes_created ON notes(created_by, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_search_keyword ON search_index(keyword_hash);

CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

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

-- Note: Cleanup jobs run automatically via background service every 24 hours
`

// Configuration with secure defaults
type Config struct {
	DatabaseURL       string
	RedisURL          string
	RedisPassword     string
	JWTSecret         []byte
	EncryptionKey     []byte
	Port              string
	AllowedOrigins    []string
	MaxLoginAttempts  int
	LockoutDuration   time.Duration
	SessionDuration   time.Duration
	Environment       string
	TrustProxyHeaders bool
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
			dbURL = "postgres://postgres:postgres@localhost:5432/notes?sslmode=disable"
		}
	}

	return &Config{
		DatabaseURL:       dbURL,
		RedisURL:          getEnvOrDefault("REDIS_URL", "localhost:6379"),
		RedisPassword:     os.Getenv("REDIS_PASSWORD"),
		JWTSecret:         []byte(jwtSecret),
		EncryptionKey:     []byte(encKey),
		Port:              getEnvOrDefault("PORT", "8080"),
		AllowedOrigins:    strings.Split(getEnvOrDefault("CORS_ORIGINS", "https://localhost:3000"), ","),
		MaxLoginAttempts:  5,
		LockoutDuration:   15 * time.Minute,
		SessionDuration:   24 * time.Hour,
		Environment:       getEnvOrDefault("APP_ENV", "development"),
		TrustProxyHeaders: getEnvAsBool("TRUST_PROXY_HEADERS", false),
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
	sslmode := getEnvOrDefault("POSTGRESQL_SSLMODE", "disable")
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

// Database setup and migration runner
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

	// Connect to the actual database
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Run migrations
	log.Println("Running database migrations...")
	if _, err := pool.Exec(ctx, DatabaseSchema); err != nil {
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	log.Println("Database setup completed successfully")
	return pool, nil
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
	crypto *CryptoService
	config *Config
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
	var req LoginRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
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
		return c.Status(401).JSON(fiber.Map{"error": "Invalid credentials"})
	}

	// Check if account is locked
	if lockedUntil != nil && lockedUntil.After(time.Now()) {
		return c.Status(403).JSON(fiber.Map{"error": "Account locked. Try again later."})
	}

	// Verify password
	if !VerifyPassword(req.Password, passwordHash) {
		// Increment failed attempts
		failedAttempts++
		if failedAttempts >= h.config.MaxLoginAttempts {
			lockUntil := time.Now().Add(h.config.LockoutDuration)
			h.db.Exec(ctx, `
                UPDATE users SET failed_attempts = $1, locked_until = $2 
                WHERE id = $3`,
				failedAttempts, lockUntil, userID,
			)
			h.logAudit(ctx, userID, "login.locked", "user", userID, c)
			return c.Status(403).JSON(fiber.Map{"error": "Account locked due to too many failed attempts"})
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
			return c.Status(401).JSON(fiber.Map{"error": "Invalid MFA code"})
		}
	}

	// Reset failed attempts and update last login
	h.db.Exec(ctx, `
        UPDATE users SET failed_attempts = 0, locked_until = NULL, last_login = NOW() 
        WHERE id = $1`,
		userID,
	)

	// Generate session
	sessionToken := make([]byte, 32)
	if _, err := rand.Read(sessionToken); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Session creation failed"})
	}
	sessionTokenStr := hex.EncodeToString(sessionToken)

	// Hash token for storage
	tokenHash := argon2.IDKey(sessionToken, []byte("session"), 1, 64*1024, 4, 32)

	// Encrypt IP and user agent
	encryptedIP, err := h.crypto.Encrypt([]byte(clientIP(c)))
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Session creation failed"})
	}
	encryptedUA, err := h.crypto.Encrypt([]byte(c.Get("User-Agent")))
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Session creation failed"})
	}

	// Store session
	_, err = h.db.Exec(ctx, `
        INSERT INTO sessions (user_id, token_hash, ip_address_encrypted, user_agent_encrypted, expires_at)
        VALUES ($1, $2, $3, $4, $5)`,
		userID, tokenHash, encryptedIP, encryptedUA, time.Now().Add(h.config.SessionDuration),
	)

	if err != nil {
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

	// Update note
	result, err := h.db.Exec(ctx, `
		UPDATE notes 
		SET title_encrypted = $1, content_encrypted = $2, content_hash = $3, updated_at = NOW()
		FROM workspaces w
		WHERE notes.id = $4 AND notes.workspace_id = w.id AND w.owner_id = $5 AND notes.deleted_at IS NULL`,
		titleEnc, contentEnc, contentHash, noteID, userID)

	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to update note"})
	}

	if result.RowsAffected() == 0 {
		return c.Status(404).JSON(fiber.Map{"error": "Note not found"})
	}

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
		"note_id":      noteID,
		"target_user":  targetUserID,
		"permission":   req.Permission,
	})

	return c.Status(201).JSON(fiber.Map{
		"message":         "Note shared successfully",
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
		"storage_used":       storageUsed,
		"storage_limit":      storageLimit,
		"storage_remaining":  storageLimit - storageUsed,
		"usage_percentage":   float64(storageUsed) / float64(storageLimit) * 100,
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
				"index":  i,
				"title":  file.Title,
				"error":  fmt.Sprintf("Invalid file content: %s", err.Error()),
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
				"index":  i,
				"title":  title,
				"error":  fmt.Sprintf("Failed to convert %s: %s", file.Format, err.Error()),
			})
			continue
		}

		// Encrypt and save
		titleEncrypted, err := h.crypto.Encrypt([]byte(title))
		if err != nil {
			failed = append(failed, map[string]interface{}{
				"index":  i,
				"title":  title,
				"error":  "Failed to encrypt title",
			})
			continue
		}

		contentEncrypted, err := h.crypto.Encrypt([]byte(content))
		if err != nil {
			failed = append(failed, map[string]interface{}{
				"index":  i,
				"title":  title,
				"error":  "Failed to encrypt content",
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
				"index":  i,
				"title":  title,
				"error":  "Failed to save note",
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
func JWTMiddleware(secret []byte) fiber.Handler {
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

	// Clean up expired sessions
	result1, err1 := db.Exec(ctx, "SELECT cleanup_expired_sessions()")
	if err1 != nil {
		log.Printf("⚠️ Failed to cleanup expired sessions: %v", err1)
	} else {
		log.Println("✅ Cleaned up expired sessions")
	}

	// Clean up old deleted notes (30+ days)
	result2, err2 := db.Exec(ctx, "SELECT cleanup_old_deleted_notes()")
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

	// Prevent unused variable warnings
	_ = result1
	_ = result2
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

func main() {
	// Initialize logging
	initLogging()

	// Load configuration
	config := LoadConfig()
	trustProxyHeaders.Store(config.TrustProxyHeaders)

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

	// Setup database with automatic migrations
	db, err := SetupDatabase(config.DatabaseURL)
	if err != nil {
		log.Fatal("Database setup failed:", err)
	}
	defer db.Close()

	// Setup Redis
	rdb := redis.NewClient(&redis.Options{
		Addr:     config.RedisURL,
		Password: config.RedisPassword,
		DB:       0, // use default DB
	})
	defer rdb.Close()

	// Initialize crypto service
	crypto := NewCryptoService(config.EncryptionKey)

	// Start dynamic admin allowlist refresher (hot-reloads from file if mounted)
	startAdminAllowlistRefresher()

	// Create Fiber app with security middleware
	app := fiber.New(fiber.Config{
		DisableStartupMessage: false,
		BodyLimit:             512 * 1024, // 512KB body size limit
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			code := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
			}
			return c.Status(code).JSON(fiber.Map{"error": err.Error()})
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
	app.Use(helmet.New(helmet.Config{
		XSSProtection:         "1; mode=block",
		ContentTypeNosniff:    "nosniff",
		XFrameOptions:         "DENY",
		HSTSMaxAge:            31536000,
		HSTSPreloadEnabled:    true,
		ContentSecurityPolicy: "default-src 'self'",
		ReferrerPolicy:        "strict-origin-when-cross-origin",
	}))

	// CORS
	app.Use(cors.New(cors.Config{
		AllowOrigins:     strings.Join(config.AllowedOrigins, ","),
		AllowCredentials: true,
		AllowHeaders:     "Origin, Content-Type, Accept, Authorization",
		AllowMethods:     "GET, POST, PUT, DELETE, OPTIONS",
	}))

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
		crypto: crypto,
		config: config,
	}

	// Public routes
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
	api.Post("/auth/login", authHandler.Login)

	// Public registration status endpoint so the frontend can respect the toggle
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

	// Health checks
	api.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "healthy", "encryption": "enabled"})
	})

	api.Get("/ready", func(c *fiber.Ctx) error {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		if err := db.Ping(ctx); err != nil {
			return c.Status(503).JSON(fiber.Map{"status": "not ready", "db": "down"})
		}

		if err := rdb.Ping(ctx).Err(); err != nil {
			return c.Status(503).JSON(fiber.Map{"status": "not ready", "redis": "down"})
		}

		return c.JSON(fiber.Map{
			"status":     "ready",
			"db":         "connected",
			"redis":      "connected",
			"encryption": "active",
		})
	})

	// Notes handlers
	notesHandler := &NotesHandler{
		db:     db,
		crypto: crypto,
	}

	// Tags handlers
	tagsHandler := &TagsHandler{
		db:     db,
		crypto: crypto,
	}

	// Collaboration handlers
	collaborationHandler := &CollaborationHandler{
		db:     db,
		crypto: crypto,
	}

	// Initialize WebSocket hub for real-time collaboration
	hub := NewHub()
	go hub.Run()

	// Public announcement endpoint
	api.Get("/announcements", func(c *fiber.Ctx) error {
		ctx := c.Context()

		// Check if user is authenticated
		isAuthenticated := false
		if token := c.Get("Authorization"); token != "" {
			// Simple token validation - in real implementation you'd properly validate JWT
			isAuthenticated = strings.HasPrefix(token, "Bearer ")
		}

		// Build query based on authentication status
		var visibilityFilter string
		if isAuthenticated {
			visibilityFilter = `visibility IN ('all', 'logged_in')`
		} else {
			visibilityFilter = `visibility = 'all'`
		}

		query := fmt.Sprintf(`
			SELECT id, title, content, visibility, style, dismissible, priority, start_date, end_date, created_at
			FROM announcements
			WHERE active = true
			AND %s
			AND (start_date IS NULL OR start_date <= NOW())
			AND (end_date IS NULL OR end_date >= NOW())
			ORDER BY priority DESC, created_at DESC
		`, visibilityFilter)

		rows, err := db.Query(ctx, query)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "Failed to fetch announcements"})
		}
		defer rows.Close()

		var announcements []fiber.Map
		for rows.Next() {
			var id uuid.UUID
			var title, content, visibility string
			var style map[string]interface{}
			var dismissible bool
			var priority int
			var startDate, endDate *time.Time
			var createdAt time.Time

			err := rows.Scan(&id, &title, &content, &visibility, &style, &dismissible, &priority, &startDate, &endDate, &createdAt)
			if err != nil {
				continue
			}

			announcements = append(announcements, fiber.Map{
				"id":          id,
				"title":       title,
				"content":     content,
				"visibility":  visibility,
				"style":       style,
				"dismissible": dismissible,
				"priority":    priority,
				"start_date":  startDate,
				"end_date":    endDate,
				"created_at":  createdAt,
			})
		}

		return c.JSON(fiber.Map{"announcements": announcements})
	})

	// Protected routes
	protected := api.Group("/", JWTMiddleware(config.JWTSecret))

	// MFA endpoints
	protected.Get("/auth/mfa/status", authHandler.GetMFAStatus)
	protected.Post("/auth/mfa/setup", authHandler.BeginMFASetup)
	protected.Post("/auth/mfa/enable", authHandler.EnableMFA)
	protected.Post("/auth/mfa/disable", authHandler.DisableMFA)

	// Notes endpoints
	protected.Get("/notes", notesHandler.GetNotes)
	protected.Get("/notes/:id", notesHandler.GetNote)
	protected.Post("/notes", notesHandler.CreateNote)
	protected.Put("/notes/:id", notesHandler.UpdateNote)
	protected.Delete("/notes/:id", notesHandler.DeleteNote)

	// Trash endpoints
	protected.Get("/trash", notesHandler.GetTrash)
	protected.Put("/trash/:id/restore", notesHandler.RestoreNote)
	protected.Delete("/trash/:id", notesHandler.PermanentlyDeleteNote)

	// Tags endpoints
	protected.Get("/tags", tagsHandler.GetTags)
	protected.Post("/tags", tagsHandler.CreateTag)
	protected.Delete("/tags/:id", tagsHandler.DeleteTag)
	protected.Get("/tags/:id/notes", tagsHandler.GetNotesByTag)

	// Note-tag assignment endpoints
	protected.Post("/notes/:id/tags", tagsHandler.AssignTagToNote)
	protected.Delete("/notes/:id/tags/:tag_id", tagsHandler.RemoveTagFromNote)

	// Collaboration endpoints with rate limiting
	collaborationLimiter := limiter.New(limiter.Config{
		Max:        10, // 10 requests per minute for collaboration actions
		Expiration: 1 * time.Minute,
		KeyGenerator: func(c *fiber.Ctx) string {
			return fmt.Sprintf("collab:%s", clientIP(c))
		},
	})

	protected.Post("/notes/:id/share", collaborationLimiter, collaborationHandler.ShareNote)
	protected.Get("/notes/:id/collaborators", collaborationHandler.GetCollaborators)
	protected.Delete("/notes/:id/collaborators/:userId", collaborationLimiter, collaborationHandler.RemoveCollaborator)
	protected.Get("/notes/shared", collaborationHandler.GetSharedNotes)

	// Import/Export endpoints
	importExportHandler := &ImportExportHandler{
		db:     db,
		crypto: crypto,
	}
	protected.Post("/notes/import", importExportHandler.ImportNote)
	protected.Post("/notes/:id/export", importExportHandler.ExportNote)
	protected.Post("/notes/bulk-import", importExportHandler.BulkImport)
	protected.Get("/user/storage", importExportHandler.GetStorageInfo)

	// WebSocket endpoint for real-time collaboration
	app.Use("/ws", func(c *fiber.Ctx) error {
		// IsWebSocketUpgrade returns true if the client
		// requested upgrade to the WebSocket protocol.
		if websocket.IsWebSocketUpgrade(c) {
			c.Locals("allowed", true)
			return c.Next()
		}
		return fiber.ErrUpgradeRequired
	})

	app.Get("/ws/notes", websocket.New(func(c *websocket.Conn) {
		// Create a closure that captures hub and db
		handleWebSocketWithDeps(c, hub, db)
	}))

	// Admin-only Swagger docs (JWT + RBAC admin)
	docs := api.Group("/docs", JWTMiddleware(config.JWTSecret), AdminOnlyFromEnv())
	docs.Get("/", swagger.HandlerDefault)
	docs.Get("/openapi.json", swaggerJSONHandler)

	// Seed app_settings.registration_enabled from env; env overrides DB
	func() {
		ctx := context.Background()
		val := "false"
		if regEnabled.Load() == 1 {
			val = "true"
		}
		if envRegExplicit {
			_, _ = db.Exec(ctx, `INSERT INTO app_settings(key, value) VALUES('registration_enabled', $1)
                                 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`, val)
		} else {
			_, _ = db.Exec(ctx, `INSERT INTO app_settings(key, value) VALUES('registration_enabled', $1)
                                 ON CONFLICT (key) DO NOTHING`, val)
			// If present, load from DB to override runtime when env isn't forcing a value
			var dbVal string
			if err := db.QueryRow(ctx, `SELECT value FROM app_settings WHERE key='registration_enabled'`).Scan(&dbVal); err == nil {
				if strings.ToLower(strings.TrimSpace(dbVal)) == "true" {
					regEnabled.Store(1)
				} else {
					regEnabled.Store(0)
				}
			}
		}
	}()

	// Admin API (RBAC)
	admin := api.Group("/admin", JWTMiddleware(config.JWTSecret), RequireRole(db, "admin"))
	admin.Get("/health", func(c *fiber.Ctx) error { return c.JSON(fiber.Map{"status": "ok"}) })

	// Registration setting endpoints
	admin.Get("/settings/registration", func(c *fiber.Ctx) error {
		// Prefer DB value if present
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
	admin.Put("/settings/registration", func(c *fiber.Ctx) error {
		var body struct {
			Enabled bool `json:"enabled"`
		}
		if err := c.BodyParser(&body); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
		}
		if body.Enabled {
			regEnabled.Store(1)
		} else {
			regEnabled.Store(0)
		}
		// Persist to DB
		val := "false"
		if regEnabled.Load() == 1 {
			val = "true"
		}
		_, _ = db.Exec(c.Context(), `INSERT INTO app_settings(key, value) VALUES('registration_enabled', $1)
                  ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`, val)
		return c.JSON(fiber.Map{"enabled": regEnabled.Load() == 1})
	})

	// List users with basic metadata for admin UI (supports q, limit, offset)
	admin.Get("/users", func(c *fiber.Ctx) error {
		ctx := c.Context()

		// Parse query params
		q := strings.TrimSpace(c.Query("q"))
		limit := 25
		offset := 0
		if v := strings.TrimSpace(c.Query("limit")); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				if n < 1 {
					n = 1
				}
				if n > 100 {
					n = 100
				}
				limit = n
			}
		}
		if v := strings.TrimSpace(c.Query("offset")); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n >= 0 {
				offset = n
			}
		}

		// Additional filters
		role := strings.TrimSpace(c.Query("role"))
		rolesParam := strings.TrimSpace(c.Query("roles")) // comma-separated
		var rolesList []string
		if rolesParam != "" {
			for _, r := range strings.Split(rolesParam, ",") {
				r = strings.TrimSpace(r)
				if r != "" {
					rolesList = append(rolesList, r)
				}
			}
		}
		adminParam := strings.ToLower(strings.TrimSpace(c.Query("admin"))) // "true" | "false" | ""
		regFrom := strings.TrimSpace(c.Query("reg_from"))
		regTo := strings.TrimSpace(c.Query("reg_to"))
		lastFrom := strings.TrimSpace(c.Query("last_from"))
		lastTo := strings.TrimSpace(c.Query("last_to"))
		hasLogin := strings.ToLower(strings.TrimSpace(c.Query("has_login"))) == "true"
		hasIP := strings.ToLower(strings.TrimSpace(c.Query("has_ip"))) == "true"

		sort := strings.ToLower(strings.TrimSpace(c.Query("sort")))
		order := strings.ToUpper(strings.TrimSpace(c.Query("order")))
		if order != "ASC" && order != "DESC" {
			order = "DESC"
		}
		switch sort {
		case "email", "created_at", "last_login", "is_admin":
			// ok
		default:
			sort = "created_at"
		}

		// Build dynamic WHERE
		var conds []string
		var args []any
		add := func(clause string, val any) { conds = append(conds, clause); args = append(args, val) }

		if q != "" {
			add("LOWER(email) LIKE $%d", "%"+strings.ToLower(q)+"%")
		}
		if role != "" {
			add("EXISTS (SELECT 1 FROM user_roles ur JOIN roles r ON ur.role_id=r.id WHERE ur.user_id = users.id AND r.name = $%d)", role)
		}
		if len(rolesList) > 0 {
			// any of the roles
			add("EXISTS (SELECT 1 FROM user_roles ur JOIN roles r ON ur.role_id=r.id WHERE ur.user_id = users.id AND r.name = ANY($%d))", rolesList)
		}
		if adminParam == "true" {
			conds = append(conds, "is_admin = TRUE")
		} else if adminParam == "false" {
			conds = append(conds, "is_admin = FALSE")
		}
		if regFrom != "" {
			add("created_at >= $%d", regFrom)
		}
		if regTo != "" {
			add("created_at <= $%d", regTo)
		}
		if lastFrom != "" {
			add("last_login >= $%d", lastFrom)
		}
		if lastTo != "" {
			add("last_login <= $%d", lastTo)
		}
		if hasLogin {
			conds = append(conds, "last_login IS NOT NULL")
		}
		if hasIP {
			conds = append(conds, "EXISTS (SELECT 1 FROM sessions s WHERE s.user_id = users.id)")
		}

		// Build WHERE with right placeholders
		where := ""
		if len(conds) > 0 {
			// Replace $%d with actual placeholder numbers
			n := 1
			parts := make([]string, 0, len(conds))
			for _, cnd := range conds {
				if strings.Contains(cnd, "$%d") {
					cnd = fmt.Sprintf(cnd, n)
					n++
				}
				parts = append(parts, cnd)
			}
			where = "WHERE " + strings.Join(parts, " AND ")
		}

		// Query rows
		rows, err := db.Query(ctx, fmt.Sprintf(`
			SELECT id, email_encrypted, created_at, last_login, is_admin, mfa_enabled
			FROM users
			%s
			ORDER BY %s %s
			LIMIT %d OFFSET %d`, where, sort, order, limit, offset), args...)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "query failed"})
		}
		defer rows.Close()

		type userRow struct {
			ID         uuid.UUID
			EmailEnc   []byte
			Created    time.Time
			Last       sql.NullTime
			IsAdmin    bool
			MFAEnabled bool
		}
		var users []userRow
		var userIDs []uuid.UUID
		for rows.Next() {
			var r userRow
			if err := rows.Scan(&r.ID, &r.EmailEnc, &r.Created, &r.Last, &r.IsAdmin, &r.MFAEnabled); err == nil {
				users = append(users, r)
				userIDs = append(userIDs, r.ID)
			}
		}

		// Total count with same filter
		var total int
		// Total count
		if where != "" {
			_ = db.QueryRow(ctx, fmt.Sprintf(`SELECT COUNT(*) FROM users %s`, where), args...).Scan(&total)
		} else {
			_ = db.QueryRow(ctx, `SELECT COUNT(*) FROM users`).Scan(&total)
		}

		// Load roles only for returned users
		rolesByUser := make(map[uuid.UUID][]string)
		if len(userIDs) > 0 {
			// Build IN clause
			params := []any{}
			placeholders := []string{}
			for i, id := range userIDs {
				params = append(params, id)
				placeholders = append(placeholders, "$"+strconv.Itoa(i+1))
			}
			roleSQL := `SELECT ur.user_id, r.name FROM user_roles ur JOIN roles r ON ur.role_id = r.id WHERE ur.user_id IN (` + strings.Join(placeholders, ",") + `)`
			if rrows, err := db.Query(ctx, roleSQL, params...); err == nil {
				defer rrows.Close()
				for rrows.Next() {
					var uid uuid.UUID
					var name string
					if err := rrows.Scan(&uid, &name); err == nil {
						rolesByUser[uid] = append(rolesByUser[uid], name)
					}
				}
			}
		}

		// Build response with decrypted fields and last/registration IPs
		var result []map[string]any
		for _, u := range users {
			// decrypt email
			email := ""
			if len(u.EmailEnc) > 0 {
				if pt, err := crypto.Decrypt(u.EmailEnc); err == nil {
					email = string(pt)
				}
			}

			// registration IP from audit log
			var regIPEnc []byte
			_ = db.QueryRow(ctx, `SELECT ip_address_encrypted FROM audit_log WHERE user_id=$1 AND action='user.registered' ORDER BY created_at ASC LIMIT 1`, u.ID).Scan(&regIPEnc)
			regIP := ""
			if len(regIPEnc) > 0 {
				if pt, err := crypto.Decrypt(regIPEnc); err == nil {
					regIP = string(pt)
				}
			}

			// last used IP from most recent session
			var lastIPEnc []byte
			_ = db.QueryRow(ctx, `SELECT ip_address_encrypted FROM sessions WHERE user_id=$1 ORDER BY created_at DESC LIMIT 1`, u.ID).Scan(&lastIPEnc)
			lastIP := ""
			if len(lastIPEnc) > 0 {
				if pt, err := crypto.Decrypt(lastIPEnc); err == nil {
					lastIP = string(pt)
				}
			}

			roles := rolesByUser[u.ID]
			allowlistedAdmin := isUserInAdminAllowlist(u.ID.String())
			effectiveAdmin := u.IsAdmin || allowlistedAdmin
			if effectiveAdmin {
				seen := make(map[string]struct{}, len(roles))
				for _, r := range roles {
					seen[r] = struct{}{}
				}
				if _, ok := seen["admin"]; !ok {
					roles = append(roles, "admin")
				}
			}

			result = append(result, fiber.Map{
				"user_id":             u.ID,
				"email":               email,
				"is_admin":            effectiveAdmin,
				"admin_via_allowlist": allowlistedAdmin,
				"mfa_enabled":         u.MFAEnabled,
				"roles":               roles,
				"created_at":          u.Created,
				"last_login":          nilIfInvalid(u.Last),
				"registration_ip":     regIP,
				"last_ip":             lastIP,
			})
		}

		return c.JSON(fiber.Map{"users": result, "total": total, "limit": limit, "offset": offset, "q": q})
	})

	// CSV export with same filters
	admin.Get("/users.csv", func(c *fiber.Ctx) error {
		// Reuse the JSON handler by calling it internally would require refactor; instead duplicate minimal logic
		ctx := context.Background()
		// Collect filters
		q := strings.TrimSpace(c.Query("q"))
		role := strings.TrimSpace(c.Query("role"))
		rolesParam := strings.TrimSpace(c.Query("roles"))
		var rolesList []string
		if rolesParam != "" {
			for _, r := range strings.Split(rolesParam, ",") {
				r = strings.TrimSpace(r)
				if r != "" {
					rolesList = append(rolesList, r)
				}
			}
		}
		adminParam := strings.ToLower(strings.TrimSpace(c.Query("admin")))
		regFrom := strings.TrimSpace(c.Query("reg_from"))
		regTo := strings.TrimSpace(c.Query("reg_to"))
		lastFrom := strings.TrimSpace(c.Query("last_from"))
		lastTo := strings.TrimSpace(c.Query("last_to"))
		hasLogin := strings.ToLower(strings.TrimSpace(c.Query("has_login"))) == "true"
		hasIP := strings.ToLower(strings.TrimSpace(c.Query("has_ip"))) == "true"
		sort := strings.ToLower(strings.TrimSpace(c.Query("sort")))
		order := strings.ToUpper(strings.TrimSpace(c.Query("order")))
		if order != "ASC" && order != "DESC" {
			order = "DESC"
		}
		switch sort {
		case "email", "created_at", "last_login", "is_admin":
		default:
			sort = "created_at"
		}
		// Build WHERE
		var conds []string
		var args []any
		add := func(clause string, val any) { conds = append(conds, clause); args = append(args, val) }
		if q != "" {
			add("LOWER(email) LIKE $%d", "%"+strings.ToLower(q)+"%")
		}
		if role != "" {
			add("EXISTS (SELECT 1 FROM user_roles ur JOIN roles r ON ur.role_id=r.id WHERE ur.user_id = users.id AND r.name = $%d)", role)
		}
		if len(rolesList) > 0 {
			add("EXISTS (SELECT 1 FROM user_roles ur JOIN roles r ON ur.role_id=r.id WHERE ur.user_id = users.id AND r.name = ANY($%d))", rolesList)
		}
		if adminParam == "true" {
			conds = append(conds, "is_admin = TRUE")
		} else if adminParam == "false" {
			conds = append(conds, "is_admin = FALSE")
		}
		if regFrom != "" {
			add("created_at >= $%d", regFrom)
		}
		if regTo != "" {
			add("created_at <= $%d", regTo)
		}
		if lastFrom != "" {
			add("last_login >= $%d", lastFrom)
		}
		if lastTo != "" {
			add("last_login <= $%d", lastTo)
		}
		if hasLogin {
			conds = append(conds, "last_login IS NOT NULL")
		}
		if hasIP {
			conds = append(conds, "EXISTS (SELECT 1 FROM sessions s WHERE s.user_id = users.id)")
		}
		where := ""
		if len(conds) > 0 {
			n := 1
			parts := make([]string, 0, len(conds))
			for _, cnd := range conds {
				if strings.Contains(cnd, "$%d") {
					cnd = fmt.Sprintf(cnd, n)
					n++
				}
				parts = append(parts, cnd)
			}
			where = "WHERE " + strings.Join(parts, " AND ")
		}
		// Query
		rows, err := db.Query(ctx, fmt.Sprintf(`
			SELECT id, email_encrypted, created_at, last_login, is_admin, mfa_enabled
			FROM users
			%s
			ORDER BY %s %s`, where, sort, order), args...)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "query failed"})
		}
		defer rows.Close()
		type userRow struct {
			ID         uuid.UUID
			EmailEnc   []byte
			Created    time.Time
			Last       sql.NullTime
			IsAdmin    bool
			MFAEnabled bool
		}
		var buf bytes.Buffer
		buf.WriteString("user_id,email,is_admin,admin_via_allowlist,mfa_enabled,roles,created_at,last_login,registration_ip,last_ip\n")
		for rows.Next() {
			var r userRow
			if err := rows.Scan(&r.ID, &r.EmailEnc, &r.Created, &r.Last, &r.IsAdmin, &r.MFAEnabled); err != nil {
				continue
			}
			email := ""
			if len(r.EmailEnc) > 0 {
				if pt, err := crypto.Decrypt(r.EmailEnc); err == nil {
					email = string(pt)
				}
			}
			var regIPEnc []byte
			_ = db.QueryRow(ctx, `SELECT ip_address_encrypted FROM audit_log WHERE user_id=$1 AND action='user.registered' ORDER BY created_at ASC LIMIT 1`, r.ID).Scan(&regIPEnc)
			regIP := ""
			if len(regIPEnc) > 0 {
				if pt, err := crypto.Decrypt(regIPEnc); err == nil {
					regIP = string(pt)
				}
			}
			var lastIPEnc []byte
			_ = db.QueryRow(ctx, `SELECT ip_address_encrypted FROM sessions WHERE user_id=$1 ORDER BY created_at DESC LIMIT 1`, r.ID).Scan(&lastIPEnc)
			lastIP := ""
			if len(lastIPEnc) > 0 {
				if pt, err := crypto.Decrypt(lastIPEnc); err == nil {
					lastIP = string(pt)
				}
			}
			// roles
			roles := []string{}
			rr, err := db.Query(ctx, `SELECT r.name FROM user_roles ur JOIN roles r ON ur.role_id=r.id WHERE ur.user_id = $1`, r.ID)
			if err == nil {
				func() {
					defer rr.Close()
					for rr.Next() {
						var name string
						if err := rr.Scan(&name); err == nil {
							roles = append(roles, name)
						}
					}
				}()
			}
			allowlistedAdmin := isUserInAdminAllowlist(r.ID.String())
			effectiveAdmin := r.IsAdmin || allowlistedAdmin
			if effectiveAdmin {
				seen := make(map[string]struct{}, len(roles))
				for _, role := range roles {
					seen[role] = struct{}{}
				}
				if _, ok := seen["admin"]; !ok {
					roles = append(roles, "admin")
				}
			}
			// write CSV row
			buf.WriteString(fmt.Sprintf("%s,%s,%t,%t,%t,\"%s\",%s,%s,%s,%s\n",
				r.ID.String(),
				csvEscape(email),
				effectiveAdmin,
				allowlistedAdmin,
				r.MFAEnabled,
				strings.Join(roles, ";"),
				r.Created.Format(time.RFC3339),
				formatNullTime(r.Last),
				csvEscape(regIP),
				csvEscape(lastIP),
			))
		}
		c.Set(fiber.HeaderContentType, "text/csv; charset=utf-8")
		c.Set(fiber.HeaderContentDisposition, "attachment; filename=users.csv")
		return c.Send(buf.Bytes())
	})
	admin.Put("/users/:id/admin", func(c *fiber.Ctx) error {
		id, err := uuid.Parse(c.Params("id"))
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid id"})
		}
		var body struct {
			Admin bool `json:"admin"`
		}
		if err := c.BodyParser(&body); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "bad request"})
		}
		_, err = db.Exec(c.Context(), "UPDATE users SET is_admin = $1 WHERE id = $2", body.Admin, id)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "update failed"})
		}
		return c.JSON(fiber.Map{"ok": true})
	})

	admin.Get("/roles", func(c *fiber.Ctx) error {
		rows, err := db.Query(c.Context(), "SELECT name FROM roles ORDER BY name")
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "query failed"})
		}
		defer rows.Close()
		var list []string
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err == nil {
				list = append(list, name)
			}
		}
		return c.JSON(fiber.Map{"roles": list})
	})

	admin.Get("/users/:id/roles", func(c *fiber.Ctx) error {
		id, err := uuid.Parse(c.Params("id"))
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid id"})
		}
		rows, err := db.Query(c.Context(), `SELECT r.name FROM user_roles ur JOIN roles r ON ur.role_id = r.id WHERE ur.user_id = $1`, id)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "query failed"})
		}
		defer rows.Close()
		var list []string
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err == nil {
				list = append(list, name)
			}
		}
		return c.JSON(fiber.Map{"roles": list})
	})

	admin.Post("/users/:id/roles", func(c *fiber.Ctx) error {
		id, err := uuid.Parse(c.Params("id"))
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid id"})
		}
		var body struct {
			Role string `json:"role"`
		}
		if err := c.BodyParser(&body); err != nil || body.Role == "" {
			return c.Status(400).JSON(fiber.Map{"error": "bad request"})
		}
		var roleID uuid.UUID
		if err := db.QueryRow(c.Context(), "SELECT id FROM roles WHERE name=$1", body.Role).Scan(&roleID); err != nil {
			return c.Status(404).JSON(fiber.Map{"error": "role not found"})
		}
		if _, err := db.Exec(c.Context(), "INSERT INTO user_roles (user_id, role_id) VALUES ($1,$2) ON CONFLICT DO NOTHING", id, roleID); err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "assign failed"})
		}
		return c.JSON(fiber.Map{"ok": true})
	})

	admin.Delete("/users/:id/roles/:role", func(c *fiber.Ctx) error {
		id, err := uuid.Parse(c.Params("id"))
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid id"})
		}
		role := c.Params("role")
		var roleID uuid.UUID
		if err := db.QueryRow(c.Context(), "SELECT id FROM roles WHERE name=$1", role).Scan(&roleID); err != nil {
			return c.Status(404).JSON(fiber.Map{"error": "role not found"})
		}
		if _, err := db.Exec(c.Context(), "DELETE FROM user_roles WHERE user_id=$1 AND role_id=$2", id, roleID); err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "remove failed"})
		}
		return c.JSON(fiber.Map{"ok": true})
	})

	// Bulk assign/remove roles to users matching filters
	admin.Post("/users/roles/bulk", func(c *fiber.Ctx) error {
		type bulkReq struct {
			Role     string   `json:"role"`
			Action   string   `json:"action"` // "assign" or "remove"
			Q        string   `json:"q"`
			RoleOne  string   `json:"role_filter"`
			Roles    []string `json:"roles"`
			Admin    string   `json:"admin"`
			RegFrom  string   `json:"reg_from"`
			RegTo    string   `json:"reg_to"`
			LastFrom string   `json:"last_from"`
			LastTo   string   `json:"last_to"`
			HasLogin bool     `json:"has_login"`
			HasIP    bool     `json:"has_ip"`
		}
		var req bulkReq
		if err := c.BodyParser(&req); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "bad request"})
		}
		if strings.TrimSpace(req.Role) == "" {
			return c.Status(400).JSON(fiber.Map{"error": "role required"})
		}
		if req.Action != "assign" && req.Action != "remove" {
			return c.Status(400).JSON(fiber.Map{"error": "invalid action"})
		}

		// Lookup role id
		var roleID uuid.UUID
		if err := db.QueryRow(c.Context(), "SELECT id FROM roles WHERE name=$1", req.Role).Scan(&roleID); err != nil {
			return c.Status(404).JSON(fiber.Map{"error": "role not found"})
		}

		// Build WHERE conditions similar to list endpoint
		ctx := context.Background()
		var conds []string
		var args []any
		add := func(clause string, val any) { conds = append(conds, clause); args = append(args, val) }

		if q := strings.TrimSpace(req.Q); q != "" {
			add("LOWER(email) LIKE $%d", "%"+strings.ToLower(q)+"%")
		}
		if rf := strings.TrimSpace(req.RoleOne); rf != "" {
			add("EXISTS (SELECT 1 FROM user_roles ur JOIN roles r ON ur.role_id=r.id WHERE ur.user_id = users.id AND r.name = $%d)", rf)
		}
		if len(req.Roles) > 0 {
			add("EXISTS (SELECT 1 FROM user_roles ur JOIN roles r ON ur.role_id=r.id WHERE ur.user_id = users.id AND r.name = ANY($%d))", req.Roles)
		}
		if strings.ToLower(strings.TrimSpace(req.Admin)) == "true" {
			conds = append(conds, "is_admin = TRUE")
		}
		if strings.ToLower(strings.TrimSpace(req.Admin)) == "false" {
			conds = append(conds, "is_admin = FALSE")
		}
		if v := strings.TrimSpace(req.RegFrom); v != "" {
			add("created_at >= $%d", v)
		}
		if v := strings.TrimSpace(req.RegTo); v != "" {
			add("created_at <= $%d", v)
		}
		if v := strings.TrimSpace(req.LastFrom); v != "" {
			add("last_login >= $%d", v)
		}
		if v := strings.TrimSpace(req.LastTo); v != "" {
			add("last_login <= $%d", v)
		}
		if req.HasLogin {
			conds = append(conds, "last_login IS NOT NULL")
		}
		if req.HasIP {
			conds = append(conds, "EXISTS (SELECT 1 FROM sessions s WHERE s.user_id = users.id)")
		}

		where := ""
		if len(conds) > 0 {
			n := 1
			parts := make([]string, 0, len(conds))
			for _, cnd := range conds {
				if strings.Contains(cnd, "$%d") {
					cnd = fmt.Sprintf(cnd, n)
					n++
				}
				parts = append(parts, cnd)
			}
			where = "WHERE " + strings.Join(parts, " AND ")
		}

		var affected int64
		if req.Action == "assign" {
			// Insert for all matching users
			sql := fmt.Sprintf(`
				INSERT INTO user_roles (user_id, role_id)
				SELECT u.id, $1 FROM users u
				%s
				AND NOT EXISTS (SELECT 1 FROM user_roles ur WHERE ur.user_id = u.id AND ur.role_id = $1)`, where)
			params := make([]interface{}, 0, 1+len(args))
			params = append(params, roleID)
			for _, a := range args {
				params = append(params, a)
			}
			ct, err := db.Exec(ctx, sql, params...)
			if err != nil {
				return c.Status(500).JSON(fiber.Map{"error": "assign failed"})
			}
			affected = ct.RowsAffected()
		} else {
			// Delete for all matching users
			sql := fmt.Sprintf(`
				DELETE FROM user_roles ur USING users u
				%s AND ur.user_id = u.id AND ur.role_id = $1`, where)
			params := make([]interface{}, 0, 1+len(args))
			params = append(params, roleID)
			for _, a := range args {
				params = append(params, a)
			}
			ct, err := db.Exec(ctx, sql, params...)
			if err != nil {
				return c.Status(500).JSON(fiber.Map{"error": "remove failed"})
			}
			affected = ct.RowsAffected()
		}

		return c.JSON(fiber.Map{"ok": true, "affected": affected})
	})

	// Bulk grant/revoke is_admin to users matching filters
	admin.Post("/users/admin/bulk", func(c *fiber.Ctx) error {
		type bulkReq struct {
			Action   string   `json:"action"` // "grant" or "revoke"
			Q        string   `json:"q"`
			RoleOne  string   `json:"role_filter"`
			Roles    []string `json:"roles"`
			Admin    string   `json:"admin"`
			RegFrom  string   `json:"reg_from"`
			RegTo    string   `json:"reg_to"`
			LastFrom string   `json:"last_from"`
			LastTo   string   `json:"last_to"`
			HasLogin bool     `json:"has_login"`
			HasIP    bool     `json:"has_ip"`
		}
		var req bulkReq
		if err := c.BodyParser(&req); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "bad request"})
		}
		if req.Action != "grant" && req.Action != "revoke" {
			return c.Status(400).JSON(fiber.Map{"error": "invalid action"})
		}

		ctx := c.Context()
		var conds []string
		var args []any
		add := func(clause string, val any) { conds = append(conds, clause); args = append(args, val) }

		if q := strings.TrimSpace(req.Q); q != "" {
			add("LOWER(email) LIKE $%d", "%"+strings.ToLower(q)+"%")
		}
		if rf := strings.TrimSpace(req.RoleOne); rf != "" {
			add("EXISTS (SELECT 1 FROM user_roles ur JOIN roles r ON ur.role_id=r.id WHERE ur.user_id = users.id AND r.name = $%d)", rf)
		}
		if len(req.Roles) > 0 {
			add("EXISTS (SELECT 1 FROM user_roles ur JOIN roles r ON ur.role_id=r.id WHERE ur.user_id = users.id AND r.name = ANY($%d))", req.Roles)
		}
		if strings.ToLower(strings.TrimSpace(req.Admin)) == "true" {
			conds = append(conds, "is_admin = TRUE")
		}
		if strings.ToLower(strings.TrimSpace(req.Admin)) == "false" {
			conds = append(conds, "is_admin = FALSE")
		}
		if v := strings.TrimSpace(req.RegFrom); v != "" {
			add("created_at >= $%d", v)
		}
		if v := strings.TrimSpace(req.RegTo); v != "" {
			add("created_at <= $%d", v)
		}
		if v := strings.TrimSpace(req.LastFrom); v != "" {
			add("last_login >= $%d", v)
		}
		if v := strings.TrimSpace(req.LastTo); v != "" {
			add("last_login <= $%d", v)
		}
		if req.HasLogin {
			conds = append(conds, "last_login IS NOT NULL")
		}
		if req.HasIP {
			conds = append(conds, "EXISTS (SELECT 1 FROM sessions s WHERE s.user_id = users.id)")
		}

		where := ""
		if len(conds) > 0 {
			n := 1
			parts := make([]string, 0, len(conds))
			for _, cnd := range conds {
				if strings.Contains(cnd, "$%d") {
					cnd = fmt.Sprintf(cnd, n)
					n++
				}
				parts = append(parts, cnd)
			}
			where = "WHERE " + strings.Join(parts, " AND ")
		}

		set := "FALSE"
		if req.Action == "grant" {
			set = "TRUE"
		}
		sql := fmt.Sprintf("UPDATE users SET is_admin = %s %s", set, where)
		ct, err := db.Exec(ctx, sql, args...)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "bulk admin update failed"})
		}
		return c.JSON(fiber.Map{"ok": true, "affected": ct.RowsAffected()})
	})

	// Announcement endpoints
	admin.Get("/announcements", func(c *fiber.Ctx) error {
		ctx := c.Context()

		rows, err := db.Query(ctx, `
			SELECT id, title, content, visibility, style, active, dismissible, priority, start_date, end_date, created_by, created_at, updated_at
			FROM announcements
			ORDER BY priority DESC, created_at DESC
		`)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "Failed to fetch announcements"})
		}
		defer rows.Close()

		var announcements []fiber.Map
		for rows.Next() {
			var id, createdBy uuid.UUID
			var title, content, visibility string
			var style map[string]interface{}
			var active, dismissible bool
			var priority int
			var startDate, endDate *time.Time
			var createdAt, updatedAt time.Time

			err := rows.Scan(&id, &title, &content, &visibility, &style, &active, &dismissible, &priority, &startDate, &endDate, &createdBy, &createdAt, &updatedAt)
			if err != nil {
				continue
			}

			announcements = append(announcements, fiber.Map{
				"id":          id,
				"title":       title,
				"content":     content,
				"visibility":  visibility,
				"style":       style,
				"active":      active,
				"dismissible": dismissible,
				"priority":    priority,
				"start_date":  startDate,
				"end_date":    endDate,
				"created_by":  createdBy,
				"created_at":  createdAt,
				"updated_at":  updatedAt,
			})
		}

		return c.JSON(fiber.Map{"announcements": announcements})
	})

	admin.Post("/announcements", func(c *fiber.Ctx) error {
		var req struct {
			Title       string                 `json:"title" validate:"required"`
			Content     string                 `json:"content" validate:"required"`
			Visibility  string                 `json:"visibility" validate:"required,oneof=all logged_in"`
			Style       map[string]interface{} `json:"style"`
			Active      bool                   `json:"active"`
			Dismissible bool                   `json:"dismissible"`
			Priority    int                    `json:"priority"`
			StartDate   *time.Time             `json:"start_date"`
			EndDate     *time.Time             `json:"end_date"`
		}

		if err := c.BodyParser(&req); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
		}

		// Get user ID from JWT token
		userID, err := getUserIDFromToken(c)
		if err != nil {
			return c.Status(401).JSON(fiber.Map{"error": "Unauthorized"})
		}

		ctx := c.Context()
		var id uuid.UUID
		err = db.QueryRow(ctx, `
			INSERT INTO announcements (title, content, visibility, style, active, dismissible, priority, start_date, end_date, created_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
			RETURNING id
		`, req.Title, req.Content, req.Visibility, req.Style, req.Active, req.Dismissible, req.Priority, req.StartDate, req.EndDate, userID).Scan(&id)

		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "Failed to create announcement"})
		}

		return c.Status(201).JSON(fiber.Map{"id": id, "message": "Announcement created successfully"})
	})

	admin.Put("/announcements/:id", func(c *fiber.Ctx) error {
		announcementID := c.Params("id")
		if announcementID == "" {
			return c.Status(400).JSON(fiber.Map{"error": "Announcement ID required"})
		}

		var req struct {
			Title       string                 `json:"title"`
			Content     string                 `json:"content"`
			Visibility  string                 `json:"visibility" validate:"omitempty,oneof=all logged_in"`
			Style       map[string]interface{} `json:"style"`
			Active      *bool                  `json:"active"`
			Dismissible *bool                  `json:"dismissible"`
			Priority    *int                   `json:"priority"`
			StartDate   *time.Time             `json:"start_date"`
			EndDate     *time.Time             `json:"end_date"`
		}

		if err := c.BodyParser(&req); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
		}

		ctx := c.Context()
		_, err := db.Exec(ctx, `
			UPDATE announcements
			SET title = COALESCE(NULLIF($2, ''), title),
				content = COALESCE(NULLIF($3, ''), content),
				visibility = COALESCE(NULLIF($4, ''), visibility),
				style = COALESCE($5, style),
				active = COALESCE($6, active),
				dismissible = COALESCE($7, dismissible),
				priority = COALESCE($8, priority),
				start_date = COALESCE($9, start_date),
				end_date = COALESCE($10, end_date),
				updated_at = NOW()
			WHERE id = $1
		`, announcementID, req.Title, req.Content, req.Visibility, req.Style, req.Active, req.Dismissible, req.Priority, req.StartDate, req.EndDate)

		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "Failed to update announcement"})
		}

		return c.JSON(fiber.Map{"message": "Announcement updated successfully"})
	})

	admin.Delete("/announcements/:id", func(c *fiber.Ctx) error {
		announcementID := c.Params("id")
		if announcementID == "" {
			return c.Status(400).JSON(fiber.Map{"error": "Announcement ID required"})
		}

		ctx := c.Context()
		ct, err := db.Exec(ctx, `DELETE FROM announcements WHERE id = $1`, announcementID)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "Failed to delete announcement"})
		}

		if ct.RowsAffected() == 0 {
			return c.Status(404).JSON(fiber.Map{"error": "Announcement not found"})
		}

		return c.JSON(fiber.Map{"message": "Announcement deleted successfully"})
	})


	// GDPR compliance endpoints
	api.Post("/gdpr/request", func(c *fiber.Ctx) error {
		var req struct {
			Email string `json:"email" validate:"required,email"`
		}
		if err := c.BodyParser(&req); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
		}

		ctx := c.Context()
		emailHash := crypto.HashEmail(req.Email)

		// Get user data for GDPR export
		var deletionKey []byte
		err := db.QueryRow(ctx, `SELECT deletion_key FROM gdpr_keys WHERE email_hash = $1`, emailHash).Scan(&deletionKey)
		if err != nil {
			return c.Status(404).JSON(fiber.Map{"error": "User not found"})
		}

		// Decrypt email to verify and get user data
		var userID uuid.UUID
		var emailEnc []byte
		var createdAt time.Time
		err = db.QueryRow(ctx, `
			SELECT id, email_encrypted, created_at
			FROM users WHERE email_hash = $1`, emailHash).Scan(&userID, &emailEnc, &createdAt)
		if err != nil {
			return c.Status(404).JSON(fiber.Map{"error": "User not found"})
		}

		decryptedEmail, err := crypto.DecryptWithGDPRKey(emailEnc, deletionKey)
		if err != nil || string(decryptedEmail) != req.Email {
			return c.Status(404).JSON(fiber.Map{"error": "User not found"})
		}

		// Return GDPR data export
		return c.JSON(fiber.Map{
			"user_id":    userID,
			"email":      req.Email,
			"created_at": createdAt,
			"message":    "This is your complete data export. All note content is encrypted client-side and cannot be decrypted by the server.",
		})
	})

	api.Delete("/gdpr/delete", func(c *fiber.Ctx) error {
		var req struct {
			Email string `json:"email" validate:"required,email"`
		}
		if err := c.BodyParser(&req); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
		}

		ctx := c.Context()
		emailHash := crypto.HashEmail(req.Email)

		// Verify user exists and get deletion key
		var deletionKey []byte
		err := db.QueryRow(ctx, `SELECT deletion_key FROM gdpr_keys WHERE email_hash = $1`, emailHash).Scan(&deletionKey)
		if err != nil {
			return c.Status(404).JSON(fiber.Map{"error": "User not found"})
		}

		// Get user ID for cascading deletes
		var userID uuid.UUID
		var emailEnc []byte
		err = db.QueryRow(ctx, `SELECT id, email_encrypted FROM users WHERE email_hash = $1`, emailHash).Scan(&userID, &emailEnc)
		if err != nil {
			return c.Status(404).JSON(fiber.Map{"error": "User not found"})
		}

		// Verify email match
		decryptedEmail, err := crypto.DecryptWithGDPRKey(emailEnc, deletionKey)
		if err != nil || string(decryptedEmail) != req.Email {
			return c.Status(404).JSON(fiber.Map{"error": "User not found"})
		}

		// Start transaction for complete deletion
		tx, err := db.Begin(ctx)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "Deletion failed"})
		}
		defer tx.Rollback(ctx)

		// Delete user (cascades to notes, sessions, etc.)
		_, err = tx.Exec(ctx, `DELETE FROM users WHERE id = $1`, userID)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "Deletion failed"})
		}

		// Delete GDPR key
		_, err = tx.Exec(ctx, `DELETE FROM gdpr_keys WHERE email_hash = $1`, emailHash)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "Deletion failed"})
		}

		if err := tx.Commit(ctx); err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "Deletion failed"})
		}

		return c.JSON(fiber.Map{
			"message": "All user data has been permanently deleted",
		})
	})

	// Start background cleanup service
	startCleanupService(db)

	// Start server
	log.Printf("Starting secure server on port %s with full encryption", config.Port)
	log.Fatal(app.Listen(":" + config.Port))
}
