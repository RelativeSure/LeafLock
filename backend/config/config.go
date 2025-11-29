// Package config manages application configuration from environment variables.
// Provides centralized configuration loading with validation and security considerations.
// Supports zero-knowledge architecture by avoiding server-side encryption key storage.
package config

import (
	"log"
	"net"
	neturl "net/url"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// Config holds application configuration loaded from environment variables
// Thread-safe configuration with atomic operations for dynamic settings
// Zero-knowledge: intentionally excludes server-side encryption keys
type Config struct {
	DatabaseURL   string
	RedisURL      string
	RedisPassword string

	// EncryptionKey removed - zero-knowledge architecture (no global encryption key)
	ClerkPublishableKey string
	ClerkSecretKey      string
	Port                string
	AllowedOrigins      []string
	MaxLoginAttempts    int
	LockoutDuration     time.Duration
	IPLockoutDuration   time.Duration
	MaxIPLoginAttempts  int
	SessionDuration     time.Duration
	Environment         string
	TrustProxyHeaders   bool
	RateLimitMode       string
	LogLevel            string
	// Default admin settings
	DefaultAdminEnabled  bool
	DefaultAdminEmail    string
	DefaultAdminPassword string
	// Email/SMTP configuration
	SMTPEnabled  bool
	SMTPHost     string
	SMTPPort     int
	SMTPUser     string
	SMTPPassword string
	SMTPFrom     string
	SMTPUseTLS   bool
	SMTPInsecure bool   // Skip TLS verification (dev only)
	FrontendURL  string // Frontend URL for password reset links
}

// Runtime feature toggles (in-memory; initialized from env at startup)
var RegEnabled atomic.Int32
var TrustProxyHeadersFlag atomic.Bool

// LoadConfig loads configuration from environment variables
func LoadConfig() *Config {
	logLevelRaw := strings.TrimSpace(os.Getenv("LOG_LEVEL"))
	if logLevelRaw == "" {
		logLevelRaw = strings.TrimSpace(os.Getenv("LOGLEVEL"))
	}
	logLevel := normalizeLogLevel(logLevelRaw)
	if logLevel != "info" && logLevelRaw != "" && logLevelRaw != logLevel {
		log.Printf("⚠️  [WARNING] Normalizing LOG_LEVEL value '%s' to '%s'", logLevelRaw, logLevel)
	}
	if logLevelRaw == "" {
		logLevel = "info"
	}
	if !isSupportedLogLevel(logLevel) {
		if logLevelRaw != "" {
			log.Printf("⚠️  [WARNING] Unrecognized LOG_LEVEL '%s'; defaulting to 'info'", logLevelRaw)
		}
		logLevel = "info"
	}

	// JWT_SECRET removed - Clerk-only authentication

	// SERVER_ENCRYPTION_KEY removed - zero-knowledge architecture
	// Emails stored in plaintext, sensitive data encrypted with password-derived keys only

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		// Try Coolify-provided Postgres envs first
		if built := buildDatabaseURLFromEnv(); built != "" {
			dbURL = built
		} else {
			// Safe local default for dev
			dbURL = "postgres://postgres:postgres@localhost:5432/leaflock?sslmode=prefer" // secretlint-disable-line
		}
	}

	// Validate admin password security
	adminPassword := GetEnvOrDefault("DEFAULT_ADMIN_PASSWORD", "ChangeThisAdminPassword123!")
	if GetEnvAsBool("ENABLE_DEFAULT_ADMIN", true) {
		// Check for weak admin passwords
		if len(adminPassword) < 12 {
			log.Fatalf("💥 [FATAL] DEFAULT_ADMIN_PASSWORD must be at least 12 characters long for security")
		}
		adminLower := strings.ToLower(adminPassword)
		weakAdminPasswords := []string{"adminpass123!", "admin123", "password", "123456", "admin", "your_", "change_me", "default"}
		for _, weak := range weakAdminPasswords {
			if strings.HasPrefix(adminLower, strings.ToLower(weak)) || strings.EqualFold(adminPassword, weak) {
				log.Fatalf("💥 [FATAL] DEFAULT_ADMIN_PASSWORD cannot be a weak/default value: '%s'", weak)
			}
		}
	}

	// Validate Redis password security
	redisPassword := resolveRedisPassword(os.Getenv("REDIS_URL"), os.Getenv("REDIS_PASSWORD"))
	if redisPassword != "" {
		if len(redisPassword) < 8 {
			log.Fatalf("💥 [FATAL] REDIS_PASSWORD must be at least 8 characters long for security")
		}
		redisLower := strings.ToLower(redisPassword)
		weakRedisPasswords := []string{"redis", "password", "123456", "your_", "change_me", "default", "insecure"}
		for _, weak := range weakRedisPasswords {
			if strings.HasPrefix(redisLower, strings.ToLower(weak)) || strings.EqualFold(redisPassword, weak) {
				log.Fatalf("💥 [FATAL] REDIS_PASSWORD cannot be a weak/default value: '%s'", weak)
			}
		}
	}

	// Validate database URL doesn't use weak passwords
	if strings.Contains(dbURL, ":postgres@") || strings.Contains(dbURL, ":password@") || strings.Contains(dbURL, ":123456@") {
		log.Printf("⚠️  [WARNING] Database URL appears to use a weak password - consider using a strong password")
	}

	return &Config{
		DatabaseURL:   dbURL,
		RedisURL:      normalizeRedisAddress(GetEnvOrDefault("REDIS_URL", "localhost:6379")),
		RedisPassword: resolveRedisPassword(os.Getenv("REDIS_URL"), os.Getenv("REDIS_PASSWORD")),

		// EncryptionKey removed - zero-knowledge architecture
		Port: GetEnvOrDefault("PORT", "8080"),
		AllowedOrigins: func() []string {
			environment := GetEnvOrDefault("APP_ENV", "development")

			// In development mode, allow all origins (CORS disabled)
			if environment == "development" {
				log.Println("🔓 Development mode: CORS restrictions disabled (allowing all origins)")
				return []string{"*"}
			}

			// Production mode: strict CORS with leaflock.app domains
			origins := strings.Split(GetEnvOrDefault("CORS_ORIGINS", "https://leaflock.app,https://*.leaflock.app"), ",")
			// Trim whitespace from each origin to prevent CORS issues
			for i := range origins {
				origins[i] = strings.TrimSpace(origins[i])
			}

			log.Printf("🔒 Production mode: CORS enabled for origins: %v", origins)
			return origins
		}(),
		MaxLoginAttempts:   GetEnvAsInt("MAX_LOGIN_ATTEMPTS", 5),
		LockoutDuration:    time.Duration(GetEnvAsInt("LOCKOUT_MINUTES", 15)) * time.Minute,
		MaxIPLoginAttempts: GetEnvAsInt("MAX_IP_LOGIN_ATTEMPTS", 15),
		IPLockoutDuration:  time.Duration(GetEnvAsInt("IP_LOCKOUT_MINUTES", 15)) * time.Minute,
		SessionDuration:    24 * time.Hour,
		Environment:        GetEnvOrDefault("APP_ENV", "development"),
		TrustProxyHeaders:  GetEnvAsBool("TRUST_PROXY_HEADERS", false),
		RateLimitMode:      GetEnvOrDefault("RATE_LIMIT_MODE", "progressive"),
		LogLevel:           logLevel,
		// Default admin configuration
		DefaultAdminEnabled:  GetEnvAsBool("ENABLE_DEFAULT_ADMIN", true),
		DefaultAdminEmail:    GetEnvOrDefault("DEFAULT_ADMIN_EMAIL", "admin@leaflock.app"),
		DefaultAdminPassword: adminPassword,
		// SMTP configuration
		SMTPEnabled:  GetEnvAsBool("SMTP_ENABLED", false),
		SMTPHost:     GetEnvOrDefault("SMTP_HOST", "localhost"),
		SMTPPort:     GetEnvAsInt("SMTP_PORT", 587),
		SMTPUser:     GetEnvOrDefault("SMTP_USER", ""),
		SMTPPassword: GetEnvOrDefault("SMTP_PASSWORD", ""),
		SMTPFrom:     GetEnvOrDefault("SMTP_FROM", "LeafLock <noreply@leaflock.app>"),
		SMTPUseTLS:   GetEnvAsBool("SMTP_USE_TLS", true),
		SMTPInsecure: GetEnvAsBool("SMTP_INSECURE", false),
		FrontendURL:  GetEnvOrDefault("FRONTEND_URL", "https://leaflock.app"),
		// Clerk authentication configuration
		ClerkPublishableKey: GetEnvOrDefault("CLERK_PUBLISHABLE_KEY", ""),
		ClerkSecretKey:      GetEnvOrDefault("CLERK_SECRET_KEY", ""),
	}
}

func normalizeLogLevel(value string) string {
	switch strings.ToLower(value) {
	case "", "info":
		return "info"
	case "debug", "trace":
		return "debug"
	case "warn", "warning":
		return "warn"
	case "error", "err":
		return "error"
	case "fatal", "critical", "panic":
		return "fatal"
	default:
		return strings.ToLower(value)
	}
}

func isSupportedLogLevel(value string) bool {
	switch value {
	case "debug", "info", "warn", "error", "fatal":
		return true
	default:
		return false
	}
}

// GetEnvOrDefault returns environment variable value or default
func GetEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// GetEnvAsBool parses environment variable as boolean
func GetEnvAsBool(key string, defaultValue bool) bool {
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

// GetEnvAsStringSlice parses environment variable as comma-separated list
func GetEnvAsStringSlice(key string, defaultValue []string) []string {
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

// GetEnvAsInt parses environment variable as integer
func GetEnvAsInt(key string, defaultValue int) int {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

// normalizeRedisAddress converts redis:// URLs into host[:port] that go-redis expects.
func normalizeRedisAddress(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return trimmed
	}
	if !strings.Contains(trimmed, "://") {
		return trimmed
	}
	u, err := neturl.Parse(trimmed)
	if err != nil {
		log.Printf("Warning: could not parse REDIS_URL '%s': %v", trimmed, err)
		return trimmed
	}
	if u.Host != "" {
		return u.Host
	}
	return trimmed
}

// resolveRedisPassword returns an explicit password if provided, otherwise pulls
// the password component from a redis:// URL when available.
func resolveRedisPassword(redisURL, explicit string) string {
	if explicit != "" {
		return explicit
	}
	trimmed := strings.TrimSpace(redisURL)
	if trimmed == "" || !strings.Contains(trimmed, "://") {
		return explicit
	}
	u, err := neturl.Parse(trimmed)
	if err != nil {
		return explicit
	}
	if u.User != nil {
		if pw, ok := u.User.Password(); ok && pw != "" {
			return pw
		}
	}
	return explicit
}

// buildDatabaseURLFromEnv builds a postgres URL from common env vars (Railway/Coolify/Postgres add-on style)
// Recognized: POSTGRESQL_* vars, Railway PG* vars, and POSTGRES_PASSWORD
func buildDatabaseURLFromEnv() string {
	host := strings.TrimSpace(os.Getenv("POSTGRESQL_HOST"))
	if host == "" {
		host = strings.TrimSpace(os.Getenv("PGHOST"))
	}
	user := strings.TrimSpace(os.Getenv("POSTGRESQL_USER"))
	if user == "" {
		user = strings.TrimSpace(os.Getenv("PGUSER"))
	}
	pass := os.Getenv("POSTGRESQL_PASSWORD") // may contain spaces/specials
	if pass == "" {
		pass = os.Getenv("PGPASSWORD")
	}
	if pass == "" {
		pass = os.Getenv("POSTGRES_PASSWORD")
	}
	db := strings.TrimSpace(os.Getenv("POSTGRESQL_DATABASE"))
	if db == "" {
		db = strings.TrimSpace(os.Getenv("PGDATABASE"))
	}
	if host == "" || user == "" || db == "" {
		return ""
	}
	port := strings.TrimSpace(os.Getenv("POSTGRESQL_PORT"))
	if port == "" {
		port = strings.TrimSpace(os.Getenv("PGPORT"))
	}
	if port == "" {
		port = "5432"
	}
	sslmode := strings.TrimSpace(os.Getenv("POSTGRESQL_SSLMODE"))
	if sslmode == "" {
		sslmode = strings.TrimSpace(os.Getenv("PGSSLMODE"))
	}
	if sslmode == "" {
		sslmode = "require"
	}
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
