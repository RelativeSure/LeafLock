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

// Config holds application configuration
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
	RateLimitMode      string
	// Default admin settings
	DefaultAdminEnabled  bool
	DefaultAdminEmail    string
	DefaultAdminPassword string
}

// Runtime feature toggles (in-memory; initialized from env at startup)
var RegEnabled atomic.Int32
var TrustProxyHeadersFlag atomic.Bool

// LoadConfig loads configuration from environment variables
func LoadConfig() *Config {
	// Generate secure random keys if not provided
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		log.Fatalf("💥 [FATAL] JWT_SECRET environment variable is required and cannot be empty")
	}
	if len(jwtSecret) < 32 {
		log.Fatalf("💥 [FATAL] JWT_SECRET must be at least 32 characters long for security")
	}
	// Check for common weak/default values and patterns
	weakSecrets := []string{"default", "secret", "jwt_secret", "change_me", "insecure", "test", "development", "password", "admin", "your_"}
	jwtLower := strings.ToLower(jwtSecret)
	for _, weak := range weakSecrets {
		if strings.HasPrefix(jwtLower, weak) || strings.EqualFold(jwtSecret, weak) {
			log.Fatalf("💥 [FATAL] JWT_SECRET cannot start with or be a weak value: '%s'", weak)
		}
	}

	encKey := os.Getenv("SERVER_ENCRYPTION_KEY")
	if encKey == "" {
		log.Fatalf("💥 [FATAL] SERVER_ENCRYPTION_KEY environment variable is required and cannot be empty")
	}
	if len(encKey) < 32 {
		log.Fatalf("💥 [FATAL] SERVER_ENCRYPTION_KEY must be at least 32 characters long for security")
	}
	// Check for common weak/default values and patterns
	encLower := strings.ToLower(encKey)
	for _, weak := range weakSecrets {
		if strings.HasPrefix(encLower, weak) || strings.EqualFold(encKey, weak) {
			log.Fatalf("💥 [FATAL] SERVER_ENCRYPTION_KEY cannot start with or be a weak value: '%s'", weak)
		}
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
		JWTSecret:     []byte(jwtSecret),
		EncryptionKey: []byte(encKey),
		Port:          GetEnvOrDefault("PORT", "8080"),
		AllowedOrigins: func() []string {
			origins := strings.Split(GetEnvOrDefault("CORS_ORIGINS", "https://localhost:3000"), ",")
			// Trim whitespace from each origin to prevent CORS issues
			for i := range origins {
				origins[i] = strings.TrimSpace(origins[i])
			}
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
		// Default admin configuration
		DefaultAdminEnabled:  GetEnvAsBool("ENABLE_DEFAULT_ADMIN", true),
		DefaultAdminEmail:    GetEnvOrDefault("DEFAULT_ADMIN_EMAIL", "admin@leaflock.app"),
		DefaultAdminPassword: adminPassword,
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
