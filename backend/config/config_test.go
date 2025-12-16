package config

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestGetEnvOrDefault(t *testing.T) {
	tests := []struct {
		name         string
		key          string
		defaultValue string
		envValue     string
		expected     string
	}{
		{"returns env value when set", "TEST_KEY", "default", "env_value", "env_value"},
		{"returns default when not set", "NONEXISTENT_KEY", "default", "", "default"},
		{"returns empty string when env is empty", "EMPTY_KEY", "default", "", "default"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envValue != "" {
				_ = os.Setenv(tt.key, tt.envValue) // Test setup
				defer func() { _ = os.Unsetenv(tt.key) }()
			}
			result := GetEnvOrDefault(tt.key, tt.defaultValue)
			if result != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestGetEnvAsBool(t *testing.T) {
	tests := []struct {
		name         string
		key          string
		defaultValue bool
		envValue     string
		expected     bool
	}{
		{"returns true for 'true'", "BOOL_KEY", false, "true", true},
		{"returns true for '1'", "BOOL_KEY", false, "1", true},
		{"returns true for 'yes'", "BOOL_KEY", false, "yes", true},
		{"returns false for 'false'", "BOOL_KEY", true, "false", false},
		{"returns false for '0'", "BOOL_KEY", true, "0", false},
		{"returns false for 'no'", "BOOL_KEY", true, "no", false},
		{"returns default for invalid", "BOOL_KEY", true, "invalid", true},
		{"returns default when not set", "NONEXISTENT_BOOL", false, "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envValue != "" {
				_ = os.Setenv(tt.key, tt.envValue) // Test setup
				defer func() { _ = os.Unsetenv(tt.key) }()
			} else {
				_ = os.Unsetenv(tt.key) // Test setup
			}
			result := GetEnvAsBool(tt.key, tt.defaultValue)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestGetEnvAsInt(t *testing.T) {
	tests := []struct {
		name         string
		key          string
		defaultValue int
		envValue     string
		expected     int
	}{
		{"returns int value", "INT_KEY", 10, "42", 42},
		{"returns default for invalid", "INT_KEY", 10, "invalid", 10},
		{"returns default when not set", "NONEXISTENT_INT", 99, "", 99},
		{"handles negative numbers", "INT_KEY", 0, "-5", -5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envValue != "" {
				_ = os.Setenv(tt.key, tt.envValue) // Test setup
				defer func() { _ = os.Unsetenv(tt.key) }()
			} else {
				_ = os.Unsetenv(tt.key) // Test setup
			}
			result := GetEnvAsInt(tt.key, tt.defaultValue)
			if result != tt.expected {
				t.Errorf("expected %d, got %d", tt.expected, result)
			}
		})
	}
}

func TestGetEnvAsStringSlice(t *testing.T) {
	tests := []struct {
		name         string
		key          string
		defaultValue []string
		envValue     string
		expected     []string
	}{
		{"returns slice from comma-separated", "SLICE_KEY", []string{"default"}, "a,b,c", []string{"a", "b", "c"}},
		{"trims whitespace", "SLICE_KEY", []string{}, "a, b , c", []string{"a", "b", "c"}},
		{"returns default when not set", "NONEXISTENT_SLICE", []string{"x", "y"}, "", []string{"x", "y"}},
		{"handles single value", "SLICE_KEY", []string{}, "single", []string{"single"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envValue != "" {
				_ = os.Setenv(tt.key, tt.envValue) // Test setup
				defer func() { _ = os.Unsetenv(tt.key) }()
			} else {
				_ = os.Unsetenv(tt.key) // Test setup
			}
			result := GetEnvAsStringSlice(tt.key, tt.defaultValue)
			if len(result) != len(tt.expected) {
				t.Errorf("expected length %d, got %d", len(tt.expected), len(result))
				return
			}
			for i := range result {
				if result[i] != tt.expected[i] {
					t.Errorf("expected %v, got %v", tt.expected, result)
					return
				}
			}
		})
	}
}

func TestNormalizeRedisAddress(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"handles plain host:port", "localhost:6379", "localhost:6379"},
		{"extracts host from redis URL", "redis://localhost:6379", "localhost:6379"},
		{"extracts host with auth", "redis://:password@localhost:6379", "localhost:6379"},
		{"handles empty string", "", ""},
		{"handles invalid URL gracefully", "not a url", "not a url"},
		{"handles URL with path", "redis://localhost:6379/0", "localhost:6379"},
		{"handles URL with query params", "redis://localhost:6379?ssl=true", "localhost:6379"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeRedisAddress(tt.input)
			if result != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestResolveRedisPassword(t *testing.T) {
	tests := []struct {
		name     string
		redisURL string
		explicit string
		expected string
	}{
		{"prefers explicit password", "redis://:urlpass@localhost:6379", "explicit", "explicit"},
		{"extracts from URL when no explicit", "redis://:urlpass@localhost:6379", "", "urlpass"},
		{"returns empty when no password", "redis://localhost:6379", "", ""},
		{"handles plain address", "localhost:6379", "", ""},
		{"handles URL with username and password", "redis://user:pass@localhost:6379", "", "pass"},
		{"handles invalid URL", "not://valid::url", "", ""},
		{"handles empty URL with explicit", "", "mypass", "mypass"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := resolveRedisPassword(tt.redisURL, tt.explicit)
			if result != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestBuildDatabaseURLFromEnv(t *testing.T) {
	originalEnvs := []struct {
		key   string
		value string
	}{
		{"POSTGRESQL_HOST", os.Getenv("POSTGRESQL_HOST")},
		{"POSTGRESQL_USER", os.Getenv("POSTGRESQL_USER")},
		{"POSTGRESQL_PASSWORD", os.Getenv("POSTGRESQL_PASSWORD")},
		{"POSTGRESQL_DATABASE", os.Getenv("POSTGRESQL_DATABASE")},
		{"POSTGRESQL_PORT", os.Getenv("POSTGRESQL_PORT")},
		{"POSTGRESQL_SSLMODE", os.Getenv("POSTGRESQL_SSLMODE")},
	}
	defer func() {
		for _, env := range originalEnvs {
			if env.value != "" {
				_ = os.Setenv(env.key, env.value)
			} else {
				_ = os.Unsetenv(env.key)
			}
			}
	}()

	t.Run("returns empty when required vars missing", func(t *testing.T) {
		_ = os.Unsetenv("POSTGRESQL_HOST")
		_ = os.Unsetenv("POSTGRESQL_USER")
		_ = os.Unsetenv("POSTGRESQL_DATABASE")
		result := buildDatabaseURLFromEnv()
		if result != "" {
			t.Errorf("expected empty string, got %s", result)
		}
	})

	t.Run("builds URL with required vars", func(t *testing.T) {
		_ = os.Setenv("POSTGRESQL_HOST", "testhost")
		_ = os.Setenv("POSTGRESQL_USER", "testuser")
		_ = os.Setenv("POSTGRESQL_PASSWORD", "testpass123")
		_ = os.Setenv("POSTGRESQL_DATABASE", "testdb")
		_ = os.Unsetenv("POSTGRESQL_PORT")
		_ = os.Unsetenv("POSTGRESQL_SSLMODE")

		result := buildDatabaseURLFromEnv()
		if result == "" {
			t.Error("expected non-empty URL")
		}
		if !contains(result, "testuser") || !contains(result, "testhost") || !contains(result, "testdb") {
			t.Errorf("URL missing expected components: %s", result)
		}
		if !contains(result, "5432") {
			t.Error("should default to port 5432")
		}
		if !contains(result, "sslmode=require") {
			t.Error("should default to sslmode=require")
		}
	})

	t.Run("uses custom port and sslmode", func(t *testing.T) {
		_ = os.Setenv("POSTGRESQL_HOST", "custom")
		_ = os.Setenv("POSTGRESQL_USER", "user")
		_ = os.Setenv("POSTGRESQL_PASSWORD", "pass")
		_ = os.Setenv("POSTGRESQL_DATABASE", "db")
		_ = os.Setenv("POSTGRESQL_PORT", "5433")
		_ = os.Setenv("POSTGRESQL_SSLMODE", "disable")

		result := buildDatabaseURLFromEnv()
		if !contains(result, "5433") {
			t.Error("should use custom port")
		}
		if !contains(result, "sslmode=disable") {
			t.Error("should use custom sslmode")
		}
	})
}

func TestNormalizeLogLevel(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"", "info"},
		{"info", "info"},
		{"INFO", "info"},
		{"debug", "debug"},
		{"DEBUG", "debug"},
		{"trace", "debug"},
		{"warn", "warn"},
		{"warning", "warn"},
		{"error", "error"},
		{"err", "error"},
		{"fatal", "fatal"},
		{"critical", "fatal"},
		{"panic", "fatal"},
		{"unknown", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := normalizeLogLevel(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeLogLevel(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestIsSupportedLogLevel(t *testing.T) {
	tests := []struct {
		level    string
		expected bool
	}{
		{"debug", true},
		{"info", true},
		{"warn", true},
		{"error", true},
		{"fatal", true},
		{"trace", false},
		{"unknown", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.level, func(t *testing.T) {
			result := isSupportedLogLevel(tt.level)
			if result != tt.expected {
				t.Errorf("isSupportedLogLevel(%q) = %v, want %v", tt.level, result, tt.expected)
			}
		})
	}
}

func TestLoadConfigUsesDefaults(t *testing.T) {
	// Zero-knowledge: SERVER_ENCRYPTION_KEY no longer used
	t.Setenv("DATABASE_URL", "postgres://user:StrongPass321!@localhost:5432/leaflock?sslmode=require") // secretlint-disable-line
	t.Setenv("LOG_LEVEL", "")
	t.Setenv("LOGLEVEL", "")
	t.Setenv("SMTP_ENABLED", "")
	t.Setenv("SMTP_HOST", "")
	t.Setenv("SMTP_PORT", "")
	t.Setenv("SMTP_USER", "")
	t.Setenv("SMTP_PASSWORD", "")
	t.Setenv("SMTP_FROM", "")
	t.Setenv("SMTP_USE_TLS", "")
	t.Setenv("SMTP_INSECURE", "")
	t.Setenv("FRONTEND_URL", "")
	t.Setenv("MAX_LOGIN_ATTEMPTS", "")
	t.Setenv("LOCKOUT_MINUTES", "")
	t.Setenv("MAX_IP_LOGIN_ATTEMPTS", "")
	t.Setenv("IP_LOCKOUT_MINUTES", "")
	t.Setenv("TRUST_PROXY_HEADERS", "")
	t.Setenv("RATE_LIMIT_MODE", "")
	t.Setenv("REDIS_URL", "")
	t.Setenv("REDIS_PASSWORD", "")
	t.Setenv("APP_ENV", "")
	t.Setenv("PORT", "")

	cfg := LoadConfig()
	if cfg == nil {
		t.Fatal("expected config, got nil")
	}

	if cfg.Port != "8080" {
		t.Fatalf("expected default port 8080, got %s", cfg.Port)
	}
	if cfg.Environment != "development" {
		t.Fatalf("expected default environment development, got %s", cfg.Environment)
	}
	if len(cfg.AllowedOrigins) != 1 || cfg.AllowedOrigins[0] != "*" {
		t.Fatalf("expected default allowed origins '*', got %v", cfg.AllowedOrigins)
	}
	if cfg.SMTPEnabled {
		t.Error("expected SMTP to be disabled by default")
	}
	if cfg.SMTPHost != "localhost" {
		t.Fatalf("expected default SMTP host localhost, got %s", cfg.SMTPHost)
	}
	if cfg.SMTPPort != 587 {
		t.Fatalf("expected default SMTP port 587, got %d", cfg.SMTPPort)
	}
	if cfg.SMTPUseTLS != true {
		t.Fatalf("expected default SMTPUseTLS true, got %v", cfg.SMTPUseTLS)
	}
	if cfg.SMTPInsecure {
		t.Error("expected SMTPInsecure to be false by default")
	}
	if cfg.LogLevel != "info" {
		t.Fatalf("expected default log level info, got %s", cfg.LogLevel)
	}
	if cfg.TrustProxyHeaders {
		t.Error("expected TrustProxyHeaders default false")
	}
	if cfg.RateLimitMode != "progressive" {
		t.Fatalf("expected default rate limit mode progressive, got %s", cfg.RateLimitMode)
	}
}

func TestLoadConfigBuildsDatabaseURLFromEnv(t *testing.T) {
	// Zero-knowledge: SERVER_ENCRYPTION_KEY no longer used
	t.Setenv("DATABASE_URL", "")
	t.Setenv("POSTGRESQL_HOST", "db.internal.local")
	t.Setenv("POSTGRESQL_USER", "appuser")
	t.Setenv("POSTGRESQL_PASSWORD", "postgres")
	t.Setenv("POSTGRESQL_DATABASE", "leaflock_prod")
	t.Setenv("POSTGRESQL_PORT", "6543")
	t.Setenv("POSTGRESQL_SSLMODE", "disable")
	t.Setenv("APP_ENV", "production")
	t.Setenv("CORS_ORIGINS", "https://example.com, https://another.example")
	t.Setenv("LOG_LEVEL", "VERBOSE")
	t.Setenv("MAX_LOGIN_ATTEMPTS", "7")
	t.Setenv("LOCKOUT_MINUTES", "45")
	t.Setenv("MAX_IP_LOGIN_ATTEMPTS", "21")
	t.Setenv("IP_LOCKOUT_MINUTES", "60")
	t.Setenv("TRUST_PROXY_HEADERS", "true")
	t.Setenv("RATE_LIMIT_MODE", "strict")
	t.Setenv("REDIS_URL", "redis://:password@redis.internal:6380/0")
	t.Setenv("REDIS_PASSWORD", "ExplicitRedisPass!")
	t.Setenv("SMTP_ENABLED", "true")
	t.Setenv("SMTP_HOST", "smtp.example.com")
	t.Setenv("SMTP_PORT", "2525")
	t.Setenv("SMTP_USER", "mailer")
	t.Setenv("SMTP_PASSWORD", "mailerpass")
	t.Setenv("SMTP_FROM", "LeafLock <noreply@example.com>")
	t.Setenv("SMTP_USE_TLS", "false")
	t.Setenv("SMTP_INSECURE", "true")
	t.Setenv("FRONTEND_URL", "https://app.example.com")
	t.Setenv("PORT", "9090")

	cfg := LoadConfig()
	if cfg == nil {
		t.Fatal("expected config, got nil")
	}

	if cfg.DatabaseURL == "" || !contains(cfg.DatabaseURL, "db.internal.local") || !contains(cfg.DatabaseURL, "6543") {
		t.Fatalf("expected DatabaseURL to be built from env vars, got %s", cfg.DatabaseURL)
	}
	if cfg.Environment != "production" {
		t.Fatalf("expected environment production, got %s", cfg.Environment)
	}
	if cfg.Port != "9090" {
		t.Fatalf("expected port 9090, got %s", cfg.Port)
	}
	expectedOrigins := []string{"https://example.com", "https://another.example"}
	if len(cfg.AllowedOrigins) != len(expectedOrigins) {
		t.Fatalf("expected %d allowed origins, got %d", len(expectedOrigins), len(cfg.AllowedOrigins))
	}
	for i, origin := range expectedOrigins {
		if cfg.AllowedOrigins[i] != origin {
			t.Fatalf("expected origin %s, got %s", origin, cfg.AllowedOrigins[i])
		}
	}
	if cfg.LogLevel != "info" {
		t.Fatalf("expected unsupported log level to normalize to info, got %s", cfg.LogLevel)
	}
	if !cfg.TrustProxyHeaders {
		t.Error("expected TrustProxyHeaders to be true")
	}
	if cfg.RateLimitMode != "strict" {
		t.Fatalf("expected rate limit mode strict, got %s", cfg.RateLimitMode)
	}
	if cfg.MaxLoginAttempts != 7 {
		t.Fatalf("expected max login attempts 7, got %d", cfg.MaxLoginAttempts)
	}
	if cfg.LockoutDuration != 45*time.Minute {
		t.Fatalf("expected lockout duration 45m, got %s", cfg.LockoutDuration)
	}
	if cfg.MaxIPLoginAttempts != 21 {
		t.Fatalf("expected max IP login attempts 21, got %d", cfg.MaxIPLoginAttempts)
	}
	if cfg.IPLockoutDuration != 60*time.Minute {
		t.Fatalf("expected IP lockout duration 60m, got %s", cfg.IPLockoutDuration)
	}
	if !cfg.SMTPEnabled {
		t.Error("expected SMTP enabled")
	}
	if cfg.SMTPHost != "smtp.example.com" {
		t.Fatalf("expected SMTP host smtp.example.com, got %s", cfg.SMTPHost)
	}
	if cfg.SMTPPort != 2525 {
		t.Fatalf("expected SMTP port 2525, got %d", cfg.SMTPPort)
	}
	if cfg.SMTPUseTLS {
		t.Error("expected SMTPUseTLS false")
	}
	if !cfg.SMTPInsecure {
		t.Error("expected SMTPInsecure true")
	}
	if cfg.FrontendURL != "https://app.example.com" {
		t.Fatalf("expected FrontendURL https://app.example.com, got %s", cfg.FrontendURL)
	}
	if cfg.RedisPassword != "ExplicitRedisPass!" {
		t.Fatalf("expected explicit Redis password, got %s", cfg.RedisPassword)
	}
}

func contains(s, substr string) bool {
	return len(substr) > 0 && len(s) >= len(substr) && (strings.Contains(s, substr) || s == substr)
}
