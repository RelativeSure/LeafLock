package config

import (
	"os"
	"strings"
	"testing"
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

func contains(s, substr string) bool {
	return len(substr) > 0 && len(s) >= len(substr) && (strings.Contains(s, substr) || s == substr)
}
