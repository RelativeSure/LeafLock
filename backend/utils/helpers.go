package utils

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"time"
)

// Context keys for storing values
type contextKey string

const (
	ContextKeyClientIP  contextKey = "client_ip"
	ContextKeyUserAgent contextKey = "user_agent"
)

// NilIfInvalid returns nil if sql.NullTime is invalid, otherwise returns the time
func NilIfInvalid(t sql.NullTime) any {
	if t.Valid {
		return t.Time
	}
	return nil
}

// Min returns the smaller of two integers
func Min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Max returns the larger of two integers
func Max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// CSVEscape escapes quotes and wraps in quotes if needed for CSV export
func CSVEscape(s string) string {
	// Escape quotes and wrap in quotes if needed
	if strings.ContainsAny(s, ",\n\r\"") {
		s = strings.ReplaceAll(s, "\"", "\"\"")
		return "\"" + s + "\""
	}
	return s
}

// FormatNullTime formats a sql.NullTime as RFC3339 string or empty string if invalid
func FormatNullTime(t sql.NullTime) string {
	if t.Valid {
		return t.Time.Format(time.RFC3339)
	}
	return ""
}

// GetClientIPFromContext retrieves client IP from context
func GetClientIPFromContext(ctx context.Context) string {
	if ip, ok := ctx.Value(ContextKeyClientIP).(string); ok {
		return ip
	}
	return ""
}

// GetUserAgentFromContext retrieves user agent from context
func GetUserAgentFromContext(ctx context.Context) string {
	if ua, ok := ctx.Value(ContextKeyUserAgent).(string); ok {
		return ua
	}
	return ""
}

// GetEnvironment returns the current application environment (development, production, etc.)
func GetEnvironment() string {
	env := os.Getenv("APP_ENV")
	if env == "" {
		env = os.Getenv("ENVIRONMENT")
	}
	if env == "" {
		env = "development"
	}
	return env
}

// IsProduction returns true if the application is running in production mode
func IsProduction() bool {
	env := GetEnvironment()
	return env == "production" || env == "prod"
}

// IsDevelopment returns true if the application is running in development mode
func IsDevelopment() bool {
	return !IsProduction()
}
