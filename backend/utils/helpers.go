package utils

import (
	"database/sql"
	"strings"
	"time"
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