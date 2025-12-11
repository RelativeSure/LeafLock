package utils

import (
	"bytes"
	"log"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

// captureLogOutput properly captures log output for testing
func captureLogOutput(f func()) string {
	// Save current log settings
	oldFlags := log.Flags()
	oldPrefix := log.Prefix()
	oldWriter := log.Writer()
	oldExitFunc := log.ExitFunc

	// Create buffer for capture
	var buf bytes.Buffer

	// Set new log settings (minimal flags for test consistency)
	log.SetFlags(0)
	log.SetPrefix("")
	log.SetOutput(&buf)
	log.SetExitFunc(func(int) {})

	// Execute the function
	f()

	// Restore original settings
	log.SetFlags(oldFlags)
	log.SetPrefix(oldPrefix)
	log.SetOutput(oldWriter)
	log.SetExitFunc(oldExitFunc)

	return buf.String()
}

// TestImprovedSecurityLogger tests all security logger functionality
func TestImprovedSecurityLogger(t *testing.T) {
	userID := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
	
	t.Run("AuthEventLogging", func(t *testing.T) {
		logger := NewSecurityLogger()
		
		output := captureLogOutput(func() {
			logger.LogAuthEvent("login_attempt", userID, true, map[string]interface{}{
				"ip": "192.168.1.1",
			})
		})
		
		assert.Contains(t, output, "AUTH_EVENT:")
		assert.Contains(t, output, "login_attempt")
		assert.Contains(t, output, "success=true")
		assert.Contains(t, output, "[uuid:")
		// Verify sanitization
		assert.NotContains(t, output, "192.168.1.1")
		assert.Contains(t, output, "[ip]")
	})
	
	t.Run("SecurityEventLogging", func(t *testing.T) {
		logger := NewSecurityLogger()
		
		output := captureLogOutput(func() {
			logger.LogSecurityEvent("suspicious_activity", "high", map[string]interface{}{
				"user_id": userID,
				"action":  "multiple_failed_attempts",
			})
		})
		
		assert.Contains(t, output, "SECURITY_EVENT:")
		assert.Contains(t, output, "suspicious_activity")
		assert.Contains(t, output, "severity=high")
		assert.Contains(t, output, "[uuid:")
	})
	
	t.Run("ErrorLogging", func(t *testing.T) {
		logger := NewSecurityLogger()
		
		output := captureLogOutput(func() {
			logger.LogError("database_query", assert.AnError, map[string]interface{}{
				"query":     "SELECT * FROM users",
				"user_id":   userID,
				"sensitive": "should_be_sanitized@example.com",
			})
		})
		
		assert.Contains(t, output, "ERROR:")
		assert.Contains(t, output, "database_query")
		assert.Contains(t, output, "assert.AnError")
		assert.Contains(t, output, "[email]")
		assert.NotContains(t, output, "should_be_sanitized@example.com")
	})
	
	t.Run("TokenEventLogging", func(t *testing.T) {
		logger := NewSecurityLogger()
		
		output := captureLogOutput(func() {
			logger.LogTokenEvent("token_generated", "token_hash_12345", userID)
		})
		
		assert.Contains(t, output, "TOKEN_EVENT:")
		assert.Contains(t, output, "token_generated")
		assert.Contains(t, output, "token_hash=token_hash_12345")
		assert.Contains(t, output, "[uuid:")
	})
	
	t.Run("SessionEventLogging", func(t *testing.T) {
		logger := NewSecurityLogger()
		
		output := captureLogOutput(func() {
			logger.LogSessionEvent("session_created", "sess_abc123xyz", userID)
		})
		
		assert.Contains(t, output, "SESSION_EVENT:")
		assert.Contains(t, output, "session_created")
		assert.Contains(t, output, "[session:")
		assert.Contains(t, output, "[uuid:")
	})
}

// TestImprovedSanitizationInLogger tests that sanitization works in all logger methods
func TestImprovedSanitizationInLogger(t *testing.T) {
	userID := uuid.New()
	
	metadata := map[string]interface{}{
		"email":      "user@example.com",
		"phone":      "+1234567890",
		"ip":         "10.0.0.1",
		"token":      "abc123def456",
		"safe_field": "safe_value",
	}
	
	output := captureLogOutput(func() {
		logger := NewSecurityLogger()
		logger.LogAuthEvent("test_event", userID, true, metadata)
	})
	
	// Verify sanitization happened
	assert.Contains(t, output, "[email]")
	assert.Contains(t, output, "[phone]")
	assert.Contains(t, output, "[ip]")
	assert.Contains(t, output, "[token]") // Assuming token > 20 chars
	assert.Contains(t, output, "safe_value")
	
	// Verify original sensitive data is NOT present
	assert.NotContains(t, output, "user@example.com")
	assert.NotContains(t, output, "+1234567890")
	assert.NotContains(t, output, "10.0.0.1")
}

// TestImprovedRedaction tests improved redaction functions
func TestImprovedRedaction(t *testing.T) {
	t.Run("RedactUUID", func(t *testing.T) {
		tests := []struct {
			input    uuid.UUID
			expected string
		}{
			{uuid.Nil, "[nil]"},
			{uuid.MustParse("550e8400-e29b-41d4-a716-446655440000"), "[uuid:550e8400...]"},
			{uuid.MustParse("12345678-1234-5678-1234-123456789abc"), "[uuid:12345678...]"},
		}
		
		for _, tc := range tests {
			result := redactUUID(tc.input)
			assert.Equal(t, tc.expected, result)
			// Ensure full UUID is not present
			if tc.input != uuid.Nil {
				assert.NotContains(t, result, tc.input.String())
			}
		}
	})
	
	t.Run("RedactSessionID", func(t *testing.T) {
		tests := []struct {
			input    string
			expected string
		}{
			{"", "[session:...]"},
			{"short", "[session:...]"},
			{"sess_1234567890abcdef", "[session:sess_123...]"},
			{"very_long_session_identifier_here", "[session:very_lon...]"},
		}
		
		for _, tc := range tests {
			result := redactSessionID(tc.input)
			assert.Equal(t, tc.expected, result)
			// Ensure full session ID is not present (unless too short)
			if len(tc.input) >= 8 {
				assert.NotContains(t, result, tc.input)
			}
		}
	})
}

// TestStructuredLoggingImproved tests structured logging format
func TestStructuredLoggingImproved(t *testing.T) {
	userID := uuid.New()
	
	output := captureLogOutput(func() {
		StructuredSecurityLog("user_login", "info", userID, map[string]interface{}{
			"location": "NYC",
			"device":   "mobile",
		})
	})
	
	assert.Contains(t, output, "SECURITY_EVENT:")
	assert.Contains(t, output, "user_login")
	assert.Contains(t, output, "severity=info")
	assert.Contains(t, output, "[uuid:")
	assert.Contains(t, output, "location")
	assert.Contains(t, output, "device")
}

// TestLoggerCreationImproved tests logger initialization
func TestLoggerCreationImproved(t *testing.T) {
	logger := NewSecurityLogger()
	
	assert.NotNil(t, logger)
	assert.NotNil(t, logger.logger)
	
	// Verify logger works
	output := captureLogOutput(func() {
		logger.LogSecurityEvent("test", "low", nil)
	})
	
	assert.Contains(t, output, "SECURITY_EVENT:")
	assert.Contains(t, output, "test")
}

// BenchmarkSecurityLogger benchmarks security logger performance
func BenchmarkSecurityLogger(b *testing.B) {
	userID := uuid.New()
	metadata := map[string]interface{}{
		"ip":    "192.168.1.1",
		"agent": "test",
	}
	
	b.Run("LogAuthEvent", func(b *testing.B) {
		logger := NewSecurityLogger()
		for i := 0; i < b.N; i++ {
			captureLogOutput(func() {
				logger.LogAuthEvent("login", userID, true, metadata)
			})
		}
	})
	
	b.Run("LogSecurityEvent", func(b *testing.B) {
		logger := NewSecurityLogger()
		for i := 0; i < b.N; i++ {
			captureLogOutput(func() {
				logger.LogSecurityEvent("test_event", "high", metadata)
			})
		}
	})
}