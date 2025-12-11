package utils

import (
	"bytes"
	"log"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

// captureLogOutput captures log output for testing
func captureLogOutput(f func()) string {
	var buf bytes.Buffer
	oldFlags := log.Flags()
	oldPrefix := log.Prefix()
	oldWriter := log.Writer()

	log.SetOutput(&buf)
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.SetPrefix("[SECURITY] ")

	f()

	log.SetOutput(oldWriter)
	log.SetFlags(oldFlags)
	log.SetPrefix(oldPrefix)

	return buf.String()
}

// TestNewSecurityLogger tests security logger creation
func TestNewSecurityLogger(t *testing.T) {
	logger := NewSecurityLogger()
	assert.NotNil(t, logger)
	assert.NotNil(t, logger.logger)
}

// TestSecurityLogger_LogAuthEvent tests authentication event logging
func TestSecurityLogger_LogAuthEvent(t *testing.T) {
	logger := NewSecurityLogger()
	userID := uuid.New()
	metadata := map[string]interface{}{
		"ip":         "192.168.1.1",
		"user_agent": "Mozilla/5.0",
	}

	output := captureLogOutput(func() {
		logger.LogAuthEvent("login_attempt", userID, true, metadata)
	})

	assert.Contains(t, output, "AUTH_EVENT:")
	assert.Contains(t, output, "login_attempt")
	assert.Contains(t, output, "success=true")
	assert.Contains(t, output, "[uuid:")
}

// TestSecurityLogger_LogSecurityEvent tests security event logging
func TestSecurityLogger_LogSecurityEvent(t *testing.T) {
	logger := NewSecurityLogger()
	details := map[string]interface{}{
		"action": "unauthorized_access",
		"ip":     "192.168.1.1",
	}

	output := captureLogOutput(func() {
		logger.LogSecurityEvent("suspicious_activity", "high", details)
	})

	assert.Contains(t, output, "SECURITY_EVENT:")
	assert.Contains(t, output, "suspicious_activity")
	assert.Contains(t, output, "severity=high")
}

// TestSecurityLogger_LogError tests error logging
func TestSecurityLogger_LogError(t *testing.T) {
	logger := NewSecurityLogger()
	context := map[string]interface{}{
		"endpoint": "/api/test",
		"method":   "POST",
	}
	err := assert.AnError

	output := captureLogOutput(func() {
		logger.LogError("test_operation", err, context)
	})

	assert.Contains(t, output, "ERROR:")
	assert.Contains(t, output, "test_operation")
	assert.Contains(t, output, err.Error())
}

// TestSecurityLogger_LogTokenEvent tests token event logging
func TestSecurityLogger_LogTokenEvent(t *testing.T) {
	logger := NewSecurityLogger()
	userID := uuid.New()
	tokenHash := "abc123"

	output := captureLogOutput(func() {
		logger.LogTokenEvent("token_refreshed", tokenHash, userID)
	})

	assert.Contains(t, output, "TOKEN_EVENT:")
	assert.Contains(t, output, "token_refreshed")
	assert.Contains(t, output, "token_hash=abc123")
}

// TestSecurityLogger_LogSessionEvent tests session event logging
func TestSecurityLogger_LogSessionEvent(t *testing.T) {
	logger := NewSecurityLogger()
	userID := uuid.New()
	sessionID := "sess_1234567890"

	output := captureLogOutput(func() {
		logger.LogSessionEvent("session_created", sessionID, userID)
	})

	assert.Contains(t, output, "SESSION_EVENT:")
	assert.Contains(t, output, "session_created")
	assert.Contains(t, output, "session=")
	assert.Contains(t, output, "[session:")
}

// TestStructuredSecurityLog tests structured security logging
func TestStructuredSecurityLog(t *testing.T) {
	userID := uuid.New()
	details := map[string]interface{}{
		"action": "test_action",
		"result": "success",
	}

	output := captureLogOutput(func() {
		StructuredSecurityLog("test_event", "medium", userID, details)
	})

	assert.Contains(t, output, "SECURITY_EVENT:")
	assert.Contains(t, output, "test_event")
	assert.Contains(t, output, "severity=medium")
}

// TestRedactUUID tests UUID redaction
func TestRedactUUID(t *testing.T) {
	tests := []struct {
		name     string
		uuid     uuid.UUID
		expected string
	}{
		{
			name:     "ValidUUID",
			uuid:     uuid.MustParse("550e8400-e29b-41d4-a716-446655440000"),
			expected: "[uuid:550e8400...]",
		},
		{
			name:     "NilUUID",
			uuid:     uuid.Nil,
			expected: "[nil]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := redactUUID(tt.uuid)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestRedactSessionID tests session ID redaction
func TestRedactSessionID(t *testing.T) {
	tests := []struct {
		name      string
		sessionID string
		expected  string
	}{
		{
			name:      "LongSessionID",
			sessionID: "sess_1234567890abcdef",
			expected:  "[session:sess_123...]",
		},
		{
			name:      "ShortSessionID",
			sessionID: "1234",
			expected:  "[session:...]",
		},
		{
			name:      "EmptySessionID",
			sessionID: "",
			expected:  "[session:...]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := redactSessionID(tt.sessionID)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestRedactUUID_Subset tests that UUID is properly redacted to 8 chars
func TestRedactUUID_Subset(t *testing.T) {
	testUUID := uuid.MustParse("12345678-1234-1234-1234-123456789012")
	result := redactUUID(testUUID)
	
	// Should contain the first 8 characters
	assert.Contains(t, result, "12345678")
	// Should not contain the full UUID
	assert.NotContains(t, result, "12345678-1234-1234-1234-123456789012")
}

// TestSanitizeValue_HappensInLogger tests that sanitization happens in logger calls
func TestSanitizeValue_HappensInLogger(t *testing.T) {
	logger := NewSecurityLogger()
	userID := uuid.New()
	email := "test@example.com"
	phone := "+1234567890"
	ip := "192.168.1.1"
	
	metadata := map[string]interface{}{
		"email": email,
		"phone": phone,
		"ip":    ip,
	}

	output := captureLogOutput(func() {
		logger.LogAuthEvent("login_attempt", userID, true, metadata)
	})

	// Should have sanitized values
	assert.Contains(t, output, "[email]")
	assert.Contains(t, output, "[phone]")
	assert.Contains(t, output, "[ip]")
	// Should NOT have raw values
	assert.NotContains(t, output, "test@example.com")
	assert.NotContains(t, output, "+1234567890")
	assert.NotContains(t, output, "192.168.1.1")
}

// TestSecurityLogger_LogSecurityEvent_WithNilDetails tests with nil details
func TestSecurityLogger_LogSecurityEvent_WithNilDetails(t *testing.T) {
	logger := NewSecurityLogger()

	output := captureLogOutput(func() {
		logger.LogSecurityEvent("test_event", "low", nil)
	})

	assert.Contains(t, output, "SECURITY_EVENT:")
}

// TestSecurityLogger_MultipleEventTypes tests all event types
func TestSecurityLogger_MultipleEventTypes(t *testing.T) {
	logger := NewSecurityLogger()
	userID := uuid.New()
	tokenHash := "hash123"
	sessionID := "sess_abc"

	outputs := []string{
		captureLogOutput(func() { logger.LogAuthEvent("login", userID, true, nil) }),
		captureLogOutput(func() { logger.LogTokenEvent("token_generated", tokenHash, userID) }),
		captureLogOutput(func() { logger.LogSessionEvent("session_ended", sessionID, userID) }),
		captureLogOutput(func() { logger.LogSecurityEvent("security_check", "high", nil) }),
		captureLogOutput(func() { logger.LogError("operation", assert.AnError, nil) }),
	}

	expectedPatterns := [][]string{
		{"AUTH_EVENT:", "login"},
		{"TOKEN_EVENT:", "token_generated"},
		{"SESSION_EVENT:", "session_ended"},
		{"SECURITY_EVENT:", "security_check", "severity=high"},
		{"ERROR:", "operation"},
	}

	for i, output := range outputs {
		for _, pattern := range expectedPatterns[i] {
			assert.Contains(t, output, pattern, "Output %d should contain %s", i, pattern)
		}
	}
}