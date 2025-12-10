package utils

import (
	"log"

	"github.com/google/uuid"
)

// SecurityLogger provides secure logging with PII redaction
type SecurityLogger struct {
	logger *log.Logger
}

// NewSecurityLogger creates a new security logger
func NewSecurityLogger() *SecurityLogger {
	return &SecurityLogger{
		logger: log.New(log.Writer(), "[SECURITY] ", log.LstdFlags|log.Lshortfile),
	}
}

// LogAuthEvent logs authentication events with PII redaction
func (sl *SecurityLogger) LogAuthEvent(event string, userID uuid.UUID, success bool, metadata map[string]interface{}) {
	// Redact user ID for privacy
	redactedUserID := redactUUID(userID)

	// Create safe metadata copy
	safeMetadata := make(map[string]interface{})
	for key, value := range metadata {
		safeMetadata[key] = SanitizeValue(value)
	}

	sl.logger.Printf("AUTH_EVENT: %s user=%s success=%v metadata=%v",
		event, redactedUserID, success, safeMetadata)
}

// LogSecurityEvent logs security-related events
func (sl *SecurityLogger) LogSecurityEvent(event string, severity string, details map[string]interface{}) {
	// Sanitize details to remove PII
	safeDetails := make(map[string]interface{})
	for key, value := range details {
		safeDetails[key] = SanitizeValue(value)
	}

	sl.logger.Printf("SECURITY_EVENT: %s severity=%s details=%v",
		event, severity, safeDetails)
}

// LogError logs errors with PII redaction
func (sl *SecurityLogger) LogError(operation string, err error, context map[string]interface{}) {
	// Sanitize context
	safeContext := make(map[string]interface{})
	for key, value := range context {
		safeContext[key] = SanitizeValue(value)
	}

	sl.logger.Printf("ERROR: operation=%s error=%v context=%v",
		operation, err.Error(), safeContext)
}

// LogTokenEvent logs token-related events (with redaction)
func (sl *SecurityLogger) LogTokenEvent(event string, tokenHash string, userID uuid.UUID) {
	redactedUserID := redactUUID(userID)
	sl.logger.Printf("TOKEN_EVENT: %s token_hash=%s user=%s",
		event, tokenHash, redactedUserID)
}

// LogSessionEvent logs session events
func (sl *SecurityLogger) LogSessionEvent(event string, sessionID string, userID uuid.UUID) {
	redactedUserID := redactUUID(userID)
	redactedSessionID := redactSessionID(sessionID)

	sl.logger.Printf("SESSION_EVENT: %s session=%s user=%s",
		event, redactedSessionID, redactedUserID)
}


// StructuredSecurityLog creates structured security log entry
func StructuredSecurityLog(event string, severity string, userID uuid.UUID, details map[string]interface{}) {
	logger := NewSecurityLogger()
	logger.LogSecurityEvent(event, severity, map[string]interface{}{
		"user_id": redactUUID(userID),
		"details": SanitizeValue(details),
	})
}

// redactUUID redacts UUID values
func redactUUID(id uuid.UUID) string {
	if id == uuid.Nil {
		return "[nil]"
	}
	return "[uuid:" + id.String()[:8] + "...]"
}

// redactSessionID redacts session IDs
func redactSessionID(sessionID string) string {
	if len(sessionID) < 8 {
		return "[session:...]"
	}
	return "[session:" + sessionID[:8] + "...]"
}

