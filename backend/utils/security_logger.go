package utils

import (
	"log"
	"strings"

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
		safeMetadata[key] = sanitizeValue(value)
	}
	
	sl.logger.Printf("AUTH_EVENT: %s user=%s success=%v metadata=%v", 
		event, redactedUserID, success, safeMetadata)
}

// LogSecurityEvent logs security-related events
func (sl *SecurityLogger) LogSecurityEvent(event string, severity string, details map[string]interface{}) {
	// Sanitize details to remove PII
	safeDetails := make(map[string]interface{})
	for key, value := range details {
		safeDetails[key] = sanitizeValue(value)
	}
	
	sl.logger.Printf("SECURITY_EVENT: %s severity=%s details=%v", 
		event, severity, safeDetails)
}

// LogError logs errors with PII redaction
func (sl *SecurityLogger) LogError(operation string, err error, context map[string]interface{}) {
	// Sanitize context
	safeContext := make(map[string]interface{})
	for key, value := range context {
		safeContext[key] = sanitizeValue(value)
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

// sanitizeValue removes or redacts sensitive values
func sanitizeValue(value interface{}) interface{} {
	switch v := value.(type) {
	case string:
		return sanitizeString(v)
	case uuid.UUID:
		return redactUUID(v)
	case []string:
		result := make([]string, len(v))
		for i, s := range v {
			result[i] = sanitizeString(s)
		}
		return result
	case map[string]interface{}:
		result := make(map[string]interface{})
		for key, val := range v {
			result[key] = sanitizeValue(val)
		}
		return result
	default:
		// For other types, return as-is (assumed safe)
		return value
	}
}

// sanitizeString removes sensitive information from strings
func sanitizeString(s string) string {
	// Remove email addresses
	if strings.Contains(s, "@") {
		parts := strings.Split(s, "@")
		if len(parts) == 2 {
			return redactEmail(parts[0]) + "@" + redactDomain(parts[1])
		}
	}
	
	// Remove phone numbers (basic pattern)
	if isPhoneNumber(s) {
		return redactPhoneNumber(s)
	}
	
	// Remove credit card numbers (basic pattern)
	if isCreditCard(s) {
		return redactCreditCard(s)
	}
	
	// Remove tokens/secrets (basic pattern)
	if isTokenOrSecret(s) {
		return redactToken(s)
	}
	
	return s
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

// redactEmail redacts email username
func redactEmail(username string) string {
	if len(username) <= 3 {
		return "[email]"
	}
	return username[:1] + "***" + username[len(username)-1:]
}

// redactDomain redacts email domain
func redactDomain(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) >= 2 {
		return "[domain]." + parts[len(parts)-1]
	}
	return "[domain]"
}

// isPhoneNumber checks if string looks like phone number
func isPhoneNumber(s string) bool {
	// Simple phone number detection
	return len(s) >= 10 && len(s) <= 15 && strings.ContainsAny(s, "0123456789+-()")
}

// redactPhoneNumber redacts phone numbers
func redactPhoneNumber(phone string) string {
	// Keep country code and last 4 digits
	cleaned := strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, phone)
	
	if len(cleaned) >= 10 {
		return "+" + cleaned[:len(cleaned)-4] + "****"
	}
	return "[phone]"
}

// isCreditCard checks if string looks like credit card
func isCreditCard(s string) bool {
	// Simple credit card detection (16 digits with spaces/dashes)
	cleaned := strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, s)
	
	return len(cleaned) >= 13 && len(cleaned) <= 19
}

// redactCreditCard redacts credit card numbers
func redactCreditCard(card string) string {
	cleaned := strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, card)
	
	if len(cleaned) >= 13 {
		return "****" + cleaned[len(cleaned)-4:]
	}
	return "[card]"
}

// isTokenOrSecret checks if string looks like token/secret
func isTokenOrSecret(s string) bool {
	// Check for common token patterns (long strings with mixed case and numbers)
	if len(s) >= 20 && strings.ContainsAny(s, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") {
		return true
	}
	
	// Check for JWT-like patterns
	if strings.Count(s, ".") >= 2 && len(s) > 20 {
		return true
	}
	
	return false
}

// redactToken redacts tokens and secrets
func redactToken(token string) string {
	if len(token) <= 8 {
		return "[token]"
	}
	return token[:4] + "****" + token[len(token)-4:]
}

// StructuredSecurityLog creates structured security log entry
func StructuredSecurityLog(event string, severity string, userID uuid.UUID, details map[string]interface{}) {
	logger := NewSecurityLogger()
	logger.LogSecurityEvent(event, severity, map[string]interface{}{
		"user_id": redactUUID(userID),
		"details": sanitizeValue(details),
	})
}