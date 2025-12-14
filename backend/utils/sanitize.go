package utils

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/google/uuid"
)

// SanitizeValue sanitizes a value for secure logging
func SanitizeValue(value interface{}) interface{} {
	if value == nil {
		return nil
	}

	// Handle UUID values specially - don't sanitize them as strings
	if u, ok := value.(uuid.UUID); ok {
		return redactUUID(u)
	}

	str := fmt.Sprintf("%v", value)

	// Remove emails
	emailRegex := regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	str = emailRegex.ReplaceAllString(str, "[email]")

	// Remove phone numbers
	phoneRegex := regexp.MustCompile(`(\+?\d{1,3})?[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}`)
	str = phoneRegex.ReplaceAllString(str, "[phone]")

	// Remove IP addresses
	ipRegex := regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)
	str = ipRegex.ReplaceAllString(str, "[ip]")

	// Remove tokens/secrets (alphanumeric strings > 10 chars)
	// Look for strings of alphanumeric characters (common token lengths)
	tokenRegex := regexp.MustCompile(`[a-zA-Z0-9]{10,}`)
	str = tokenRegex.ReplaceAllString(str, "[token]")

	return str
}

// RedactIP redacts IP addresses for privacy
func RedactIP(ip string) string {
	if ip == "" {
		return ""
	}

	// Simple IP redaction - keep first octet only
	if strings.Contains(ip, ".") {
		parts := strings.Split(ip, ".")
		if len(parts) == 4 {
			return parts[0] + ".***.***.***"
		}
	}

	return "***.***.***.***"
}

// SanitizeUserAgent sanitizes user agent strings
func SanitizeUserAgent(userAgent string) string {
	if userAgent == "" {
		return ""
	}

	// Remove version numbers and specific identifiers
	ua := regexp.MustCompile(`\d+\.\d+(\.\d+)*`).ReplaceAllString(userAgent, "[version]")
	ua = regexp.MustCompile(`\([a-zA-Z0-9_;.:\s]+\)`).ReplaceAllString(ua, "[platform]")

	return ua
}
