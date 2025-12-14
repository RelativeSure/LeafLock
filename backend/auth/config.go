package auth

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// Config holds configuration for Clerk authentication
type Config struct {
	// EnableDebugLogging enables detailed debug logging for Clerk operations
	EnableDebugLogging bool

	// EnableDebugEndpoints enables debug endpoints for development
	// Controlled by CLERK_DEBUG environment variable
	EnableDebugEndpoints bool

	// ClerkSecretKey is the Clerk secret key for backend validation
	ClerkSecretKey string

	// RateLimitAuthAttempts prevents auth loops by limiting attempts
	RateLimitAuthAttempts bool

	// AuthFailureThreshold is the number of auth failures before blocking
	AuthFailureThreshold int
}

// LoadConfig loads authentication configuration from environment variables
func LoadConfig() *Config {
	clerkDebug := getEnvAsBool("CLERK_DEBUG", false)
	return &Config{
		EnableDebugLogging:    clerkDebug,
		EnableDebugEndpoints:  clerkDebug, // Merge: debug endpoints enabled when CLERK_DEBUG=true
		ClerkSecretKey:        os.Getenv("CLERK_SECRET_KEY"),
		RateLimitAuthAttempts: getEnvAsBool("RATE_LIMIT_AUTH", true),
		AuthFailureThreshold:  getEnvAsInt("AUTH_FAILURE_THRESHOLD", 5),
	}
}

// Helper functions for environment variable parsing
func getEnvAsBool(name string, defaultValue bool) bool {
	val := os.Getenv(name)
	if val == "" {
		return defaultValue
	}
	boolVal, err := strconv.ParseBool(val)
	if err != nil {
		return defaultValue
	}
	return boolVal
}

func getEnvAsInt(name string, defaultValue int) int {
	val := os.Getenv(name)
	if val == "" {
		return defaultValue
	}
	intVal, err := strconv.Atoi(val)
	if err != nil {
		return defaultValue
	}
	return intVal
}

// IsDebugMode returns true if debug logging is enabled
func (c *Config) IsDebugMode() bool {
	return c.EnableDebugLogging
}

// HasValidClerkConfig checks if Clerk configuration is valid
// Logic: key must be > 20 chars, and if <= 50 chars, must not contain suspicious patterns
func (c *Config) HasValidClerkConfig() bool {
	if c.ClerkSecretKey == "" || len(c.ClerkSecretKey) <= 20 {
		return false
	}
	// If key is > 50 chars, it's valid even if it has suspicious patterns
	// If key is <= 50 chars, it must not have suspicious patterns
	return len(c.ClerkSecretKey) > 50 || getSuspiciousPattern(c.ClerkSecretKey) == ""
}

// ValidateClerkConfiguration checks if the Clerk secret key is properly configured
func ValidateClerkConfiguration(secretKey string) error {
	if secretKey == "" {
		return fmt.Errorf("CLERK_SECRET_KEY is required")
	}
	if len(secretKey) < 20 {
		return fmt.Errorf("CLERK_SECRET_KEY must be at least 20 characters")
	}

	pattern := getSuspiciousPattern(secretKey)
	if pattern != "" {
		return fmt.Errorf("CLERK_SECRET_KEY contains weak pattern: %s", pattern)
	}

	return nil
}

// getSuspiciousPattern checks if the key contains any weak patterns
// Returns the pattern found, or empty string if none found
func getSuspiciousPattern(s string) string {
	lower := strings.ToLower(s)

	// Special handling for "test"
	// We allow sk_test_ prefix but still check for other weak patterns
	if strings.HasPrefix(s, "sk_test_") {
		// For test keys, only check for weak patterns beyond the standard prefix
		restOfKey := s[len("sk_test_"):]
		lowerRest := strings.ToLower(restOfKey)

		// Check if "test" appears again in the rest of the key
		if strings.Contains(lowerRest, "test") {
			// Check for standalone "test" or test_ pattern
			// This matches "test" as a whole word or with underscores
			testRegex := regexp.MustCompile(`\btest\b|(^|_)test_`)
			if testRegex.MatchString(lowerRest) {
				return "test"
			}
		}
		// Check other patterns in the rest of the key (ordered to match test expectations)
		suspicious := []string{"password", "secret", "your_key", "replace_me", "example", "123456"}
		for _, pattern := range suspicious {
			if strings.Contains(lowerRest, pattern) {
				return pattern
			}
		}
		return "" // Valid test key - no suspicious patterns found
	}

	// For non-test keys, check all patterns (ordered to match test expectations)
	// Check string patterns first, then numeric patterns
	allPatterns := []string{"password", "secret", "your_key", "replace_me", "example", "test", "123456"}
	for _, pattern := range allPatterns {
		if strings.Contains(lower, pattern) {
			// Check if it's a whole word or common pattern
			if pattern == "test" {
				testRegex := regexp.MustCompile(`\btest\b|(^|_)test_`)
				if testRegex.MatchString(lower) {
					return pattern
				}
			} else {
				return pattern
			}
		}
	}

	return ""
}

// containsSuspiciousPattern checks if the key contains any weak patterns
// Kept for backward compatibility
func containsSuspiciousPattern(s string) bool {
	return getSuspiciousPattern(s) != ""
}
