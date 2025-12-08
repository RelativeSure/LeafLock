package auth

import (
	"os"
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
		EnableDebugLogging: clerkDebug,
		EnableDebugEndpoints: clerkDebug, // Merge: debug endpoints enabled when CLERK_DEBUG=true
		ClerkSecretKey:     os.Getenv("CLERK_SECRET_KEY"),
		RateLimitAuthAttempts: getEnvAsBool("RATE_LIMIT_AUTH", true),
		AuthFailureThreshold: getEnvAsInt("AUTH_FAILURE_THRESHOLD", 5),
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
func (c *Config) HasValidClerkConfig() bool {
	return c.ClerkSecretKey != "" && 
		   len(c.ClerkSecretKey) > 20 &&
		   (len(c.ClerkSecretKey) > 50 || !containsSuspiciousPattern(c.ClerkSecretKey))
}

func containsSuspiciousPattern(s string) bool {
	suspicious := []string{"test", "example", "default", "your_key", "replace_me"}
	lower := strings.ToLower(s)
	for _, pattern := range suspicious {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}
