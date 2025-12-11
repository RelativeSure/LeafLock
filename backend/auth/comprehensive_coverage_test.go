package auth

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestComprehensiveConfigCoverage tests all config functionality
func TestComprehensiveConfigCoverage(t *testing.T) {
	t.Run("LoadConfigDefaults", func(t *testing.T) {
		config := LoadConfig()
		assert.NotNil(t, config)
		assert.False(t, config.EnableDebugLogging)
		assert.False(t, config.EnableDebugEndpoints)
		assert.True(t, config.RateLimitAuthAttempts)
		assert.Equal(t, 5, config.AuthFailureThreshold)
		assert.Empty(t, config.ClerkSecretKey)
	})
	
	t.Run("LoadConfigWithEnvVars", func(t *testing.T) {
		t.Setenv("CLERK_DEBUG", "true")
		t.Setenv("AUTH_FAILURE_THRESHOLD", "10")
		t.Setenv("RATE_LIMIT_AUTH", "false")
		t.Setenv("CLERK_SECRET_KEY", "sk_test_PLACEHOLDER_FOR_TESTING_ONLY_ENV")
		
		config := LoadConfig()
		assert.True(t, config.EnableDebugLogging)
		assert.True(t, config.EnableDebugEndpoints)
		assert.False(t, config.RateLimitAuthAttempts)
		assert.Equal(t, 10, config.AuthFailureThreshold)
		assert.Equal(t, "sk_test_PLACEHOLDER_FOR_TESTING_ONLY_ENV", config.ClerkSecretKey)
	})
	
	t.Run("GetEnvAsBoolEdgeCases", func(t *testing.T) {
		// Test all boolean parsing scenarios
		tests := []struct {
			value     string
			defaultVal bool
			expected  bool
		}{
			{"", true, true},      // Empty returns default
			{"invalid", false, false}, // Invalid returns default
			{"true", false, true},
			{"TRUE", false, true},
			{"True", false, true},
			{"false", true, false},
			{"FALSE", true, false},
			{"False", true, false},
			{"1", false, true},
			{"0", true, false},
		}
		
		for i, tc := range tests {
			key := "TEST_BOOL_" + string(rune('A'+i))
			if tc.value != "" {
				t.Setenv(key, tc.value)
			} else {
				os.Unsetenv(key)
			}
			result := getEnvAsBool(key, tc.defaultVal)
			assert.Equal(t, tc.expected, result, "Failed for value: %s", tc.value)
		}
	})
	
	t.Run("GetEnvAsIntEdgeCases", func(t *testing.T) {
		tests := []struct {
			value     string
			defaultVal int
			expected   int
		}{
			{"", 42, 42},
			{"invalid", 42, 42},
			{"100", 42, 100},
			{"-50", 42, -50},
			{"0", 42, 0},
			{"999999", 42, 999999},
		}
		
		for i, tc := range tests {
			key := "TEST_INT_" + string(rune('A'+i))
			if tc.value != "" {
				t.Setenv(key, tc.value)
			} else {
				os.Unsetenv(key)
			}
			result := getEnvAsInt(key, tc.defaultVal)
			assert.Equal(t, tc.expected, result, "Failed for value: %s", tc.value)
		}
	})
	
	t.Run("ConfigHasValidClerkConfigComprehensive", func(t *testing.T) {
		tests := []struct {
			secretKey string
			valid     bool
			reason    string
		}{
			{"", false, "empty"},
			{"short", false, "too short"},
			{"sk_test_PLACEHOLDER_TOO_SHORT", false, "contains test and too short"},
			{"sk_test_PLACEHOLDER_LONG_ENOUGH_TO_PASS_LENGTH_CHECK", true, "long enough despite test"},
			{"sk_live_PLACEHOLDER_VALID_PRODUCTION_KEY", true, "valid production key"},
			{"sk_live_PLACEHOLDER_WITH_PASSWORD_LIKE_STRING", true, "contains password but long enough"},
			{"sk_live_PLACEHOLDER_WITH_DEFAULT_LIKE_STRING", true, "contains default but long enough"},
			{"sk_live_PLACEHOLDER_CONTAINS_YOUR_KEY", false, "contains your_key"},
			{"sk_live_PLACEHOLDER_CONTAINS_REPLACE_ME", false, "contains replace_me"},
		}
		
		for _, tc := range tests {
			config := &Config{ClerkSecretKey: tc.secretKey}
			result := config.HasValidClerkConfig()
			assert.Equal(t, tc.valid, result, "Key %s should be %s", tc.secretKey, tc.reason)
		}
	})
}

// TestComprehensiveClerkErrorHandler tests all error handler functionality
func TestComprehensiveClerkErrorHandler(t *testing.T) {
	handler := NewClerkErrorHandler()
	assert.NotNil(t, handler)
	
	t.Run("CategorizeAllErrorTypesComprehensive", func(t *testing.T) {
		testCases := []struct {
			errorMsg     string
			expectedType string
			expectedSev  string
			expectedMsg  string
		}{
			// Expired token variations
			{"token expired", "token_expired", "info", "Your session has expired. Please sign in again."},
			{"expired token", "token_expired", "info", "Your session has expired. Please sign in again."},
			{"Token expired at 12345", "token_expired", "info", "Your session has expired. Please sign in again."},
			{"TOKEN EXPIRED", "unknown_error", "error", "An error occurred. Please try again."}, // Case-sensitive
			
			// Invalid token variations
			{"invalid token", "invalid_token", "info", "Invalid authentication. Please try again."},
			{"invalid signature", "invalid_token", "info", "Invalid authentication. Please try again."},
			{"token is invalid", "invalid_token", "info", "Invalid authentication. Please try again."},
			
			// Rate limit variations
			{"rate limit", "rate_limited", "warning", "Too many requests. Please try again later."},
			{"rate limit exceeded", "rate_limited", "warning", "Too many requests. Please try again later."},
			{"exceeded rate limit", "rate_limited", "warning", "Too many requests. Please try again later."},
			
			// Unauthorized variations
			{"unauthorized", "unauthorized", "info", "You don't have permission to perform this action."},
			{"unauthorized access", "unauthorized", "info", "You don't have permission to perform this action."},
			{"access unauthorized", "unauthorized", "info", "You don't have permission to perform this action."},
			
			// Not found variations
			{"not found", "not_found", "info", "The requested resource was not found."},
			{"user not found", "not_found", "info", "The requested resource was not found."},
			{"resource not found", "not_found", "info", "The requested resource was not found."},
			
			// Already exists variations
			{"already exists", "already_exists", "info", "This resource already exists."},
			{"user already exists", "already_exists", "info", "This resource already exists."},
			{"already exists in database", "already_exists", "info", "This resource already exists."},
			
			// Network error variations
			{"network error", "network_error", "error", "Network error. Please try again."},
			{"connection failed", "network_error", "error", "Network error. Please try again."},
			{"network timeout", "network_error", "error", "Network error. Please try again."},
			
			// Timeout variations
			{"timeout", "timeout", "error", "Request timed out. Please try again."},
			{"request timeout", "timeout", "error", "Request timed out. Please try again."},
			{"operation timed out", "timeout", "error", "Request timed out. Please try again."},
			
			// Unknown variations
			{"unknown error", "unknown_error", "error", "An error occurred. Please try again."},
			{"something weird", "unknown_error", "error", "An error occurred. Please try again."},
			{"unexpected failure", "unknown_error", "error", "An error occurred. Please try again."},
		}
		
		for _, tc := range testCases {
			err := &customError{msg: tc.errorMsg}
			errType, sev, msg := handler.categorizeClerkError(err)
			
			assert.Equal(t, tc.expectedType, errType, "Wrong type for: %s", tc.errorMsg)
			assert.Equal(t, tc.expectedSev, sev, "Wrong severity for: %s", tc.errorMsg)
			assert.Equal(t, tc.expectedMsg, msg, "Wrong message for: %s", tc.errorMsg)
		}
	})
	
	t.Run("SecureClerkErrorEdgeCases", func(t *testing.T) {
		// Nil error returns nil
		err := SecureClerkError(nil, "test_op")
		assert.Nil(t, err)
		
		// Error with PII gets sanitized
		err = SecureClerkError(&customError{msg: "user@example.com failed authentication"}, "authenticate")
		assert.NotNil(t, err)
		assert.NotContains(t, err.Error(), "user@example.com")
		
		// Error without PII passes through
		err = SecureClerkError(&customError{msg: "authentication failed"}, "authenticate")
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "authentication failed")
		
		// Complex error with multiple PII
		err = SecureClerkError(&customError{msg: "user bob@example.com from 192.168.1.1 with token abc12345"}, "validate")
		assert.NotNil(t, err)
		assert.NotContains(t, err.Error(), "bob@example.com")
		assert.NotContains(t, err.Error(), "192.168.1.1")
	})
	
	t.Run("ValidateClerkConfigurationEdgeCases", func(t *testing.T) {
		testCases := []struct {
			key      string
			expected bool
		}{
			{"sk_live_PLACEHOLDER_PRODUCTION_KEY", true},
			{"sk_test_PLACEHOLDER_DEVELOPMENT_KEY", true},
			{"INVALID_KEY_1234567890123456789012345678901234567890", false},
			{"pk_test_1234567890123456789012345678901234567890", false}, // Wrong prefix
			{"sk_live", false},
			{"   ", false}, // Whitespace
		}
		
		for _, tc := range testCases {
			err := ValidateClerkConfiguration(tc.key)
			if tc.expected {
				assert.NoError(t, err, "Should be valid: %s", tc.key)
			} else {
				assert.Error(t, err, "Should be invalid: %s", tc.key)
			}
		}
	})
}

// TestComprehensiveSanitization tests all sanitization functions
func TestComprehensiveSanitization(t *testing.T) {
	t.Run("SanitizeClerkErrorComprehensive", func(t *testing.T) {
		testCases := []struct {
			input    string
			expected string
		}{
			{"simple error", "simple error"},
			{"user@example.com failed", "[email] failed"},
			{"token FAKE_TOKEN_FOR_TESTING failed", "token [token] failed"},
			{"call +1234567890 for help", "call [phone] for help"},
			{"access from 10.0.0.1", "[ip]"},
			{"multi: user@example.com, +1234567890, 192.168.1.1", "multi: [email], [phone] [phone]"},
		}
		
		for _, tc := range testCases {
			err := &customError{msg: tc.input}
			result := SanitizeClerkError(err)
			assert.Equal(t, tc.expected, result, "Input: %s", tc.input)
		}
		
		// Nil error
		assert.Equal(t, "", SanitizeClerkError(nil))
	})
	
	t.Run("SanitizeClerkErrorComplexScenarios", func(t *testing.T) {
		// Complex multi-PII scenarios
		err := &customError{msg: "user john.doe@example.com from 10.0.0.1 called +1234567890 with token FAKE_JWT_TOKEN_FOR_TESTING"}
		result := SanitizeClerkError(err)
		
		assert.NotContains(t, result, "john.doe@example.com")
		assert.NotContains(t, result, "10.0.0.1")
		assert.NotContains(t, result, "+1234567890")
	})
}

// TestComprehensiveMiddlewareCoverage tests middleware functionality
func TestComprehensiveMiddlewareCoverage(t *testing.T) {
	t.Run("IsClerkInitializedComprehensive", func(t *testing.T) {
		handler := &Handler{}
		
		handler.config = nil
		assert.False(t, handler.isClerkInitialized())
		
		handler.config = &Config{ClerkSecretKey: ""}
		assert.False(t, handler.isClerkInitialized())
		
		handler.config = &Config{ClerkSecretKey: "sk_test_PLACEHOLDER_KEY_SHORT"}
		assert.True(t, handler.isClerkInitialized())
		
		handler.config = &Config{ClerkSecretKey: "sk_live_PLACEHOLDER_KEY_LONG"}
		assert.True(t, handler.isClerkInitialized())
	})
	
	t.Run("IsTokenExpiredComprehensive", func(t *testing.T) {
		testCases := []struct {
			msg      string
			expected bool
		}{
			{"", false}, // nil check handled separately
			{"token expired", true},
			{"expired token", true},
			{"Token expired at 12345", true},
			{"invalid token", true},
			{"invalid signature", true},
			{"network error", false},
			{"timeout", false},
			{"rate limit", false},
		}
		
		for _, tc := range testCases {
			assert.Equal(t, tc.expected, isTokenExpired(&customError{msg: tc.msg}), 
				"Wrong result for: %s", tc.msg)
		}
		
		assert.False(t, isTokenExpired(nil))
	})
	
	t.Run("MinFunctionComprehensive", func(t *testing.T) {
		testCases := []struct {
			a, b, expected int
		}{
			{5, 10, 5},
			{10, 5, 5},
			{5, 5, 5},
			{0, 100, 0},
			{-10, 10, -10},
			{10, -10, -10},
			{-50, -100, -100},
			{100, 200, 100},
		}
		
		for _, tc := range testCases {
			assert.Equal(t, tc.expected, min(tc.a, tc.b), 
				"min(%d, %d) should be %d", tc.a, tc.b, tc.expected)
		}
	})
}

// customError is a simple error implementation for testing
type customError struct {
	msg string
}

func (e *customError) Error() string {
	return e.msg
}

// BenchmarkAllCoverageFunctions benchmarks key functions
func BenchmarkAllCoverageFunctions(b *testing.B) {
	b.Run("LoadConfig", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = LoadConfig()
		}
	})
	
	b.Run("CategorizeClerkError", func(b *testing.B) {
		handler := NewClerkErrorHandler()
		err := &customError{msg: "token expired"}
		for i := 0; i < b.N; i++ {
			handler.categorizeClerkError(err)
		}
	})
	
	b.Run("ValidateClerkConfiguration", func(b *testing.B) {
		key := "sk_test_PLACEHOLDER_FOR_BENCHMARKING"
		for i := 0; i < b.N; i++ {
			ValidateClerkConfiguration(key)
		}
	})
	
	b.Run("SanitizeClerkError", func(b *testing.B) {
		err := &customError{msg: "user@example.com failed with token abc1234567890"}
		for i := 0; i < b.N; i++ {
			SanitizeClerkError(err)
		}
	})
}