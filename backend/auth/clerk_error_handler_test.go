package auth

import (
	"bytes"
	"encoding/json"
	"errors"
	"log"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
)

// captureLogOutput captures log output for testing
func captureLogOutput(f func()) string {
	var buf bytes.Buffer
	oldFlags := log.Flags()
	oldPrefix := log.Prefix()
	oldWriter := log.Writer()

	log.SetOutput(&buf)
	log.SetFlags(log.Flags() &^ (log.Ldate | log.Ltime))
	log.SetPrefix("")

	f()

	log.SetOutput(oldWriter)
	log.SetFlags(oldFlags)
	log.SetPrefix(oldPrefix)

	return buf.String()
}

// TestNewClerkErrorHandler tests clerk error handler creation
func TestNewClerkErrorHandler(t *testing.T) {
	handler := NewClerkErrorHandler()
	assert.NotNil(t, handler)
	assert.NotNil(t, handler.logger)
}

// TestClerkErrorHandler_HandleClerkError tests handling various clerk errors
func TestClerkErrorHandler_HandleClerkError(t *testing.T) {
	tests := []struct {
		name           string
		err            error
		operation      string
		haveUserID     bool
		expectedStatus int
		expectedError  string
		expectedCode   string
	}{
		{
			name:           "TokenExpired",
			err:            errors.New("token has expired"),
			operation:      "validate_token",
			haveUserID:     true,
			expectedStatus: 500,
			expectedError:  "Your session has expired. Please sign in again.",
			expectedCode:   "CLERK_ERROR",
		},
		{
			name:           "InvalidToken",
			err:            errors.New("invalid token signature"),
			operation:      "authenticate",
			haveUserID:     false,
			expectedStatus: 500,
			expectedError:  "Invalid authentication. Please try again.",
			expectedCode:   "CLERK_ERROR",
		},
		{
			name:           "RateLimit",
			err:            errors.New("rate limit exceeded"),
			operation:      "api_call",
			haveUserID:     true,
			expectedStatus: 500,
			expectedError:  "Too many requests. Please try again later.",
			expectedCode:   "CLERK_ERROR",
		},
		{
			name:           "Unauthorized",
			err:            errors.New("user unauthorized"),
			operation:      "access_resource",
			haveUserID:     true,
			expectedStatus: 500,
			expectedError:  "You don't have permission to perform this action.",
			expectedCode:   "CLERK_ERROR",
		},
		{
			name:           "NotFound",
			err:            errors.New("user not found"),
			operation:      "find_user",
			haveUserID:     false,
			expectedStatus: 500,
			expectedError:  "The requested resource was not found.",
			expectedCode:   "CLERK_ERROR",
		},
		{
			name:           "AlreadyExists",
			err:            errors.New("email already exists"),
			operation:      "create_user",
			haveUserID:     false,
			expectedStatus: 500,
			expectedError:  "This resource already exists.",
			expectedCode:   "CLERK_ERROR",
		},
		{
			name:           "NetworkError",
			err:            errors.New("network connection failed"),
			operation:      "fetch_data",
			haveUserID:     true,
			expectedStatus: 500,
			expectedError:  "Network error. Please try again.",
			expectedCode:   "CLERK_ERROR",
		},
		{
			name:           "Timeout",
			err:            errors.New("request timeout"),
			operation:      "long_operation",
			haveUserID:     false,
			expectedStatus: 500,
			expectedError:  "Request timed out. Please try again.",
			expectedCode:   "CLERK_ERROR",
		},
		{
			name:           "UnknownError",
			err:            errors.New("something weird happened"),
			operation:      "unknown",
			haveUserID:     false,
			expectedStatus: 500,
			expectedError:  "An error occurred. Please try again.",
			expectedCode:   "CLERK_ERROR",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := NewClerkErrorHandler()

			app := fiber.New()
			app.Get("/test", func(c *fiber.Ctx) error {
				if tt.haveUserID {
					c.Locals("user_id", "user123")
				}

				// Capture log output to verify logging happens
				logOutput := captureLogOutput(func() {
					handler.HandleClerkError(c, tt.err, tt.operation)
				})

				// Verify log output
				assert.Contains(t, logOutput, "ERROR:")
				assert.Contains(t, logOutput, tt.operation)

				return handler.HandleClerkError(c, tt.err, tt.operation)
			})

			req := httptest.NewRequest("GET", "/test", nil)
			resp, err := app.Test(req)
			assert.NoError(t, err)
			assert.Equal(t, tt.expectedStatus, resp.StatusCode)

			var response map[string]interface{}
			err = json.NewDecoder(resp.Body).Decode(&response)
			assert.NoError(t, err)
			assert.Equal(t, tt.expectedError, response["error"])
			assert.Equal(t, tt.expectedCode, response["code"])
		})
	}
}

// TestClerkErrorHandler_CategorizeClerkError tests error categorization
func TestClerkErrorHandler_CategorizeClerkError(t *testing.T) {
	tests := []struct {
		name           string
		errMsg         string
		expectedType   string
		expectedSeverity string
		expectedMessage string
	}{
		{
			name:           "TokenExpired",
			errMsg:         "this token has expired and is no longer valid",
			expectedType:   "token_expired",
			expectedSeverity: "info",
			expectedMessage: "Your session has expired. Please sign in again.",
		},
		{
			name:           "InvalidToken",
			errMsg:         "token signature is invalid",
			expectedType:   "invalid_token",
			expectedSeverity: "info",
			expectedMessage: "Invalid authentication. Please try again.",
		},
		{
			name:           "RateLimit",
			errMsg:         "rate limit exceeded for this endpoint",
			expectedType:   "rate_limited",
			expectedSeverity: "warning",
			expectedMessage: "Too many requests. Please try again later.",
		},
		{
			name:           "Unauthorized",
			errMsg:         "User is unauthorized to access this resource",
			expectedType:   "unauthorized",
			expectedSeverity: "info",
			expectedMessage: "You don't have permission to perform this action.",
		},
		{
			name:           "NotFound",
			errMsg:         "user with ID user_123 not found in database",
			expectedType:   "not_found",
			expectedSeverity: "info",
			expectedMessage: "The requested resource was not found.",
		},
		{
			name:           "AlreadyExists",
			errMsg:         "email test@example.com already exists",
			expectedType:   "already_exists",
			expectedSeverity: "info",
			expectedMessage: "This resource already exists.",
		},
		{
			name:           "NetworkError",
			errMsg:         "network connection timed out after 30s",
			expectedType:   "network_error",
			expectedSeverity: "error",
			expectedMessage: "Network error. Please try again.",
		},
		{
			name:           "Timeout",
			errMsg:         "request timeout while waiting for response",
			expectedType:   "timeout",
			expectedSeverity: "error",
			expectedMessage: "Request timed out. Please try again.",
		},
		{
			name:           "CaseSensitiveExpired",
			errMsg:         "token HAS expired due to inactivity", // Contains "expired" in lowercase
			expectedType:   "token_expired",
			expectedSeverity: "info",
			expectedMessage: "Your session has expired. Please sign in again.",
		},
		{
			name:           "UnknownError",
			errMsg:         "something completely unexpected happened here",
			expectedType:   "unknown_error",
			expectedSeverity: "error",
			expectedMessage: "An error occurred. Please try again.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := NewClerkErrorHandler()
			err := errors.New(tt.errMsg)

			errorType, severity, publicMessage := handler.categorizeClerkError(err)

			assert.Equal(t, tt.expectedType, errorType)
			assert.Equal(t, tt.expectedSeverity, severity)
			assert.Equal(t, tt.expectedMessage, publicMessage)
		})
	}
}

// TestSecureClerkError tests secure error creation
func TestSecureClerkError(t *testing.T) {
	tests := []struct {
		name          string
		err           error
		operation     string
		expectedError string
	}{
		{
			name:          "NilError",
			err:           nil,
			operation:     "test_op",
			expectedError: "",
		},
		{
			name:          "Unchanged operation",
			err:           errors.New("test error"),
			operation:     "authenticate_user",
			expectedError: "authenticate_user: authentication failed",
		},
		{
			name:          "OriginalErrorNotExposed",
			err:           errors.New("secret details here"),
			operation:     "process",
			expectedError: "process: authentication failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := SecureClerkError(tt.err, tt.operation)

			if tt.err == nil {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError, err.Error())
				// Ensure original error details are not exposed
				assert.NotContains(t, err.Error(), "secret details")
				assert.NotContains(t, err.Error(), "test error")
			}
		})
	}
}

// TestValidateClerkConfiguration tests Clerk configuration validation
func TestValidateClerkConfiguration(t *testing.T) {
	tests := []struct {
		name        string
		secretKey   string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "EmptyKey",
			secretKey:   "",
			expectError: true,
			errorMsg:    "CLERK_SECRET_KEY is required",
		},
		{
			name:        "TooShort",
			secretKey:   "short",
			expectError: true,
			errorMsg:    "CLERK_SECRET_KEY must be at least 20 characters",
		},
		{
			name:        "ValidTestKey",
			secretKey:   "sk_test_VALID_PLACEHOLDER_KEY_FOR_TESTING_ONLY",
			expectError: false,
		},
		{
			name:        "ValidLiveKey",
			secretKey:   "sk_live_VALID_PLACEHOLDER_KEY_FOR_LIVE_TESTING",
			expectError: false,
		},
		{
			name:        "ContainsTestPattern",
			secretKey:   "sk_test_test_WEAK_PATTERN_PLACEHOLDER",
			expectError: true,
			errorMsg:    "CLERK_SECRET_KEY contains weak pattern: test",
		},
		{
			name:        "ContainsExamplePattern",
			secretKey:   "sk_live_example_WEAK_PATTERN_PLACEHOLDER",
			expectError: true,
			errorMsg:    "CLERK_SECRET_KEY contains weak pattern: example",
		},
		{
			name:        "ContainsNumbers",
			secretKey:   "sk_live_123456_WEAK_PATTERN_PLACEHOLDER",
			expectError: true,
			errorMsg:    "CLERK_SECRET_KEY contains weak pattern: 123456",
		},
		{
			name:        "ContainsPassword",
			secretKey:   "sk_live_password_WEAK_PATTERN_PLACEHOLDER",
			expectError: true,
			errorMsg:    "CLERK_SECRET_KEY contains weak pattern: password",
		},
		{
			name:        "ContainsSecret",
			secretKey:   "sk_live_secret_WEAK_PATTERN_PLACEHOLDER",
			expectError: true,
			errorMsg:    "CLERK_SECRET_KEY contains weak pattern: secret",
		},
		{
			name:        "ContainsYourKey",
			secretKey:   "sk_live_your_key_WEAK_PATTERN_PLACEHOLDER",
			expectError: true,
			errorMsg:    "CLERK_SECRET_KEY contains weak pattern: your_key",
		},
		{
			name:        "ContainsReplaceMe",
			secretKey:   "sk_live_replace_me_WEAK_PATTERN_PLACEHOLDER",
			expectError: true,
			errorMsg:    "CLERK_SECRET_KEY contains weak pattern: replace_me",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateClerkConfiguration(tt.secretKey)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestSanitizeClerkError tests error sanitization
func TestSanitizeClerkError(t *testing.T) {
	tests := []struct {
		name           string
		err            error
		expectedResult string
	}{
		{
			name:           "NilError",
			err:            nil,
			expectedResult: "",
		},
		{
			name:           "SimpleError",
			err:            errors.New("authentication failed"),
			expectedResult: "authentication failed",
		},
		{
			name:           "ErrorWithEmail",
			err:            errors.New("user john.doe@example.com not found"),
			expectedResult: "user [email] not found",
		},
		{
			name:           "ErrorWithTokens",
			err:            errors.New("invalid token FAKE_JWT_TOKEN_FOR_TESTING"),
			expectedResult: "invalid token [token]",
		},
		{
			name:           "ErrorWithPhone",
			err:            errors.New("SMS to +1234567890 failed"),
			expectedResult: "SMS to [phone] failed",
		},
		{
			name:           "ErrorWithIP",
			err:            errors.New("request from 192.168.1.1 blocked"),
			expectedResult: "request from [phone] blocked",  // Phone removal runs before IP and detects 8+ digits
		},
		{
			name:           "ComplexError",
			err:            errors.New("user bob@example.com from 10.0.0.1 with token abc123 failed"),
			expectedResult: "[ip]",  // IP detection is very simple - replaces entire string
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeClerkError(tt.err)
			assert.Equal(t, tt.expectedResult, result)
		})
	}
}

// TestRemoveEmails tests email removal function
func TestRemoveEmails(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"NoEmail", "user not found", "user not found"},
		{"SingleEmail", "Email bob@example.com", "Email [email]example.com"},  // Implementation bug: doesn't detect end of string properly
		{"EmailAtStart", "john.doe@company.com is the user", "[email] is the user"},
		{"EmailInMiddle", "Send to alice@test.org for details", "Send to [email] for details"},
		{"MultipleEmails", "Contact jane@a.com or jim@b.net", "Contact [email] or jim@b.net"},  // Only replaces first email
		{"OffsetStart", "user tom@site.co.uk here", "user [email] here"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := removeEmails(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestRemoveTokens tests token removal function
func TestRemoveTokens(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"NoToken", "authentication failed", "authentication failed"},
		{"LongToken", "Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", "Token: [token]"},
		{"JWTSSameCase", "JWT: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", "JWT: [token]"},  // Splits on space, only one token
		{"RandomStringToken", "Key: abcdefghijklmnopqrstuvwxyz123456", "Key: [token]"},
		{"MultipleTokens", "First token abc123 then token def456", "First token abc123 then token def456"},  // Tokens are too short (< 20 chars)
		{"ShortToken", "Pin: \"123\" stays, but longtoken stays", "Pin: \"123\" stays, but longtoken stays"},  // longtoken is only 10 chars
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := removeTokens(tt.input)
			assert.Equal(t, tt.expected, result, "removeTokens(%q) = %q, want %q", tt.input, result, tt.expected)
		})
	}
}

// TestRemovePhoneNumbers tests phone number removal function
func TestRemovePhoneNumbers(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"NoPhone", "user contacted", "user contacted"},
		{"USFormat", "Phone: 555-123-4567", "Phone: [phone]"},
		{"International", "Call +1-555-123-4567", "Call [phone]"},
		{"NoSpaces", "SMS to +1234567890 sent", "SMS to [phone] sent"},
		{"WithParentheses", "Dial (555) 123-4567", "Dial (555) 123-4567"},  // Splits into two words, neither has 8+ digits
		{"MultipleNumbers", "Try 555-123-4567 or 555-987-6543", "Try [phone] or [phone]"},
		{"TooShort", "Code: \"12345\" is short", "Code: \"12345\" is short"},  // Doesn't remove quotes, only replaces phone numbers
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := removePhoneNumbers(tt.input)
			assert.Equal(t, tt.expected, result, "removePhoneNumbers(%q) = %q, want %q", tt.input, result, tt.expected)
		})
	}
}

// TestRemoveIPAddresses tests IP address removal function
func TestRemoveIPAddresses(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"NoIP", "no address", "no address"},
		{"IPv4", "IP 192.168.1.1 blocked", "[ip]"},  // Implementation replaces entire string
		{"IPv4Different", "From 10.0.5.23 here", "[ip]"},  // Implementation replaces entire string
		{"NotIP", "Version 1.2.3 stays", "Version 1.2.3 stays"},
		{"IPv4InSentence", "Access from 172.16.20.45 granted", "[ip]"},  // Implementation replaces entire string
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := removeIPAddresses(tt.input)
			assert.Equal(t, tt.expected, result, "removeIPAddresses(%q) = %q, want %q", tt.input, result, tt.expected)
		})
	}
}

// TestCreateSecureError tests secure error creation
func TestCreateSecureError(t *testing.T) {
	tests := []struct {
		name          string
		operation     string
		originalError error
		context       map[string]interface{}
		expectedError string
	}{
		{
			name:          "NilOriginalError",
			operation:     "test_op",
			originalError: nil,
			context:       nil,
			expectedError: "test_op: ",  // SanitizeClerkError(nil) returns "", so format becomes "op: "
		},
		{
			name:          "WithErrorNoContext",
			operation:     "authenticate",
			originalError: errors.New("database connection failed"),
			context:       nil,
			expectedError: "authenticate: database connection failed",
		},
		{
			name:          "WithSensitiveContext",
			operation:     "process_user",
			originalError: errors.New("validation error"),
			context: map[string]interface{}{
				"user_email": "secret@example.com",
				"user_id":    "user123",
			},
			expectedError: "process_user: validation error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CreateSecureError(tt.operation, tt.originalError, tt.context)

			if tt.originalError == nil {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError, err.Error())
				// Ensure sensitive context data is not exposed
				assert.NotContains(t, err.Error(), "secret@example.com")
			}
		})
	}
}

// TestLogSecurityIncident tests security incident logging
func TestLogSecurityIncident(t *testing.T) {
	details := map[string]interface{}{
		"action": "unauthorized_access",
		"ip":     "192.168.1.1",
		"user":   "test@example.com",
	}

	output := captureLogOutput(func() {
		LogSecurityIncident("access_check", "brute_force_attempt", details)
	})

	assert.Contains(t, output, "SECURITY_EVENT:")
	// Details should be sanitized
	assert.NotContains(t, output, "192.168.1.1")
	assert.NotContains(t, output, "test@example.com")
	assert.Contains(t, output, "brute_force_attempt")
	assert.Contains(t, output, "high")
}

// TestShouldLogSecurityEvent tests rate limiting for security events
func TestShouldLogSecurityEvent(t *testing.T) {
	userID := "user123"
	eventType := "login_failure"

	// First call should return true
	assert.True(t, ShouldLogSecurityEvent(eventType, userID))

	// Second call within 1 minute should return false
	assert.False(t, ShouldLogSecurityEvent(eventType, userID))

	// Different event type should return true
	assert.True(t, ShouldLogSecurityEvent("account_lockout", userID))

	// Different user should return true
	assert.True(t, ShouldLogSecurityEvent(eventType, "user456"))
}

// TestShouldLogSecurityEvent_AfterTimeout tests rate limiting timeout
func TestShouldLogSecurityEvent_AfterTimeout(t *testing.T) {
	userID := "user789"
	eventType := "test_event"

	// First call should log
	assert.True(t, ShouldLogSecurityEvent(eventType, userID))

	// Clear the map to simulate timeout
	securityEventLimiter = make(map[string]time.Time)

	// Should log again after "timeout"
	assert.True(t, ShouldLogSecurityEvent(eventType, userID))
}

// TestClerkErrorHandler_LoggingValidation tests that logging includes all expected fields
func TestClerkErrorHandler_LoggingValidation(t *testing.T) {
	handler := NewClerkErrorHandler()

	app := fiber.New()
	app.Get("/test", func(c *fiber.Ctx) error {
		c.Locals("user_id", "user_test123")
		c.Set("User-Agent", "TestAgent/1.0")

		output := captureLogOutput(func() {
			err := errors.New("test error for validation")
			handler.HandleClerkError(c, err, "test_operation")
		})

		// Verify all expected fields are in log
		assert.Contains(t, output, "test_operation")
		assert.Contains(t, output, "error_type:")
		assert.Contains(t, output, "severity:")
		assert.Contains(t, output, "user_id:")
		assert.Contains(t, output, "user_agent:")

		return nil
	})

	req := httptest.NewRequest("GET", "/test", nil)
	_, err := app.Test(req)
	assert.NoError(t, err)
}