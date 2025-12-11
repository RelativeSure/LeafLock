package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)


// TestEnhancedClerkMiddleware_NoAuthHeader tests missing Authorization header
func TestEnhancedClerkMiddleware_NoAuthHeader(t *testing.T) {
	app := fiber.New()
	handler := &Handler{
		config: &Config{EnableDebugLogging: false},
	}

	app.Use(handler.EnhancedClerkMiddleware)
	app.Get("/test", func(c *fiber.Ctx) error {
		return c.SendString("OK")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	resp, err := app.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, 401, resp.StatusCode)

	var errorResp ErrorResponse
	err = json.NewDecoder(resp.Body).Decode(&errorResp)
	assert.NoError(t, err)
	assert.Equal(t, "No authorization token provided", errorResp.Error)
}

// TestEnhancedClerkMiddleware_InvalidFormat tests invalid authorization format
func TestEnhancedClerkMiddleware_InvalidFormat(t *testing.T) {
	app := fiber.New()
	handler := &Handler{
		config: &Config{EnableDebugLogging: false},
	}

	app.Use(handler.EnhancedClerkMiddleware)
	app.Get("/test", func(c *fiber.Ctx) error {
		return c.SendString("OK")
	})

	tests := []struct {
		name          string
		authHeader    string
		expectedError string
	}{
		{"NoBearer", "Token abc123", "Invalid authorization format"},
		{"WrongFormat", "Bearer", "Invalid authorization format"},
		{"MultipleParts", "Bearer token extra", "Invalid authorization format"},
		{"WrongScheme", "Basic abc123", "Invalid authorization format"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			req.Header.Set("Authorization", tt.authHeader)
			resp, err := app.Test(req)
			assert.NoError(t, err)
			assert.Equal(t, 401, resp.StatusCode)

			var errorResp ErrorResponse
			err = json.NewDecoder(resp.Body).Decode(&errorResp)
			assert.NoError(t, err)
			assert.Contains(t, errorResp.Error, tt.expectedError)
		})
	}
}

// TestEnhancedClerkMiddleware_DebugLogging tests debug logging mode
func TestEnhancedClerkMiddleware_DebugLogging(t *testing.T) {
	app := fiber.New()
	handler := &Handler{
		config: &Config{EnableDebugLogging: true},
	}

	app.Use(handler.EnhancedClerkMiddleware)
	app.Get("/test", func(c *fiber.Ctx) error {
		return c.SendString("OK")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer invalid_token")
	resp, err := app.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, 401, resp.StatusCode)
}

// TestValidateClerkTokenEnhancedWithDebug_NotInitialized tests uninitialized Clerk
func TestValidateClerkTokenEnhancedWithDebug_NotInitialized(t *testing.T) {
	handler := &Handler{
		config: &Config{
			EnableDebugLogging: false,
			ClerkSecretKey:       "",
		},
	}

	ctx := context.Background()
	_, err := handler.validateClerkTokenEnhancedWithDebug(ctx, "test_token")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "clerk SDK not initialized")
}

// TestValidateClerkTokenEnhancedWithDebug_DebugLogging tests debug logging in validation
func TestValidateClerkTokenEnhancedWithDebug_DebugLogging(t *testing.T) {
	handler := &Handler{
		config: &Config{
			EnableDebugLogging: true,
			ClerkSecretKey:       "sk_test_abcdefghijklmnopqrstuvwxyz1234567890abcdef",
		},
	}

	ctx := context.Background()
	_, err := handler.validateClerkTokenEnhancedWithDebug(ctx, "test_token")
	assert.Error(t, err)
}

// TestGetDebugInfo tests debug info generation
func TestGetDebugInfo(t *testing.T) {
	tests := []struct {
		name          string
		debugEnabled  bool
		token         string
		err           error
		expectNil     bool
	}{
		{"DebugEnabled", true, "header.payload.signature", errors.New("test error"), false},
		{"DebugDisabled", false, "header.payload.signature", errors.New("test error"), true},
		{"InvalidToken", true, "invalidtoken", errors.New("test error"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := &Handler{
				config: &Config{EnableDebugLogging: tt.debugEnabled},
			}

			info := handler.getDebugInfo(tt.err, tt.token)
			if tt.expectNil {
				assert.Nil(t, info)
			} else {
				assert.NotNil(t, info)
				assert.Equal(t, tt.err.Error(), info["error"])
				assert.NotNil(t, info["token_structure"])
				assert.NotNil(t, info["token_length"])
				assert.NotNil(t, info["timestamp"])
			}
		})
	}
}

// TestIsClerkInitialized tests clerk initialization check
func TestIsClerkInitialized(t *testing.T) {
	tests := []struct {
		name        string
		config      *Config
		expected    bool
	}{
		{"NilConfig", nil, false},
		{"EmptySecret", &Config{ClerkSecretKey: ""}, false},
		{"ValidConfig", &Config{ClerkSecretKey: "sk_test_1234567890"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := &Handler{config: tt.config}
			assert.Equal(t, tt.expected, handler.isClerkInitialized())
		})
	}
}

// TestSafeClerkMiddleware tests safe middleware with redirect loop detection
func TestSafeClerkMiddleware(t *testing.T) {
	app := fiber.New()
	handler := &Handler{
		config: &Config{EnableDebugLogging: false},
	}

	app.Use(handler.SafeClerkMiddleware)
	app.Get("/test", func(c *fiber.Ctx) error {
		return c.SendString("OK")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer invalid_token")
	resp, err := app.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, 401, resp.StatusCode)
}

// TestIsRedirectLoopDetected tests redirect loop detection
func TestIsRedirectLoopDetected(t *testing.T) {
	app := fiber.New()
	handler := &Handler{config: &Config{}}

	app.Use(func(c *fiber.Ctx) error {
		// Simulate multiple requests from same client
		for i := 0; i < 6; i++ {
			if handler.isRedirectLoopDetected(c) {
				assert.True(t, true)
				return c.Status(429).SendString("Rate limited")
			}
		}
		return c.Next()
	})
	app.Get("/test", func(c *fiber.Ctx) error {
		return c.SendString("OK")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	resp, err := app.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, 429, resp.StatusCode)
}

// TestIsTokenExpired tests token expiration check
func TestIsTokenExpired(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{"NilError", nil, false},
		{"ExpiredError", errors.New("token expired at 12345"), true},
		{"ExpiredError2", errors.New("Token expired at 12345"), true},
		{"InvalidError", errors.New("invalid token"), true},
		{"OtherError", errors.New("some other error"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isTokenExpired(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestMinFunction tests the min utility function
func TestMinFunction(t *testing.T) {
	tests := []struct {
		a, b     int
		expected int
	}{
		{5, 10, 5},
		{10, 5, 5},
		{5, 5, 5},
		{0, 100, 0},
		{-5, 5, -5},
	}

	for _, tt := range tests {
		result := min(tt.a, tt.b)
		assert.Equal(t, tt.expected, result)
	}
}

// Mock helpers
type MockHandlerRow struct {
	mock.Mock
}

func (m *MockHandlerRow) Scan(dest ...interface{}) error {
	args := m.Called(dest)
	return args.Error(0)
}

func containsHandlers(sql, keyword string) bool {
	return strings.Contains(sql, keyword)
}