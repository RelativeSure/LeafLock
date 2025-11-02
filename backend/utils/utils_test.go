package utils

import (
	"context"
	"database/sql"
	"io"
	"net"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
)

// Test helpers.go functions

func TestNilIfInvalid(t *testing.T) {
	t.Run("Valid NullTime", func(t *testing.T) {
		now := time.Now()
		nt := sql.NullTime{Time: now, Valid: true}
		result := NilIfInvalid(nt)
		assert.NotNil(t, result)
		assert.Equal(t, now, result)
	})

	t.Run("Invalid NullTime", func(t *testing.T) {
		nt := sql.NullTime{Valid: false}
		result := NilIfInvalid(nt)
		assert.Nil(t, result)
	})
}

func TestMin(t *testing.T) {
	tests := []struct {
		name     string
		a        int
		b        int
		expected int
	}{
		{"a less than b", 5, 10, 5},
		{"b less than a", 10, 5, 5},
		{"equal values", 7, 7, 7},
		{"negative numbers", -5, -10, -10},
		{"mixed positive negative", -5, 10, -5},
		{"zero", 0, 5, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Min(tt.a, tt.b)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMax(t *testing.T) {
	tests := []struct {
		name     string
		a        int
		b        int
		expected int
	}{
		{"a greater than b", 10, 5, 10},
		{"b greater than a", 5, 10, 10},
		{"equal values", 7, 7, 7},
		{"negative numbers", -5, -10, -5},
		{"mixed positive negative", -5, 10, 10},
		{"zero", 0, -5, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Max(tt.a, tt.b)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCSVEscape(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"No special chars", "Hello World", "Hello World"},
		{"Contains comma", "Hello, World", "\"Hello, World\""},
		{"Contains newline", "Hello\nWorld", "\"Hello\nWorld\""},
		{"Contains carriage return", "Hello\rWorld", "\"Hello\rWorld\""},
		{"Contains quotes", "Hello \"World\"", "\"Hello \"\"World\"\"\""},
		{"Multiple special chars", "Hello, \"World\"\nTest", "\"Hello, \"\"World\"\"\nTest\""},
		{"Empty string", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CSVEscape(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFormatNullTime(t *testing.T) {
	t.Run("Valid NullTime", func(t *testing.T) {
		now := time.Date(2023, 12, 25, 10, 30, 0, 0, time.UTC)
		nt := sql.NullTime{Time: now, Valid: true}
		result := FormatNullTime(nt)
		assert.Equal(t, "2023-12-25T10:30:00Z", result)
	})

	t.Run("Invalid NullTime", func(t *testing.T) {
		nt := sql.NullTime{Valid: false}
		result := FormatNullTime(nt)
		assert.Equal(t, "", result)
	})
}

func TestContextHelpers(t *testing.T) {
	ctx := context.Background()
	ctx = context.WithValue(ctx, ContextKeyClientIP, "203.0.113.5")
	ctx = context.WithValue(ctx, ContextKeyUserAgent, "LeafLockTest/1.0")

	assert.Equal(t, "203.0.113.5", GetClientIPFromContext(ctx))
	assert.Equal(t, "LeafLockTest/1.0", GetUserAgentFromContext(ctx))
	assert.Equal(t, "", GetClientIPFromContext(context.Background()))
	assert.Equal(t, "", GetUserAgentFromContext(context.Background()))
}

// Test network.go functions

func TestIsPublicIP(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		// Public IPs
		{"Google DNS", "8.8.8.8", true},
		{"Cloudflare DNS", "1.1.1.1", true},
		{"Random public IP", "93.184.216.34", true},

		// Private IPs
		{"Private 10.x", "10.0.0.1", false},
		{"Private 172.16.x", "172.16.0.1", false},
		{"Private 192.168.x", "192.168.1.1", false},
		{"Localhost", "127.0.0.1", false},
		{"IPv6 localhost", "::1", false},
		{"IPv6 private fc00", "fc00::1", false},
		{"IPv6 link-local", "fe80::1", false},

		// Invalid/special
		{"Unspecified IPv4", "0.0.0.0", false},
		{"Unspecified IPv6", "::", false},
		{"Nil IP", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ip net.IP
			if tt.ip != "" {
				ip = net.ParseIP(tt.ip)
			}
			result := IsPublicIP(ip)
			assert.Equal(t, tt.expected, result, "IP: %s", tt.ip)
		})
	}
}

func TestClientIP(t *testing.T) {
	TrustProxyHeaders.Store(false)

	app := fiber.New()
	app.Get("/client", func(c *fiber.Ctx) error {
		return c.SendString(ClientIP(c))
	})

	resp, err := app.Test(httptest.NewRequest("GET", "/client", nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	resp.Body.Close()

	TrustProxyHeaders.Store(true)

	tests := []struct {
		name   string
		header string
		value  string
		expect string
	}{
		{"CF connecting", "CF-Connecting-IP", "1.2.3.4", "1.2.3.4"},
		{"XFF public", "X-Forwarded-For", "8.8.8.8, 10.0.0.1", "8.8.8.8"},
		{"XFF private fallback", "X-Forwarded-For", "10.0.0.1, 192.168.1.1", "10.0.0.1"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/client", nil)
			req.Header.Set("X-Real-IP", "203.0.113.1")
			if tc.header != "" {
				req.Header.Set(tc.header, tc.value)
			}
			resp, err := app.Test(req, -1)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			assert.Equal(t, tc.expect, string(body))
		})
	}
}

// Test validation.go functions

func TestIsValidHexColor(t *testing.T) {
	tests := []struct {
		name     string
		color    string
		expected bool
	}{
		// Valid hex colors
		{"Valid uppercase", "#FF5733", true},
		{"Valid lowercase", "#ff5733", true},
		{"Valid mixed case", "#Ff5733", true},
		{"Valid all zeros", "#000000", true},
		{"Valid all Fs", "#FFFFFF", true},
		{"Valid with numbers", "#123456", true},

		// Invalid hex colors
		{"Missing hash", "FF5733", false},
		{"Too short", "#FF573", false},
		{"Too long", "#FF57333", false},
		{"Invalid character G", "#GG5733", false},
		{"Invalid character Z", "#FF57ZZ", false},
		{"Empty string", "", false},
		{"Just hash", "#", false},
		{"Space in color", "#FF 573", false},
		{"Special char", "#FF573!", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsValidHexColor(tt.color)
			assert.Equal(t, tt.expected, result, "Color: %s", tt.color)
		})
	}
}

// Benchmark tests

func BenchmarkMin(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Min(42, 100)
	}
}

func BenchmarkMax(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Max(42, 100)
	}
}

func BenchmarkCSVEscape(b *testing.B) {
	input := "Hello, \"World\"\nTest"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CSVEscape(input)
	}
}

func BenchmarkIsValidHexColor(b *testing.B) {
	color := "#FF5733"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		IsValidHexColor(color)
	}
}

func BenchmarkIsPublicIP(b *testing.B) {
	ip := net.ParseIP("8.8.8.8")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		IsPublicIP(ip)
	}
}
