package utils

import (
	"database/sql"
	"net"
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
	app := fiber.New()

	t.Run("No proxy headers - trust disabled", func(t *testing.T) {
		TrustProxyHeaders.Store(false)

		app.Get("/test", func(c *fiber.Ctx) error {
			ip := ClientIP(c)
			assert.NotEmpty(t, ip)
			return c.SendString(ip)
		})
	})

	t.Run("CF-Connecting-IP header - trust enabled", func(t *testing.T) {
		TrustProxyHeaders.Store(true)

		app.Get("/test-cf", func(c *fiber.Ctx) error {
			c.Request().Header.Set("CF-Connecting-IP", "1.2.3.4")
			ip := ClientIP(c)
			assert.Equal(t, "1.2.3.4", ip)
			return c.SendString(ip)
		})
	})

	t.Run("X-Forwarded-For with public IP - trust enabled", func(t *testing.T) {
		TrustProxyHeaders.Store(true)

		app.Get("/test-xff", func(c *fiber.Ctx) error {
			c.Request().Header.Set("X-Forwarded-For", "8.8.8.8, 10.0.0.1")
			ip := ClientIP(c)
			assert.Equal(t, "8.8.8.8", ip)
			return c.SendString(ip)
		})
	})

	t.Run("X-Forwarded-For with only private IPs - trust enabled", func(t *testing.T) {
		TrustProxyHeaders.Store(true)

		app.Get("/test-xff-private", func(c *fiber.Ctx) error {
			c.Request().Header.Set("X-Forwarded-For", "10.0.0.1, 192.168.1.1")
			ip := ClientIP(c)
			// Should return the first private IP as fallback
			assert.Equal(t, "10.0.0.1", ip)
			return c.SendString(ip)
		})
	})

	t.Run("X-Real-IP header - trust enabled", func(t *testing.T) {
		TrustProxyHeaders.Store(true)

		app.Get("/test-real-ip", func(c *fiber.Ctx) error {
			c.Request().Header.Set("X-Real-IP", "9.9.9.9")
			ip := ClientIP(c)
			assert.Equal(t, "9.9.9.9", ip)
			return c.SendString(ip)
		})
	})

	t.Run("X-Client-IP header - trust enabled", func(t *testing.T) {
		TrustProxyHeaders.Store(true)

		app.Get("/test-client-ip", func(c *fiber.Ctx) error {
			c.Request().Header.Set("X-Client-IP", "7.7.7.7")
			ip := ClientIP(c)
			assert.Equal(t, "7.7.7.7", ip)
			return c.SendString(ip)
		})
	})
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