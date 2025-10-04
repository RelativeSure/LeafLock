package middleware

import (
	"net/http/httptest"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/gofiber/fiber/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"leaflock/utils"
)

func TestNewRateLimitConfig(t *testing.T) {
	// Create mock Redis server
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	// Create Redis client
	rdb := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})
	defer func() {
		_ = rdb.Close()
	}()

	// Create rate limit config
	rateLimits := NewRateLimitConfig(rdb)

	// Verify all limiters are created
	assert.NotNil(t, rateLimits.AuthLimiter)
	assert.NotNil(t, rateLimits.RegisterLimiter)
	assert.NotNil(t, rateLimits.MFAVerifyLimiter)
	assert.NotNil(t, rateLimits.AdminRecoveryLimiter)
	assert.NotNil(t, rateLimits.ShareLinkPublicLimiter)
	assert.NotNil(t, rateLimits.ShareLinkCreateLimiter)
	assert.NotNil(t, rateLimits.SearchLimiter)
	assert.NotNil(t, rateLimits.ImportExportLimiter)
	assert.NotNil(t, rateLimits.BulkImportLimiter)
	assert.NotNil(t, rateLimits.AttachmentUploadLimiter)
	assert.NotNil(t, rateLimits.StandardCRUDLimiter)
	assert.NotNil(t, rateLimits.CollaborationLimiter)
	assert.NotNil(t, rateLimits.LightweightLimiter)
}

func TestAuthLimiterEnforcement(t *testing.T) {
	// Create mock Redis server
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	// Create Redis client
	rdb := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})
	defer func() {
		_ = rdb.Close()
	}()

	// Create rate limit config
	rateLimits := NewRateLimitConfig(rdb)

	// Create test Fiber app
	app := fiber.New()
	app.Post("/auth/login", rateLimits.AuthLimiter, func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	// Test auth limiter (10 requests per 5 minutes)
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest(fiber.MethodPost, "/auth/login", nil)
		req.Header.Set("X-Forwarded-For", "192.168.1.1")
		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	}

	// 11th request should be rate limited
	req := httptest.NewRequest(fiber.MethodPost, "/auth/login", nil)
	req.Header.Set("X-Forwarded-For", "192.168.1.1")
	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusTooManyRequests, resp.StatusCode)
}

func TestRegisterLimiterEnforcement(t *testing.T) {
	// Create mock Redis server
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	// Create Redis client
	rdb := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})
	defer func() {
		_ = rdb.Close()
	}()

	// Create rate limit config
	rateLimits := NewRateLimitConfig(rdb)

	// Create test Fiber app
	app := fiber.New()
	app.Post("/auth/register", rateLimits.RegisterLimiter, func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	// Test register limiter (5 requests per 15 minutes)
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(fiber.MethodPost, "/auth/register", nil)
		req.Header.Set("X-Forwarded-For", "192.168.1.2")
		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	}

	// 6th request should be rate limited
	req := httptest.NewRequest(fiber.MethodPost, "/auth/register", nil)
	req.Header.Set("X-Forwarded-For", "192.168.1.2")
	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusTooManyRequests, resp.StatusCode)
}

func TestShareLinkPublicLimiterEnforcement(t *testing.T) {
	// Create mock Redis server
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	// Create Redis client
	rdb := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})
	defer func() {
		_ = rdb.Close()
	}()

	// Create rate limit config
	rateLimits := NewRateLimitConfig(rdb)

	// Create test Fiber app
	app := fiber.New()
	app.Get("/share/:token", rateLimits.ShareLinkPublicLimiter, func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	// Test share link limiter (20 requests per 5 minutes)
	for i := 0; i < 20; i++ {
		req := httptest.NewRequest(fiber.MethodGet, "/share/test-token", nil)
		req.Header.Set("X-Forwarded-For", "192.168.1.3")
		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	}

	// 21st request should be rate limited
	req := httptest.NewRequest(fiber.MethodGet, "/share/test-token", nil)
	req.Header.Set("X-Forwarded-For", "192.168.1.3")
	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusTooManyRequests, resp.StatusCode)
}

func TestStandardCRUDLimiterEnforcement(t *testing.T) {
	// Create mock Redis server
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	// Create Redis client
	rdb := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})
	defer func() {
		_ = rdb.Close()
	}()

	// Create rate limit config
	rateLimits := NewRateLimitConfig(rdb)

	// Create test Fiber app
	app := fiber.New()
	app.Get("/notes", rateLimits.StandardCRUDLimiter, func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	// Test CRUD limiter (100 requests per minute)
	for i := 0; i < 100; i++ {
		req := httptest.NewRequest(fiber.MethodGet, "/notes", nil)
		req.Header.Set("X-Forwarded-For", "192.168.1.4")
		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	}

	// 101st request should be rate limited
	req := httptest.NewRequest(fiber.MethodGet, "/notes", nil)
	req.Header.Set("X-Forwarded-For", "192.168.1.4")
	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusTooManyRequests, resp.StatusCode)
}

func TestSearchLimiterEnforcement(t *testing.T) {
	// Create mock Redis server
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	// Create Redis client
	rdb := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})
	defer func() {
		_ = rdb.Close()
	}()

	// Create rate limit config
	rateLimits := NewRateLimitConfig(rdb)

	// Create test Fiber app
	app := fiber.New()
	app.Post("/search", rateLimits.SearchLimiter, func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	// Test search limiter (30 requests per minute)
	for i := 0; i < 30; i++ {
		req := httptest.NewRequest(fiber.MethodPost, "/search", nil)
		req.Header.Set("X-Forwarded-For", "192.168.1.5")
		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	}

	// 31st request should be rate limited
	req := httptest.NewRequest(fiber.MethodPost, "/search", nil)
	req.Header.Set("X-Forwarded-For", "192.168.1.5")
	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusTooManyRequests, resp.StatusCode)
}

func TestDifferentIPsNotAffected(t *testing.T) {
	// Enable proxy header trust for testing
	utils.TrustProxyHeaders.Store(true)
	defer utils.TrustProxyHeaders.Store(false)

	// Create mock Redis server
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	// Create Redis client
	rdb := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})
	defer func() {
		_ = rdb.Close()
	}()

	// Create rate limit config
	rateLimits := NewRateLimitConfig(rdb)

	// Create test Fiber app
	app := fiber.New()
	app.Post("/auth/login", rateLimits.AuthLimiter, func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	// IP2 should be able to make requests (test first)
	req2 := httptest.NewRequest(fiber.MethodPost, "/auth/login", nil)
	req2.Header.Set("X-Forwarded-For", "203.0.113.200")
	resp2, err := app.Test(req2, -1)
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp2.StatusCode)

	// Max out requests from IP1
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest(fiber.MethodPost, "/auth/login", nil)
		req.Header.Set("X-Forwarded-For", "203.0.113.100")
		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	}

	// IP1 should now be rate limited
	req1 := httptest.NewRequest(fiber.MethodPost, "/auth/login", nil)
	req1.Header.Set("X-Forwarded-For", "203.0.113.100")
	resp1, err := app.Test(req1, -1)
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusTooManyRequests, resp1.StatusCode)

	// IP2 should still be able to make more requests
	req3 := httptest.NewRequest(fiber.MethodPost, "/auth/login", nil)
	req3.Header.Set("X-Forwarded-For", "203.0.113.200")
	resp3, err := app.Test(req3, -1)
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp3.StatusCode)
}

func BenchmarkAuthLimiter(b *testing.B) {
	mr, err := miniredis.Run()
	require.NoError(b, err)
	defer mr.Close()

	rdb := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})
	defer func() {
		_ = rdb.Close()
	}()

	rateLimits := NewRateLimitConfig(rdb)
	app := fiber.New()
	app.Post("/auth/login", rateLimits.AuthLimiter, func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(fiber.MethodPost, "/auth/login", nil)
		req.Header.Set("X-Forwarded-For", "192.168.1.1")
		_, _ = app.Test(req, -1)
	}
}

func BenchmarkStandardCRUDLimiter(b *testing.B) {
	mr, err := miniredis.Run()
	require.NoError(b, err)
	defer mr.Close()

	rdb := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})
	defer func() {
		_ = rdb.Close()
	}()

	rateLimits := NewRateLimitConfig(rdb)
	app := fiber.New()
	app.Get("/notes", rateLimits.StandardCRUDLimiter, func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(fiber.MethodGet, "/notes", nil)
		req.Header.Set("X-Forwarded-For", "192.168.1.1")
		_, _ = app.Test(req, -1)
	}
}
