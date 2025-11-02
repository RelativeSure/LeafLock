package middleware

import (
	"net/http/httptest"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/gofiber/fiber/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

func TestNewRateLimitConfig(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	cfg := NewRateLimitConfig(rdb)
	require.NotNil(t, cfg)
	require.NotNil(t, cfg.AuthLimiter)
	require.NotNil(t, cfg.RegisterLimiter)
	require.NotNil(t, cfg.AttachmentUploadLimiter)

	app := fiber.New()
	app.Use(cfg.AuthLimiter)
	app.Get("/", func(c *fiber.Ctx) error { return c.SendStatus(fiber.StatusOK) })

	resp, err := app.Test(httptest.NewRequest("GET", "/", nil))
	require.NoError(t, err)
	require.Equal(t, fiber.StatusOK, resp.StatusCode)
}
