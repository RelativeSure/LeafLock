package metrics

import (
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
)

func TestPrometheusMiddleware(t *testing.T) {
	// Create a test Fiber app
	app := fiber.New()

	// Add the Prometheus middleware
	app.Use(PrometheusMiddleware())

	// Add a test route
	app.Get("/test", func(c *fiber.Ctx) error {
		return c.SendString("OK")
	})

	// Create a test request
	req := httptest.NewRequest("GET", "/test", nil)

	// Execute the request
	resp, err := app.Test(req)

	// Verify the middleware didn't break the request
	assert.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)

	// Note: We can't easily verify the Prometheus metrics were recorded without
	// accessing the Prometheus registry, but this test ensures the middleware executes
}

func TestPrometheusMiddleware_404(t *testing.T) {
	// Create a test Fiber app
	app := fiber.New()

	// Add the Prometheus middleware
	app.Use(PrometheusMiddleware())

	// Create a test request for a non-existent route
	req := httptest.NewRequest("GET", "/nonexistent", nil)

	// Execute the request
	resp, err := app.Test(req)

	// Verify the middleware handles 404s
	assert.NoError(t, err)
	assert.Equal(t, 404, resp.StatusCode)
}

func TestPrometheusMiddleware_POST(t *testing.T) {
	// Create a test Fiber app
	app := fiber.New()

	// Add the Prometheus middleware
	app.Use(PrometheusMiddleware())

	// Add a test route
	app.Post("/api/test", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "ok"})
	})

	// Create a test request
	req := httptest.NewRequest("POST", "/api/test", nil)
	req.Header.Set("Content-Type", "application/json")

	// Execute the request
	resp, err := app.Test(req)

	// Verify the middleware works with POST requests
	assert.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
}
