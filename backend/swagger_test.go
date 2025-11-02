package main

import (
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gofiber/fiber/v2"
)

func TestAdminOnlyFromEnv(t *testing.T) {
	os.Setenv("ADMIN_USER_IDS", "123e4567-e89b-12d3-a456-426614174000,abcd")
	defer os.Unsetenv("ADMIN_USER_IDS")

	unauthorizedApp := fiber.New()
	unauthorizedApp.Get("/protected", AdminOnlyFromEnv(), func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	resp, err := unauthorizedApp.Test(httptest.NewRequest("GET", "/protected", nil), -1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != fiber.StatusUnauthorized {
		t.Fatalf("expected 401 for missing user, got %d", resp.StatusCode)
	}

	authorizedApp := fiber.New()
	authorizedApp.Get("/protected", func(c *fiber.Ctx) error {
		c.Locals("user_id", "123e4567-e89b-12d3-a456-426614174000")
		return c.Next()
	}, AdminOnlyFromEnv(), func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	resp, err = authorizedApp.Test(httptest.NewRequest("GET", "/protected", nil), -1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != fiber.StatusOK {
		t.Fatalf("expected 200 for allowlisted user, got %d", resp.StatusCode)
	}
}

func TestSwaggerHandlers(t *testing.T) {
	app := fiber.New()
	app.Get("/docs", swaggerUIHandler)
	app.Get("/json", swaggerJSONHandler)

	resp, err := app.Test(httptest.NewRequest("GET", "/json", nil), -1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != fiber.StatusOK {
		t.Fatalf("expected 200 from swaggerJSONHandler, got %d", resp.StatusCode)
	}
	contentType := resp.Header.Get("Content-Type")
	if contentType != "application/json" {
		t.Fatalf("expected json content type, got %s", contentType)
	}

	resp, err = app.Test(httptest.NewRequest("GET", "/docs", nil), -1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != fiber.StatusOK {
		t.Fatalf("expected 200 from swaggerUIHandler, got %d", resp.StatusCode)
	}
	if resp.Header.Get("Content-Type") != "text/html" {
		t.Fatalf("expected html content type, got %s", resp.Header.Get("Content-Type"))
	}
}
