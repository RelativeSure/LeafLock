package auth

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/require"
)

func TestHandlerRequestPasswordResetInvalidBody(t *testing.T) {
	handler := &Handler{service: &Service{}}
	app := fiber.New()
	app.Post("/auth/password/reset-request", handler.RequestPasswordReset)

	req := httptest.NewRequest("POST", "/auth/password/reset-request", strings.NewReader("not-json"))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	require.Equal(t, fiber.StatusBadRequest, resp.StatusCode)
}

func TestHandlerVerifyResetTokenMissing(t *testing.T) {
	handler := &Handler{service: &Service{}}
	app := fiber.New()
	app.Get("/auth/password/reset-verify", handler.VerifyResetToken)

	resp, err := app.Test(httptest.NewRequest("GET", "/auth/password/reset-verify", nil), -1)
	require.NoError(t, err)
	require.Equal(t, fiber.StatusBadRequest, resp.StatusCode)
}

func TestHandlerConfirmPasswordResetInvalidBody(t *testing.T) {
	handler := &Handler{service: &Service{}}
	app := fiber.New()
	app.Post("/auth/password/reset-confirm", handler.ConfirmPasswordReset)

	req := httptest.NewRequest("POST", "/auth/password/reset-confirm", strings.NewReader("not-json"))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	require.Equal(t, fiber.StatusBadRequest, resp.StatusCode)
}
