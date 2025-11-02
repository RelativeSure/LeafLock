package auth

import (
	"context"
	"crypto/rand"
	"net/http/httptest"
	"testing"

	miniredis "github.com/alicebob/miniredis/v2"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	appcrypto "leaflock/crypto"
)

func newTestService(t *testing.T) (*Service, *SessionManager, *miniredis.Miniredis) {
	mr := miniredis.RunT(t)
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	cryptoSvc := appcrypto.NewCryptoService(key)
	session := NewSessionManager(redis.NewClient(&redis.Options{Addr: mr.Addr()}), cryptoSvc)
	return &Service{session: session}, session, mr
}

func TestHandlerLogoutSuccess(t *testing.T) {
	service, session, _ := newTestService(t)
	handler := NewHandler(service)

	ctx := context.Background()
	userID := uuid.New()
	_, token, err := session.CreateSession(ctx, userID, "127.0.0.1", "agent", true)
	require.NoError(t, err)

	app := fiber.New()
	app.Post("/auth/logout", func(c *fiber.Ctx) error {
		c.Locals("user_id", userID)
		c.Request().Header.Set("Authorization", "Bearer "+token)
		return handler.Logout(c)
	})

	resp, err := app.Test(httptest.NewRequest("POST", "/auth/logout", nil))
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)
}

func TestHandlerLogoutMissingToken(t *testing.T) {
	service, _, _ := newTestService(t)
	handler := NewHandler(service)

	app := fiber.New()
	app.Post("/auth/logout", func(c *fiber.Ctx) error {
		return handler.Logout(c)
	})

	resp, err := app.Test(httptest.NewRequest("POST", "/auth/logout", nil))
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
}

func TestHandlerLogoutInvalidFormat(t *testing.T) {
	service, _, _ := newTestService(t)
	handler := NewHandler(service)

	app := fiber.New()
	app.Post("/auth/logout", func(c *fiber.Ctx) error {
		c.Request().Header.Set("Authorization", "Token value")
		return handler.Logout(c)
	})

	resp, err := app.Test(httptest.NewRequest("POST", "/auth/logout", nil))
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
}

func TestHandlerLogoutInternalError(t *testing.T) {
	service, session, mr := newTestService(t)
	handler := NewHandler(service)

	ctx := context.Background()
	userID := uuid.New()
	_, token, err := session.CreateSession(ctx, userID, "127.0.0.1", "agent", true)
	require.NoError(t, err)

	require.NoError(t, session.redis.Close())
	mr.Close()

	app := fiber.New()
	app.Post("/auth/logout", func(c *fiber.Ctx) error {
		c.Request().Header.Set("Authorization", "Bearer "+token)
		return handler.Logout(c)
	})

	resp, err := app.Test(httptest.NewRequest("POST", "/auth/logout", nil))
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusInternalServerError, resp.StatusCode)
}
