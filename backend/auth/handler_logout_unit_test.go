package auth

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	miniredis "github.com/alicebob/miniredis/v2"
	"github.com/gofiber/fiber/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	appcrypto "leaflock/crypto"
)

func TestHandlerLogoutSuccess(t *testing.T) {
	handler, cleanup := newLogoutHandler(t)
	defer cleanup()

	app := fiber.New()
	app.Post("/auth/logout", handler.Logout)

	req := httptest.NewRequest("POST", "/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer test-token")

	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	require.Equal(t, fiber.StatusOK, resp.StatusCode)

	var body map[string]string
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	require.Equal(t, "Logged out successfully", body["message"])
}

func TestHandlerLogoutMissingHeader(t *testing.T) {
	handler, cleanup := newLogoutHandler(t)
	defer cleanup()

	app := fiber.New()
	app.Post("/auth/logout", handler.Logout)

	resp, err := app.Test(httptest.NewRequest("POST", "/auth/logout", nil), -1)
	require.NoError(t, err)
	require.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
}

func TestHandlerLogoutInvalidFormat(t *testing.T) {
	handler, cleanup := newLogoutHandler(t)
	defer cleanup()

	app := fiber.New()
	app.Post("/auth/logout", handler.Logout)

	req := httptest.NewRequest("POST", "/auth/logout", nil)
	req.Header.Set("Authorization", "Token bad-format")

	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	require.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
}

func TestHandlerLogoutSessionError(t *testing.T) {
	mr := miniredis.RunT(t)
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	crypto := appcrypto.NewCryptoService(repeatKey('e'))
	service := &Service{session: NewSessionManager(redisClient, crypto)}
	handler := &Handler{service: service}

	mr.Close() // force Redis operations to fail

	app := fiber.New()
	app.Post("/auth/logout", handler.Logout)

	req := httptest.NewRequest("POST", "/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer failing-token")

	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	require.Equal(t, fiber.StatusInternalServerError, resp.StatusCode)
}

func newLogoutHandler(t *testing.T) (*Handler, func()) {
	t.Helper()
	mr := miniredis.RunT(t)
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	crypto := appcrypto.NewCryptoService(repeatKey('s'))
	service := &Service{session: NewSessionManager(redisClient, crypto)}
	handler := &Handler{service: service}
	cleanup := func() {
		_ = redisClient.Close()
		mr.Close()
	}
	return handler, cleanup
}

func repeatKey(b byte) []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = b
	}
	return key
}
