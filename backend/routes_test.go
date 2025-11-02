package main

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gofiber/fiber/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	appconfig "leaflock/config"
	appcrypto "leaflock/crypto"
	appserver "leaflock/server"
)

func TestSetupRoutesInitializesDocs(t *testing.T) {
	app := fiber.New(fiber.Config{DisableStartupMessage: true})

	t.Setenv("ENABLE_DEBUG_ENDPOINTS", "true")

	cfg := &appconfig.Config{
		AllowedOrigins: []string{"*"},
		JWTSecret:      []byte(strings.Repeat("s", 32)),
		Environment:    "development",
	}

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	cryptoSvc := appcrypto.NewCryptoService(key)

	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	readyState := appserver.NewReadyState(nil, cryptoSvc, cfg, rdb)

	require.NotPanics(t, func() {
		setupRoutes(app, nil, rdb, cryptoSvc, cfg, time.Now(), readyState)
	})

	resp, err := app.Test(httptest.NewRequest("GET", "/api/v1/docs/openapi.json", nil))
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	require.NoError(t, resp.Body.Close())
}

func TestSetupRoutesCorsAndMetricsInProduction(t *testing.T) {
	app := fiber.New(fiber.Config{DisableStartupMessage: true})

	t.Setenv("ENABLE_METRICS", "true")

	cfg := &appconfig.Config{
		AllowedOrigins: []string{"https://example.com", "https://*.example.com"},
		JWTSecret:      []byte(strings.Repeat("p", 32)),
		Environment:    "production",
	}

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(32 - i)
	}
	cryptoSvc := appcrypto.NewCryptoService(key)

	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	readyState := appserver.NewReadyState(nil, cryptoSvc, cfg, rdb)

	require.NotPanics(t, func() {
		setupRoutes(app, nil, rdb, cryptoSvc, cfg, time.Now(), readyState)
	})

	// Exact origin match
	reqExact := httptest.NewRequest("GET", "/api/v1/docs/openapi.json", nil)
	reqExact.Header.Set("Origin", "https://example.com")
	respExact, err := app.Test(reqExact)
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, respExact.StatusCode)
	assert.Equal(t, "https://example.com", respExact.Header.Get("Access-Control-Allow-Origin"))
	require.NoError(t, respExact.Body.Close())

	// Wildcard origin match
	reqWildcard := httptest.NewRequest("GET", "/api/v1/docs/openapi.json", nil)
	reqWildcard.Header.Set("Origin", "https://sub.example.com")
	respWildcard, err := app.Test(reqWildcard)
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, respWildcard.StatusCode)
	assert.Equal(t, "https://sub.example.com", respWildcard.Header.Get("Access-Control-Allow-Origin"))
	require.NoError(t, respWildcard.Body.Close())
}
