package server

import (
	"log"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"leaflock/config"
	"leaflock/utils"
)

// setupTestEnvironment initializes the test environment
func setupTestEnvironment() error {
	// Initialize loggers if not already initialized
	if utils.InfoLogger == nil {
		utils.InfoLogger = log.New(os.Stdout, "TEST-INFO: ", log.Ldate|log.Ltime)
	}
	if utils.ErrorLogger == nil {
		utils.ErrorLogger = log.New(os.Stderr, "TEST-ERROR: ", log.Ldate|log.Ltime)
	}
	return nil
}

// MockCryptoService implements CryptoService for testing
type MockCryptoService struct{}

func (m *MockCryptoService) Encrypt(plaintext []byte) ([]byte, error) {
	return plaintext, nil
}

func (m *MockCryptoService) Decrypt(ciphertext []byte) ([]byte, error) {
	return ciphertext, nil
}

// TestReadyState tests the ReadyState struct and its methods
func TestReadyState(t *testing.T) {
	cfg := &config.Config{
		Port: "8080",
	}
	crypto := &MockCryptoService{}

	// Create ReadyState with nil pool and redis for basic testing
	readyState := NewReadyState(nil, crypto, cfg, nil)

	t.Run("Initial state should be not ready", func(t *testing.T) {
		assert.False(t, readyState.IsFullyReady())
		assert.False(t, readyState.IsAdminReady())
		assert.False(t, readyState.IsTemplatesReady())
		assert.False(t, readyState.IsAllowlistReady())
		assert.False(t, readyState.IsRedisReady())
	})

	t.Run("Mark components ready individually", func(t *testing.T) {
		readyState.MarkAdminReady()
		assert.True(t, readyState.IsAdminReady())
		assert.False(t, readyState.IsFullyReady())

		readyState.MarkTemplatesReady()
		assert.True(t, readyState.IsTemplatesReady())
		assert.False(t, readyState.IsFullyReady())

		readyState.MarkAllowlistReady()
		assert.True(t, readyState.IsAllowlistReady())
		assert.False(t, readyState.IsFullyReady())

		readyState.MarkRedisReady()
		assert.True(t, readyState.IsRedisReady())
		assert.True(t, readyState.IsFullyReady())
	})

	t.Run("Getters return correct values", func(t *testing.T) {
		assert.Equal(t, cfg, readyState.GetConfig())
		assert.Equal(t, crypto, readyState.GetCrypto())
	})
}

// TestCreateFiberApp tests the Fiber application creation
func TestCreateFiberApp(t *testing.T) {
	// Initialize utils package (required for logging)
	if err := setupTestEnvironment(); err != nil {
		t.Skip("Skipping test - unable to initialize test environment")
	}

	cfg := &config.Config{
		Port: "8080",
	}
	crypto := &MockCryptoService{}
	readyState := NewReadyState(nil, crypto, cfg, nil)
	startTime := time.Now()

	app := CreateFiberApp(startTime, readyState)
	require.NotNil(t, app)

	t.Run("Health live endpoint should work", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/health/live", nil)
		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, 200, resp.StatusCode)
	})

	t.Run("Health ready endpoint should return initializing when not ready", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/health/ready", nil)
		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, 503, resp.StatusCode)
	})
}

// TestFiberResponseWriter tests the adapter implementation
func TestFiberResponseWriter(t *testing.T) {
	app := fiber.New()

	t.Run("NewFiberResponseWriter creates valid writer", func(t *testing.T) {
		app.Get("/test", func(c *fiber.Ctx) error {
			writer := NewFiberResponseWriter(c)
			assert.NotNil(t, writer)
			assert.NotNil(t, writer.Header())
			return c.SendString("ok")
		})

		req := httptest.NewRequest("GET", "/test", nil)
		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, 200, resp.StatusCode)
	})

	t.Run("WriteHeader sets status code", func(t *testing.T) {
		app.Get("/status", func(c *fiber.Ctx) error {
			writer := NewFiberResponseWriter(c)
			writer.WriteHeader(201)
			_, err := writer.Write([]byte("created"))
			return err
		})

		req := httptest.NewRequest("GET", "/status", nil)
		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, 201, resp.StatusCode)
	})

	t.Run("Header modification works", func(t *testing.T) {
		app.Get("/headers", func(c *fiber.Ctx) error {
			writer := NewFiberResponseWriter(c)
			writer.Header().Set("X-Custom-Header", "test-value")
			_, err := writer.Write([]byte("ok"))
			return err
		})

		req := httptest.NewRequest("GET", "/headers", nil)
		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, "test-value", resp.Header.Get("X-Custom-Header"))
	})
}

// TestReadyStateWithMockServices tests ReadyState with mock services
func TestReadyStateWithMockServices(t *testing.T) {
	// Setup mock Redis client
	rdb := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})
	defer func() { _ = rdb.Close() }() // Test cleanup

	cfg := &config.Config{
		Port:          "8080",
		DatabaseURL:   "postgres://test:test@localhost:5432/testdb",
		RedisURL:      "localhost:6379",
		JWTSecret:     []byte("test-secret-key-at-least-32-characters-long"),
		EncryptionKey: []byte("test-encryption-key-32-chars!!"),
	}
	crypto := &MockCryptoService{}

	t.Run("ReadyState stores and retrieves services correctly", func(t *testing.T) {
		readyState := NewReadyState(nil, crypto, cfg, rdb)

		assert.Equal(t, cfg, readyState.GetConfig())
		assert.Equal(t, crypto, readyState.GetCrypto())
		assert.Equal(t, rdb, readyState.GetRedis())
	})

	t.Run("Concurrent ready state updates", func(t *testing.T) {
		readyState := NewReadyState(nil, crypto, cfg, rdb)

		// Simulate concurrent initialization
		done := make(chan bool, 4)

		go func() {
			readyState.MarkAdminReady()
			done <- true
		}()
		go func() {
			readyState.MarkTemplatesReady()
			done <- true
		}()
		go func() {
			readyState.MarkAllowlistReady()
			done <- true
		}()
		go func() {
			readyState.MarkRedisReady()
			done <- true
		}()

		// Wait for all goroutines
		for i := 0; i < 4; i++ {
			<-done
		}

		assert.True(t, readyState.IsFullyReady())
	})
}

// BenchmarkReadyStateCheck benchmarks the IsFullyReady check
func BenchmarkReadyStateCheck(b *testing.B) {
	cfg := &config.Config{Port: "8080"}
	crypto := &MockCryptoService{}
	readyState := NewReadyState(nil, crypto, cfg, nil)

	// Mark all as ready
	readyState.MarkAdminReady()
	readyState.MarkTemplatesReady()
	readyState.MarkAllowlistReady()
	readyState.MarkRedisReady()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = readyState.IsFullyReady()
	}
}

// BenchmarkFiberResponseWriter benchmarks the adapter write operations
func BenchmarkFiberResponseWriter(b *testing.B) {
	app := fiber.New()

	// Use a test request to get a valid context
	app.Get("/bench", func(c *fiber.Ctx) error {
		writer := NewFiberResponseWriter(c)
		data := []byte("benchmark test data")

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = writer.Write(data)
		}
		b.StopTimer()
		return c.SendString("done")
	})

	req := httptest.NewRequest("GET", "/bench", nil)
	_, _ = app.Test(req, -1)
}