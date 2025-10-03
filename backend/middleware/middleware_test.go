package middleware

import (
	"context"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// MockDatabase implements Database interface for testing
type MockDatabase struct {
	mock.Mock
}

func (m *MockDatabase) QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row {
	mockArgs := m.Called(ctx, sql, args)
	return mockArgs.Get(0).(pgx.Row)
}

func (m *MockDatabase) Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error) {
	mockArgs := m.Called(ctx, sql, args)
	return mockArgs.Get(0).(pgx.Rows), mockArgs.Error(1)
}

func (m *MockDatabase) Exec(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
	mockArgs := m.Called(ctx, sql, args)
	return mockArgs.Get(0).(pgconn.CommandTag), mockArgs.Error(1)
}

func (m *MockDatabase) Begin(ctx context.Context) (pgx.Tx, error) {
	mockArgs := m.Called(ctx)
	return mockArgs.Get(0).(pgx.Tx), mockArgs.Error(1)
}

// MockRow implements pgx.Row for testing
type MockRow struct {
	scanFunc func(dest ...interface{}) error
}

func (m *MockRow) Scan(dest ...interface{}) error {
	if m.scanFunc != nil {
		return m.scanFunc(dest...)
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

// TestGetUserIDFromToken tests the getUserIDFromToken function
func TestGetUserIDFromToken(t *testing.T) {
	app := fiber.New()

	t.Run("Successfully extract user ID from context", func(t *testing.T) {
		testUserID := uuid.New()

		app.Get("/test", func(c *fiber.Ctx) error {
			c.Locals("user_id", testUserID)
			userID, err := GetUserIDFromToken(c)
			assert.NoError(t, err)
			assert.Equal(t, testUserID, userID)
			return c.SendString("ok")
		})

		req := httptest.NewRequest("GET", "/test", nil)
		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, 200, resp.StatusCode)
	})

	t.Run("Return error when user ID not in context", func(t *testing.T) {
		app.Get("/no-user", func(c *fiber.Ctx) error {
			_, err := GetUserIDFromToken(c)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "user ID not found")
			return c.SendString("error")
		})

		req := httptest.NewRequest("GET", "/no-user", nil)
		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, 200, resp.StatusCode)
	})
}

// TestHasRole tests the HasRole function
func TestHasRole(t *testing.T) {
	testUserID := uuid.New()
	ctx := context.Background()

	t.Run("User is admin in database", func(t *testing.T) {
		mockDB := new(MockDatabase)
		mockRow := &MockRow{
			scanFunc: func(dest ...interface{}) error {
				if isAdmin, ok := dest[0].(*bool); ok {
					*isAdmin = true
				}
				return nil
			},
		}
		// Use mock.Anything for all arguments to match variadic args slice
		mockDB.On("QueryRow", ctx, mock.Anything, mock.Anything).Return(mockRow)

		hasRole := HasRole(ctx, mockDB, testUserID, "admin")
		assert.True(t, hasRole)
	})

	t.Run("User has specific role", func(t *testing.T) {
		mockDB := new(MockDatabase)

		// First call returns false for is_admin
		adminRow := &MockRow{
			scanFunc: func(dest ...interface{}) error {
				if isAdmin, ok := dest[0].(*bool); ok {
					*isAdmin = false
				}
				return nil
			},
		}
		mockDB.On("QueryRow", ctx, "SELECT is_admin FROM users WHERE id = $1", mock.Anything).Return(adminRow)

		// Second call checks user_roles
		roleRow := &MockRow{
			scanFunc: func(dest ...interface{}) error {
				if exists, ok := dest[0].(*bool); ok {
					*exists = true
				}
				return nil
			},
		}
		mockDB.On("QueryRow", ctx, mock.MatchedBy(func(s string) bool {
			return s != "SELECT is_admin FROM users WHERE id = $1"
		}), mock.Anything, mock.Anything).Return(roleRow)

		hasRole := HasRole(ctx, mockDB, testUserID, "editor")
		assert.True(t, hasRole)
	})
}

// TestRequireRole tests the RequireRole middleware
func TestRequireRole(t *testing.T) {
	testUserID := uuid.New()

	t.Run("Authorized user with role can access", func(t *testing.T) {
		mockDB := new(MockDatabase)

		adminRow := &MockRow{
			scanFunc: func(dest ...interface{}) error {
				if isAdmin, ok := dest[0].(*bool); ok {
					*isAdmin = true
				}
				return nil
			},
		}
		mockDB.On("QueryRow", mock.Anything, mock.Anything, mock.Anything).Return(adminRow)

		app := fiber.New()
		app.Get("/admin", func(c *fiber.Ctx) error {
			c.Locals("user_id", testUserID)
			return c.Next()
		}, RequireRole(mockDB, "admin"), func(c *fiber.Ctx) error {
			return c.SendString("authorized")
		})

		req := httptest.NewRequest("GET", "/admin", nil)
		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, 200, resp.StatusCode)
	})

	t.Run("Unauthorized when user_id missing", func(t *testing.T) {
		mockDB := new(MockDatabase)

		app := fiber.New()
		app.Get("/admin", RequireRole(mockDB, "admin"), func(c *fiber.Ctx) error {
			return c.SendString("authorized")
		})

		req := httptest.NewRequest("GET", "/admin", nil)
		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, 401, resp.StatusCode)
	})
}

// TestJWTMiddleware tests the JWT middleware
func TestJWTMiddleware(t *testing.T) {
	secret := []byte("test-secret-key-at-least-32-characters-long")
	crypto := &MockCryptoService{}

	// Setup mock Redis
	rdb := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})
	defer func() { _ = rdb.Close() }() // Test cleanup

	t.Run("Valid JWT token is accepted", func(t *testing.T) {
		app := fiber.New()
		testUserID := uuid.New()

		// Create valid token
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"user_id": testUserID.String(),
			"exp":     time.Now().Add(time.Hour).Unix(),
		})
		tokenString, err := token.SignedString(secret)
		require.NoError(t, err)

		app.Get("/protected", JWTMiddleware(secret, rdb, crypto), func(c *fiber.Ctx) error {
			userID := c.Locals("user_id").(uuid.UUID)
			assert.Equal(t, testUserID, userID)
			return c.SendString("authorized")
		})

		req := httptest.NewRequest("GET", "/protected", nil)
		req.Header.Set("Authorization", "Bearer "+tokenString)
		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, 200, resp.StatusCode)
	})

	t.Run("Missing authorization header returns 401", func(t *testing.T) {
		app := fiber.New()
		app.Get("/protected", JWTMiddleware(secret, rdb, crypto), func(c *fiber.Ctx) error {
			return c.SendString("authorized")
		})

		req := httptest.NewRequest("GET", "/protected", nil)
		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, 401, resp.StatusCode)
	})

	t.Run("Invalid JWT token returns 401", func(t *testing.T) {
		app := fiber.New()
		app.Get("/protected", JWTMiddleware(secret, rdb, crypto), func(c *fiber.Ctx) error {
			return c.SendString("authorized")
		})

		req := httptest.NewRequest("GET", "/protected", nil)
		req.Header.Set("Authorization", "Bearer invalid.token.here")
		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, 401, resp.StatusCode)
	})

	t.Run("Token without user_id claim returns 401", func(t *testing.T) {
		app := fiber.New()

		// Create token without user_id
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"exp": time.Now().Add(time.Hour).Unix(),
		})
		tokenString, err := token.SignedString(secret)
		require.NoError(t, err)

		app.Get("/protected", JWTMiddleware(secret, rdb, crypto), func(c *fiber.Ctx) error {
			return c.SendString("authorized")
		})

		req := httptest.NewRequest("GET", "/protected", nil)
		req.Header.Set("Authorization", "Bearer "+tokenString)
		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, 401, resp.StatusCode)
	})
}

// TestAdminAllowlist tests the admin allowlist functions
func TestAdminAllowlist(t *testing.T) {
	// Clear environment
	_ = os.Unsetenv("ADMIN_USER_IDS") // Test setup

	t.Run("Empty allowlist returns false", func(t *testing.T) {
		StoreAllowlist(make(map[string]struct{}))
		result := IsUserInAdminAllowlist("test-user-id")
		assert.False(t, result)
	})

	t.Run("User in allowlist returns true", func(t *testing.T) {
		allowlist := map[string]struct{}{
			"user-123": {},
		}
		StoreAllowlist(allowlist)
		result := IsUserInAdminAllowlist("user-123")
		assert.True(t, result)
	})

	t.Run("User with whitespace in allowlist", func(t *testing.T) {
		allowlist := map[string]struct{}{
			"user-456": {},
		}
		StoreAllowlist(allowlist)
		result := IsUserInAdminAllowlist("  user-456  ")
		assert.True(t, result)
	})

	t.Run("LoadAllowlistFromSources with env only", func(t *testing.T) {
		allowlist, sig := LoadAllowlistFromSources("user-1,user-2,user-3", "")
		assert.Len(t, allowlist, 3)
		assert.Contains(t, allowlist, "user-1")
		assert.Contains(t, allowlist, "user-2")
		assert.Contains(t, allowlist, "user-3")
		assert.Contains(t, sig, "ENV:")
	})

	t.Run("CurrentAllowlist returns stored value", func(t *testing.T) {
		testAllowlist := map[string]struct{}{
			"test-user": {},
		}
		StoreAllowlist(testAllowlist)
		result := CurrentAllowlist()
		assert.Len(t, result, 1)
		assert.Contains(t, result, "test-user")
	})
}

// BenchmarkJWTMiddleware benchmarks JWT token validation
func BenchmarkJWTMiddleware(b *testing.B) {
	secret := []byte("test-secret-key-at-least-32-characters-long")
	crypto := &MockCryptoService{}
	rdb := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
	defer func() { _ = rdb.Close() }() // Benchmark cleanup

	app := fiber.New()
	testUserID := uuid.New()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": testUserID.String(),
		"exp":     time.Now().Add(time.Hour).Unix(),
	})
	tokenString, _ := token.SignedString(secret)

	app.Get("/bench", JWTMiddleware(secret, rdb, crypto), func(c *fiber.Ctx) error {
		return c.SendString("ok")
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("GET", "/bench", nil)
		req.Header.Set("Authorization", "Bearer "+tokenString)
		_, _ = app.Test(req, -1)
	}
}

// BenchmarkHasRole benchmarks role checking
func BenchmarkHasRole(b *testing.B) {
	mockDB := new(MockDatabase)
	testUserID := uuid.New()
	ctx := context.Background()

	adminRow := &MockRow{
		scanFunc: func(dest ...interface{}) error {
			if isAdmin, ok := dest[0].(*bool); ok {
				*isAdmin = true
			}
			return nil
		},
	}
	mockDB.On("QueryRow", mock.Anything, mock.Anything, mock.Anything).Return(adminRow)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = HasRole(ctx, mockDB, testUserID, "admin")
	}
}