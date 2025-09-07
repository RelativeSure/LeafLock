// Copyright (c) 2025 RelativeSure
// main_test.go - Comprehensive test suite for the secure notes backend
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// Test configuration.
const (
	TestDatabaseURL = "postgres://test:test@localhost:5433/test_notes?sslmode=disable"
	TestRedisURL    = "localhost:6380"
)

// MockDB represents a mock database connection for unit tests.
type MockDB struct {
	mock.Mock
}

func (m *MockDB) QueryRow(ctx context.Context, sql string, args ...interface{}) *MockRow {
	mockArgs := m.Called(ctx, sql, args)
	return mockArgs.Get(0).(*MockRow)
}

func (m *MockDB) Exec(ctx context.Context, sql string, args ...interface{}) (*MockResult, error) {
	mockArgs := m.Called(ctx, sql, args)
	return mockArgs.Get(0).(*MockResult), mockArgs.Error(1)
}

func (m *MockDB) Query(ctx context.Context, sql string, args ...interface{}) (*MockRows, error) {
	mockArgs := m.Called(ctx, sql, args)
	return mockArgs.Get(0).(*MockRows), mockArgs.Error(1)
}

func (m *MockDB) Begin(ctx context.Context) (*MockTx, error) {
	mockArgs := m.Called(ctx)
	return mockArgs.Get(0).(*MockTx), mockArgs.Error(1)
}

func (m *MockDB) Close() {}
func (m *MockDB) Ping(ctx context.Context) error {
	mockArgs := m.Called(ctx)
	return mockArgs.Error(0)
}

type MockRow struct {
	mock.Mock
}

func (m *MockRow) Scan(dest ...interface{}) error {
	mockArgs := m.Called(dest)
	return mockArgs.Error(0)
}

type MockRows struct {
	mock.Mock
	closed bool
}

func (m *MockRows) Next() bool {
	mockArgs := m.Called()
	return mockArgs.Bool(0)
}

func (m *MockRows) Scan(dest ...interface{}) error {
	mockArgs := m.Called(dest)
	return mockArgs.Error(0)
}

func (m *MockRows) Close() {
	m.closed = true
}

type MockTx struct {
	mock.Mock
}

func (m *MockTx) QueryRow(ctx context.Context, sql string, args ...interface{}) *MockRow {
	mockArgs := m.Called(ctx, sql, args)
	return mockArgs.Get(0).(*MockRow)
}

func (m *MockTx) Exec(ctx context.Context, sql string, args ...interface{}) (*MockResult, error) {
	mockArgs := m.Called(ctx, sql, args)
	return mockArgs.Get(0).(*MockResult), mockArgs.Error(1)
}

func (m *MockTx) Rollback(ctx context.Context) error {
	mockArgs := m.Called(ctx)
	return mockArgs.Error(0)
}

func (m *MockTx) Commit(ctx context.Context) error {
	mockArgs := m.Called(ctx)
	return mockArgs.Error(0)
}

type MockResult struct {
	mock.Mock
}

func (m *MockResult) RowsAffected() int64 {
	mockArgs := m.Called()
	return mockArgs.Get(0).(int64)
}

// CryptoService Tests.
func TestCryptoService(t *testing.T) {
	// Generate test key.
	testKey := make([]byte, 32)
	_, err := rand.Read(testKey)
	require.NoError(t, err)

	crypto := NewCryptoService(testKey)

	t.Run("EncryptDecrypt", func(t *testing.T) {
		plaintext := []byte("test message for encryption")

		// Test encryption.
		ciphertext, err := crypto.Encrypt(plaintext)
		assert.NoError(t, err)
		assert.NotNil(t, ciphertext)
		assert.NotEqual(t, plaintext, ciphertext)

		// Test decryption.
		decrypted, err := crypto.Decrypt(ciphertext)
		assert.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("EncryptEmptyData", func(t *testing.T) {
		plaintext := []byte("")

		ciphertext, err := crypto.Encrypt(plaintext)
		assert.NoError(t, err)

		decrypted, err := crypto.Decrypt(ciphertext)
		assert.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("DecryptInvalidData", func(t *testing.T) {
		invalidData := []byte("invalid ciphertext")

		_, err := crypto.Decrypt(invalidData)
		assert.Error(t, err)
	})

	t.Run("DecryptTooShort", func(t *testing.T) {
		shortData := make([]byte, 10) // Less than nonce size

		_, err := crypto.Decrypt(shortData)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "ciphertext too short")
	})
}

// Password Hashing Tests.
func TestPasswordHashing(t *testing.T) {
	password := "TestPassword123!"
	passwordSalt := make([]byte, 32)
	if _, err := rand.Read(passwordSalt); err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	t.Run("HashPassword", func(t *testing.T) {
		hash := HashPassword(password, passwordSalt)
		assert.NotEmpty(t, hash)
		assert.Contains(t, hash, "$argon2id$")
	})

	t.Run("VerifyPassword", func(t *testing.T) {
		hash := HashPassword(password, passwordSalt)

		// Correct password should verify.
		assert.True(t, VerifyPassword(password, hash))

		// Wrong password should not verify.
		assert.False(t, VerifyPassword("WrongPassword", hash))
	})

	t.Run("VerifyInvalidHash", func(t *testing.T) {
		assert.False(t, VerifyPassword(password, "invalid$hash$format"))
	})

	t.Run("ConstantTimeComparison", func(t *testing.T) {
		hash := HashPassword(password, passwordSalt)

		// Multiple verifications should take similar time (constant time).
		start1 := time.Now()
		VerifyPassword(password, hash)
		duration1 := time.Since(start1)

		start2 := time.Now()
		VerifyPassword("WrongPassword", hash)
		duration2 := time.Since(start2)

		// Times should be within reasonable range (not exact due to system variations)
		ratio := float64(duration1) / float64(duration2)
		assert.True(t, ratio > 0.5 && ratio < 2.0, "Password verification should be constant time")
	})
}

// Configuration Tests.
func TestConfig(t *testing.T) {
	// Store original environment
	originalJWT := os.Getenv("JWT_SECRET")
	originalEncKey := os.Getenv("SERVER_ENCRYPTION_KEY")
	originalDBURL := os.Getenv("DATABASE_URL")

	defer func() {
		// Restore environment
		os.Setenv("JWT_SECRET", originalJWT)
		os.Setenv("SERVER_ENCRYPTION_KEY", originalEncKey)
		os.Setenv("DATABASE_URL", originalDBURL)
	}()

	t.Run("LoadConfigWithDefaults", func(t *testing.T) {
		// Clear environment variables
		os.Unsetenv("JWT_SECRET")
		os.Unsetenv("SERVER_ENCRYPTION_KEY")
		os.Unsetenv("DATABASE_URL")

		config := LoadConfig()

		assert.NotEmpty(t, config.JWTSecret)
		assert.NotEmpty(t, config.EncryptionKey)
		assert.Equal(t, "postgres://postgres:postgres@localhost:5432/notes?sslmode=disable", config.DatabaseURL)
		assert.Equal(t, "8080", config.Port)
		assert.Equal(t, 5, config.MaxLoginAttempts)
		assert.Equal(t, 15*time.Minute, config.LockoutDuration)
	})

	t.Run("LoadConfigWithEnvironment", func(t *testing.T) {
		testJWT := "test-jwt-secret-key-with-sufficient-length-for-hs512-algorithm"
		testEncKey := base64.StdEncoding.EncodeToString(make([]byte, 32))
		testDBURL := "postgres://test:test@localhost:5432/testdb"

		os.Setenv("JWT_SECRET", testJWT)
		os.Setenv("SERVER_ENCRYPTION_KEY", testEncKey)
		os.Setenv("DATABASE_URL", testDBURL)

		config := LoadConfig()

		assert.Equal(t, testJWT, string(config.JWTSecret))
		assert.Equal(t, testEncKey, string(config.EncryptionKey))
		assert.Equal(t, testDBURL, config.DatabaseURL)
	})
}

// JWT Middleware Tests.
func TestJWTMiddleware(t *testing.T) {
	secret := []byte("test-secret-key-for-jwt-tokens-with-sufficient-length")
	middleware := JWTMiddleware(secret)

	t.Run("ValidToken", func(t *testing.T) {
		app := fiber.New()
		app.Use(middleware)
		app.Get("/test", func(c *fiber.Ctx) error {
			userID := c.Locals("user_id").(uuid.UUID)
			return c.JSON(fiber.Map{"user_id": userID.String()})
		})

		// Generate valid token
		userID := uuid.New()
		claims := jwt.MapClaims{
			"user_id": userID.String(),
			"exp":     time.Now().Add(time.Hour).Unix(),
			"iat":     time.Now().Unix(),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
		tokenString, err := token.SignedString(secret)
		require.NoError(t, err)

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer "+tokenString)

		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, 200, resp.StatusCode)
	})

	t.Run("MissingToken", func(t *testing.T) {
		app := fiber.New()
		app.Use(middleware)
		app.Get("/test", func(c *fiber.Ctx) error {
			return c.JSON(fiber.Map{"status": "ok"})
		})

		req := httptest.NewRequest("GET", "/test", nil)
		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, 401, resp.StatusCode)
	})

	t.Run("InvalidToken", func(t *testing.T) {
		app := fiber.New()
		app.Use(middleware)
		app.Get("/test", func(c *fiber.Ctx) error {
			return c.JSON(fiber.Map{"status": "ok"})
		})

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer invalid.token.here")

		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, 401, resp.StatusCode)
	})

	t.Run("ExpiredToken", func(t *testing.T) {
		app := fiber.New()
		app.Use(middleware)
		app.Get("/test", func(c *fiber.Ctx) error {
			return c.JSON(fiber.Map{"status": "ok"})
		})

		// Generate expired token
		userID := uuid.New()
		claims := jwt.MapClaims{
			"user_id": userID.String(),
			"exp":     time.Now().Add(-time.Hour).Unix(), // Expired 1 hour ago
			"iat":     time.Now().Add(-2 * time.Hour).Unix(),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
		tokenString, err := token.SignedString(secret)
		require.NoError(t, err)

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer "+tokenString)

		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, 401, resp.StatusCode)
	})
}

// AuthHandler Test Suite
type AuthHandlerTestSuite struct {
	suite.Suite
	handler *AuthHandler
	mockDB  *MockDB
	crypto  *CryptoService
	config  *Config
}

func (suite *AuthHandlerTestSuite) SetupTest() {
	suite.mockDB = &MockDB{}

	// Generate test encryption key
	key := make([]byte, 32)
	rand.Read(key)
	suite.crypto = NewCryptoService(key)

	suite.config = &Config{
		JWTSecret:        []byte("test-jwt-secret-key-for-testing-purposes-with-sufficient-length"),
		EncryptionKey:    key,
		MaxLoginAttempts: 5,
		LockoutDuration:  15 * time.Minute,
		SessionDuration:  24 * time.Hour,
	}

	suite.handler = &AuthHandler{
		crypto: suite.crypto,
		config: suite.config,
	}
}

func (suite *AuthHandlerTestSuite) TestRegisterSuccess() {
	app := fiber.New()

	// Mock successful database interactions
	mockTx := &MockTx{}
	mockRow := &MockRow{}
	userID := uuid.New()
	workspaceID := uuid.New()

	suite.mockDB.On("Begin", mock.Anything).Return(mockTx, nil)
	mockTx.On("QueryRow", mock.Anything, mock.AnythingOfType("string"), mock.Anything).Return(mockRow).Once()
	mockRow.On("Scan", mock.Anything).Run(func(args mock.Arguments) {
		// Set the user ID in the first argument (should be *uuid.UUID)
		if uid, ok := args[0].(*uuid.UUID); ok {
			*uid = userID
		}
	}).Return(nil).Once()

	// Mock workspace creation
	mockRow2 := &MockRow{}
	mockTx.On("QueryRow", mock.Anything, mock.AnythingOfType("string"), mock.Anything).Return(mockRow2).Once()
	mockRow2.On("Scan", mock.Anything).Run(func(args mock.Arguments) {
		if wid, ok := args[0].(*uuid.UUID); ok {
			*wid = workspaceID
		}
	}).Return(nil).Once()

	mockTx.On("Commit", mock.Anything).Return(nil)
	mockTx.On("Rollback", mock.Anything).Return(nil)

	// Mock audit log
	suite.mockDB.On("Exec", mock.Anything, mock.AnythingOfType("string"), mock.Anything).Return(&MockResult{}, nil)

	req := RegisterRequest{
		Email:    "test@example.com",
		Password: "SuperSecurePassword123!@#",
	}

	body, _ := json.Marshal(req)
	httpReq := httptest.NewRequest("POST", "/register", bytes.NewBuffer(body))
	httpReq.Header.Set("Content-Type", "application/json")

	app.Post("/register", suite.handler.Register)
	resp, err := app.Test(httpReq)

	suite.NoError(err)
	suite.Equal(201, resp.StatusCode)

	var response map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&response)

	suite.Equal("Registration successful", response["message"])
	suite.NotEmpty(response["token"])
	suite.Equal(userID.String(), response["user_id"])
}

func (suite *AuthHandlerTestSuite) TestRegisterWeakPassword() {
	app := fiber.New()

	req := RegisterRequest{
		Email:    "test@example.com",
		Password: "weak", // Too short
	}

	body, _ := json.Marshal(req)
	httpReq := httptest.NewRequest("POST", "/register", bytes.NewBuffer(body))
	httpReq.Header.Set("Content-Type", "application/json")

	app.Post("/register", suite.handler.Register)
	resp, err := app.Test(httpReq)

	suite.NoError(err)
	suite.Equal(400, resp.StatusCode)
}

func (suite *AuthHandlerTestSuite) TestRegisterDuplicateEmail() {
	app := fiber.New()

	// Mock database error for duplicate email
	mockTx := &MockTx{}
	suite.mockDB.On("Begin", mock.Anything).Return(mockTx, nil)
	mockTx.On("QueryRow", mock.Anything, mock.AnythingOfType("string"), mock.Anything).Return(&MockRow{})
	mockTx.On("Rollback", mock.Anything).Return(nil)

	mockRow := &MockRow{}
	mockRow.On("Scan", mock.Anything).Return(fmt.Errorf("duplicate key value violates unique constraint"))

	req := RegisterRequest{
		Email:    "existing@example.com",
		Password: "SuperSecurePassword123!@#",
	}

	body, _ := json.Marshal(req)
	httpReq := httptest.NewRequest("POST", "/register", bytes.NewBuffer(body))
	httpReq.Header.Set("Content-Type", "application/json")

	app.Post("/register", suite.handler.Register)
	resp, err := app.Test(httpReq)

	suite.NoError(err)
	suite.Equal(409, resp.StatusCode)
}

func (suite *AuthHandlerTestSuite) TestLoginSuccess() {
	app := fiber.New()

	userID := uuid.New()
	passwordHash := HashPassword("TestPassword123!", make([]byte, 32))

	// Mock user lookup
	mockRow := &MockRow{}
	suite.mockDB.On("QueryRow", mock.Anything, mock.AnythingOfType("string"), mock.Anything).Return(mockRow)
	mockRow.On("Scan", mock.Anything).Run(func(args mock.Arguments) {
		// Set mock data in scan arguments
		if uid, ok := args[0].(*uuid.UUID); ok {
			*uid = userID
		}
		if hash, ok := args[1].(*string); ok {
			*hash = passwordHash
		}
		if attempts, ok := args[2].(*int); ok {
			*attempts = 0
		}
		if locked, ok := args[3].(**time.Time); ok {
			*locked = nil
		}
		if mfaEnabled, ok := args[4].(*bool); ok {
			*mfaEnabled = false
		}
		if mfaSecret, ok := args[5].(*[]byte); ok {
			*mfaSecret = nil
		}
	}).Return(nil)

	// Mock updates and session creation
	mockResult := &MockResult{}
	mockResult.On("RowsAffected").Return(int64(1))
	suite.mockDB.On("Exec", mock.Anything, mock.AnythingOfType("string"), mock.Anything).Return(mockResult, nil)

	// Mock workspace lookup
	mockRow2 := &MockRow{}
	suite.mockDB.On("QueryRow", mock.Anything, mock.AnythingOfType("string"), userID).Return(mockRow2)
	mockRow2.On("Scan", mock.Anything).Return(nil)

	req := LoginRequest{
		Email:    "test@example.com",
		Password: "TestPassword123!",
	}

	body, _ := json.Marshal(req)
	httpReq := httptest.NewRequest("POST", "/login", bytes.NewBuffer(body))
	httpReq.Header.Set("Content-Type", "application/json")

	app.Post("/login", suite.handler.Login)
	resp, err := app.Test(httpReq)

	suite.NoError(err)
	suite.Equal(200, resp.StatusCode)

	var response map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&response)

	suite.NotEmpty(response["token"])
	suite.NotEmpty(response["session"])
}

func (suite *AuthHandlerTestSuite) TestLoginInvalidCredentials() {
	app := fiber.New()

	// Mock database returning error (user not found)
	mockRow := &MockRow{}
	suite.mockDB.On("QueryRow", mock.Anything, mock.AnythingOfType("string"), mock.Anything).Return(mockRow)
	mockRow.On("Scan", mock.Anything).Return(fmt.Errorf("no rows in result set"))

	req := LoginRequest{
		Email:    "nonexistent@example.com",
		Password: "TestPassword123!",
	}

	body, _ := json.Marshal(req)
	httpReq := httptest.NewRequest("POST", "/login", bytes.NewBuffer(body))
	httpReq.Header.Set("Content-Type", "application/json")

	app.Post("/login", suite.handler.Login)
	resp, err := app.Test(httpReq)

	suite.NoError(err)
	suite.Equal(401, resp.StatusCode)
}

func (suite *AuthHandlerTestSuite) TestLoginAccountLocked() {
	app := fiber.New()

	userID := uuid.New()
	lockTime := time.Now().Add(10 * time.Minute) // Locked for 10 more minutes

	mockRow := &MockRow{}
	suite.mockDB.On("QueryRow", mock.Anything, mock.AnythingOfType("string"), mock.Anything).Return(mockRow)
	mockRow.On("Scan", mock.Anything).Run(func(args mock.Arguments) {
		if uid, ok := args[0].(*uuid.UUID); ok {
			*uid = userID
		}
		if hash, ok := args[1].(*string); ok {
			*hash = "dummy_hash"
		}
		if attempts, ok := args[2].(*int); ok {
			*attempts = 5
		}
		if locked, ok := args[3].(**time.Time); ok {
			*locked = &lockTime
		}
		if mfaEnabled, ok := args[4].(*bool); ok {
			*mfaEnabled = false
		}
		if mfaSecret, ok := args[5].(*[]byte); ok {
			*mfaSecret = nil
		}
	}).Return(nil)

	req := LoginRequest{
		Email:    "locked@example.com",
		Password: "TestPassword123!",
	}

	body, _ := json.Marshal(req)
	httpReq := httptest.NewRequest("POST", "/login", bytes.NewBuffer(body))
	httpReq.Header.Set("Content-Type", "application/json")

	app.Post("/login", suite.handler.Login)
	resp, err := app.Test(httpReq)

	suite.NoError(err)
	suite.Equal(403, resp.StatusCode)
}

// Run the test suites
func TestAuthHandlerSuite(t *testing.T) {
	suite.Run(t, new(AuthHandlerTestSuite))
}

// Integration test helper functions
func setupTestDB(t *testing.T) (*pgxpool.Pool, func()) {
	// Skip integration tests if no test database available
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, TestDatabaseURL)
	if err != nil {
		t.Skipf("Cannot connect to test database: %v", err)
	}

	// Run schema setup
	_, err = pool.Exec(ctx, DatabaseSchema)
	if err != nil {
		pool.Close()
		t.Fatalf("Failed to setup test schema: %v", err)
	}

	cleanup := func() {
		// Clean up test data
		pool.Exec(ctx, "TRUNCATE users, workspaces, notes, sessions, audit_log CASCADE")
		pool.Close()
	}

	return pool, cleanup
}

// setupTestRedis function removed as it was unused

// Benchmarks for performance testing
func BenchmarkPasswordHashing(b *testing.B) {
	password := "TestPassword123!"
	salt := make([]byte, 32)
	rand.Read(salt)

	b.Run("HashPassword", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			HashPassword(password, salt)
		}
	})

	hash := HashPassword(password, salt)
	b.Run("VerifyPassword", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			VerifyPassword(password, hash)
		}
	})
}

func BenchmarkCryptoService(b *testing.B) {
	key := make([]byte, 32)
	rand.Read(key)
	crypto := NewCryptoService(key)

	plaintext := make([]byte, 1024) // 1KB test data
	rand.Read(plaintext)

	b.Run("Encrypt", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			crypto.Encrypt(plaintext)
		}
	})

	ciphertext, _ := crypto.Encrypt(plaintext)
	b.Run("Decrypt", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			crypto.Decrypt(ciphertext)
		}
	})
}
