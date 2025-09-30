package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	appconfig "leaflock/config"
	appcrypto "leaflock/crypto"
	appdb "leaflock/database"
)

// Test configuration
const (
	TestDatabaseURL = "postgres://test:test@localhost:5433/test_leaflock?sslmode=disable"
	TestRedisURL    = "localhost:6380"
)

// MockDB represents a mock database connection for unit tests
type MockDB struct {
	mock.Mock
}

// pgx interface compatibility methods
func (m *MockDB) QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row {
	callArgs := append([]interface{}{ctx, sql}, args...)
	mockArgs := m.Called(callArgs...)
	return mockArgs.Get(0).(*MockRow)
}

func (m *MockDB) Exec(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
	callArgs := append([]interface{}{ctx, sql}, args...)
	mockArgs := m.Called(callArgs...)
	result := mockArgs.Get(0).(*MockResult)
	// Create a command tag that uses our mock's RowsAffected value
	tag := pgconn.NewCommandTag("UPDATE " + fmt.Sprintf("%d", result.RowsAffected()))
	return tag, mockArgs.Error(1)
}

func (m *MockDB) Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error) {
	callArgs := append([]interface{}{ctx, sql}, args...)
	mockArgs := m.Called(callArgs...)
	return mockArgs.Get(0).(*MockRows), mockArgs.Error(1)
}

func (m *MockDB) Begin(ctx context.Context) (pgx.Tx, error) {
	mockArgs := m.Called(ctx)
	return mockArgs.Get(0).(*MockTx), mockArgs.Error(1)
}

// Legacy methods for backward compatibility
func (m *MockDB) QueryRowLegacy(ctx context.Context, sql string, args ...interface{}) *MockRow {
	callArgs := append([]interface{}{ctx, sql}, args...)
	mockArgs := m.Called(callArgs...)
	return mockArgs.Get(0).(*MockRow)
}

func (m *MockDB) ExecLegacy(ctx context.Context, sql string, args ...interface{}) (*MockResult, error) {
	callArgs := append([]interface{}{ctx, sql}, args...)
	mockArgs := m.Called(callArgs...)
	return mockArgs.Get(0).(*MockResult), mockArgs.Error(1)
}

func (m *MockDB) QueryLegacy(ctx context.Context, sql string, args ...interface{}) (*MockRows, error) {
	callArgs := append([]interface{}{ctx, sql}, args...)
	mockArgs := m.Called(callArgs...)
	return mockArgs.Get(0).(*MockRows), mockArgs.Error(1)
}

func (m *MockDB) BeginLegacy(ctx context.Context) (*MockTx, error) {
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
	mockArgs := m.Called(dest...)
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
	mockArgs := m.Called(dest...)
	return mockArgs.Error(0)
}

func (m *MockRows) Close() {
	m.closed = true
}

// Additional methods required by pgx.Rows interface
func (m *MockRows) Err() error {
	mockArgs := m.Called()
	return mockArgs.Error(0)
}

func (m *MockRows) CommandTag() pgconn.CommandTag {
	mockArgs := m.Called()
	return pgconn.NewCommandTag(mockArgs.String(0))
}

func (m *MockRows) FieldDescriptions() []pgconn.FieldDescription {
	mockArgs := m.Called()
	return mockArgs.Get(0).([]pgconn.FieldDescription)
}

func (m *MockRows) Values() ([]interface{}, error) {
	mockArgs := m.Called()
	return mockArgs.Get(0).([]interface{}), mockArgs.Error(1)
}

func (m *MockRows) RawValues() [][]byte {
	mockArgs := m.Called()
	return mockArgs.Get(0).([][]byte)
}

func (m *MockRows) Conn() *pgx.Conn {
	mockArgs := m.Called()
	return mockArgs.Get(0).(*pgx.Conn)
}

type MockTx struct {
	mock.Mock
}

// pgx.Tx interface methods
func (m *MockTx) QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row {
	callArgs := append([]interface{}{ctx, sql}, args...)
	mockArgs := m.Called(callArgs...)
	return mockArgs.Get(0).(*MockRow)
}

func (m *MockTx) Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error) {
	callArgs := append([]interface{}{ctx, sql}, args...)
	mockArgs := m.Called(callArgs...)
	return mockArgs.Get(0).(*MockRows), mockArgs.Error(1)
}

func (m *MockTx) Exec(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
	callArgs := append([]interface{}{ctx, sql}, args...)
	mockArgs := m.Called(callArgs...)
	result := mockArgs.Get(0).(*MockResult)
	return pgconn.NewCommandTag(result.tag), mockArgs.Error(1)
}

func (m *MockTx) Rollback(ctx context.Context) error {
	mockArgs := m.Called(ctx)
	return mockArgs.Error(0)
}

func (m *MockTx) Commit(ctx context.Context) error {
	mockArgs := m.Called(ctx)
	return mockArgs.Error(0)
}

// Additional methods required by pgx.Tx interface
func (m *MockTx) Begin(ctx context.Context) (pgx.Tx, error) {
	mockArgs := m.Called(ctx)
	return mockArgs.Get(0).(pgx.Tx), mockArgs.Error(1)
}

func (m *MockTx) CopyFrom(ctx context.Context, tableName pgx.Identifier, columnNames []string, rowSrc pgx.CopyFromSource) (int64, error) {
	mockArgs := m.Called(ctx, tableName, columnNames, rowSrc)
	return mockArgs.Get(0).(int64), mockArgs.Error(1)
}

func (m *MockTx) SendBatch(ctx context.Context, b *pgx.Batch) pgx.BatchResults {
	mockArgs := m.Called(ctx, b)
	return mockArgs.Get(0).(pgx.BatchResults)
}

func (m *MockTx) LargeObjects() pgx.LargeObjects {
	mockArgs := m.Called()
	return mockArgs.Get(0).(pgx.LargeObjects)
}

func (m *MockTx) Prepare(ctx context.Context, name, sql string) (*pgconn.StatementDescription, error) {
	mockArgs := m.Called(ctx, name, sql)
	return mockArgs.Get(0).(*pgconn.StatementDescription), mockArgs.Error(1)
}

func (m *MockTx) Deallocate(ctx context.Context, name string) error {
	mockArgs := m.Called(ctx, name)
	return mockArgs.Error(0)
}

func (m *MockTx) Conn() *pgx.Conn {
	mockArgs := m.Called()
	return mockArgs.Get(0).(*pgx.Conn)
}

type MockResult struct {
	mock.Mock
	tag string
}

func (m *MockResult) RowsAffected() int64 {
	mockArgs := m.Called()
	return mockArgs.Get(0).(int64)
}

// CryptoService Tests
func TestCryptoService(t *testing.T) {
	// Generate test key
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	crypto := appcrypto.NewCryptoService(key)

	t.Run("EncryptDecrypt", func(t *testing.T) {
		plaintext := []byte("test message for encryption")

		// Test encryption
		ciphertext, err := crypto.Encrypt(plaintext)
		assert.NoError(t, err)
		assert.NotNil(t, ciphertext)
		assert.NotEqual(t, plaintext, ciphertext)

		// Test decryption
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
		// Handle the case where empty data might return nil instead of empty slice
		if decrypted == nil {
			decrypted = []byte("")
		}
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

// Password Hashing Tests
func TestPasswordHashing(t *testing.T) {
	password := "TestPassword123!"
	salt := make([]byte, 32)
	rand.Read(salt)

	t.Run("appcrypto.HashPassword", func(t *testing.T) {
		hash := appcrypto.HashPassword(password, salt)
		assert.NotEmpty(t, hash)
		assert.Contains(t, hash, "$argon2id$")
	})

	t.Run("appcrypto.VerifyPassword", func(t *testing.T) {
		hash := appcrypto.HashPassword(password, salt)

		// Correct password should verify
		assert.True(t, appcrypto.VerifyPassword(password, hash))

		// Wrong password should not verify
		assert.False(t, appcrypto.VerifyPassword("WrongPassword", hash))
	})

	t.Run("VerifyInvalidHash", func(t *testing.T) {
		assert.False(t, appcrypto.VerifyPassword(password, "invalid$hash$format"))
	})

	t.Run("ConstantTimeComparison", func(t *testing.T) {
		hash := appcrypto.HashPassword(password, salt)

		// Multiple verifications should take similar time (constant time)
		start1 := time.Now()
		appcrypto.VerifyPassword(password, hash)
		duration1 := time.Since(start1)

		start2 := time.Now()
		appcrypto.VerifyPassword("WrongPassword", hash)
		duration2 := time.Since(start2)

		// Times should be within reasonable range (not exact due to system variations)
		ratio := float64(duration1) / float64(duration2)
		assert.True(t, ratio > 0.5 && ratio < 2.0, "Password verification should be constant time")
	})
}

// Configuration Tests
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
		assert.Equal(t, "postgres://postgres:postgres@localhost:5432/leaflock?sslmode=prefer", config.DatabaseURL)
		assert.Equal(t, "8080", config.Port)
		assert.Equal(t, 5, config.MaxLoginAttempts)
		assert.Equal(t, 15*time.Minute, config.LockoutDuration)
	})

	t.Run("LoadConfigWithEnvironment", func(t *testing.T) {
		testJWT := "unit-test-jwt-secret-key-with-sufficient-length-1234567890"
		testEncKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
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

// JWT Middleware Tests
func TestJWTMiddleware(t *testing.T) {
	secret := []byte("test-secret-key-for-jwt-tokens-with-sufficient-length")

	// Set up test dependencies
	rdb, cleanupRedis := setupTestRedis(t)
	defer cleanupRedis()

	// Generate test encryption key
	key := make([]byte, 32)
	rand.Read(key)
	crypto := appcrypto.NewCryptoService(key)

	middleware := JWTMiddleware(secret, rdb, crypto)

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
	handler      *AuthHandler
	mockDB       *MockDB
	crypto       *CryptoService
	config       *appconfig.Config
	rdb          *redis.Client
	cleanupRedis func()
}

func (suite *AuthHandlerTestSuite) SetupTest() {
	suite.mockDB = &MockDB{}

	// Ensure registration toggle is enabled for auth tests
	regEnabled.Store(1)
	suite.T().Cleanup(func() {
		regEnabled.Store(0)
	})

	// Generate test encryption key
	key := make([]byte, 32)
	rand.Read(key)
	suite.crypto = appcrypto.NewCryptoService(key)

	suite.config = &appconfig.Config{
		JWTSecret:        []byte("test-jwt-secret-key-for-testing-purposes-with-sufficient-length"),
		EncryptionKey:    key,
		MaxLoginAttempts: 5,
		LockoutDuration:  15 * time.Minute,
		SessionDuration:  24 * time.Hour,
	}

	suite.handler = &AuthHandler{
		db:     suite.mockDB,
		crypto: suite.crypto,
		config: suite.config,
	}

	suite.rdb, suite.cleanupRedis = setupTestRedis(suite.T())
	suite.handler.redis = suite.rdb
}

func (suite *AuthHandlerTestSuite) TearDownTest() {
	if suite.cleanupRedis != nil {
		suite.cleanupRedis()
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
	mockTx.On("QueryRow", mock.Anything, mock.AnythingOfType("string"), mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(mockRow).Once()
	mockRow.On("Scan", mock.Anything).Run(func(args mock.Arguments) {
		// Set the user ID in the first argument (should be *uuid.UUID)
		if uid, ok := args[0].(*uuid.UUID); ok {
			*uid = userID
		}
	}).Return(nil).Once()

	// Mock workspace creation
	mockRow2 := &MockRow{}
	mockTx.On("QueryRow", mock.Anything, mock.AnythingOfType("string"), mock.Anything, mock.Anything, mock.Anything).Return(mockRow2).Once()
	mockRow2.On("Scan", mock.Anything).Run(func(args mock.Arguments) {
		if wid, ok := args[0].(*uuid.UUID); ok {
			*wid = workspaceID
		}
	}).Return(nil).Once()

	mockTx.On("Commit", mock.Anything).Return(nil)
	mockTx.On("Rollback", mock.Anything).Return(nil)

	// Mock audit log
	auditResult := &MockResult{}
	auditResult.On("RowsAffected").Return(int64(1))
	suite.mockDB.On("Exec", mock.Anything, mock.AnythingOfType("string"), mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(auditResult, nil)

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

	// No mocks needed - password validation prevents database access

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
	mockRow := &MockRow{}
	suite.mockDB.On("Begin", mock.Anything).Return(mockTx, nil)
	mockTx.On("QueryRow", mock.Anything, mock.AnythingOfType("string"), mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(mockRow)
	mockTx.On("Rollback", mock.Anything).Return(nil)

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
	passwordHash := appcrypto.HashPassword("TestPassword123!", make([]byte, 32))

	// Mock user lookup
	mockRow := &MockRow{}
	suite.mockDB.On("QueryRow", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return strings.Contains(sql, "SELECT id, password_hash")
	}), mock.Anything).Return(mockRow).Once()
	mockRow.On("Scan", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
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
	// Mock failed attempts reset (3 args: ctx, sql, userID)
	suite.mockDB.On("Exec", mock.Anything, mock.AnythingOfType("string"), mock.Anything).Return(mockResult, nil).Once()
	// Mock session creation (7 args: ctx, sql, userID, tokenHash, encryptedIP, encryptedUA, expiresAt)
	suite.mockDB.On("Exec", mock.Anything, mock.AnythingOfType("string"), mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(mockResult, nil).Once()
	// Mock audit log creation (8 args: ctx, sql, userID, action, resourceType, resourceID, encryptedIP, encryptedUA)
	suite.mockDB.On("Exec", mock.Anything, mock.AnythingOfType("string"), mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(mockResult, nil).Once()

	// Mock workspace lookup
	mockRow2 := &MockRow{}
	suite.mockDB.On("QueryRow", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return strings.Contains(sql, "SELECT id FROM workspaces")
	}), userID).Return(mockRow2).Once()
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
	mockRow.On("Scan", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(fmt.Errorf("no rows in result set"))

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
	mockRow.On("Scan", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
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
	suite.Equal(423, resp.StatusCode)
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
	_, err = pool.Exec(ctx, appdb.DatabaseSchema)
	if err != nil {
		pool.Close()
		t.Skipf("Failed to setup test schema: %v", err)
	}

	cleanup := func() {
		// Clean up test data
		pool.Exec(ctx, "TRUNCATE users, workspaces, notes, audit_log CASCADE")
		pool.Close()
	}

	return pool, cleanup
}

func setupTestRedis(t *testing.T) (*redis.Client, func()) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	rdb := redis.NewClient(&redis.Options{
		Addr: TestRedisURL,
		DB:   1, // Use test database
	})

	ctx := context.Background()
	if err := rdb.Ping(ctx).Err(); err != nil {
		t.Skipf("Cannot connect to test Redis: %v", err)
	}

	cleanup := func() {
		rdb.FlushDB(ctx)
		rdb.Close()
	}

	return rdb, cleanup
}

// Benchmarks for performance testing
func BenchmarkPasswordHashing(b *testing.B) {
	password := "TestPassword123!"
	salt := make([]byte, 32)
	rand.Read(salt)

	b.Run("appcrypto.HashPassword", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			appcrypto.HashPassword(password, salt)
		}
	})

	hash := appcrypto.HashPassword(password, salt)
	b.Run("appcrypto.VerifyPassword", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			appcrypto.VerifyPassword(password, hash)
		}
	})
}

func BenchmarkCryptoService(b *testing.B) {
	key := make([]byte, 32)
	rand.Read(key)
	crypto := appcrypto.NewCryptoService(key)

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

// Additional coverage: database setup error path and registration disabled
func TestSetupDatabase_InvalidConnection(t *testing.T) {
	// Use an unreachable port to fail fast without external dependencies
	badURL := "postgres://postgres:postgres@127.0.0.1:1/notes?sslmode=disable"
	pool, err := appdb.SetupDatabase(badURL)
	if pool != nil {
		pool.Close()
	}
	require.Error(t, err, "expected error when database is unreachable")
}

func TestRegister_Disabled(t *testing.T) {
	t.Setenv("ENABLE_REGISTRATION", "false")

	h := &AuthHandler{}
	app := fiber.New()
	app.Post("/register", h.Register)

	body := bytes.NewBufferString(`{"email":"test@example.com","password":"averylongsecurepassword"}`)
	req := httptest.NewRequest("POST", "/register", body)
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, 403, resp.StatusCode)
}

type LockoutTestSuite struct {
	suite.Suite
	app          *fiber.App
	config       *appconfig.Config
	rdb          *redis.Client
	crypto       *CryptoService
	db           Database
	cleanupRedis func()
	cleanupDB    func()
	authHandler  *AuthHandler
}

func (suite *LockoutTestSuite) SetupTest() {
	// Test config
	suite.config = &appconfig.Config{
		JWTSecret:            []byte("test-secret"),
		EncryptionKey:        []byte("12345678901234567890123456789012"),
		MaxLoginAttempts:     3,
		MaxIPLoginAttempts:   5,
		IPLockoutDuration:    3 * time.Second, // Short duration for testing
		LockoutDuration:      3 * time.Second, // Short duration for testing
		SessionDuration:      1 * time.Hour,
		DefaultAdminEmail:    "admin@test.com",
		DefaultAdminPassword: "password",
		DefaultAdminEnabled:  true,
	}

	// Test DB and Redis
	suite.db, suite.cleanupDB = setupTestDB(suite.T())
	suite.rdb, suite.cleanupRedis = setupTestRedis(suite.T())
	suite.crypto = appcrypto.NewCryptoService(suite.config.EncryptionKey)

	// Create app
	suite.app = fiber.New()
	suite.authHandler = &AuthHandler{
		db:     suite.db,
		redis:  suite.rdb,
		crypto: suite.crypto,
		config: suite.config,
	}
	suite.app.Post("/auth/login", suite.authHandler.Login)

	// Create test user
	err := seedDefaultAdminUser(suite.db, suite.crypto, suite.config)
	require.NoError(suite.T(), err)
}

func (suite *LockoutTestSuite) TearDownTest() {
	suite.cleanupDB()
	suite.cleanupRedis()
}

func (suite *LockoutTestSuite) TestProgressiveRateLimit() {
	// Skip this test if progressive rate limiting is disabled
	if suite.config.RateLimitMode == "disabled" {
		suite.T().Skip("Rate limiting is disabled")
	}

	// 1. Successful login should work
	loginReq := LoginRequest{Email: "admin@test.com", Password: "password"}
	body, _ := json.Marshal(loginReq)
	req := httptest.NewRequest("POST", "/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := suite.app.Test(req)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode, "First login should be successful")

	// 2. Fail login attempts - first few should have no delay
	for i := 0; i < 3; i++ {
		loginReq.Password = "wrong-password"
		body, _ = json.Marshal(loginReq)
		req = httptest.NewRequest("POST", "/auth/login", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		start := time.Now()
		resp, err = suite.app.Test(req)
		elapsed := time.Since(start)

		require.NoError(suite.T(), err)
		assert.Contains(suite.T(), []int{http.StatusUnauthorized, http.StatusLocked}, resp.StatusCode)
		assert.Less(suite.T(), elapsed.Milliseconds(), int64(500), "First few attempts should have no significant delay")
	}

	// 3. Additional attempts should start showing progressive delays
	loginReq.Password = "wrong-password"
	body, _ = json.Marshal(loginReq)
	req = httptest.NewRequest("POST", "/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	start := time.Now()
	resp, err = suite.app.Test(req)
	elapsed := time.Since(start)

	require.NoError(suite.T(), err)
	assert.Contains(suite.T(), []int{http.StatusUnauthorized, http.StatusLocked}, resp.StatusCode)

	if suite.config.RateLimitMode == "progressive" {
		// Should have at least some delay (around 1 second for 4th attempt)
		assert.Greater(suite.T(), elapsed.Milliseconds(), int64(800), "4th attempt should have progressive delay")
	}

	// 4. Correct password should still work (progressive delays don't prevent correct logins)
	loginReq.Password = "password"
	body, _ = json.Marshal(loginReq)
	req = httptest.NewRequest("POST", "/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err = suite.app.Test(req)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode, "Correct password should work despite rate limiting")
}

func (suite *LockoutTestSuite) TestUserLockout() {
	// Use a different IP to not interfere with other tests
	const testIP = "1.2.3.4:1234"

	// 1. Fail login attempts up to the user limit
	for i := 0; i < suite.config.MaxLoginAttempts; i++ {
		loginReq := LoginRequest{Email: "admin@test.com", Password: "wrong-password"}
		body, _ := json.Marshal(loginReq)
		req := httptest.NewRequest("POST", "/auth/login", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = testIP
		resp, err := suite.app.Test(req)
		require.NoError(suite.T(), err)
		if i < suite.config.MaxLoginAttempts-1 {
			assert.Equal(suite.T(), http.StatusUnauthorized, resp.StatusCode)
		} else {
			// The last attempt that triggers the lockout
			assert.Equal(suite.T(), http.StatusLocked, resp.StatusCode)
		}
	}

	// 2. User should be locked now
	loginReq := LoginRequest{Email: "admin@test.com", Password: "password"}
	body, _ := json.Marshal(loginReq)
	req := httptest.NewRequest("POST", "/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = testIP
	resp, err := suite.app.Test(req)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), http.StatusLocked, resp.StatusCode, "User account should be locked")

	// 3. Wait for lockout to expire
	time.Sleep(suite.config.LockoutDuration + 1*time.Second)

	// 4. User should be able to log in again
	req = httptest.NewRequest("POST", "/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = testIP
	resp, err = suite.app.Test(req)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode, "Should be able to login after user lockout expires")
}

func TestLockoutTestSuite(t *testing.T) {
	suite.Run(t, new(LockoutTestSuite))
}
