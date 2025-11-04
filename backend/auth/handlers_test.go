//go:build integration

package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"

	"leaflock/config"
	appcrypto "leaflock/crypto"
)

// MockEmailService is a mock email service for testing
type MockEmailService struct{}

func (m *MockEmailService) SendPasswordResetEmail(toEmail string, resetToken string, ipAddress string) error {
	return nil
}

// AuthHandlersTestSuite tests auth Handler
type AuthHandlersTestSuite struct {
	suite.Suite
	handler   *Handler
	mockSvc   *MockAuthService
	cryptoSvc *appcrypto.CryptoService
	jwtSecret string
}

func (suite *AuthHandlersTestSuite) SetupTest() {
	suite.mockSvc = &MockAuthService{}

	// Create a mock service instance
	mockService := &Service{}
	suite.mockSvc.service = mockService

	suite.handler = NewHandler(mockService, &MockEmailService{})

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		suite.T().Fatalf("Failed to generate random key: %v", err)
	}
	suite.cryptoSvc = appcrypto.NewCryptoService(key)
	suite.jwtSecret = "test-jwt-secret-key-for-testing-purposes-only"
}

func TestAuthHandlersTestSuite(t *testing.T) {
	suite.Run(t, new(AuthHandlersTestSuite))
}

// =====================================
// Test Register Handler
// =====================================

func (suite *AuthHandlersTestSuite) TestRegister_Success() {
	app := fiber.New()
	app.Post("/auth/register", suite.handler.Register)

	reqBody := map[string]string{
		"email":    "test@example.com",
		"password": "SecureP@ssw0rd123!",
	}
	body, _ := json.Marshal(reqBody)

	// Enable registration
	config.RegEnabled.Store(1)

	// Mock successful registration
	suite.mockSvc.On("Register", mock.Anything, "test@example.com", "SecureP@ssw0rd123!").
		Return(&AuthResponse{UserID: uuid.New().String()}, nil)

	req := httptest.NewRequest("POST", "/auth/register", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(fiber.StatusAccepted, resp.StatusCode)

	var response map[string]string
	err = json.NewDecoder(resp.Body).Decode(&response)
	suite.NoError(err)
	suite.Contains(response["message"], "email")
}

func (suite *AuthHandlersTestSuite) TestRegister_InvalidRequestBody() {
	app := fiber.New()
	app.Post("/auth/register", suite.handler.Register)

	req := httptest.NewRequest("POST", "/auth/register", bytes.NewBufferString("invalid json"))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(400, resp.StatusCode)

	var errResp ErrorResponse
	err = json.NewDecoder(resp.Body).Decode(&errResp)
	suite.NoError(err)
	suite.Equal(ErrCodeValidationFailed, errResp.Code)
}

func (suite *AuthHandlersTestSuite) TestRegister_RegistrationDisabled() {
	app := fiber.New()
	app.Post("/auth/register", suite.handler.Register)

	reqBody := map[string]string{
		"email":    "test@example.com",
		"password": "SecureP@ssw0rd123!",
	}
	body, _ := json.Marshal(reqBody)

	// Disable registration
	config.RegEnabled.Store(0)

	req := httptest.NewRequest("POST", "/auth/register", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(403, resp.StatusCode)

	var errResp ErrorResponse
	err = json.NewDecoder(resp.Body).Decode(&errResp)
	suite.NoError(err)
	suite.Equal(ErrCodeRegistrationDisabled, errResp.Code)
}

func (suite *AuthHandlersTestSuite) TestRegister_InvalidEmail() {
	app := fiber.New()
	app.Post("/auth/register", suite.handler.Register)

	reqBody := map[string]string{
		"email":    "invalid-email", // Missing @
		"password": "SecureP@ssw0rd123!",
	}
	body, _ := json.Marshal(reqBody)

	// Enable registration
	config.RegEnabled.Store(1)

	req := httptest.NewRequest("POST", "/auth/register", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(400, resp.StatusCode)

	var errResp ErrorResponse
	err = json.NewDecoder(resp.Body).Decode(&errResp)
	suite.NoError(err)
	suite.Equal(ErrCodeValidationFailed, errResp.Code)
	suite.Contains(errResp.Error, "Invalid email")
}

func (suite *AuthHandlersTestSuite) TestRegister_EmailAlreadyExists() {
	app := fiber.New()
	app.Post("/auth/register", suite.handler.Register)

	reqBody := map[string]string{
		"email":    "existing@example.com",
		"password": "SecureP@ssw0rd123!",
	}
	body, _ := json.Marshal(reqBody)

	// Enable registration
	config.RegEnabled.Store(1)

	// Mock service returns duplicate email error
	suite.mockSvc.On("Register", mock.Anything, "existing@example.com", "SecureP@ssw0rd123!").
		Return((*AuthResponse)(nil), ErrEmailAlreadyExists)

	req := httptest.NewRequest("POST", "/auth/register", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(fiber.StatusAccepted, resp.StatusCode)

	var response map[string]string
	err = json.NewDecoder(resp.Body).Decode(&response)
	suite.NoError(err)
	suite.Contains(response["message"], "email")
}

func (suite *AuthHandlersTestSuite) TestRegister_WeakPassword() {
	app := fiber.New()
	app.Post("/auth/register", suite.handler.Register)

	reqBody := map[string]string{
		"email":    "test@example.com",
		"password": "weak", // Too short, no uppercase, no special char
	}
	body, _ := json.Marshal(reqBody)

	// Enable registration
	config.RegEnabled.Store(1)

	// Mock service returns password validation error
	suite.mockSvc.On("Register", mock.Anything, "test@example.com", "weak").
		Return((*AuthResponse)(nil), fmt.Errorf("password must be at least 12 characters"))

	req := httptest.NewRequest("POST", "/auth/register", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(400, resp.StatusCode)

	var errResp ErrorResponse
	err = json.NewDecoder(resp.Body).Decode(&errResp)
	suite.NoError(err)
	suite.Equal(ErrCodeValidationFailed, errResp.Code)
}

// =====================================
// Test Login Handler
// =====================================

func (suite *AuthHandlersTestSuite) TestLogin_Success() {
	app := fiber.New()
	app.Post("/auth/login", suite.handler.Login)

	reqBody := map[string]string{
		"email":    "test@example.com",
		"password": "CorrectP@ssw0rd123!",
	}
	body, _ := json.Marshal(reqBody)

	expectedResponse := &AuthResponse{
		Token:   "mock-jwt-token",
		UserID:  uuid.New().String(),
		IsAdmin: false,
	}
	suite.mockSvc.On("Login", mock.Anything, "test@example.com", "CorrectP@ssw0rd123!", "").
		Return(expectedResponse, nil)

	req := httptest.NewRequest("POST", "/auth/login", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(200, resp.StatusCode)

	var response AuthResponse
	err = json.NewDecoder(resp.Body).Decode(&response)
	suite.NoError(err)
	suite.Equal(expectedResponse.Token, response.Token)
}

func (suite *AuthHandlersTestSuite) TestLogin_InvalidCredentials() {
	app := fiber.New()
	app.Post("/auth/login", suite.handler.Login)

	reqBody := map[string]string{
		"email":    "test@example.com",
		"password": "WrongPassword",
	}
	body, _ := json.Marshal(reqBody)

	suite.mockSvc.On("Login", mock.Anything, "test@example.com", "WrongPassword", "").
		Return((*AuthResponse)(nil), fmt.Errorf("invalid credentials"))

	req := httptest.NewRequest("POST", "/auth/login", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(401, resp.StatusCode)

	var errResp ErrorResponse
	err = json.NewDecoder(resp.Body).Decode(&errResp)
	suite.NoError(err)
	suite.Equal(ErrCodeInvalidCredentials, errResp.Code)
}

func (suite *AuthHandlersTestSuite) TestLogin_AccountLocked() {
	app := fiber.New()
	app.Post("/auth/login", suite.handler.Login)

	reqBody := map[string]string{
		"email":    "locked@example.com",
		"password": "AnyPassword123!",
	}
	body, _ := json.Marshal(reqBody)

	suite.mockSvc.On("Login", mock.Anything, "locked@example.com", "AnyPassword123!", "").
		Return((*AuthResponse)(nil), fmt.Errorf("account locked due to too many failed attempts"))

	req := httptest.NewRequest("POST", "/auth/login", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(403, resp.StatusCode)

	var errResp ErrorResponse
	err = json.NewDecoder(resp.Body).Decode(&errResp)
	suite.NoError(err)
	suite.Equal(ErrCodeAccountLocked, errResp.Code)
}

func (suite *AuthHandlersTestSuite) TestLogin_MFARequired() {
	app := fiber.New()
	app.Post("/auth/login", suite.handler.Login)

	reqBody := map[string]string{
		"email":    "mfa@example.com",
		"password": "CorrectPassword123!",
	}
	body, _ := json.Marshal(reqBody)

	// Mock service returns MFA code required error
	suite.mockSvc.On("Login", mock.Anything, "mfa@example.com", "CorrectPassword123!", "").
		Return((*AuthResponse)(nil), fmt.Errorf("MFA code required"))

	req := httptest.NewRequest("POST", "/auth/login", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(401, resp.StatusCode)

	var errResp ErrorResponse
	err = json.NewDecoder(resp.Body).Decode(&errResp)
	suite.NoError(err)
	suite.Equal(ErrCodeInvalidMFACode, errResp.Code)
}

// =====================================
// Test VerifyMFA Handler
// =====================================

func (suite *AuthHandlersTestSuite) TestVerifyMFA_Success() {
	app := fiber.New()
	app.Post("/auth/mfa/verify", suite.handler.VerifyMFA)

	reqBody := map[string]string{
		"session_token": "half-authed-session-token",
		"code":          "123456",
	}
	body, _ := json.Marshal(reqBody)

	expectedResponse := &AuthResponse{
		Token:   "full-jwt-token",
		UserID:  uuid.New().String(),
		IsAdmin: false,
	}
	suite.mockSvc.On("VerifyMFA", mock.Anything, "half-authed-session-token", "123456").
		Return(expectedResponse, nil)

	req := httptest.NewRequest("POST", "/auth/mfa/verify", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(200, resp.StatusCode)

	var response AuthResponse
	err = json.NewDecoder(resp.Body).Decode(&response)
	suite.NoError(err)
	suite.Equal(expectedResponse.Token, response.Token)
}

func (suite *AuthHandlersTestSuite) TestVerifyMFA_InvalidCode() {
	app := fiber.New()
	app.Post("/auth/mfa/verify", suite.handler.VerifyMFA)

	reqBody := map[string]string{
		"session_token": "half-authed-session-token",
		"code":          "wrong-code",
	}
	body, _ := json.Marshal(reqBody)

	suite.mockSvc.On("VerifyMFA", mock.Anything, "half-authed-session-token", "wrong-code").
		Return((*AuthResponse)(nil), fmt.Errorf("invalid MFA code"))

	req := httptest.NewRequest("POST", "/auth/mfa/verify", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(401, resp.StatusCode)

	var errResp ErrorResponse
	err = json.NewDecoder(resp.Body).Decode(&errResp)
	suite.NoError(err)
	suite.Equal(ErrCodeInvalidMFACode, errResp.Code)
}

func (suite *AuthHandlersTestSuite) TestVerifyMFA_ExpiredSession() {
	app := fiber.New()
	app.Post("/auth/mfa/verify", suite.handler.VerifyMFA)

	reqBody := map[string]string{
		"session_token": "expired-session-token",
		"code":          "123456",
	}
	body, _ := json.Marshal(reqBody)

	suite.mockSvc.On("VerifyMFA", mock.Anything, "expired-session-token", "123456").
		Return((*AuthResponse)(nil), fmt.Errorf("session expired"))

	req := httptest.NewRequest("POST", "/auth/mfa/verify", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(401, resp.StatusCode)

	var errResp ErrorResponse
	err = json.NewDecoder(resp.Body).Decode(&errResp)
	suite.NoError(err)
	suite.Equal(ErrCodeExpiredToken, errResp.Code)
}

// =====================================
// Test Logout Handler
// =====================================

func (suite *AuthHandlersTestSuite) TestLogout_Success() {
	app := fiber.New()
	app.Post("/auth/logout", suite.handler.Logout)

	suite.mockSvc.On("Logout", mock.Anything, "Bearer valid-jwt-token").Return(nil)

	req := httptest.NewRequest("POST", "/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer valid-jwt-token")

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(200, resp.StatusCode)

	var response map[string]string
	err = json.NewDecoder(resp.Body).Decode(&response)
	suite.NoError(err)
	suite.Equal("Successfully logged out", response["message"])
}

func (suite *AuthHandlersTestSuite) TestLogout_MissingAuthHeader() {
	app := fiber.New()
	app.Post("/auth/logout", suite.handler.Logout)

	req := httptest.NewRequest("POST", "/auth/logout", nil)
	// No Authorization header

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(401, resp.StatusCode)
}

func (suite *AuthHandlersTestSuite) TestLogout_InvalidTokenFormat() {
	app := fiber.New()
	app.Post("/auth/logout", suite.handler.Logout)

	req := httptest.NewRequest("POST", "/auth/logout", nil)
	req.Header.Set("Authorization", "InvalidFormat")

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(401, resp.StatusCode)
}

// =====================================
// Test Password Reset Flow
// =====================================

func (suite *AuthHandlersTestSuite) TestRequestPasswordReset_Success() {
	app := fiber.New()
	app.Post("/auth/password/reset", suite.handler.RequestPasswordReset)

	reqBody := map[string]string{
		"email": "test@example.com",
	}
	body, _ := json.Marshal(reqBody)

	suite.mockSvc.On("RequestPasswordReset", mock.Anything, "test@example.com").Return(nil)

	req := httptest.NewRequest("POST", "/auth/password/reset", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(200, resp.StatusCode)

	var response map[string]string
	err = json.NewDecoder(resp.Body).Decode(&response)
	suite.NoError(err)
	suite.Contains(response["message"], "reset instructions")
}

func (suite *AuthHandlersTestSuite) TestRequestPasswordReset_EmailEnumerationPrevention() {
	app := fiber.New()
	app.Post("/auth/password/reset", suite.handler.RequestPasswordReset)

	reqBody := map[string]string{
		"email": "nonexistent@example.com",
	}
	body, _ := json.Marshal(reqBody)

	// Even if service returns error (user not found), handler should return 200
	suite.mockSvc.On("RequestPasswordReset", mock.Anything, "nonexistent@example.com").
		Return(fmt.Errorf("user not found"))

	req := httptest.NewRequest("POST", "/auth/password/reset", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(200, resp.StatusCode) // Always 200 to prevent enumeration
}

func (suite *AuthHandlersTestSuite) TestVerifyResetToken_ValidToken() {
	app := fiber.New()
	app.Get("/auth/password/reset/verify", suite.handler.VerifyResetToken)

	suite.mockSvc.On("VerifyResetToken", mock.Anything, "valid-token").
		Return(uuid.New(), nil)

	req := httptest.NewRequest("GET", "/auth/password/reset/verify?token=valid-token", nil)

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(200, resp.StatusCode)

	var response map[string]bool
	err = json.NewDecoder(resp.Body).Decode(&response)
	suite.NoError(err)
	suite.True(response["valid"])
}

func (suite *AuthHandlersTestSuite) TestVerifyResetToken_InvalidToken() {
	app := fiber.New()
	app.Get("/auth/password/reset/verify", suite.handler.VerifyResetToken)

	suite.mockSvc.On("VerifyResetToken", mock.Anything, "invalid-token").
		Return(uuid.Nil, fmt.Errorf("invalid token"))

	req := httptest.NewRequest("GET", "/auth/password/reset/verify?token=invalid-token", nil)

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(400, resp.StatusCode)
}

func (suite *AuthHandlersTestSuite) TestConfirmPasswordReset_Success() {
	app := fiber.New()
	app.Post("/auth/password/reset/confirm", suite.handler.ConfirmPasswordReset)

	reqBody := map[string]string{
		"token":       "valid-reset-token",
		"newPassword": "NewSecureP@ssw0rd123!",
	}
	body, _ := json.Marshal(reqBody)

	suite.mockSvc.On("CompletePasswordReset", mock.Anything, "valid-reset-token", "NewSecureP@ssw0rd123!").
		Return(nil)

	req := httptest.NewRequest("POST", "/auth/password/reset/confirm", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(200, resp.StatusCode)
}

func (suite *AuthHandlersTestSuite) TestConfirmPasswordReset_WeakPassword() {
	app := fiber.New()
	app.Post("/auth/password/reset/confirm", suite.handler.ConfirmPasswordReset)

	reqBody := map[string]string{
		"token":       "valid-reset-token",
		"newPassword": "weak",
	}
	body, _ := json.Marshal(reqBody)

	suite.mockSvc.On("CompletePasswordReset", mock.Anything, "valid-reset-token", "weak").
		Return(fmt.Errorf("password must be at least 12 characters"))

	req := httptest.NewRequest("POST", "/auth/password/reset/confirm", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(400, resp.StatusCode)
}

// =====================================
// Test MFA Management
// =====================================

func (suite *AuthHandlersTestSuite) TestBeginMFASetup_Success() {
	app := fiber.New()
	app.Post("/auth/mfa/setup", func(c *fiber.Ctx) error {
		// Simulate authenticated user
		c.Locals("user_id", uuid.New())
		return suite.handler.BeginMFASetup(c)
	})

	setup := &MFASetupResponse{
		Secret:    "JBSWY3DPEHPK3PXP",
		QRCodeURL: "otpauth://totp/LeafLock:test@example.com?secret=JBSWY3DPEHPK3PXP&issuer=LeafLock",
	}
	suite.mockSvc.On("BeginMFASetup", mock.Anything, mock.Anything).Return(setup, nil)

	req := httptest.NewRequest("POST", "/auth/mfa/setup", nil)

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(200, resp.StatusCode)

	var response MFASetupResponse
	err = json.NewDecoder(resp.Body).Decode(&response)
	suite.NoError(err)
	suite.Equal(setup.Secret, response.Secret)
	suite.Equal(setup.QRCodeURL, response.QRCodeURL)
}

func (suite *AuthHandlersTestSuite) TestEnableMFA_Success() {
	app := fiber.New()
	app.Post("/auth/mfa/enable", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		return suite.handler.EnableMFA(c)
	})

	reqBody := map[string]string{
		"code": "123456",
	}
	body, _ := json.Marshal(reqBody)

	backupCodes := []string{"AAAA-BBBB-CCCC", "DDDD-EEEE-FFFF"}
	suite.mockSvc.On("EnableMFA", mock.Anything, mock.Anything, "123456").Return(backupCodes, nil)

	req := httptest.NewRequest("POST", "/auth/mfa/enable", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(200, resp.StatusCode)

	var response map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&response)
	suite.NoError(err)
	suite.True(response["enabled"].(bool))
}

func (suite *AuthHandlersTestSuite) TestDisableMFA_Success() {
	app := fiber.New()
	app.Post("/auth/mfa/disable", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		return suite.handler.DisableMFA(c)
	})

	reqBody := map[string]string{
		"code": "123456",
	}
	body, _ := json.Marshal(reqBody)

	suite.mockSvc.On("DisableMFA", mock.Anything, mock.Anything, "123456").Return(nil)

	req := httptest.NewRequest("POST", "/auth/mfa/disable", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(200, resp.StatusCode)
}

// =====================================
// Helper Functions and Mocks
// =====================================

// containsHandlers checks if string contains substring
func containsHandlers(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && (s[:len(substr)] == substr || containsHandlers(s[1:], substr))))
}

// MockAuthService mocks the auth Service
type MockAuthService struct {
	mock.Mock
	service *Service
}

func (m *MockAuthService) Register(ctx context.Context, email, password string) (*AuthResponse, error) {
	args := m.Called(ctx, email, password)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*AuthResponse), args.Error(1)
}

func (m *MockAuthService) Login(ctx context.Context, email, password, mfaCode string) (*AuthResponse, error) {
	args := m.Called(ctx, email, password, mfaCode)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*AuthResponse), args.Error(1)
}

func (m *MockAuthService) VerifyMFA(ctx context.Context, sessionToken, code string) (*AuthResponse, error) {
	args := m.Called(ctx, sessionToken, code)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*AuthResponse), args.Error(1)
}

func (m *MockAuthService) Logout(ctx context.Context, token string) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}

func (m *MockAuthService) BeginMFASetup(ctx context.Context, userID uuid.UUID) (*MFASetupResponse, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*MFASetupResponse), args.Error(1)
}

func (m *MockAuthService) EnableMFA(ctx context.Context, userID uuid.UUID, code string) ([]string, error) {
	args := m.Called(ctx, userID, code)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]string), args.Error(1)
}

func (m *MockAuthService) DisableMFA(ctx context.Context, userID uuid.UUID, code string) error {
	args := m.Called(ctx, userID, code)
	return args.Error(0)
}

func (m *MockAuthService) RequestPasswordReset(ctx context.Context, email string) error {
	args := m.Called(ctx, email)
	return args.Error(0)
}

func (m *MockAuthService) VerifyResetToken(ctx context.Context, token string) (uuid.UUID, error) {
	args := m.Called(ctx, token)
	return args.Get(0).(uuid.UUID), args.Error(1)
}

func (m *MockAuthService) CompletePasswordReset(ctx context.Context, token, newPassword string) error {
	args := m.Called(ctx, token, newPassword)
	return args.Error(0)
}

func (m *MockAuthService) QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row {
	callArgs := append([]interface{}{ctx, sql}, args...)
	mockArgs := m.Called(callArgs...)
	return mockArgs.Get(0).(pgx.Row)
}

// MockHandlerRow mocks pgx.Row for handlers tests
type MockHandlerRow struct {
	mock.Mock
}

func (m *MockHandlerRow) Scan(dest ...interface{}) error {
	args := m.Called(dest...)
	return args.Error(0)
}
