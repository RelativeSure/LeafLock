package auth

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// AuthMiddlewareTestSuite tests auth middleware
type AuthMiddlewareTestSuite struct {
	suite.Suite
	handler     *TestableHandler
	mockService *MockMiddlewareService
	validToken  string
	validUserID uuid.UUID
}

func (suite *AuthMiddlewareTestSuite) SetupTest() {
	suite.mockService = &MockMiddlewareService{}
	suite.handler = &TestableHandler{
		validator: suite.mockService,
	}
	suite.validToken = "valid-jwt-token-123"
	suite.validUserID = uuid.New()
}

// TestableHandler wraps Handler with injectable validator
type TestableHandler struct {
	validator JWTValidator
}

// JWTValidator interface for testing
type JWTValidator interface {
	ValidateJWT(token string) (uuid.UUID, bool, error)
}

// Middleware methods for TestableHandler (copy from Handler with validator injection)
func (h *TestableHandler) JWTMiddleware(c *fiber.Ctx) error {
	authHeader := c.Get("Authorization")
	if authHeader == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(ErrorResponse{
			Error: "No authorization token provided",
			Code:  ErrCodeInvalidToken,
		})
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return c.Status(fiber.StatusUnauthorized).JSON(ErrorResponse{
			Error: "Invalid authorization format",
			Code:  ErrCodeInvalidToken,
		})
	}

	token := parts[1]
	userID, isAdmin, err := h.validator.ValidateJWT(token)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(ErrorResponse{
			Error: "Invalid or expired token",
			Code:  ErrCodeInvalidToken,
		})
	}

	c.Locals("user_id", userID)
	c.Locals("is_admin", isAdmin)
	c.Locals("token", token)

	return c.Next()
}

func (h *TestableHandler) OptionalJWTMiddleware(c *fiber.Ctx) error {
	authHeader := c.Get("Authorization")
	if authHeader == "" {
		return c.Next()
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return c.Next()
	}

	token := parts[1]
	userID, isAdmin, err := h.validator.ValidateJWT(token)
	if err != nil {
		return c.Next()
	}

	c.Locals("user_id", userID)
	c.Locals("is_admin", isAdmin)
	c.Locals("token", token)

	return c.Next()
}

func (h *TestableHandler) RequireAuthMiddleware(c *fiber.Ctx) error {
	userID := c.Locals("user_id")
	if userID == nil {
		return c.Status(fiber.StatusUnauthorized).JSON(ErrorResponse{
			Error: "Authentication required",
			Code:  ErrCodeInvalidToken,
		})
	}
	return c.Next()
}

func (h *TestableHandler) RequireAdminMiddleware(c *fiber.Ctx) error {
	isAdmin, ok := c.Locals("is_admin").(bool)
	if !ok || !isAdmin {
		return c.Status(fiber.StatusForbidden).JSON(ErrorResponse{
			Error: "Admin access required",
			Code:  "FORBIDDEN",
		})
	}
	return c.Next()
}

func TestAuthMiddlewareTestSuite(t *testing.T) {
	suite.Run(t, new(AuthMiddlewareTestSuite))
}

// =====================================
// Test JWTMiddleware
// =====================================

func (suite *AuthMiddlewareTestSuite) TestJWTMiddleware_ValidToken() {
	app := fiber.New()

	app.Use(suite.handler.JWTMiddleware)
	app.Get("/protected", func(c *fiber.Ctx) error {
		userID := c.Locals("user_id").(uuid.UUID)
		isAdmin := c.Locals("is_admin").(bool)
		token := c.Locals("token").(string)

		return c.JSON(fiber.Map{
			"user_id":  userID.String(),
			"is_admin": isAdmin,
			"token":    token,
		})
	})

	suite.mockService.On("ValidateJWT", suite.validToken).Return(suite.validUserID, false, nil)

	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+suite.validToken)

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(200, resp.StatusCode)
}

func (suite *AuthMiddlewareTestSuite) TestJWTMiddleware_ValidTokenAdmin() {
	app := fiber.New()

	app.Use(suite.handler.JWTMiddleware)
	app.Get("/protected", func(c *fiber.Ctx) error {
		isAdmin := c.Locals("is_admin").(bool)
		return c.JSON(fiber.Map{"is_admin": isAdmin})
	})

	suite.mockService.On("ValidateJWT", suite.validToken).Return(suite.validUserID, true, nil)

	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+suite.validToken)

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(200, resp.StatusCode)
}

func (suite *AuthMiddlewareTestSuite) TestJWTMiddleware_MissingAuthHeader() {
	app := fiber.New()
	app.Use(suite.handler.JWTMiddleware)
	app.Get("/protected", func(c *fiber.Ctx) error {
		return c.SendString("OK")
	})

	req := httptest.NewRequest("GET", "/protected", nil)
	// No Authorization header

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(401, resp.StatusCode)
}

func (suite *AuthMiddlewareTestSuite) TestJWTMiddleware_InvalidAuthFormat_NoBearer() {
	app := fiber.New()
	app.Use(suite.handler.JWTMiddleware)
	app.Get("/protected", func(c *fiber.Ctx) error {
		return c.SendString("OK")
	})

	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "InvalidFormat token123")

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(401, resp.StatusCode)
}

func (suite *AuthMiddlewareTestSuite) TestJWTMiddleware_InvalidAuthFormat_TokenOnly() {
	app := fiber.New()
	app.Use(suite.handler.JWTMiddleware)
	app.Get("/protected", func(c *fiber.Ctx) error {
		return c.SendString("OK")
	})

	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "token-without-bearer")

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(401, resp.StatusCode)
}

func (suite *AuthMiddlewareTestSuite) TestJWTMiddleware_ExpiredToken() {
	app := fiber.New()
	app.Use(suite.handler.JWTMiddleware)
	app.Get("/protected", func(c *fiber.Ctx) error {
		return c.SendString("OK")
	})

	expiredToken := "expired-jwt-token"
	suite.mockService.On("ValidateJWT", expiredToken).Return(uuid.Nil, false, fmt.Errorf("token expired"))

	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+expiredToken)

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(401, resp.StatusCode)
}

func (suite *AuthMiddlewareTestSuite) TestJWTMiddleware_InvalidToken() {
	app := fiber.New()
	app.Use(suite.handler.JWTMiddleware)
	app.Get("/protected", func(c *fiber.Ctx) error {
		return c.SendString("OK")
	})

	invalidToken := "invalid-jwt-token"
	suite.mockService.On("ValidateJWT", invalidToken).Return(uuid.Nil, false, fmt.Errorf("invalid token"))

	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+invalidToken)

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(401, resp.StatusCode)
}

// =====================================
// Test OptionalJWTMiddleware
// =====================================

func (suite *AuthMiddlewareTestSuite) TestOptionalJWTMiddleware_ValidToken() {
	app := fiber.New()

	app.Use(suite.handler.OptionalJWTMiddleware)
	app.Get("/public", func(c *fiber.Ctx) error {
		userID := c.Locals("user_id")
		if userID != nil {
			return c.JSON(fiber.Map{"authenticated": true})
		}
		return c.JSON(fiber.Map{"authenticated": false})
	})

	suite.mockService.On("ValidateJWT", suite.validToken).Return(suite.validUserID, false, nil)

	req := httptest.NewRequest("GET", "/public", nil)
	req.Header.Set("Authorization", "Bearer "+suite.validToken)

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(200, resp.StatusCode)
}

func (suite *AuthMiddlewareTestSuite) TestOptionalJWTMiddleware_NoToken() {
	app := fiber.New()

	app.Use(suite.handler.OptionalJWTMiddleware)
	app.Get("/public", func(c *fiber.Ctx) error {
		userID := c.Locals("user_id")
		return c.JSON(fiber.Map{"authenticated": userID != nil})
	})

	req := httptest.NewRequest("GET", "/public", nil)
	// No Authorization header

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(200, resp.StatusCode) // Should continue without auth
}

func (suite *AuthMiddlewareTestSuite) TestOptionalJWTMiddleware_InvalidFormat() {
	app := fiber.New()

	app.Use(suite.handler.OptionalJWTMiddleware)
	app.Get("/public", func(c *fiber.Ctx) error {
		userID := c.Locals("user_id")
		return c.JSON(fiber.Map{"authenticated": userID != nil})
	})

	req := httptest.NewRequest("GET", "/public", nil)
	req.Header.Set("Authorization", "InvalidFormat")

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(200, resp.StatusCode) // Should continue without auth
}

func (suite *AuthMiddlewareTestSuite) TestOptionalJWTMiddleware_InvalidToken() {
	app := fiber.New()

	app.Use(suite.handler.OptionalJWTMiddleware)
	app.Get("/public", func(c *fiber.Ctx) error {
		userID := c.Locals("user_id")
		return c.JSON(fiber.Map{"authenticated": userID != nil})
	})

	invalidToken := "invalid-token"
	suite.mockService.On("ValidateJWT", invalidToken).Return(uuid.Nil, false, fmt.Errorf("invalid"))

	req := httptest.NewRequest("GET", "/public", nil)
	req.Header.Set("Authorization", "Bearer "+invalidToken)

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(200, resp.StatusCode) // Should continue without auth
}

// =====================================
// Test RequireAuthMiddleware
// =====================================

func (suite *AuthMiddlewareTestSuite) TestRequireAuthMiddleware_Authenticated() {
	app := fiber.New()

	app.Use(func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.validUserID)
		return c.Next()
	})
	app.Use(suite.handler.RequireAuthMiddleware)
	app.Get("/protected", func(c *fiber.Ctx) error {
		return c.SendString("OK")
	})

	req := httptest.NewRequest("GET", "/protected", nil)

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(200, resp.StatusCode)
}

func (suite *AuthMiddlewareTestSuite) TestRequireAuthMiddleware_NotAuthenticated() {
	app := fiber.New()

	app.Use(suite.handler.RequireAuthMiddleware)
	app.Get("/protected", func(c *fiber.Ctx) error {
		return c.SendString("OK")
	})

	req := httptest.NewRequest("GET", "/protected", nil)
	// No user_id in context

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(401, resp.StatusCode)
}

func (suite *AuthMiddlewareTestSuite) TestRequireAuthMiddleware_NilUserID() {
	app := fiber.New()

	app.Use(func(c *fiber.Ctx) error {
		c.Locals("user_id", nil) // Explicitly set to nil
		return c.Next()
	})
	app.Use(suite.handler.RequireAuthMiddleware)
	app.Get("/protected", func(c *fiber.Ctx) error {
		return c.SendString("OK")
	})

	req := httptest.NewRequest("GET", "/protected", nil)

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(401, resp.StatusCode)
}

// =====================================
// Test RequireAdminMiddleware
// =====================================

func (suite *AuthMiddlewareTestSuite) TestRequireAdminMiddleware_IsAdmin() {
	app := fiber.New()

	app.Use(func(c *fiber.Ctx) error {
		c.Locals("is_admin", true)
		return c.Next()
	})
	app.Use(suite.handler.RequireAdminMiddleware)
	app.Get("/admin", func(c *fiber.Ctx) error {
		return c.SendString("Admin OK")
	})

	req := httptest.NewRequest("GET", "/admin", nil)

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(200, resp.StatusCode)
}

func (suite *AuthMiddlewareTestSuite) TestRequireAdminMiddleware_NotAdmin() {
	app := fiber.New()

	app.Use(func(c *fiber.Ctx) error {
		c.Locals("is_admin", false)
		return c.Next()
	})
	app.Use(suite.handler.RequireAdminMiddleware)
	app.Get("/admin", func(c *fiber.Ctx) error {
		return c.SendString("Admin OK")
	})

	req := httptest.NewRequest("GET", "/admin", nil)

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(403, resp.StatusCode)
}

func (suite *AuthMiddlewareTestSuite) TestRequireAdminMiddleware_MissingIsAdmin() {
	app := fiber.New()

	app.Use(suite.handler.RequireAdminMiddleware)
	app.Get("/admin", func(c *fiber.Ctx) error {
		return c.SendString("Admin OK")
	})

	req := httptest.NewRequest("GET", "/admin", nil)
	// No is_admin in context

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(403, resp.StatusCode)
}

func (suite *AuthMiddlewareTestSuite) TestRequireAdminMiddleware_InvalidType() {
	app := fiber.New()

	app.Use(func(c *fiber.Ctx) error {
		c.Locals("is_admin", "not-a-bool") // Wrong type
		return c.Next()
	})
	app.Use(suite.handler.RequireAdminMiddleware)
	app.Get("/admin", func(c *fiber.Ctx) error {
		return c.SendString("Admin OK")
	})

	req := httptest.NewRequest("GET", "/admin", nil)

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(403, resp.StatusCode)
}

// =====================================
// Test GetUserID Helper
// =====================================

func (suite *AuthMiddlewareTestSuite) TestGetUserID_ValidUserID() {
	app := fiber.New()
	app.Get("/test", func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.validUserID)
		userID, err := GetUserID(c)
		assert.NoError(suite.T(), err)
		assert.Equal(suite.T(), suite.validUserID, userID)
		return c.SendString("OK")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(200, resp.StatusCode)
}

func (suite *AuthMiddlewareTestSuite) TestGetUserID_MissingUserID() {
	app := fiber.New()
	app.Get("/test", func(c *fiber.Ctx) error {
		userID, err := GetUserID(c)
		assert.Error(suite.T(), err)
		assert.Equal(suite.T(), uuid.Nil, userID)
		assert.Contains(suite.T(), err.Error(), "not authenticated")
		return c.SendString("OK")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(200, resp.StatusCode)
}

func (suite *AuthMiddlewareTestSuite) TestGetUserID_InvalidType() {
	app := fiber.New()
	app.Get("/test", func(c *fiber.Ctx) error {
		c.Locals("user_id", "not-a-uuid") // Wrong type
		userID, err := GetUserID(c)
		assert.Error(suite.T(), err)
		assert.Equal(suite.T(), uuid.Nil, userID)
		return c.SendString("OK")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(200, resp.StatusCode)
}

func (suite *AuthMiddlewareTestSuite) TestGetUserID_NilValue() {
	app := fiber.New()
	app.Get("/test", func(c *fiber.Ctx) error {
		c.Locals("user_id", nil)
		userID, err := GetUserID(c)
		assert.Error(suite.T(), err)
		assert.Equal(suite.T(), uuid.Nil, userID)
		return c.SendString("OK")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(200, resp.StatusCode)
}

// =====================================
// Test IsAdmin Helper
// =====================================

func (suite *AuthMiddlewareTestSuite) TestIsAdmin_True() {
	app := fiber.New()
	app.Get("/test", func(c *fiber.Ctx) error {
		c.Locals("is_admin", true)
		result := IsAdmin(c)
		assert.True(suite.T(), result)
		return c.SendString("OK")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(200, resp.StatusCode)
}

func (suite *AuthMiddlewareTestSuite) TestIsAdmin_False() {
	app := fiber.New()
	app.Get("/test", func(c *fiber.Ctx) error {
		c.Locals("is_admin", false)
		result := IsAdmin(c)
		assert.False(suite.T(), result)
		return c.SendString("OK")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(200, resp.StatusCode)
}

func (suite *AuthMiddlewareTestSuite) TestIsAdmin_Missing() {
	app := fiber.New()
	app.Get("/test", func(c *fiber.Ctx) error {
		result := IsAdmin(c)
		assert.False(suite.T(), result)
		return c.SendString("OK")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(200, resp.StatusCode)
}

func (suite *AuthMiddlewareTestSuite) TestIsAdmin_InvalidType() {
	app := fiber.New()
	app.Get("/test", func(c *fiber.Ctx) error {
		c.Locals("is_admin", "not-a-bool")
		result := IsAdmin(c)
		assert.False(suite.T(), result)
		return c.SendString("OK")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(200, resp.StatusCode)
}

// =====================================
// Test Middleware Chain
// =====================================

func (suite *AuthMiddlewareTestSuite) TestMiddlewareChain_JWTThenRequireAuth() {
	app := fiber.New()

	app.Use(suite.handler.JWTMiddleware)
	app.Use(suite.handler.RequireAuthMiddleware)
	app.Get("/protected", func(c *fiber.Ctx) error {
		return c.SendString("OK")
	})

	suite.mockService.On("ValidateJWT", suite.validToken).Return(suite.validUserID, false, nil)

	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+suite.validToken)

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(200, resp.StatusCode)
}

func (suite *AuthMiddlewareTestSuite) TestMiddlewareChain_JWTThenRequireAdmin() {
	app := fiber.New()

	app.Use(suite.handler.JWTMiddleware)
	app.Use(suite.handler.RequireAdminMiddleware)
	app.Get("/admin", func(c *fiber.Ctx) error {
		return c.SendString("Admin OK")
	})

	suite.mockService.On("ValidateJWT", suite.validToken).Return(suite.validUserID, true, nil)

	req := httptest.NewRequest("GET", "/admin", nil)
	req.Header.Set("Authorization", "Bearer "+suite.validToken)

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(200, resp.StatusCode)
}

func (suite *AuthMiddlewareTestSuite) TestMiddlewareChain_NonAdminAccessingAdminRoute() {
	app := fiber.New()

	app.Use(suite.handler.JWTMiddleware)
	app.Use(suite.handler.RequireAdminMiddleware)
	app.Get("/admin", func(c *fiber.Ctx) error {
		return c.SendString("Admin OK")
	})

	suite.mockService.On("ValidateJWT", suite.validToken).Return(suite.validUserID, false, nil) // Not admin

	req := httptest.NewRequest("GET", "/admin", nil)
	req.Header.Set("Authorization", "Bearer "+suite.validToken)

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(403, resp.StatusCode) // Forbidden
}

// =====================================
// Mock Service
// =====================================

type MockMiddlewareService struct {
	mock.Mock
}

func (m *MockMiddlewareService) ValidateJWT(token string) (uuid.UUID, bool, error) {
	args := m.Called(token)
	return args.Get(0).(uuid.UUID), args.Bool(1), args.Error(2)
}

func TestHandlerJWTMiddlewareValidToken(t *testing.T) {
	handler, userID, token := createHandlerWithToken(t, true)

	app := fiber.New()
	app.Use(handler.JWTMiddleware)
	app.Get("/protected", func(c *fiber.Ctx) error {
		require.Equal(t, userID, c.Locals("user_id"))
		isAdmin, _ := c.Locals("is_admin").(bool)
		require.True(t, isAdmin)
		return c.SendStatus(fiber.StatusNoContent)
	})

	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	require.Equal(t, fiber.StatusNoContent, resp.StatusCode)
}

func TestHandlerJWTMiddlewareInvalidToken(t *testing.T) {
	handler, _, _ := createHandlerWithToken(t, false)

	app := fiber.New()
	app.Use(handler.JWTMiddleware)
	app.Get("/protected", func(c *fiber.Ctx) error {
		t.Fatal("handler should not be reached with invalid token")
		return nil
	})

	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer not-a-jwt")
	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	require.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
}

func TestHandlerOptionalJWTMiddleware(t *testing.T) {
	handler, userID, token := createHandlerWithToken(t, false)

	t.Run("valid token sets locals", func(t *testing.T) {
		app := fiber.New()
		app.Use(handler.OptionalJWTMiddleware)
		app.Get("/optional", func(c *fiber.Ctx) error {
			require.Equal(t, userID, c.Locals("user_id"))
			return c.SendStatus(fiber.StatusOK)
		})

		req := httptest.NewRequest("GET", "/optional", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		require.Equal(t, fiber.StatusOK, resp.StatusCode)
	})

	t.Run("invalid token passes without locals", func(t *testing.T) {
		app := fiber.New()
		app.Use(handler.OptionalJWTMiddleware)
		app.Get("/optional", func(c *fiber.Ctx) error {
			require.Nil(t, c.Locals("user_id"))
			return c.SendStatus(fiber.StatusOK)
		})

		req := httptest.NewRequest("GET", "/optional", nil)
		req.Header.Set("Authorization", "Bearer invalid")
		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		require.Equal(t, fiber.StatusOK, resp.StatusCode)
	})
}

func TestHandlerRequireAuthMiddleware(t *testing.T) {
	handler, userID, _ := createHandlerWithToken(t, false)

	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		c.Locals("user_id", userID)
		return handler.RequireAuthMiddleware(c)
	})
	app.Get("/protected", func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	resp, err := app.Test(httptest.NewRequest("GET", "/protected", nil), -1)
	require.NoError(t, err)
	require.Equal(t, fiber.StatusOK, resp.StatusCode)

	appMissing := fiber.New()
	appMissing.Use(handler.RequireAuthMiddleware)
	appMissing.Get("/protected", func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	respMissing, err := appMissing.Test(httptest.NewRequest("GET", "/protected", nil), -1)
	require.NoError(t, err)
	require.Equal(t, fiber.StatusUnauthorized, respMissing.StatusCode)
}

func TestHandlerRequireAdminMiddleware(t *testing.T) {
	handler, _, _ := createHandlerWithToken(t, true)

	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		c.Locals("is_admin", true)
		return handler.RequireAdminMiddleware(c)
	})
	app.Get("/admin", func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	resp, err := app.Test(httptest.NewRequest("GET", "/admin", nil), -1)
	require.NoError(t, err)
	require.Equal(t, fiber.StatusOK, resp.StatusCode)

	appForbidden := fiber.New()
	appForbidden.Use(handler.RequireAdminMiddleware)
	appForbidden.Get("/admin", func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	respForbidden, err := appForbidden.Test(httptest.NewRequest("GET", "/admin", nil), -1)
	require.NoError(t, err)
	require.Equal(t, fiber.StatusForbidden, respForbidden.StatusCode)
}

func createHandlerWithToken(t *testing.T, isAdmin bool) (*Handler, uuid.UUID, string) {
	t.Helper()
	svc := &Service{jwtSecret: "unit-test-secret"}
	userID := uuid.New()
	token, err := svc.GenerateJWT(userID, isAdmin)
	require.NoError(t, err)
	return &Handler{service: svc}, userID, token
}
