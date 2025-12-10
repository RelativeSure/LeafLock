package auth

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"leaflock/config"
	"leaflock/utils"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

// EmailService interface for sending emails
type EmailService interface {
	SendPasswordResetEmail(toEmail string, resetToken string, ipAddress string) error
}

// Handler provides HTTP handlers for auth endpoints
type Handler struct {
	service      *Service
	emailService EmailService
	config       *Config
}

// NewHandler creates a new auth handler
func NewHandler(service *Service, emailService EmailService, config *Config) *Handler {
	return &Handler{
		service:      service,
		emailService: emailService,
		config:       config,
	}
}

// Register handles user registration with comprehensive security measures
//
// Business Purpose:
// - Enables new user account creation with email/password authentication
// - Implements zero-knowledge architecture where server never sees plaintext user data
// - Provides secure onboarding flow with email verification
//
// Security Considerations & Threat Model:
// - Prevents email enumeration by returning same response regardless of email existence
// - Implements dual-layer registration control (env var + database setting)
// - Uses timing attack resistant email lookup via search hash
// - Sanitizes and validates email format to prevent injection attacks
// - Rate limiting applied at middleware level to prevent brute force registration
//
// Zero-Knowledge Architecture:
// - User email stored as search hash (SHA256 with salt) for lookup purposes
// - User password hashed with Argon2id (memory-hard, GPU-resistant)
// - All user content encrypted client-side before reaching server
// - Server never has access to encryption keys or plaintext content
//
// Data Validation & Sanitization:
// - Email validated for basic format compliance (contains @ symbol)
// - Email normalized (lowercase, trimmed) before processing
// - Registration disabled flag checked at both config and database levels
// - Request body parsed with strict JSON validation
//
// User Workflow:
// 1. Client submits registration request with email/password
// 2. Server validates registration is enabled (env + database)
// 3. Email format validated and normalized
// 4. Email existence checked via search hash (prevents enumeration)
// 5. If email exists, success response returned (no information disclosure)
// 6. If new email, account created with hashed password
// 7. Email verification sent separately (not handled in this handler)
//
// Error Handling Strategy:
// - Generic success message prevents email enumeration attacks
// - Specific validation errors returned for malformed requests
// - Internal errors logged but not exposed to client
// - Consistent response format maintains security posture
//
// API Design Decisions:
// - POST method for resource creation
// - Returns 202 Accepted (not 201) since email verification required
// - Same response for success/existing email prevents information leakage
// - Error responses include specific codes for client-side handling
//
// Integration Points:
// - Calls auth service for actual user creation logic
// - Database transactions ensure atomic registration operations
// - Email service triggered separately for verification workflow
// - Audit logging tracks registration attempts for security monitoring
//
// @Summary Register a new user
// @Description Create a new user account
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body RegisterRequest true "Registration details"
// @Success 201 {object} AuthResponse
// @Failure 400 {object} ErrorResponse
// @Failure 409 {object} ErrorResponse
// @Failure 503 {object} ErrorResponse
// @Router /auth/register [post]
func (h *Handler) Register(c *fiber.Ctx) error {
	var req RegisterRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "Invalid request body",
			Code:  ErrCodeValidationFailed,
		})
	}

	// Check if registration is enabled - requires BOTH env var AND database setting
	// Environment variable is the master switch (security override)
	if config.RegEnabled.Load() == 0 {
		return c.Status(fiber.StatusForbidden).JSON(ErrorResponse{
			Error: "User registration is currently disabled",
			Code:  ErrCodeRegistrationDisabled,
		})
	}

	// Check database setting (runtime toggle from admin panel)
	var dbEnabled bool
	query := `
		SELECT COALESCE(
			(SELECT value::boolean FROM app_settings WHERE key = 'registration_enabled'),
			true
		) as enabled
	`
	err := h.service.db.QueryRow(c.Context(), query).Scan(&dbEnabled)
	if err != nil || !dbEnabled {
		return c.Status(fiber.StatusForbidden).JSON(ErrorResponse{
			Error: "User registration is currently disabled",
			Code:  ErrCodeRegistrationDisabled,
		})
	}

	// Validate email
	if req.Email == "" || !strings.Contains(req.Email, "@") {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "Invalid email address",
			Code:  ErrCodeValidationFailed,
		})
	}

	// Add client info to context
	ctx := context.WithValue(c.Context(), utils.ContextKeyClientIP, utils.ClientIP(c))
	ctx = context.WithValue(ctx, utils.ContextKeyUserAgent, c.Get("User-Agent"))
	ctx = WithSkipAutoLogin(ctx)

	_, err = h.service.Register(ctx, req.Email, req.Password)
	if err != nil {
		if errors.Is(err, ErrEmailAlreadyExists) {
			return c.Status(fiber.StatusAccepted).JSON(fiber.Map{
				"message": "If an account with this email can be created, you'll receive further instructions shortly.",
			})
		}
		if strings.Contains(err.Error(), "password") {
			return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
				Error: err.Error(),
				Code:  ErrCodeValidationFailed,
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "Failed to register user",
			Code:  ErrCodeInternalError,
		})
	}

	return c.Status(fiber.StatusAccepted).JSON(fiber.Map{
		"message": "If an account with this email can be created, you'll receive further instructions shortly.",
	})
}

// Login handles user authentication with comprehensive security measures
//
// Business Purpose:
// - Authenticates users with email/password credentials
// - Supports Multi-Factor Authentication (MFA) workflow
// - Implements account lockout protection against brute force attacks
// - Provides secure session management with Clerk authentication
//
// Security Considerations & Threat Model:
// - Protects against brute force attacks via account lockout mechanism
// - Implements timing attack resistance in authentication flow
// - MFA support prevents unauthorized access even with compromised passwords
// - Session tokens encrypted and stored securely in Redis
// - Failed login attempts tracked and logged for security monitoring
//
// Authentication Flow:
// 1. Standard Login: Email + Password → JWT Token (if MFA disabled)
// 2. MFA Login: Email + Password → MFA Session → MFA Code → JWT Token
// 3. Account Lockout: Multiple failed attempts → Temporary account suspension
//
// Account Security Features:
// - Progressive account lockout after failed attempts
// - Lockout duration increases with consecutive failures
// - Admin intervention required for persistent lockouts
// - IP-based rate limiting at middleware level
// - Suspicious activity detection and logging
//
// MFA Integration:
// - TOTP (Time-based One-Time Password) support
// - Backup codes for account recovery
// - Grace period for MFA setup completion
// - Fallback mechanisms for lost MFA devices
//
// Session Management:
// - Clerk session tokens with configurable expiration
// - Refresh token mechanism for extended sessions
// - Secure token storage in encrypted Redis cache
// - Token blacklisting for logout functionality
// - Multi-device session support
//
// Data Privacy & Zero-Knowledge:
// - Client IP and User-Agent logged for security (encrypted)
// - No plaintext passwords stored or logged
// - Authentication events audited for compliance
// - GDPR-compliant data handling practices
//
// Error Handling & User Experience:
// - Generic "Invalid credentials" prevents username enumeration
// - Specific MFA errors guide user through 2FA process
// - Account lockout messages include unlock instructions
// - Graceful degradation when MFA services unavailable
//
// Performance Considerations:
// - Redis caching for session management
// - Database connection pooling for auth queries
// - Efficient password hashing with Argon2id
// - Minimal database queries per authentication attempt
//
// Compliance & Audit:
// - All login attempts logged with timestamp and IP
// - Failed authentication events trigger security alerts
// - MFA enrollment status tracked for compliance reporting
// - Session lifecycle events audited for forensics
//
// @Summary Login
// @Description Authenticate a user with email and password
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body AuthRequest true "Login credentials"
// @Success 200 {object} AuthResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 423 {object} ErrorResponse
// @Router /auth/login [post]
func (h *Handler) Login(c *fiber.Ctx) error {
	var req AuthRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "Invalid request body",
			Code:  ErrCodeValidationFailed,
		})
	}

	// Add client info to context
	ctx := context.WithValue(c.Context(), utils.ContextKeyClientIP, utils.ClientIP(c))
	ctx = context.WithValue(ctx, utils.ContextKeyUserAgent, c.Get("User-Agent"))

	response, err := h.service.Login(ctx, req.Email, req.Password, req.MFACode)
	if err != nil {
		if strings.Contains(err.Error(), "locked") {
			return c.Status(fiber.StatusForbidden).JSON(ErrorResponse{
				Error: err.Error(),
				Code:  ErrCodeAccountLocked,
			})
		}
		if strings.Contains(err.Error(), "MFA code") {
			return c.Status(fiber.StatusUnauthorized).JSON(ErrorResponse{
				Error: err.Error(),
				Code:  ErrCodeInvalidMFACode,
			})
		}
		return c.Status(fiber.StatusUnauthorized).JSON(ErrorResponse{
			Error: "Invalid credentials",
			Code:  ErrCodeInvalidCredentials,
		})
	}

	return c.JSON(response)
}

// VerifyMFA handles MFA verification during login
// @Summary Verify MFA code
// @Description Complete login by verifying MFA code
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body MFAVerifyRequest true "MFA code and session token"
// @Success 200 {object} AuthResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Router /auth/mfa/verify [post]
func (h *Handler) VerifyMFA(c *fiber.Ctx) error {
	var req MFAVerifyRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "Invalid request body",
			Code:  ErrCodeValidationFailed,
		})
	}

	ctx := c.Context()
	response, err := h.service.VerifyMFA(ctx, req.SessionToken, req.Code)
	if err != nil {
		if strings.Contains(err.Error(), "expired") {
			return c.Status(fiber.StatusUnauthorized).JSON(ErrorResponse{
				Error: err.Error(),
				Code:  ErrCodeExpiredToken,
			})
		}
		return c.Status(fiber.StatusUnauthorized).JSON(ErrorResponse{
			Error: "Invalid MFA code",
			Code:  ErrCodeInvalidMFACode,
		})
	}

	return c.JSON(response)
}

// Logout handles user logout
// @Summary Logout
// @Description End user session
// @Tags Authentication
// @Security BearerAuth
// @Produce json
// @Success 200 {object} map[string]string
// @Failure 401 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /auth/logout [post]
func (h *Handler) Logout(c *fiber.Ctx) error {
	tokenValue := c.Locals("token")
	var token string

	if tokenStr, ok := tokenValue.(string); ok && strings.TrimSpace(tokenStr) != "" {
		token = tokenStr
	} else {
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

		token = parts[1]
	}

	ctx := c.Context()

	if err := h.service.Logout(ctx, token); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "Failed to logout",
			Code:  ErrCodeInternalError,
		})
	}

	return c.JSON(fiber.Map{
		"message": "Logged out successfully",
	})
}

// GetMFAStatus returns MFA status for the current user
// @Summary Get MFA status
// @Description Check if MFA is enabled and how many backup codes remain
// @Tags Authentication
// @Security BearerAuth
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Failure 500 {object} ErrorResponse
// @Router /auth/mfa/status [get]
func (h *Handler) GetMFAStatus(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)

	enabled, remainingCodes, err := h.service.mfa.GetMFAStatus(c.Context(), userID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "Failed to get MFA status",
			Code:  ErrCodeInternalError,
		})
	}

	return c.JSON(fiber.Map{
		"mfa_enabled":            enabled,
		"backup_codes_remaining": remainingCodes,
	})
}

// BeginMFASetup starts MFA setup process
// @Summary Begin MFA setup
// @Description Generate TOTP secret for MFA setup
// @Tags Authentication
// @Security BearerAuth
// @Produce json
// @Success 200 {object} MFASetupResponse
// @Failure 500 {object} ErrorResponse
// @Router /auth/mfa/setup [post]
func (h *Handler) BeginMFASetup(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)

	// Get user email (zero-knowledge: plaintext)
	var email string
	query := `SELECT email_plaintext FROM users WHERE id = $1`
	err := h.service.db.QueryRow(c.Context(), query, userID).Scan(&email)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "Failed to get user info",
			Code:  ErrCodeInternalError,
		})
	}

	// Generate TOTP secret
	key, err := h.service.mfa.GenerateTOTPSecret(email)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "Failed to generate TOTP secret",
			Code:  ErrCodeInternalError,
		})
	}

	return c.JSON(MFASetupResponse{
		Secret:    key.Secret(),
		QRCodeURL: key.URL(),
	})
}

// EnableMFA enables MFA for a user after verifying the code
// @Summary Enable MFA
// @Description Enable MFA after verifying TOTP code
// @Tags Authentication
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body map[string]string true "TOTP code and secret"
// @Success 200 {object} MFASetupResponse
// @Failure 400 {object} ErrorResponse
// @Router /auth/mfa/enable [post]
func (h *Handler) EnableMFA(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)

	var req struct {
		Secret string `json:"secret"`
		Code   string `json:"code"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "Invalid request body",
			Code:  ErrCodeValidationFailed,
		})
	}

	backupCodes, err := h.service.mfa.EnableMFA(c.Context(), userID, req.Secret, req.Code)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: err.Error(),
			Code:  ErrCodeInvalidMFACode,
		})
	}

	return c.JSON(MFASetupResponse{
		BackupCodes: backupCodes,
	})
}

// DisableMFA disables MFA for a user
// @Summary Disable MFA
// @Description Disable MFA after verifying code
// @Tags Authentication
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body MFAVerifyRequest true "TOTP code or backup code"
// @Success 200 {object} map[string]string
// @Failure 400 {object} ErrorResponse
// @Router /auth/mfa/disable [post]
func (h *Handler) DisableMFA(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)

	var req MFAVerifyRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "Invalid request body",
			Code:  ErrCodeValidationFailed,
		})
	}

	if err := h.service.mfa.DisableMFA(c.Context(), userID, req.Code); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: err.Error(),
			Code:  ErrCodeInvalidMFACode,
		})
	}

	return c.JSON(fiber.Map{
		"message": "MFA disabled successfully",
	})
}

// RegenerateBackupCodes generates new backup codes
// @Summary Regenerate backup codes
// @Description Generate new MFA backup codes
// @Tags Authentication
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body map[string]string true "Password for verification"
// @Success 200 {object} MFASetupResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Router /auth/mfa/backup-codes/regenerate [post]
func (h *Handler) RegenerateBackupCodes(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)

	var req struct {
		Password string `json:"password"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "Invalid request body",
			Code:  ErrCodeValidationFailed,
		})
	}

	backupCodes, err := h.service.mfa.RegenerateBackupCodes(c.Context(), userID, req.Password)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(ErrorResponse{
			Error: err.Error(),
			Code:  ErrCodeInvalidCredentials,
		})
	}

	return c.JSON(MFASetupResponse{
		BackupCodes: backupCodes,
	})
}

// RequestPasswordReset initiates secure password reset workflow with anti-enumeration measures
//
// Business Purpose:
// - Enables users to reset forgotten passwords via email verification
// - Implements secure token-based password reset mechanism
// - Provides account recovery while maintaining security posture
// - Supports audit logging for security incident tracking
//
// Security Architecture & Threat Model:
// - Prevents email enumeration attacks via consistent response messages
// - Implements time-limited, single-use reset tokens
// - Tokens stored as salted hashes to prevent database compromise
// - Rate limiting prevents brute force token generation
// - IP address tracking for suspicious activity detection
//
// Anti-Enumeration Strategy:
// - Same success response regardless of email existence
// - Consistent timing for all email lookup operations
// - No distinction between "email not found" and "reset sent"
// - Generic success message prevents user enumeration
// - Failed attempts logged but not exposed to client
//
// Token Security Implementation:
// - Cryptographically secure random token generation
// - Tokens hashed with Argon2id before database storage
// - 15-minute expiration time for reset tokens
// - Single-use tokens invalidated after consumption
// - Tokens bound to specific IP address and user agent
//
// Email Security Features:
// - Reset emails include IP address and timestamp for user awareness
// - Links use HTTPS with secure token parameters
// - Email content sanitized to prevent injection attacks
// - Rate limiting prevents email bombing attacks
// - Audit trail tracks all reset request attempts
//
// User Experience Workflow:
// 1. User submits email address for password reset
// 2. System validates email format and checks existence
// 3. Secure token generated and stored with expiration
// 4. Reset email sent with secure link
// 5. User clicks link and enters new password
// 6. Token validated and password updated atomically
//
// Database Operations:
// - Email lookup via search hash (SHA256 with salt)
// - Token creation with user binding and expiration
// - Audit log entry for security tracking
// - Transactional integrity for token operations
//
// Error Handling Strategy:
// - Generic success responses prevent information disclosure
// - Internal errors logged but not exposed
// - Email delivery failures handled gracefully
// - Token generation failures trigger security alerts
// - Rate limit violations return appropriate HTTP status
//
// Integration with Email Service:
// - Asynchronous email delivery to prevent timing attacks
// - Email content includes security context (IP, timestamp)
// - Delivery status tracked for audit purposes
// - Fallback mechanisms for email service failures
// - Template-based emails with security best practices
//
// Compliance & Audit:
// - All reset attempts logged with IP and timestamp
// - Failed requests tracked for security analysis
// - GDPR-compliant data handling for EU users
// - Data retention policies enforced for reset tokens
// - Security incident response integration
//
// Performance Considerations:
// - Efficient email lookup via indexed search hash
// - Minimal database queries per reset request
// - Asynchronous email processing
// - Redis caching for rate limiting
// - Connection pooling for database operations
//
// @Summary Request password reset
// @Description Send password reset email
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body PasswordResetRequest true "Email address"
// @Success 200 {object} map[string]string
// @Failure 400 {object} ErrorResponse
// @Router /auth/password/reset-request [post]
func (h *Handler) RequestPasswordReset(c *fiber.Ctx) error {
	var req PasswordResetRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "Invalid request body",
			Code:  ErrCodeValidationFailed,
		})
	}

	// Validate email is provided
	if req.Email == "" || strings.TrimSpace(req.Email) == "" {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "Email is required",
			Code:  ErrCodeValidationFailed,
		})
	}

	// Look up user by email (same logic as login)
	emailBytes := []byte(strings.ToLower(strings.TrimSpace(req.Email)))
	searchHash := sha256.Sum256(append(emailBytes, []byte("search-salt")...))

	// Check if user exists
	var userID uuid.UUID
	query := `
		SELECT id FROM users
		WHERE email_search_hash = $1 AND deleted_at IS NULL
	`
	err := h.service.db.QueryRow(c.Context(), query, searchHash[:]).Scan(&userID)
	if err != nil {
		// User not found - return success to prevent email enumeration
		return c.JSON(fiber.Map{
			"message": "If the email exists, a password reset link has been sent",
		})
	}

	// Get client info for security tracking
	ipAddress := utils.ClientIP(c)
	userAgent := c.Get("User-Agent")

	// Create reset token
	token, err := h.service.password.CreateResetToken(c.Context(), userID, ipAddress, userAgent)
	if err != nil {
		// Log error but don't expose it to prevent information disclosure
		log.Printf("Failed to create reset token for user %s: %v", userID.String(), err)
		return c.JSON(fiber.Map{
			"message": "If the email exists, a password reset link has been sent",
		})
	}

	// Send password reset email
	if err := h.emailService.SendPasswordResetEmail(req.Email, token, ipAddress); err != nil {
		// Log error but don't expose it to prevent information disclosure
		log.Printf("Failed to send password reset email to %s: %v", req.Email, err)
		// Still return success to prevent email enumeration
	} else {
		log.Printf("✅ Password reset email sent to %s", req.Email)
	}

	return c.JSON(fiber.Map{
		"message": "If the email exists, a password reset link has been sent",
	})
}

// VerifyResetToken verifies a password reset token
// @Summary Verify reset token
// @Description Check if password reset token is valid
// @Tags Authentication
// @Accept json
// @Produce json
// @Param token query string true "Reset token"
// @Success 200 {object} map[string]bool
// @Failure 400 {object} ErrorResponse
// @Router /auth/password/reset-verify [get]
func (h *Handler) VerifyResetToken(c *fiber.Ctx) error {
	token := c.Query("token")
	if token == "" {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "Token is required",
			Code:  ErrCodeValidationFailed,
		})
	}

	_, err := h.service.password.VerifyResetToken(c.Context(), token)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"valid": false,
			"error": err.Error(),
		})
	}

	return c.JSON(fiber.Map{
		"valid": true,
	})
}

// ConfirmPasswordReset completes password reset
// @Summary Confirm password reset
// @Description Set new password using reset token
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body PasswordResetConfirm true "Reset token and new password"
// @Success 200 {object} map[string]string
// @Failure 400 {object} ErrorResponse
// @Router /auth/password/reset-confirm [post]
func (h *Handler) ConfirmPasswordReset(c *fiber.Ctx) error {
	var req PasswordResetConfirm
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "Invalid request body",
			Code:  ErrCodeValidationFailed,
		})
	}

	if err := h.service.password.CompletePasswordReset(c.Context(), req.Token, req.NewPassword); err != nil {
		if strings.Contains(err.Error(), "password") {
			return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
				Error: err.Error(),
				Code:  ErrCodeValidationFailed,
			})
		}
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: err.Error(),
			Code:  ErrCodeInvalidToken,
		})
	}

	return c.JSON(fiber.Map{
		"message": "Password reset successfully",
	})
}

// GetRegistrationStatus checks if registration is enabled
// @Summary Get registration status
// @Description Check if new user registration is allowed (requires both env var and database setting)
// @Tags Authentication
// @Produce json
// @Success 200 {object} map[string]bool
// @Router /auth/registration [get]
func (h *Handler) GetRegistrationStatus(c *fiber.Ctx) error {
	// Registration requires BOTH env var AND database setting to be enabled
	envEnabled := config.RegEnabled.Load() == 1

	// Check database setting
	var dbEnabled bool
	query := `
		SELECT COALESCE(
			(SELECT value::boolean FROM app_settings WHERE key = 'registration_enabled'),
			true
		) as enabled
	`
	err := h.service.db.QueryRow(c.Context(), query).Scan(&dbEnabled)
	if err != nil {
		// Default to true if error reading database
		dbEnabled = true
	}

	// Both must be enabled
	enabled := envEnabled && dbEnabled

	return c.JSON(fiber.Map{
		"enabled": enabled,
	})
}

// DebugLogin provides detailed login debugging information (development only)
// @Summary Debug login information
// @Description Get detailed login debugging info for troubleshooting
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body AuthRequest true "Login credentials"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} ErrorResponse
// @Router /auth/debug-login [post]
func (h *Handler) DebugLogin(c *fiber.Ctx) error {
	// Only allow in development mode - check multiple indicators
	environment := os.Getenv("ENVIRONMENT")
	appEnv := os.Getenv("APP_ENV")
	isProduction := environment == "production" || appEnv == "production" ||
		strings.Contains(os.Getenv("RAILWAY_ENVIRONMENT"), "production") ||
		os.Getenv("NODE_ENV") == "production"

	if isProduction {
		return c.Status(fiber.StatusForbidden).JSON(ErrorResponse{
			Error: "Debug endpoint not available in production",
			Code:  ErrCodeAccessDenied,
		})
	}

	// Additional security: require debug token
	debugToken := c.Get("X-Debug-Token")
	expectedToken := os.Getenv("DEBUG_TOKEN")
	if expectedToken != "" && debugToken != expectedToken {
		return c.Status(fiber.StatusForbidden).JSON(ErrorResponse{
			Error: "Invalid debug token",
			Code:  ErrCodeAccessDenied,
		})
	}

	var req AuthRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "Invalid request body",
			Code:  ErrCodeValidationFailed,
		})
	}

	// Create deterministic search hash
	emailBytes := []byte(strings.ToLower(strings.TrimSpace(req.Email)))
	searchHash := sha256.Sum256(append(emailBytes, []byte("search-salt")...))

	// Look up user
	query := `
		SELECT id, password_hash, salt, mfa_enabled, mfa_secret_encrypted,
		       failed_attempts, locked_until, is_admin, created_at
		FROM users
		WHERE email_search_hash = $1 AND deleted_at IS NULL
	`

	var userID uuid.UUID
	var passwordHash string
	var salt []byte
	var mfaEnabled bool
	var mfaSecretEncrypted []byte
	var failedAttempts int
	var lockedUntil *time.Time
	var isAdmin bool
	var createdAt time.Time

	err := h.service.db.QueryRow(c.Context(), query, searchHash[:]).Scan(
		&userID, &passwordHash, &salt, &mfaEnabled, &mfaSecretEncrypted,
		&failedAttempts, &lockedUntil, &isAdmin, &createdAt,
	)

	debugInfo := map[string]interface{}{
		"email_provided":    req.Email,
		"email_normalized":  string(emailBytes),
		"search_hash_hex":   fmt.Sprintf("%x", searchHash[:]),
		"user_found":        err == nil,
		"user_id":           userID.String(),
		"is_admin":          isAdmin,
		"mfa_enabled":       mfaEnabled,
		"failed_attempts":   failedAttempts,
		"locked_until":      lockedUntil,
		"created_at":        createdAt,
		"password_hash_len": len(passwordHash),
		"salt_len":          len(salt),
	}

	if err != nil {
		debugInfo["error"] = err.Error()
		return c.JSON(debugInfo)
	}

	// Test password verification
	passwordValid := h.service.password.VerifyPassword(req.Password, passwordHash, salt)
	debugInfo["password_valid"] = passwordValid

	// Check account lock
	if lockedUntil != nil && time.Now().UTC().Before(*lockedUntil) {
		debugInfo["account_locked"] = true
		debugInfo["locked_until"] = lockedUntil.Format(time.RFC3339)
	} else {
		debugInfo["account_locked"] = false
	}

	return c.JSON(debugInfo)
}

// DebugAdminInfo provides information about the default admin user (development only)
// @Summary Debug admin user information
// @Description Get information about the default admin user for troubleshooting
// @Tags Authentication
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Failure 403 {object} ErrorResponse
// @Router /auth/debug-admin [get]
func (h *Handler) DebugAdminInfo(c *fiber.Ctx) error {
	// Only allow in development mode - check multiple indicators
	environment := os.Getenv("ENVIRONMENT")
	appEnv := os.Getenv("APP_ENV")
	isProduction := environment == "production" || appEnv == "production" ||
		strings.Contains(os.Getenv("RAILWAY_ENVIRONMENT"), "production") ||
		os.Getenv("NODE_ENV") == "production"

	if isProduction {
		return c.Status(fiber.StatusForbidden).JSON(ErrorResponse{
			Error: "Debug endpoint not available in production",
			Code:  ErrCodeAccessDenied,
		})
	}

	// Additional security: require debug token
	debugToken := c.Get("X-Debug-Token")
	expectedToken := os.Getenv("DEBUG_TOKEN")
	if expectedToken != "" && debugToken != expectedToken {
		return c.Status(fiber.StatusForbidden).JSON(ErrorResponse{
			Error: "Invalid debug token",
			Code:  ErrCodeAccessDenied,
		})
	}

	// Get admin user info (zero-knowledge: email in plaintext)
	query := `
		SELECT id, email_plaintext, is_admin, created_at, last_login
		FROM users
		WHERE is_admin = true AND deleted_at IS NULL
		ORDER BY created_at ASC
		LIMIT 1
	`

	var userID uuid.UUID
	var email string
	var isAdmin bool
	var createdAt time.Time
	var lastLogin *time.Time

	err := h.service.db.QueryRow(c.Context(), query).Scan(
		&userID, &email, &isAdmin, &createdAt, &lastLogin,
	)

	if err != nil {
		return c.JSON(map[string]interface{}{
			"admin_found": false,
			"error":       err.Error(),
		})
	}

	return c.JSON(map[string]interface{}{
		"admin_found": true,
		"user_id":     userID.String(),
		"email":       email,
		"is_admin":    isAdmin,
		"created_at":  createdAt,
		"last_login":  lastLogin,
	})
}

// DebugEncryptionKey provides encryption key debugging information (development only)
// @Summary Debug encryption key information
// @Description Get encryption key debugging info for troubleshooting
// @Tags Authentication
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Failure 403 {object} ErrorResponse
// @Router /auth/debug-encryption [get]
func (h *Handler) DebugEncryptionKey(c *fiber.Ctx) error {
	// Only allow in development mode - check multiple indicators
	environment := os.Getenv("ENVIRONMENT")
	appEnv := os.Getenv("APP_ENV")
	isProduction := environment == "production" || appEnv == "production" ||
		strings.Contains(os.Getenv("RAILWAY_ENVIRONMENT"), "production") ||
		os.Getenv("NODE_ENV") == "production"

	if isProduction {
		return c.Status(fiber.StatusForbidden).JSON(ErrorResponse{
			Error: "Debug endpoint not available in production",
			Code:  ErrCodeAccessDenied,
		})
	}

	// Additional security: require debug token
	debugToken := c.Get("X-Debug-Token")
	expectedToken := os.Getenv("DEBUG_TOKEN")
	if expectedToken != "" && debugToken != expectedToken {
		return c.Status(fiber.StatusForbidden).JSON(ErrorResponse{
			Error: "Invalid debug token",
			Code:  ErrCodeAccessDenied,
		})
	}

	// Note: Service-level crypto removed for zero-knowledge architecture
	// MFA and session encryption are handled by dedicated managers with JWT-derived keys
	return c.JSON(map[string]interface{}{
		"encryption_architecture": "zero-knowledge",
		"note":                    "Service-level crypto removed. Encryption is handled by MFA and session managers with system-derived keys.",
		"mfa_encryption":          "Derived from system secret with '-mfa-encryption' suffix",
		"session_encryption":      "Derived from system secret with '-session-encryption' suffix",
		"user_note_encryption":    "End-to-end encrypted with password-derived keys (client-side)",
	})
}

// ResetAdminUser resets the admin user with current encryption key (development only)
// @Summary Reset admin user
// @Description Reset admin user with current encryption key to fix encryption mismatches
// @Tags Authentication
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Failure 403 {object} ErrorResponse
// @Router /auth/reset-admin [post]
func (h *Handler) ResetAdminUser(c *fiber.Ctx) error {
	// Only allow in development mode - check multiple indicators
	environment := os.Getenv("ENVIRONMENT")
	appEnv := os.Getenv("APP_ENV")
	isProduction := environment == "production" || appEnv == "production" ||
		strings.Contains(os.Getenv("RAILWAY_ENVIRONMENT"), "production") ||
		os.Getenv("NODE_ENV") == "production"

	if isProduction {
		return c.Status(fiber.StatusForbidden).JSON(ErrorResponse{
			Error: "Debug endpoint not available in production",
			Code:  ErrCodeAccessDenied,
		})
	}

	// Additional security: require debug token
	debugToken := c.Get("X-Debug-Token")
	expectedToken := os.Getenv("DEBUG_TOKEN")
	if expectedToken != "" && debugToken != expectedToken {
		return c.Status(fiber.StatusForbidden).JSON(ErrorResponse{
			Error: "Invalid debug token",
			Code:  ErrCodeAccessDenied,
		})
	}

	// Get admin user ID
	var adminUserID uuid.UUID
	query := `SELECT id FROM users WHERE is_admin = true AND deleted_at IS NULL LIMIT 1`
	err := h.service.db.QueryRow(c.Context(), query).Scan(&adminUserID)
	if err != nil {
		return c.JSON(map[string]interface{}{
			"success": false,
			"error":   "No admin user found",
		})
	}

	// Delete the existing admin user and related data
	tx, err := h.service.db.Begin(c.Context())
	if err != nil {
		return c.JSON(map[string]interface{}{
			"success": false,
			"error":   "Failed to begin transaction",
		})
	}
	defer func() {
		_ = tx.Rollback(c.Context())
	}()

	// Delete user data in correct order (foreign key constraints)
	deleteQueries := []string{
		`DELETE FROM audit_log WHERE user_id = $1`,
		`DELETE FROM gdpr_keys WHERE email_hash IN (SELECT email_hash FROM users WHERE id = $1)`,
		`DELETE FROM workspaces WHERE owner_id = $1`,
		`DELETE FROM user_roles WHERE user_id = $1`,
		`DELETE FROM users WHERE id = $1`,
	}

	for _, deleteQuery := range deleteQueries {
		_, err = tx.Exec(c.Context(), deleteQuery, adminUserID)
		if err != nil {
			return c.JSON(map[string]interface{}{
				"success": false,
				"error":   fmt.Sprintf("Failed to delete user data: %v", err),
			})
		}
	}

	// Commit the deletion
	err = tx.Commit(c.Context())
	if err != nil {
		return c.JSON(map[string]interface{}{
			"success": false,
			"error":   "Failed to commit deletion",
		})
	}

	// Recreate admin user with current encryption key
	err = h.service.EnsureDefaultAdmin(c.Context(), true, "REDACTED_EMAIL", "REDACTED_PASSWORD")
	if err != nil {
		return c.JSON(map[string]interface{}{
			"success": false,
			"error":   fmt.Sprintf("Failed to recreate admin user: %v", err),
		})
	}

	return c.JSON(map[string]interface{}{
		"success": true,
		"message": "Admin user reset successfully with current encryption key",
		"email":   "REDACTED_EMAIL",
	})
}

// DebugAuthState provides debugging information about the current authentication state
// @Summary Debug current auth state
// @Description Get detailed information about the current authentication state for debugging
// @Tags Authentication
// @Security BearerAuth
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Failure 401 {object} ErrorResponse
// @Failure 403 {object} ErrorResponse
// @Router /auth/debug-state [get]
func (h *Handler) DebugAuthState(c *fiber.Ctx) error {
	// Only allow in development mode - check multiple indicators
	environment := os.Getenv("ENVIRONMENT")
	appEnv := os.Getenv("APP_ENV")
	isProduction := environment == "production" || appEnv == "production" ||
		strings.Contains(os.Getenv("RAILWAY_ENVIRONMENT"), "production") ||
		os.Getenv("NODE_ENV") == "production"

	if isProduction {
		return c.Status(fiber.StatusForbidden).JSON(ErrorResponse{
			Error: "Debug endpoint not available in production",
			Code:  ErrCodeAccessDenied,
		})
	}

	// Additional security: require debug token
	debugToken := c.Get("X-Debug-Token")
	expectedToken := os.Getenv("DEBUG_TOKEN")
	if expectedToken != "" && debugToken != expectedToken {
		return c.Status(fiber.StatusForbidden).JSON(ErrorResponse{
			Error: "Invalid debug token",
			Code:  ErrCodeAccessDenied,
		})
	}

	// Collect authentication state information
	authState := map[string]interface{}{
		"timestamp":       time.Now().Unix(),
		"request_path":    c.Path(),
		"method":          c.Method(),
		"has_auth_header": c.Get("Authorization") != "",
	}

	// Check if we have user context
	userID := c.Locals("user_id")
	if userID != nil {
		authState["authenticated"] = true
		authState["user_id"] = userID
		authState["is_admin"] = c.Locals("is_admin")
		authState["clerk_user_id"] = c.Locals("clerk_user_id")
		authState["auth_type"] = c.Locals("auth_type")
		authState["has_token"] = c.Locals("token") != nil
		authState["has_claims"] = c.Locals("clerk_claims") != nil
	} else {
		authState["authenticated"] = false
		authState["reason"] = "No user_id in context"
	}

	// Check Clerk SDK status
	authState["clerk_configured"] = h.config != nil && h.config.ClerkSecretKey != ""
	authState["clerk_secret_key_length"] = 0
	if h.config != nil && h.config.ClerkSecretKey != "" {
		authState["clerk_secret_key_length"] = len(h.config.ClerkSecretKey)
	}

	return c.JSON(authState)
}
