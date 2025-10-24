package auth

import (
	"context"
	"strings"

	"leaflock/utils"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

// Handler provides HTTP handlers for auth endpoints
type Handler struct {
	service *Service
}

// NewHandler creates a new auth handler
func NewHandler(service *Service) *Handler {
	return &Handler{
		service: service,
	}
}

// Register handles user registration
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

	response, err := h.service.Register(ctx, req.Email, req.Password)
	if err != nil {
		if strings.Contains(err.Error(), "already exists") {
			return c.Status(fiber.StatusConflict).JSON(ErrorResponse{
				Error: err.Error(),
				Code:  ErrCodeEmailExists,
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

	return c.JSON(response)
}

// Login handles user login
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
	// Get token from Authorization header
	authHeader := c.Get("Authorization")
	if authHeader == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(ErrorResponse{
			Error: "No authorization token provided",
			Code:  ErrCodeInvalidToken,
		})
	}

	// Extract token (format: "Bearer <token>")
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return c.Status(fiber.StatusUnauthorized).JSON(ErrorResponse{
			Error: "Invalid authorization format",
			Code:  ErrCodeInvalidToken,
		})
	}

	token := parts[1]
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

	// Get user email
	var email string
	query := `SELECT email_encrypted FROM users WHERE id = $1`
	var emailEncrypted []byte
	err := h.service.db.QueryRow(c.Context(), query, userID).Scan(&emailEncrypted)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "Failed to get user info",
			Code:  ErrCodeInternalError,
		})
	}

	// Decrypt email
	emailBytes, err := h.service.crypto.DecryptBytes(emailEncrypted)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "Failed to decrypt email",
			Code:  ErrCodeInternalError,
		})
	}
	email = string(emailBytes)

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

// RequestPasswordReset initiates password reset
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

	// Look up user by email (same logic as login)
	// TODO: Implement email lookup and token generation
	// For now, always return success to prevent email enumeration
	// Note: Client IP and User-Agent tracking will be added when TODO is implemented

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
// @Description Check if new user registration is allowed
// @Tags Authentication
// @Produce json
// @Success 200 {object} map[string]bool
// @Router /auth/registration [get]
func (h *Handler) GetRegistrationStatus(c *fiber.Ctx) error {
	// This would check the registration toggle
	// For now, we'll return true
	return c.JSON(fiber.Map{
		"enabled": true,
	})
}
