package auth

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

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

	// Check if registration is enabled
	var registrationEnabled bool
	query := `
		SELECT COALESCE(
			(SELECT value::boolean FROM app_settings WHERE key = 'registration_enabled'),
			true
		) as enabled
	`
	err := h.service.db.QueryRow(c.Context(), query).Scan(&registrationEnabled)
	if err != nil || !registrationEnabled {
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
		return c.JSON(fiber.Map{
			"message": "If the email exists, a password reset link has been sent",
		})
	}

	// TODO: Send email with reset link
	// For now, we'll log the token for development purposes
	// In production, this should be sent via email
	log.Printf("Password reset token for user %s: %s", userID.String(), token)

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
	// Check registration setting from app_settings table
	var enabled bool
	query := `
		SELECT COALESCE(
			(SELECT value::boolean FROM app_settings WHERE key = 'registration_enabled'),
			true
		) as enabled
	`
	err := h.service.db.QueryRow(c.Context(), query).Scan(&enabled)
	if err != nil {
		// If there's an error, default to enabled for backward compatibility
		enabled = true
	}

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
	// Only allow in development mode
	if os.Getenv("ENVIRONMENT") == "production" {
		return c.Status(fiber.StatusForbidden).JSON(ErrorResponse{
			Error: "Debug endpoint not available in production",
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
	// Only allow in development mode
	if os.Getenv("ENVIRONMENT") == "production" {
		return c.Status(fiber.StatusForbidden).JSON(ErrorResponse{
			Error: "Debug endpoint not available in production",
			Code:  ErrCodeAccessDenied,
		})
	}

	// Get admin user info
	query := `
		SELECT id, email_encrypted, is_admin, created_at, last_login
		FROM users
		WHERE is_admin = true AND deleted_at IS NULL
		ORDER BY created_at ASC
		LIMIT 1
	`

	var userID uuid.UUID
	var emailEncrypted []byte
	var isAdmin bool
	var createdAt time.Time
	var lastLogin *time.Time

	err := h.service.db.QueryRow(c.Context(), query).Scan(
		&userID, &emailEncrypted, &isAdmin, &createdAt, &lastLogin,
	)

	if err != nil {
		return c.JSON(map[string]interface{}{
			"admin_found": false,
			"error":       err.Error(),
		})
	}

	// Decrypt email
	emailBytes, err := h.service.crypto.DecryptBytes(emailEncrypted)
	if err != nil {
		return c.JSON(map[string]interface{}{
			"admin_found": true,
			"user_id":     userID.String(),
			"is_admin":    isAdmin,
			"created_at":  createdAt,
			"last_login":  lastLogin,
			"email_error": "Failed to decrypt email",
		})
	}

	return c.JSON(map[string]interface{}{
		"admin_found": true,
		"user_id":     userID.String(),
		"email":       string(emailBytes),
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
	// Only allow in development mode
	if os.Getenv("ENVIRONMENT") == "production" {
		return c.Status(fiber.StatusForbidden).JSON(ErrorResponse{
			Error: "Debug endpoint not available in production",
			Code:  ErrCodeAccessDenied,
		})
	}

	// Test encryption/decryption with a known value
	testValue := []byte("test-encryption-key")
	encrypted, err := h.service.crypto.EncryptBytes(testValue)
	if err != nil {
		return c.JSON(map[string]interface{}{
			"encryption_test": "failed",
			"error":           err.Error(),
		})
	}

	decrypted, err := h.service.crypto.DecryptBytes(encrypted)
	if err != nil {
		return c.JSON(map[string]interface{}{
			"encryption_test": "failed",
			"encrypt_success": true,
			"decrypt_error":   err.Error(),
		})
	}

	success := string(decrypted) == string(testValue)

	return c.JSON(map[string]interface{}{
		"encryption_test":   "passed",
		"encrypt_success":   true,
		"decrypt_success":   true,
		"roundtrip_success": success,
		"test_value":        string(testValue),
		"decrypted_value":   string(decrypted),
		"encrypted_length":  len(encrypted),
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
	// Only allow in development mode
	if os.Getenv("ENVIRONMENT") == "production" {
		return c.Status(fiber.StatusForbidden).JSON(ErrorResponse{
			Error: "Debug endpoint not available in production",
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
	err = h.service.EnsureDefaultAdmin(c.Context(), true, "mail@rasmusj.dk", "UW^kHWhgbvsAN7TV#B!ySeXG&mq%Zz")
	if err != nil {
		return c.JSON(map[string]interface{}{
			"success": false,
			"error":   fmt.Sprintf("Failed to recreate admin user: %v", err),
		})
	}

	return c.JSON(map[string]interface{}{
		"success": true,
		"message": "Admin user reset successfully with current encryption key",
		"email":   "mail@rasmusj.dk",
	})
}
