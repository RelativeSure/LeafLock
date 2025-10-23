package auth

import (
	"time"

	"github.com/google/uuid"
)

// User represents an authenticated user with modern, clean interfaces
type User struct {
	ID                  uuid.UUID  `json:"id"`
	EmailHash           []byte     `json:"-"` // SHA-256 for uniqueness
	EmailEncrypted      []byte     `json:"-"` // For privacy
	EmailSearchHash     []byte     `json:"-"` // Deterministic for login
	PasswordHash        string     `json:"-"` // Argon2id
	Salt                []byte     `json:"-"`
	MasterKeyEncrypted  []byte     `json:"-"`
	PublicKey           []byte     `json:"-"`
	PrivateKeyEncrypted []byte     `json:"-"`
	MFASecretEncrypted  []byte     `json:"-"`
	MFAEnabled          bool       `json:"mfa_enabled"`
	MFABackupCodes      [][]byte   `json:"-"`
	MFABackupCodesUsed  [][]byte   `json:"-"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
	LastLogin           *time.Time `json:"last_login,omitempty"`
	FailedAttempts      int        `json:"-"`
	LockedUntil         *time.Time `json:"-"`
	DeletedAt           *time.Time `json:"-"`
	IsAdmin             bool       `json:"is_admin"`
	StorageUsed         int64      `json:"storage_used"`
	StorageLimit        int64      `json:"storage_limit"`
	ThemePreference     string     `json:"theme_preference"`
}

// Session represents an authenticated session
type Session struct {
	UserID       uuid.UUID `json:"user_id"`
	Token        string    `json:"token"`
	IPAddress    string    `json:"ip_address"`
	UserAgent    string    `json:"user_agent"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	MFAVerified  bool      `json:"mfa_verified"`
	IsHalfAuthed bool      `json:"is_half_authed"` // For remember-me or pending MFA
}

// MFASession represents a temporary MFA verification session
type MFASession struct {
	UserID           uuid.UUID `json:"user_id"`
	Email            string    `json:"email"`
	IPAddress        string    `json:"ip_address"`
	UserAgent        string    `json:"user_agent"`
	CreatedAt        time.Time `json:"created_at"`
	ExpiresAt        time.Time `json:"expires_at"`
	MFAEnabled       bool      `json:"mfa_enabled"`
	PasswordVerified bool      `json:"password_verified"`
}

// PasswordResetToken represents a password reset token
type PasswordResetToken struct {
	ID                 uuid.UUID `json:"id"`
	UserID             uuid.UUID `json:"user_id"`
	TokenHash          []byte    `json:"-"` // SHA-256
	ExpiresAt          time.Time `json:"expires_at"`
	Used               bool      `json:"used"`
	CreatedAt          time.Time `json:"created_at"`
	IPAddressEncrypted []byte    `json:"-"`
	UserAgentEncrypted []byte    `json:"-"`
}

// AuthRequest represents a login request
type AuthRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=12"`
	MFACode  string `json:"mfa_code,omitempty"`
}

// RegisterRequest represents a registration request
type RegisterRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=12"`
}

// MFASetupResponse contains MFA setup information
type MFASetupResponse struct {
	Secret      string   `json:"secret"`
	QRCodeURL   string   `json:"qr_code_url"`
	BackupCodes []string `json:"backup_codes,omitempty"`
}

// MFAVerifyRequest represents MFA verification
type MFAVerifyRequest struct {
	Code         string `json:"code" validate:"required"`
	SessionToken string `json:"session_token,omitempty"`
}

// PasswordResetRequest represents a password reset request
type PasswordResetRequest struct {
	Email string `json:"email" validate:"required,email"`
}

// PasswordResetConfirm represents password reset confirmation
type PasswordResetConfirm struct {
	Token       string `json:"token" validate:"required"`
	NewPassword string `json:"new_password" validate:"required,min=12"`
}

// AuthResponse represents successful authentication
type AuthResponse struct {
	Token        string    `json:"token"`
	UserID       string    `json:"user_id"`
	WorkspaceID  string    `json:"workspace_id,omitempty"`
	MFARequired  bool      `json:"mfa_required,omitempty"`
	SessionToken string    `json:"session_token,omitempty"` // For MFA flow
	IsAdmin      bool      `json:"is_admin"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error   string                 `json:"error"`
	Code    string                 `json:"code,omitempty"`
	Details map[string]interface{} `json:"details,omitempty"`
}

// Constants for error codes
const (
	ErrCodeInvalidCredentials   = "INVALID_CREDENTIALS"
	ErrCodeAccountLocked        = "ACCOUNT_LOCKED"
	ErrCodeMFARequired          = "MFA_REQUIRED"
	ErrCodeInvalidMFACode       = "INVALID_MFA_CODE"
	ErrCodeInvalidToken         = "INVALID_TOKEN"
	ErrCodeExpiredToken         = "EXPIRED_TOKEN"
	ErrCodeUserNotFound         = "USER_NOT_FOUND"
	ErrCodeEmailExists          = "EMAIL_EXISTS"
	ErrCodeValidationFailed     = "VALIDATION_FAILED"
	ErrCodeInternalError        = "INTERNAL_ERROR"
	ErrCodeRegistrationDisabled = "REGISTRATION_DISABLED"
)
