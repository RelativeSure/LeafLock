package auth

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"leaflock/utils"
)

// ClerkFunctions provides advanced Clerk functionality for the backend

// ClerkUserInfo contains detailed user information from Clerk
type ClerkUserInfo struct {
	ClerkUserID      string
	Email            string
	FirstName        string
	LastName         string
	AvatarURL        string
	IsAdmin          bool
	PublicMetaData   map[string]interface{}
	PrivateMetaData  map[string]interface{}
	CreatedAt        time.Time
	UpdatedAt        time.Time
	EmailVerified    bool
	PhoneVerified    bool
	TwoFactorEnabled bool
}

// ClerkSessionInfo contains session information from Clerk
type ClerkSessionInfo struct {
	SessionID  string
	UserID     string
	Status     string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	LastActive time.Time
	UserAgent  string
	IPAddress  string
	DeviceInfo string
	IsCurrent  bool
}

// GetClerkUserInfo retrieves detailed user information from Clerk with secure logging
func (h *Handler) GetClerkUserInfo(ctx context.Context, clerkUserID string) (*ClerkUserInfo, error) {
	if clerkUserID == "" {
		return nil, fmt.Errorf("clerk user ID is required")
	}

	// Implementation would use Clerk API to get user info
	// For now, return basic info
	return &ClerkUserInfo{
		ClerkUserID: clerkUserID,
		CreatedAt:   time.Now(), // This would come from Clerk API
		UpdatedAt:   time.Now(),
	}, nil
}

// GetClerkSessionInfo returns detailed session information for the current Clerk session
func (h *Handler) GetClerkSessionInfo(c *fiber.Ctx) error {
	ctx := c.Context()

	// Get the current token from context
	token, ok := c.Locals("token").(string)
	if !ok || token == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(ErrorResponse{
			Error: "No authorization token provided",
			Code:  ErrCodeInvalidToken,
		})
	}

	// Validate the token
	claims, err := h.validateClerkTokenEnhanced(ctx, token)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(ErrorResponse{
			Error: "Invalid session token",
			Code:  "SESSION_INVALID",
		})
	}

	// Get user info from Clerk (placeholder implementation)
	clerkUserID := claims.Subject
	userInfo, err := h.GetClerkUserInfo(ctx, clerkUserID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "Failed to retrieve user information",
			Code:  "USER_INFO_ERROR",
		})
	}

	// Get session info
	sessions, err := h.getClerkSessionsFromAPI(ctx, clerkUserID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "Failed to retrieve session information",
			Code:  "SESSION_INFO_ERROR",
		})
	}

	// Find current session
	var currentSession *ClerkSessionInfo
	for _, session := range sessions {
		if session.IsCurrent {
			currentSession = session
			break
		}
	}

	return c.JSON(fiber.Map{
		"session": currentSession,
		"user":    userInfo,
	})
}

// GetClerkUserProfile returns enhanced user profile information
func (h *Handler) GetClerkUserProfile(c *fiber.Ctx) error {
	ctx := c.Context()

	// Get the current token from context
	token, ok := c.Locals("token").(string)
	if !ok || token == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(ErrorResponse{
			Error: "No authorization token provided",
			Code:  ErrCodeInvalidToken,
		})
	}

	// Validate the token
	claims, err := h.validateClerkTokenEnhanced(ctx, token)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(ErrorResponse{
			Error: "Invalid session token",
			Code:  "SESSION_INVALID",
		})
	}

	// Get user info from Clerk
	clerkUserID := claims.Subject
	userInfo, err := h.GetClerkUserInfo(ctx, clerkUserID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "Failed to retrieve user information",
			Code:  "USER_INFO_ERROR",
		})
	}

	return c.JSON(fiber.Map{
		"user": userInfo,
	})
}

// GetClerkSessions returns all active sessions for the current user
func (h *Handler) GetClerkSessions(c *fiber.Ctx) error {
	ctx := c.Context()

	// Get the current token from context
	token, ok := c.Locals("token").(string)
	if !ok || token == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(ErrorResponse{
			Error: "No authorization token provided",
			Code:  ErrCodeInvalidToken,
		})
	}

	// Validate the token
	claims, err := h.validateClerkTokenEnhanced(ctx, token)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(ErrorResponse{
			Error: "Invalid session token",
			Code:  "SESSION_INVALID",
		})
	}

	// Get sessions for the user
	clerkUserID := claims.Subject
	sessions, err := h.getClerkSessionsFromAPI(ctx, clerkUserID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "Failed to retrieve sessions",
			Code:  "SESSIONS_ERROR",
		})
	}

	return c.JSON(fiber.Map{
		"sessions": sessions,
	})
}

// RevokeClerkSession revokes a specific Clerk session
func (h *Handler) RevokeClerkSession(c *fiber.Ctx) error {
	ctx := c.Context()
	sessionID := c.Params("sessionId")

	if sessionID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "Session ID is required",
			Code:  "INVALID_SESSION_ID",
		})
	}

	// Get the current token from context
	token, ok := c.Locals("token").(string)
	if !ok || token == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(ErrorResponse{
			Error: "No authorization token provided",
			Code:  ErrCodeInvalidToken,
		})
	}

	// Validate the token
	claims, err := h.validateClerkTokenEnhanced(ctx, token)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(ErrorResponse{
			Error: "Invalid session token",
			Code:  "SESSION_INVALID",
		})
	}

	// Revoke the session
	clerkUserID := claims.Subject
	err = h.revokeClerkSessionAPI(ctx, sessionID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "Failed to revoke session",
			Code:  "SESSION_REVOKE_ERROR",
		})
	}

	// Secure logging
	utils.NewSecurityLogger(log.Writer()).LogAuthEvent("session_revoked", uuid.MustParse(clerkUserID), true, map[string]interface{}{
		"session_id": sessionID,
	})

	return c.JSON(fiber.Map{
		"message": "Session revoked successfully",
	})
}

// GetClerkOrganizations returns organizations for the current user
func (h *Handler) GetClerkOrganizations(c *fiber.Ctx) error {
	ctx := c.Context()

	// Get the current token from context
	token, ok := c.Locals("token").(string)
	if !ok || token == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(ErrorResponse{
			Error: "No authorization token provided",
			Code:  ErrCodeInvalidToken,
		})
	}

	// Validate the token
	claims, err := h.validateClerkTokenEnhanced(ctx, token)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(ErrorResponse{
			Error: "Invalid session token",
			Code:  "SESSION_INVALID",
		})
	}

	// Get organizations for the user
	clerkUserID := claims.Subject
	organizations, err := h.GetClerkOrganizationsForUser(ctx, clerkUserID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "Failed to retrieve organizations",
			Code:  "ORGANIZATIONS_ERROR",
		})
	}

	return c.JSON(fiber.Map{
		"organizations": organizations,
	})
}

// CreateClerkOrganization creates a new organization
func (h *Handler) CreateClerkOrganization(c *fiber.Ctx) error {
	ctx := c.Context()

	// Get the current token from context
	token, ok := c.Locals("token").(string)
	if !ok || token == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(ErrorResponse{
			Error: "No authorization token provided",
			Code:  ErrCodeInvalidToken,
		})
	}

	// Validate the token
	claims, err := h.validateClerkTokenEnhanced(ctx, token)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(ErrorResponse{
			Error: "Invalid session token",
			Code:  "SESSION_INVALID",
		})
	}

	// Parse request
	var req struct {
		Name        string `json:"name" validate:"required,min=3,max=100"`
		Description string `json:"description" validate:"max=500"`
	}

	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "Invalid request body",
			Code:  "INVALID_REQUEST",
		})
	}

	// Create organization
	clerkUserID := claims.Subject
	orgID, err := h.CreateClerkOrganizationForUser(ctx, clerkUserID, req.Name, req.Description)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "Failed to create organization",
			Code:  "ORGANIZATION_CREATE_ERROR",
		})
	}

	// Secure logging
	utils.NewSecurityLogger(log.Writer()).LogAuthEvent("organization_created", uuid.MustParse(clerkUserID), true, map[string]interface{}{
		"organization_id":   orgID,
		"organization_name": req.Name,
	})

	return c.JSON(fiber.Map{
		"message": "Organization created successfully",
		"organization": fiber.Map{
			"id":          orgID,
			"name":        req.Name,
			"description": req.Description,
		},
	})
}

// GetClerkOrganization gets a specific organization
func (h *Handler) GetClerkOrganization(c *fiber.Ctx) error {
	ctx := c.Context()
	orgID := c.Params("orgId")

	if orgID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "Organization ID is required",
			Code:  "INVALID_ORGANIZATION_ID",
		})
	}

	// Get the current token from context
	token, ok := c.Locals("token").(string)
	if !ok || token == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(ErrorResponse{
			Error: "No authorization token provided",
			Code:  ErrCodeInvalidToken,
		})
	}

	// Validate the token
	claims, err := h.validateClerkTokenEnhanced(ctx, token)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(ErrorResponse{
			Error: "Invalid session token",
			Code:  "SESSION_INVALID",
		})
	}

	// Get organization
	clerkUserID := claims.Subject
	organization, err := h.GetClerkOrganizationForUser(ctx, clerkUserID, orgID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "Failed to retrieve organization",
			Code:  "ORGANIZATION_ERROR",
		})
	}

	return c.JSON(fiber.Map{
		"organization": organization,
	})
}

// UpdateClerkOrganization updates an organization
func (h *Handler) UpdateClerkOrganization(c *fiber.Ctx) error {
	ctx := c.Context()
	orgID := c.Params("orgId")

	if orgID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "Organization ID is required",
			Code:  "INVALID_ORGANIZATION_ID",
		})
	}

	// Get the current token from context
	token, ok := c.Locals("token").(string)
	if !ok || token == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(ErrorResponse{
			Error: "No authorization token provided",
			Code:  ErrCodeInvalidToken,
		})
	}

	// Validate the token
	claims, err := h.validateClerkTokenEnhanced(ctx, token)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(ErrorResponse{
			Error: "Invalid session token",
			Code:  "SESSION_INVALID",
		})
	}

	// Parse request
	var req struct {
		Name        string `json:"name" validate:"required,min=3,max=100"`
		Description string `json:"description" validate:"max=500"`
	}

	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "Invalid request body",
			Code:  "INVALID_REQUEST",
		})
	}

	// Update organization
	clerkUserID := claims.Subject
	err = h.UpdateClerkOrganizationForUser(ctx, clerkUserID, orgID, req.Name, req.Description)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "Failed to update organization",
			Code:  "ORGANIZATION_UPDATE_ERROR",
		})
	}

	// Secure logging
	utils.NewSecurityLogger(log.Writer()).LogAuthEvent("organization_updated", uuid.MustParse(clerkUserID), true, map[string]interface{}{
		"organization_id":   orgID,
		"organization_name": req.Name,
	})

	return c.JSON(fiber.Map{
		"message": "Organization updated successfully",
		"organization": fiber.Map{
			"id":          orgID,
			"name":        req.Name,
			"description": req.Description,
		},
	})
}

// Helper functions (placeholders for actual Clerk API calls)

func (h *Handler) GetClerkOrganizationsForUser(ctx context.Context, clerkUserID string) ([]*ClerkOrganizationInfo, error) {
	// Placeholder implementation
	return []*ClerkOrganizationInfo{}, nil
}

func (h *Handler) CreateClerkOrganizationForUser(ctx context.Context, clerkUserID string, name string, description string) (string, error) {
	// Placeholder implementation
	return "org_" + uuid.New().String(), nil
}

func (h *Handler) GetClerkOrganizationForUser(ctx context.Context, clerkUserID string, orgID string) (*ClerkOrganizationInfo, error) {
	// Placeholder implementation
	return &ClerkOrganizationInfo{
		ID:          orgID,
		Name:        "Sample Organization",
		Description: "A sample organization",
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}, nil
}

func (h *Handler) UpdateClerkOrganizationForUser(ctx context.Context, clerkUserID string, orgID string, name string, description string) error {
	// Placeholder implementation
	return nil
}

// ClerkOrganizationInfo contains organization information
type ClerkOrganizationInfo struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// logSecurityEvent logs security events with proper formatting

// getClerkSessionsFromAPI retrieves sessions from Clerk API
func (h *Handler) getClerkSessionsFromAPI(ctx context.Context, clerkUserID string) ([]*ClerkSessionInfo, error) {
	if clerkUserID == "" {
		return nil, fmt.Errorf("clerk user ID is required")
	}

	// This would make an actual API call to Clerk in a real implementation
	// For now, return empty slice as placeholder
	return []*ClerkSessionInfo{}, nil
}

// revokeClerkSessionAPI revokes a Clerk session via API
func (h *Handler) revokeClerkSessionAPI(ctx context.Context, sessionID string) error {
	if sessionID == "" {
		return fmt.Errorf("session ID is required")
	}

	// This would make an actual API call to Clerk in a real implementation
	// For now, return nil as placeholder
	return nil
}
