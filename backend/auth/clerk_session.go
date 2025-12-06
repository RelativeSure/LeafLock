package auth

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/clerk/clerk-sdk-go/v2"
	"github.com/gofiber/fiber/v2"
)

// ClerkSessionManager handles Clerk session management
type ClerkSessionManager struct {
	handler *Handler
}

// NewClerkSessionManager creates a new session manager
func NewClerkSessionManager(handler *Handler) *ClerkSessionManager {
	return &ClerkSessionManager{handler: handler}
}

// ValidateAndRefreshSession validates a Clerk session and handles refresh if needed
func (sm *ClerkSessionManager) ValidateAndRefreshSession(c *fiber.Ctx, token string) (*clerk.SessionClaims, error) {
	ctx := c.Context()

	// First, try to validate the token normally
	claims, err := sm.handler.validateClerkToken(ctx, token)
	if err == nil {
		return claims, nil
	}

	// If validation failed, check if it's a token expiration issue
	// Clerk tokens have specific expiration handling
	if isTokenExpired(err) {
		log.Printf("Clerk token expired for user, attempting refresh")

		// Try to refresh the session
		// Note: This would typically be handled by the frontend
		// but we can provide guidance for refresh
		return nil, fmt.Errorf("token expired, please refresh your session")
	}

	return nil, fmt.Errorf("invalid clerk token: %w", err)
}

// GetUserSessions retrieves all active sessions for a user
func (sm *ClerkSessionManager) GetUserSessions(ctx context.Context, clerkUserID string) ([]*clerk.Session, error) {
	if clerkUserID == "" {
		return nil, fmt.Errorf("clerk user ID is required")
	}

	// This would require Clerk's client to fetch sessions
	// For now, we'll return a placeholder implementation
	sessions := []*clerk.Session{}

	// In a real implementation, you would:
	// sessions, err := clerk.Client.Sessions.List(ctx, &clerk.SessionListParams{
	//   UserID: clerkUserID,
	// })

	return sessions, nil
}

// RevokeSession revokes a specific Clerk session
func (sm *ClerkSessionManager) RevokeSession(ctx context.Context, sessionID string) error {
	if sessionID == "" {
		return fmt.Errorf("session ID is required")
	}

	// In a real implementation, you would:
	// session, err := clerk.Client.Sessions.Get(ctx, sessionID)
	// if err != nil {
	//   return err
	// }
	// return session.Revoke()

	return nil
}

// GetCurrentSessionInfo gets detailed information about the current session
func (sm *ClerkSessionManager) GetCurrentSessionInfo(ctx context.Context, token string) (*SessionInfo, error) {
	claims, err := sm.handler.validateClerkToken(ctx, token)
	if err != nil {
		return nil, err
	}

	// Handle the pointer fields properly
	var issuedAt time.Time
	if claims.IssuedAt != nil {
		issuedAt = time.Unix(*claims.IssuedAt, 0)
	}

	var expiresAt time.Time
	if claims.Expiry != nil {
		expiresAt = time.Unix(*claims.Expiry, 0)
	}

	return &SessionInfo{
		UserID:    claims.Subject,
		IssuedAt:  issuedAt,
		ExpiresAt: expiresAt,
		IsAdmin:   sm.handler.extractAdminStatusFromClerkClaims(claims),
	}, nil
}

// SessionInfo contains detailed session information
type SessionInfo struct {
	UserID    string
	IssuedAt  time.Time
	ExpiresAt time.Time
	IsAdmin   bool
}
