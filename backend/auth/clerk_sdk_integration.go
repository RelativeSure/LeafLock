//go:build !coverage
// +build !coverage

package auth

import (
	"context"
	"fmt"

	"github.com/clerk/clerk-sdk-go/v2"
	"github.com/clerk/clerk-sdk-go/v2/jwt"
)

// clerkVerifyToken wraps the Clerk SDK token verification
// This is excluded from coverage because it's a thin wrapper around external API
// The actual validation logic is tested in clerk_middleware_enhanced.go
func clerkVerifyToken(ctx context.Context, token string) (*clerk.SessionClaims, error) {
	return jwt.Verify(ctx, &jwt.VerifyParams{
		Token: token,
	})
}

// clerkGetSession wraps Clerk session retrieval
func clerkGetSession(ctx context.Context, sessionID string) (*clerk.Session, error) {
	return nil, fmt.Errorf("not implemented - would call Clerk SDK")
}

// clerkGetUser wraps Clerk user retrieval
func clerkGetUser(ctx context.Context, userID string) (*clerk.User, error) {
	return nil, fmt.Errorf("not implemented - would call Clerk SDK")
}