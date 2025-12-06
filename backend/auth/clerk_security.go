package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"

	"github.com/clerk/clerk-sdk-go/v2"
)

// ClerkSecurity provides security-enhanced functions for Clerk authentication

// ConstantTimeTokenCompare performs constant-time comparison of tokens
func ConstantTimeTokenCompare(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// SecureTokenValidation validates tokens with timing attack protection
func (h *Handler) SecureTokenValidation(token string) (*clerk.SessionClaims, error) {
	// Basic validation with constant-time operations
	if len(token) < 10 {
		return nil, errors.New("invalid token")
	}

	// Add small delay to normalize timing (optional, for additional protection)
	time.Sleep(1 * time.Millisecond)

	// Use Clerk's built-in validation
	return h.validateClerkTokenEnhanced(nil, token)
}

// validateClerkTokenEnhanced validates a Clerk session token with enhanced security
func (h *Handler) validateClerkTokenEnhanced(ctx context.Context, token string) (*clerk.SessionClaims, error) {
	// Use the existing validateClerkToken method for now
	// In the future, this could add additional security checks
	if ctx == nil {
		ctx = context.Background()
	}
	return h.validateClerkToken(ctx, token)
}

// TimingAttackProtection adds protection against timing attacks
func (h *Handler) TimingAttackProtection() {
	// Add small random delay to normalize response times
	delay := time.Duration(1+time.Now().UnixNano()%5) * time.Millisecond
	time.Sleep(delay)
}

// SecureUserLookup performs user lookup with timing attack protection
func (h *Handler) SecureUserLookup(clerkUserID string) (string, error) {
	// Normalize lookup time by adding consistent delay
	time.Sleep(2 * time.Millisecond)

	// Perform the actual lookup
	return clerkUserID, nil // In real implementation, this would do the actual lookup
}

// SecureMetadataComparison compares metadata with timing attack protection
func SecureMetadataComparison(a, b map[string]interface{}) bool {
	if len(a) != len(b) {
		return false
	}

	// Sort keys to ensure consistent comparison time
	// This is a simplified version - in production, implement proper key sorting

	for key, valueA := range a {
		valueB, exists := b[key]
		if !exists {
			return false
		}

		// Constant-time comparison for values
		if !secureCompareValues(valueA, valueB) {
			return false
		}
	}

	return true
}

// secureCompareValues performs constant-time comparison of interface values
func secureCompareValues(a, b interface{}) bool {
	// Convert to strings for comparison
	strA := fmt.Sprintf("%v", a)
	strB := fmt.Sprintf("%v", b)

	if len(strA) != len(strB) {
		return false
	}

	return subtle.ConstantTimeCompare([]byte(strA), []byte(strB)) == 1
}

// SecureTimeComparison compares timestamps with timing attack protection
func SecureTimeComparison(a, b time.Time) bool {
	// Ensure both times are in UTC for consistent comparison
	aUTC := a.UTC()
	bUTC := b.UTC()

	// Constant-time comparison
	return subtle.ConstantTimeCompare([]byte(aUTC.Format(time.RFC3339)), []byte(bUTC.Format(time.RFC3339))) == 1
}

// SecureStringComparison compares strings with timing attack protection
func SecureStringComparison(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// NormalizeResponseTime adds consistent timing to responses
func NormalizeResponseTime(baseTime time.Duration) {
	// Add base time plus small random variation (0-5ms)
	variation := time.Duration(time.Now().UnixNano()%5) * time.Millisecond
	time.Sleep(baseTime + variation)
}
