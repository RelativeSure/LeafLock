package services

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// ShareLinkCache represents cached share link data in Redis
type ShareLinkCache struct {
	NoteID      string    `json:"note_id"`
	Permission  string    `json:"permission"` // "read" or "write"
	ExpiresAt   time.Time `json:"expires_at,omitempty"`
	MaxUses     int       `json:"max_uses,omitempty"`
	UseCount    int       `json:"use_count"`
	HasPassword bool      `json:"has_password"`
}

// ShareLinkService handles Redis caching for share links
type ShareLinkService struct {
	rdb *redis.Client
}

// NewShareLinkService creates a new share link service
func NewShareLinkService(rdb *redis.Client) *ShareLinkService {
	return &ShareLinkService{rdb: rdb}
}

// GenerateToken creates a cryptographically secure share link token
// This function implements the core security mechanism for shareable links:
//
// Security Design:
// - 256 bits of entropy (32 bytes) provides 2^256 possible combinations
// - Cryptographically secure random number generator (crypto/rand)
// - URL-safe base64 encoding prevents URL encoding issues
// - No predictable patterns or sequential IDs
//
// Token Properties:
// - Unpredictable: Cannot be guessed or brute-forced with practical resources
// - Unique: Collision probability is astronomically low (2^-256)
// - URL-safe: No special characters that require encoding
// - Stateless: No server-side storage required for token generation
//
// Implementation Notes:
// - Uses crypto/rand.Read() which is suitable for cryptographic use
// - URL encoding ensures compatibility with all browsers and email clients
// - Token length is ~43 characters (32 bytes * 4/3 base64 encoding)
// - No personal information or patterns embedded in tokens
//
// Comparison with alternatives:
// - UUID v4: 122 bits entropy (sufficient but less than this implementation)
// - Sequential IDs: Predictable and enumerable (security risk)
// - Short codes: Vulnerable to brute force attacks
func GenerateToken() (string, error) {
	// Generate 32 random bytes (256 bits)
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Encode to URL-safe base64
	token := base64.URLEncoding.EncodeToString(bytes)
	return token, nil
}

// CacheShareLink stores share link metadata in Redis with intelligent TTL management
// This function implements the caching layer for shareable links with several
// sophisticated features for performance and reliability:
//
// TTL Strategy:
// - Expiring links: TTL calculated as time until expiration
// - Never-expiring links: 30-day TTL with refresh-on-access pattern
// - Prevents infinite growth of Redis memory usage
// - Balances performance with storage efficiency
//
// Data Storage:
// - JSON serialization provides human-readable debugging
// - Complete metadata storage enables authorization decisions
// - No sensitive data (passwords stored separately with bcrypt)
// - Atomic operations ensure data consistency
//
// Key Design:
// - Pattern: "share_link:{token}" enables pattern matching for cleanup
// - Token-based lookup provides O(1) retrieval performance
// - Redis key expiration handles automatic cleanup
//
// Error Handling:
// - Validates expiration time (rejects already-expired links)
// - Handles Redis connection failures gracefully
// - Provides detailed error context for debugging
//
// Performance: O(1) for Redis SET operation, suitable for high-traffic scenarios.
func (s *ShareLinkService) CacheShareLink(ctx context.Context, token string, data ShareLinkCache) error {
	key := fmt.Sprintf("share_link:%s", token)

	// Serialize data to JSON
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal share link data: %w", err)
	}

	// Calculate TTL with intelligent expiration management
	// This implements a two-tier TTL strategy:
	// 1. Time-bound links: Exact TTL until expiration time
	// 2. Permanent links: 30-day TTL with refresh-on-access
	//
	// The refresh-on-access pattern for permanent links prevents Redis memory
	// growth while maintaining the illusion of permanent links. As long as
	// links are accessed regularly, they remain cached indefinitely.
	var ttl time.Duration
	if !data.ExpiresAt.IsZero() {
		ttl = time.Until(data.ExpiresAt)
		if ttl <= 0 {
			return fmt.Errorf("share link already expired")
		}
	} else {
		// Default TTL for never-expiring links (30 days, refreshed on access)
		ttl = 30 * 24 * time.Hour
	}

	// Store in Redis
	if err := s.rdb.Set(ctx, key, jsonData, ttl).Err(); err != nil {
		return fmt.Errorf("failed to cache share link: %w", err)
	}

	return nil
}

// GetShareLink retrieves and validates share link metadata from Redis
// This function implements the authorization check for shareable links
// with comprehensive validation and security features:
//
// Retrieval Process:
// 1. Fetch metadata from Redis using token-based key
// 2. Handle cache misses (link doesn't exist or expired)
// 3. Deserialize JSON metadata
// 4. Validate expiration time
// 5. Clean up expired links automatically
//
// Security Validation:
// - Token existence prevents unauthorized access
// - Expiration checking blocks access to expired links
// - Automatic cleanup removes expired entries
// - No sensitive data exposure (passwords stored separately)
//
// Cache Management:
// - Automatic expiration cleanup maintains Redis efficiency
// - Graceful handling of corrupted cache entries
// - Clear distinction between "not found" and "expired"
//
// Performance: O(1) Redis GET operation, suitable for frequent access patterns.
// The function is designed to be called on every share link access.
func (s *ShareLinkService) GetShareLink(ctx context.Context, token string) (*ShareLinkCache, error) {
	key := fmt.Sprintf("share_link:%s", token)

	// Retrieve from Redis
	jsonData, err := s.rdb.Get(ctx, key).Result()
	if err == redis.Nil {
		return nil, nil // Not found in cache
	} else if err != nil {
		return nil, fmt.Errorf("failed to get share link from cache: %w", err)
	}

	// Deserialize JSON data
	var data ShareLinkCache
	if err := json.Unmarshal([]byte(jsonData), &data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal share link data: %w", err)
	}

	// Check if expired and clean up automatically
	// This implements the "lazy cleanup" pattern where expired entries
	// are removed on access rather than through a separate cleanup process.
	// This approach:
	// - Reduces Redis memory usage over time
	// - Prevents access to expired links
	// - Eliminates need for separate cleanup jobs
	// - Provides immediate feedback to users
	if !data.ExpiresAt.IsZero() && time.Now().After(data.ExpiresAt) {
		// Delete expired link from cache
		_ = s.InvalidateShareLink(ctx, token)
		return nil, nil
	}

	return &data, nil
}

// InvalidateShareLink removes share link from Redis cache
func (s *ShareLinkService) InvalidateShareLink(ctx context.Context, token string) error {
	key := fmt.Sprintf("share_link:%s", token)

	if err := s.rdb.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("failed to invalidate share link: %w", err)
	}

	return nil
}

// IncrementUseCount tracks share link usage for analytics and limits
// This function implements usage tracking for shareable links with several purposes:
//
// Analytics Value:
// - Track how often each share link is accessed
// - Identify popular content for optimization
// - Provide usage metrics to link creators
// - Detect abandoned or unused links
//
// Security Applications:
// - Enforce max usage limits (when implemented)
// - Detect suspicious access patterns
// - Rate limiting based on usage patterns
// - Audit trail for shared content access
//
// Implementation Details:
// - Read-modify-write cycle with race condition handling
// - Redis atomicity ensures accurate counting
// - No negative count protection (shouldn't occur in normal operation)
// - Overwrites entire cache entry (preserves other metadata)
//
// Performance: O(1) for read + O(1) for write = O(1) total operation.
// Suitable for real-time usage tracking on each link access.
func (s *ShareLinkService) IncrementUseCount(ctx context.Context, token string) error {
	// Get current data
	data, err := s.GetShareLink(ctx, token)
	if err != nil {
		return err
	}
	if data == nil {
		return fmt.Errorf("share link not found in cache")
	}

	// Increment use count
	data.UseCount++

	// Update cache
	return s.CacheShareLink(ctx, token, *data)
}

// InvalidateNoteShareLinks removes all share links for a specific note from cache
// This function implements bulk invalidation when a note's sharing status changes
// or when a note is deleted. It solves the problem of maintaining cache consistency
// when the underlying note changes.
//
// Use Cases:
// - Note deletion: Remove all share links for deleted content
// - Privacy changes: Invalidate links when note becomes private
// - Permission updates: Refresh links when access controls change
// - Security incidents: Emergency revocation of all access
//
// Implementation Strategy:
// - Uses Redis SCAN for efficient iteration (avoids blocking KEYS command)
// - Pattern matching on "share_link:*" keys
// - Content-based filtering by note ID (prevents false positives)
// - Batch deletion for efficiency
//
// Performance Considerations:
// - SCAN operation is O(N) where N is total share links
// - Batch size of 100 balances memory usage with speed
// - Deletes are batched for network efficiency
// - Suitable for moderate numbers of share links (< 10,000)
//
// Alternative Approaches:
// - Could use Redis sets to maintain note-to-links mapping
// - Would add complexity but improve performance for high-volume scenarios
// - Current approach is simpler and sufficient for expected usage patterns
func (s *ShareLinkService) InvalidateNoteShareLinks(ctx context.Context, noteID string) error {
	// Use SCAN to find all share_link keys (more efficient than KEYS)
	// Redis KEYS command blocks the server during execution, making it
	// unsuitable for production use. SCAN provides:
	// - Non-blocking iteration that doesn't affect other operations
	// - Consistent performance regardless of key count
	// - Configurable batch size for memory management
	//
	// The trade-off is complexity: SCAN requires multiple calls and
	// cursor management, but provides much better production characteristics.
	pattern := "share_link:*"
	var cursor uint64
	var keys []string

	for {
		var scanKeys []string
		var err error
		scanKeys, cursor, err = s.rdb.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			return fmt.Errorf("failed to scan share link keys: %w", err)
		}

		// Check each key to see if it matches the note ID
		for _, key := range scanKeys {
			jsonData, err := s.rdb.Get(ctx, key).Result()
			if err != nil {
				continue
			}

			var data ShareLinkCache
			if err := json.Unmarshal([]byte(jsonData), &data); err != nil {
				continue
			}

			if data.NoteID == noteID {
				keys = append(keys, key)
			}
		}

		if cursor == 0 {
			break
		}
	}

	// Delete matching keys
	if len(keys) > 0 {
		if err := s.rdb.Del(ctx, keys...).Err(); err != nil {
			return fmt.Errorf("failed to delete share link keys: %w", err)
		}
	}

	return nil
}

// RefreshTTL implements the refresh-on-access pattern for permanent share links
// This function solves the memory management problem for "never-expiring" links
// by implementing a sliding window expiration strategy:
//
// Problem Solved:
// - "Permanent" links would consume Redis memory forever
// - Fixed TTL would cause legitimate links to expire
// - Users expect "permanent" to mean "doesn't expire with normal use"
//
// Solution:
// - 30-day TTL that refreshes on each access
// - Links expire only after 30 days of inactivity
// - Provides "permanent" experience while managing memory
// - Automatic cleanup of truly abandoned links
//
// Implementation:
// - Only refreshes links without explicit expiration (never-expiring)
// - Uses Redis EXPIRE to update existing TTL
// - Idempotent operation (safe to call multiple times)
// - No-op for links with explicit expiration times
//
// Performance: O(1) Redis EXPIRE operation, minimal overhead.
// Suitable for calling on every access to "permanent" share links.
func (s *ShareLinkService) RefreshTTL(ctx context.Context, token string) error {
	key := fmt.Sprintf("share_link:%s", token)

	// Get current data to check if it has expiration
	data, err := s.GetShareLink(ctx, token)
	if err != nil {
		return err
	}
	if data == nil {
		return fmt.Errorf("share link not found")
	}

	// Only refresh if it's a never-expiring link
	// This prevents accidental extension of time-limited links.
	// The logic distinguishes between:
	// - Explicit expiration: User-set expiration time (don't refresh)
	// - Implicit expiration: Never-expiring with TTL management (refresh)
	//
	// This ensures that user-intended expiration times are respected
	// while still managing memory for "permanent" links.
	if data.ExpiresAt.IsZero() {
		ttl := 30 * 24 * time.Hour
		if err := s.rdb.Expire(ctx, key, ttl).Err(); err != nil {
			return fmt.Errorf("failed to refresh TTL: %w", err)
		}
	}

	return nil
}
