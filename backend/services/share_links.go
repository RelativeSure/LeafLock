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
	NoteID     string    `json:"note_id"`
	Permission string    `json:"permission"` // "read" or "write"
	ExpiresAt  time.Time `json:"expires_at,omitempty"`
	MaxUses    int       `json:"max_uses,omitempty"`
	UseCount   int       `json:"use_count"`
	HasPassword bool     `json:"has_password"`
}

// ShareLinkService handles Redis caching for share links
type ShareLinkService struct {
	rdb *redis.Client
}

// NewShareLinkService creates a new share link service
func NewShareLinkService(rdb *redis.Client) *ShareLinkService {
	return &ShareLinkService{rdb: rdb}
}

// GenerateToken generates a cryptographically secure URL-safe token
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

// CacheShareLink stores share link data in Redis with appropriate TTL
func (s *ShareLinkService) CacheShareLink(ctx context.Context, token string, data ShareLinkCache) error {
	key := fmt.Sprintf("share_link:%s", token)

	// Serialize data to JSON
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal share link data: %w", err)
	}

	// Calculate TTL
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

// GetShareLink retrieves share link data from Redis cache
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

	// Check if expired
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

// IncrementUseCount increments the use count for a share link in cache
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
func (s *ShareLinkService) InvalidateNoteShareLinks(ctx context.Context, noteID string) error {
	// Use SCAN to find all share_link keys (more efficient than KEYS)
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

// RefreshTTL extends the TTL for a share link (used when accessing never-expiring links)
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
	if data.ExpiresAt.IsZero() {
		ttl := 30 * 24 * time.Hour
		if err := s.rdb.Expire(ctx, key, ttl).Err(); err != nil {
			return fmt.Errorf("failed to refresh TTL: %w", err)
		}
	}

	return nil
}
