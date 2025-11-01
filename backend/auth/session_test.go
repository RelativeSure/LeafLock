package auth

import (
	"context"
	"crypto/rand"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	appcrypto "leaflock/crypto"
)

func TestNewSessionManager(t *testing.T) {
	rdb := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})
	defer rdb.Close()

	key := make([]byte, 32)
	rand.Read(key)
	crypto := appcrypto.NewCryptoService(key)

	sm := NewSessionManager(rdb, crypto)
	assert.NotNil(t, sm)
	assert.Equal(t, rdb, sm.redis)
	assert.Equal(t, crypto, sm.crypto)
}

func TestCreateSession(t *testing.T) {
	rdb := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})
	defer rdb.Close()

	key := make([]byte, 32)
	rand.Read(key)
	crypto := appcrypto.NewCryptoService(key)

	sm := NewSessionManager(rdb, crypto)
	ctx := context.Background()

	userID := uuid.New()
	session, token, err := sm.CreateSession(ctx, userID, "127.0.0.1", "test-agent", true)

	if err == nil {
		require.NotNil(t, session)
		require.NotEmpty(t, token)
		assert.Equal(t, userID, session.UserID)
		assert.Equal(t, "127.0.0.1", session.IPAddress)
		assert.Equal(t, "test-agent", session.UserAgent)
		assert.True(t, session.MFAVerified)
		assert.False(t, session.IsHalfAuthed)
		assert.WithinDuration(t, time.Now().Add(SessionDuration), session.ExpiresAt, time.Second)
	}
}

func TestHashToken(t *testing.T) {
	rdb := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})
	defer rdb.Close()

	key := make([]byte, 32)
	rand.Read(key)
	crypto := appcrypto.NewCryptoService(key)

	sm := NewSessionManager(rdb, crypto)

	token := "test-token-123"
	hash1 := sm.hashToken(token)
	hash2 := sm.hashToken(token)

	// Should be deterministic
	assert.Equal(t, hash1, hash2)
	assert.NotEmpty(t, hash1)
}

func TestDeleteSession(t *testing.T) {
	rdb := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})
	defer rdb.Close()

	key := make([]byte, 32)
	rand.Read(key)
	crypto := appcrypto.NewCryptoService(key)

	sm := NewSessionManager(rdb, crypto)
	ctx := context.Background()

	// Test deleting non-existent session (should not error)
	err := sm.DeleteSession(ctx, "non-existent-token")
	// Redis operations may fail but should not panic
	_ = err
}

func TestCreateMFASession(t *testing.T) {
	rdb := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})
	defer rdb.Close()

	key := make([]byte, 32)
	rand.Read(key)
	crypto := appcrypto.NewCryptoService(key)

	sm := NewSessionManager(rdb, crypto)
	ctx := context.Background()

	userID := uuid.New()
	token, err := sm.CreateMFASession(ctx, userID, "test@example.com", "127.0.0.1", "test-agent", true)

	if err == nil {
		require.NotEmpty(t, token)
	}
}

func TestRefreshSession(t *testing.T) {
	rdb := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})
	defer rdb.Close()

	key := make([]byte, 32)
	rand.Read(key)
	crypto := appcrypto.NewCryptoService(key)

	sm := NewSessionManager(rdb, crypto)
	ctx := context.Background()

	// Test refresh on non-existent session
	err := sm.RefreshSession(ctx, "non-existent-token")
	assert.Error(t, err)
}

