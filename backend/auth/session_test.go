package auth

import (
	"context"
	"crypto/rand"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	appcrypto "leaflock/crypto"
)

func newTestSessionManager(t *testing.T) (*SessionManager, *redis.Client, func()) {
	t.Helper()

	mr := miniredis.RunT(t)

	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	sm := NewSessionManager(rdb, appcrypto.NewCryptoService(key))

	cleanup := func() {
		require.NoError(t, rdb.Close())
		mr.Close()
	}

	return sm, rdb, cleanup
}

func TestSessionLifecycle(t *testing.T) {
	sm, _, cleanup := newTestSessionManager(t)
	defer cleanup()

	ctx := context.Background()
	userID := uuid.New()

	session, token, err := sm.CreateSession(ctx, userID, "127.0.0.1", "test-agent", true)
	require.NoError(t, err)
	require.NotNil(t, session)
	require.NotEmpty(t, token)

	fetched, err := sm.GetSession(ctx, token)
	require.NoError(t, err)
	assert.Equal(t, userID, fetched.UserID)
	assert.Equal(t, "127.0.0.1", fetched.IPAddress)
	assert.Equal(t, "test-agent", fetched.UserAgent)
	assert.True(t, fetched.MFAVerified)

	require.NoError(t, sm.DeleteSession(ctx, token))

	_, err = sm.GetSession(ctx, token)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "session not found")
}

func TestRefreshSessionExtendsExpiration(t *testing.T) {
	sm, _, cleanup := newTestSessionManager(t)
	defer cleanup()

	ctx := context.Background()
	userID := uuid.New()

	session, token, err := sm.CreateSession(ctx, userID, "192.168.1.10", "refresh-agent", false)
	require.NoError(t, err)

	initialExpiry := session.ExpiresAt

	time.Sleep(10 * time.Millisecond)
	require.NoError(t, sm.RefreshSession(ctx, token))

	refreshed, err := sm.GetSession(ctx, token)
	require.NoError(t, err)
	assert.True(t, refreshed.ExpiresAt.After(initialExpiry))
}

func TestMFASessionLifecycle(t *testing.T) {
	sm, _, cleanup := newTestSessionManager(t)
	defer cleanup()

	ctx := context.Background()
	userID := uuid.New()

	token, err := sm.CreateMFASession(ctx, userID, "test@example.com", "10.0.0.1", "mfa-agent", true)
	require.NoError(t, err)
	require.NotEmpty(t, token)

	mfaSession, err := sm.GetMFASession(ctx, token)
	require.NoError(t, err)
	assert.Equal(t, userID, mfaSession.UserID)
	assert.Equal(t, "test@example.com", mfaSession.Email)
	assert.Equal(t, true, mfaSession.MFAEnabled)

	require.NoError(t, sm.DeleteMFASession(ctx, token))

	_, err = sm.GetMFASession(ctx, token)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "MFA session not found")
}


