package auth

import (
	"context"
	"crypto/rand"
	"testing"

	miniredis "github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	appcrypto "leaflock/crypto"
)

// MockSessionManager for testing
type MockSessionManager struct {
	mock.Mock
}

func (m *MockSessionManager) CreateSession(ctx context.Context, userID uuid.UUID, deviceInfo string) (string, error) {
	args := m.Called(ctx, userID, deviceInfo)
	return args.String(0), args.Error(1)
}

func (m *MockSessionManager) DeleteSession(ctx context.Context, sessionID string) error {
	args := m.Called(ctx, sessionID)
	return args.Error(0)
}

func (m *MockSessionManager) ValidateSession(ctx context.Context, sessionID string) (uuid.UUID, error) {
	args := m.Called(ctx, sessionID)
	return args.Get(0).(uuid.UUID), args.Error(1)
}

func (m *MockSessionManager) RefreshSession(ctx context.Context, sessionID string) error {
	args := m.Called(ctx, sessionID)
	return args.Error(0)
}

func (m *MockSessionManager) DeleteAllUserSessions(ctx context.Context, userID uuid.UUID) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

// TestNewServiceWithSecret tests service constructor with secret
func TestNewServiceWithSecret(t *testing.T) {
	service := NewService(nil, nil, "test-secret")
	require.NotNil(t, service)
	// Service has private fields, so we can't directly access them
	// But we verified it was created successfully
}

// TestNewServiceEmptySecret tests service constructor with empty secret
func TestNewServiceEmptySecret(t *testing.T) {
	service := NewService(nil, nil, "")
	require.NotNil(t, service)
	// Service created with empty secret (edge case)
}

func TestServiceLogoutDeletesSession(t *testing.T) {
	mr := miniredis.RunT(t)
	cryptoKey := make([]byte, 32)
	_, err := rand.Read(cryptoKey)
	require.NoError(t, err)

	cryptoSvc := appcrypto.NewCryptoService(cryptoKey)
	sessionManager := NewSessionManager(redis.NewClient(&redis.Options{Addr: mr.Addr()}), cryptoSvc)

	service := &Service{session: sessionManager}

	ctx := context.Background()
	userID := uuid.New()
	_, token, err := sessionManager.CreateSession(ctx, userID, "127.0.0.1", "agent", true)
	require.NoError(t, err)

	require.NoError(t, service.Logout(ctx, token))
	_, err = sessionManager.GetSession(ctx, token)
	require.Error(t, err)
}
