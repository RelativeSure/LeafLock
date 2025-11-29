package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/argon2"
	appcrypto "leaflock/crypto"
)

const (
	// Session durations
	SessionDuration    = 24 * time.Hour
	MFASessionDuration = 5 * time.Minute

	// Redis key prefixes
	sessionPrefix    = "session:"
	mfaSessionPrefix = "mfa_session:"
)

// SessionManager handles session operations
type SessionManager struct {
	redis  *redis.Client
	crypto *appcrypto.CryptoService // Derived from system secret, not server encryption key
}

// NewSessionManager creates a new session manager
// Zero-knowledge: crypto param is system-derived, not from SERVER_ENCRYPTION_KEY
func NewSessionManager(rdb *redis.Client, crypto *appcrypto.CryptoService) *SessionManager {
	return &SessionManager{
		redis:  rdb,
		crypto: crypto,
	}
}

// CreateSession creates a new authenticated session
func (sm *SessionManager) CreateSession(ctx context.Context, userID uuid.UUID, ipAddress, userAgent string, mfaVerified bool) (*Session, string, error) {
	// Generate secure session token (32 bytes = 256 bits)
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, "", fmt.Errorf("failed to generate session token: %w", err)
	}
	token := base64.URLEncoding.EncodeToString(tokenBytes)

	// Create session
	session := &Session{
		UserID:       userID,
		Token:        token,
		IPAddress:    ipAddress,
		UserAgent:    userAgent,
		CreatedAt:    time.Now().UTC(),
		ExpiresAt:    time.Now().UTC().Add(SessionDuration),
		MFAVerified:  mfaVerified,
		IsHalfAuthed: false,
	}

	// Hash token for Redis key (Argon2id for consistency)
	tokenHash := sm.hashToken(token)
	redisKey := sessionPrefix + tokenHash

	// Serialize session
	sessionData, err := json.Marshal(session)
	if err != nil {
		return nil, "", fmt.Errorf("failed to marshal session: %w", err)
	}

	// Encrypt session data
	encryptedData, err := sm.crypto.EncryptBytes(sessionData)
	if err != nil {
		return nil, "", fmt.Errorf("failed to encrypt session: %w", err)
	}

	// Store in Redis with expiration
	if err := sm.redis.Set(ctx, redisKey, encryptedData, SessionDuration).Err(); err != nil {
		return nil, "", fmt.Errorf("failed to store session: %w", err)
	}

	return session, token, nil
}

// GetSession retrieves a session by token
func (sm *SessionManager) GetSession(ctx context.Context, token string) (*Session, error) {
	tokenHash := sm.hashToken(token)
	redisKey := sessionPrefix + tokenHash

	// Get encrypted session from Redis
	encryptedData, err := sm.redis.Get(ctx, redisKey).Bytes()
	if err == redis.Nil {
		return nil, fmt.Errorf("session not found or expired")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	// Decrypt session
	sessionData, err := sm.crypto.DecryptBytes(encryptedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt session: %w", err)
	}

	// Unmarshal session
	var session Session
	if err := json.Unmarshal(sessionData, &session); err != nil {
		return nil, fmt.Errorf("failed to unmarshal session: %w", err)
	}

	// Check expiration
	if time.Now().UTC().After(session.ExpiresAt) {
		_ = sm.DeleteSession(ctx, token) // Clean up expired session
		return nil, fmt.Errorf("session expired")
	}

	return &session, nil
}

// DeleteSession removes a session
func (sm *SessionManager) DeleteSession(ctx context.Context, token string) error {
	tokenHash := sm.hashToken(token)
	redisKey := sessionPrefix + tokenHash

	if err := sm.redis.Del(ctx, redisKey).Err(); err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}

	return nil
}


// CreateMFASession creates a temporary MFA verification session
func (sm *SessionManager) CreateMFASession(ctx context.Context, userID uuid.UUID, email, ipAddress, userAgent string, mfaEnabled bool) (string, error) {
	// Generate MFA session token
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", fmt.Errorf("failed to generate MFA session token: %w", err)
	}
	token := base64.URLEncoding.EncodeToString(tokenBytes)

	// Create MFA session
	mfaSession := &MFASession{
		UserID:           userID,
		Email:            email,
		IPAddress:        ipAddress,
		UserAgent:        userAgent,
		CreatedAt:        time.Now().UTC(),
		ExpiresAt:        time.Now().UTC().Add(MFASessionDuration),
		MFAEnabled:       mfaEnabled,
		PasswordVerified: true,
	}

	// Hash token for Redis key
	tokenHash := sm.hashToken(token)
	redisKey := mfaSessionPrefix + tokenHash

	// Serialize and encrypt
	sessionData, err := json.Marshal(mfaSession)
	if err != nil {
		return "", fmt.Errorf("failed to marshal MFA session: %w", err)
	}

	encryptedData, err := sm.crypto.EncryptBytes(sessionData)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt MFA session: %w", err)
	}

	// Store in Redis with expiration
	if err := sm.redis.Set(ctx, redisKey, encryptedData, MFASessionDuration).Err(); err != nil {
		return "", fmt.Errorf("failed to store MFA session: %w", err)
	}

	return token, nil
}

// GetMFASession retrieves an MFA session
func (sm *SessionManager) GetMFASession(ctx context.Context, token string) (*MFASession, error) {
	tokenHash := sm.hashToken(token)
	redisKey := mfaSessionPrefix + tokenHash

	// Get encrypted session from Redis
	encryptedData, err := sm.redis.Get(ctx, redisKey).Bytes()
	if err == redis.Nil {
		return nil, fmt.Errorf("MFA session not found or expired")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get MFA session: %w", err)
	}

	// Decrypt session
	sessionData, err := sm.crypto.DecryptBytes(encryptedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt MFA session: %w", err)
	}

	// Unmarshal session
	var mfaSession MFASession
	if err := json.Unmarshal(sessionData, &mfaSession); err != nil {
		return nil, fmt.Errorf("failed to unmarshal MFA session: %w", err)
	}

	// Check expiration
	if time.Now().UTC().After(mfaSession.ExpiresAt) {
		_ = sm.DeleteMFASession(ctx, token) // Clean up expired session
		return nil, fmt.Errorf("MFA session expired")
	}

	return &mfaSession, nil
}

// DeleteMFASession removes an MFA session
func (sm *SessionManager) DeleteMFASession(ctx context.Context, token string) error {
	tokenHash := sm.hashToken(token)
	redisKey := mfaSessionPrefix + tokenHash

	if err := sm.redis.Del(ctx, redisKey).Err(); err != nil {
		return fmt.Errorf("failed to delete MFA session: %w", err)
	}

	return nil
}

// hashToken creates a deterministic hash of a token for Redis keys
func (sm *SessionManager) hashToken(token string) string {
	// Use Argon2id for consistent hashing (lighter params for token hashing)
	hash := argon2.IDKey([]byte(token), []byte("session-salt"), 1, 32*1024, 2, 32)
	return base64.URLEncoding.EncodeToString(hash)
}

// RefreshSession extends the session expiration
func (sm *SessionManager) RefreshSession(ctx context.Context, token string) error {
	session, err := sm.GetSession(ctx, token)
	if err != nil {
		return err
	}

	// Update expiration
	session.ExpiresAt = time.Now().UTC().Add(SessionDuration)

	// Re-save session
	tokenHash := sm.hashToken(token)
	redisKey := sessionPrefix + tokenHash

	sessionData, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("failed to marshal session: %w", err)
	}

	encryptedData, err := sm.crypto.EncryptBytes(sessionData)
	if err != nil {
		return fmt.Errorf("failed to encrypt session: %w", err)
	}

	if err := sm.redis.Set(ctx, redisKey, encryptedData, SessionDuration).Err(); err != nil {
		return fmt.Errorf("failed to refresh session: %w", err)
	}

	return nil
}
