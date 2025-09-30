package server

import (
	"sync/atomic"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"leaflock/config"
)

// CryptoService interface defines cryptographic operations needed by the server
type CryptoService interface {
	Encrypt(plaintext []byte) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
}

// ReadyState tracks initialization state for health checks
type ReadyState struct {
	db             *pgxpool.Pool
	crypto         CryptoService
	config         *config.Config
	rdb            *redis.Client
	adminReady     atomic.Bool
	templatesReady atomic.Bool
	allowlistReady atomic.Bool
	redisReady     atomic.Bool
}

// NewReadyState creates a new ReadyState instance
func NewReadyState(db *pgxpool.Pool, crypto CryptoService, cfg *config.Config, rdb *redis.Client) *ReadyState {
	return &ReadyState{
		db:     db,
		crypto: crypto,
		config: cfg,
		rdb:    rdb,
	}
}

// MarkAdminReady marks the admin initialization as complete
func (r *ReadyState) MarkAdminReady() {
	r.adminReady.Store(true)
}

// MarkTemplatesReady marks the templates initialization as complete
func (r *ReadyState) MarkTemplatesReady() {
	r.templatesReady.Store(true)
}

// MarkAllowlistReady marks the allowlist initialization as complete
func (r *ReadyState) MarkAllowlistReady() {
	r.allowlistReady.Store(true)
}

// MarkRedisReady marks the Redis initialization as complete
func (r *ReadyState) MarkRedisReady() {
	r.redisReady.Store(true)
}

// IsFullyReady returns true if all initialization steps are complete
func (r *ReadyState) IsFullyReady() bool {
	return r.adminReady.Load() &&
		r.templatesReady.Load() &&
		r.allowlistReady.Load() &&
		r.redisReady.Load()
}

// GetDB returns the database connection pool
func (r *ReadyState) GetDB() *pgxpool.Pool {
	return r.db
}

// GetRedis returns the Redis client
func (r *ReadyState) GetRedis() *redis.Client {
	return r.rdb
}

// GetConfig returns the application configuration
func (r *ReadyState) GetConfig() *config.Config {
	return r.config
}

// GetCrypto returns the crypto service
func (r *ReadyState) GetCrypto() CryptoService {
	return r.crypto
}

// IsAdminReady returns true if admin initialization is complete
func (r *ReadyState) IsAdminReady() bool {
	return r.adminReady.Load()
}

// IsTemplatesReady returns true if templates initialization is complete
func (r *ReadyState) IsTemplatesReady() bool {
	return r.templatesReady.Load()
}

// IsAllowlistReady returns true if allowlist initialization is complete
func (r *ReadyState) IsAllowlistReady() bool {
	return r.allowlistReady.Load()
}

// IsRedisReady returns true if Redis initialization is complete
func (r *ReadyState) IsRedisReady() bool {
	return r.redisReady.Load()
}