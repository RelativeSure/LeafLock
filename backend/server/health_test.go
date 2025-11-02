package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReadyStateLifecycle(t *testing.T) {
	ready := NewReadyState(nil, nil, nil, nil)

	assert.False(t, ready.IsFullyReady())
	assert.False(t, ready.IsAdminReady())
	assert.False(t, ready.IsTemplatesReady())
	assert.False(t, ready.IsAllowlistReady())
	assert.False(t, ready.IsRedisReady())

	ready.MarkAdminReady()
	ready.MarkTemplatesReady()
	ready.MarkAllowlistReady()
	ready.MarkRedisReady()

	assert.True(t, ready.IsAdminReady())
	assert.True(t, ready.IsTemplatesReady())
	assert.True(t, ready.IsAllowlistReady())
	assert.True(t, ready.IsRedisReady())
	assert.True(t, ready.IsFullyReady())
}

func TestReadyStateGetters(t *testing.T) {
	ready := NewReadyState(nil, nil, nil, nil)
	assert.Nil(t, ready.GetDB())
	assert.Nil(t, ready.GetRedis())
	assert.Nil(t, ready.GetConfig())
	assert.Nil(t, ready.GetCrypto())
}
