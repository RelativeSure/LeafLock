package server

import (
	"testing"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

func TestReadyStateAccessors(t *testing.T) {
	ready := NewReadyState(nil, nil, nil, redis.NewClient(&redis.Options{Addr: "localhost:0"}))
	require.False(t, ready.IsFullyReady())

	ready.MarkAdminReady()
	ready.MarkTemplatesReady()
	ready.MarkAllowlistReady()
	ready.MarkRedisReady()
	require.True(t, ready.IsFullyReady())

	if ready.GetDB() != nil {
		t.Fatalf("expected nil DB by default")
	}
	if ready.GetConfig() != nil {
		t.Fatalf("expected nil config by default")
	}
	if ready.GetRedis() == nil {
		t.Fatalf("expected redis client to be set")
	}
}
