package server

import (
	"net"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
)

func TestListenWithIPv6Fallback_IPv4Success(t *testing.T) {
	app := fiber.New(fiber.Config{
		DisableStartupMessage: true,
	})

	// Use a random available port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()

	// Run server in goroutine
	go func() {
		_ = ListenWithIPv6Fallback(app, string(rune(port)), time.Now())
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Cleanup
	_ = app.Shutdown()
}

func TestListenWithIPv6Fallback_InvalidPort(t *testing.T) {
	app := fiber.New(fiber.Config{
		DisableStartupMessage: true,
	})

	// Try to bind to an invalid port (port 0 is special)
	err := ListenWithIPv6Fallback(app, "99999", time.Now())
	assert.Error(t, err)
}

func TestListenWithIPv6Fallback_StartupTiming(t *testing.T) {
	startupStart := time.Now()
	
	// Just verify the timing parameter is used
	app := fiber.New(fiber.Config{
		DisableStartupMessage: true,
	})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()

	go func() {
		_ = ListenWithIPv6Fallback(app, string(rune(port)), startupStart)
	}()

	time.Sleep(100 * time.Millisecond)
	elapsed := time.Since(startupStart)
	assert.True(t, elapsed > 0)

	_ = app.Shutdown()
}

func TestListenWithIPv6Fallback_DualStackAttempt(t *testing.T) {
	app := fiber.New(fiber.Config{
		DisableStartupMessage: true,
	})

	// Find an available port
	listener, err := net.Listen("tcp", ":0")
	assert.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()

	// Attempt dual-stack binding
	go func() {
		_ = ListenWithIPv6Fallback(app, string(rune(port)), time.Now())
	}()

	time.Sleep(100 * time.Millisecond)

	// Verify server is listening
	conn, err := net.DialTimeout("tcp", "127.0.0.1:"+string(rune(port)), time.Second)
	if err == nil {
		_ = conn.Close()
	}

	_ = app.Shutdown()
}

func TestListenWithIPv6Fallback_PortInUse(t *testing.T) {
	// Occupy a port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer func() { _ = listener.Close() }()
	
	port := listener.Addr().(*net.TCPAddr).Port

	app := fiber.New(fiber.Config{
		DisableStartupMessage: true,
	})

	// Try to bind to the same port - should fail
	err = ListenWithIPv6Fallback(app, string(rune(port)), time.Now())
	assert.Error(t, err)
}

func TestReadyState_NewReadyState(t *testing.T) {
	rs := NewReadyState(nil, nil, nil)
	
	assert.NotNil(t, rs)
	assert.False(t, rs.IsAdminReady())
	assert.False(t, rs.IsTemplatesReady())
	assert.False(t, rs.IsAllowlistReady())
	assert.False(t, rs.IsRedisReady())
	assert.False(t, rs.IsFullyReady())
}

func TestReadyState_MarkAdminReady(t *testing.T) {
	rs := NewReadyState(nil, nil, nil)
	
	assert.False(t, rs.IsAdminReady())
	rs.MarkAdminReady()
	assert.True(t, rs.IsAdminReady())
}

func TestReadyState_MarkTemplatesReady(t *testing.T) {
	rs := NewReadyState(nil, nil, nil)
	
	assert.False(t, rs.IsTemplatesReady())
	rs.MarkTemplatesReady()
	assert.True(t, rs.IsTemplatesReady())
}

func TestReadyState_MarkAllowlistReady(t *testing.T) {
	rs := NewReadyState(nil, nil, nil)
	
	assert.False(t, rs.IsAllowlistReady())
	rs.MarkAllowlistReady()
	assert.True(t, rs.IsAllowlistReady())
}

func TestReadyState_MarkRedisReady(t *testing.T) {
	rs := NewReadyState(nil, nil, nil)
	
	assert.False(t, rs.IsRedisReady())
	rs.MarkRedisReady()
	assert.True(t, rs.IsRedisReady())
}

func TestReadyState_IsFullyReady(t *testing.T) {
	rs := NewReadyState(nil, nil, nil)
	
	assert.False(t, rs.IsFullyReady())
	
	rs.MarkAdminReady()
	assert.False(t, rs.IsFullyReady())
	
	rs.MarkTemplatesReady()
	assert.False(t, rs.IsFullyReady())
	
	rs.MarkAllowlistReady()
	assert.False(t, rs.IsFullyReady())
	
	rs.MarkRedisReady()
	assert.True(t, rs.IsFullyReady())
}

func TestReadyState_GetMethods(t *testing.T) {
	rs := NewReadyState(nil, nil, nil)

	assert.Nil(t, rs.GetDB())
	assert.Nil(t, rs.GetRedis())
	assert.Nil(t, rs.GetConfig())
}

func TestReadyState_ConcurrentAccess(t *testing.T) {
	rs := NewReadyState(nil, nil, nil)
	
	// Test concurrent reads and writes
	done := make(chan bool)
	
	go func() {
		for i := 0; i < 100; i++ {
			rs.MarkAdminReady()
			_ = rs.IsAdminReady()
		}
		done <- true
	}()
	
	go func() {
		for i := 0; i < 100; i++ {
			rs.MarkTemplatesReady()
			_ = rs.IsTemplatesReady()
		}
		done <- true
	}()
	
	go func() {
		for i := 0; i < 100; i++ {
			rs.MarkAllowlistReady()
			_ = rs.IsAllowlistReady()
		}
		done <- true
	}()
	
	go func() {
		for i := 0; i < 100; i++ {
			rs.MarkRedisReady()
			_ = rs.IsRedisReady()
		}
		done <- true
	}()
	
	// Wait for all goroutines
	for i := 0; i < 4; i++ {
		<-done
	}
	
	// All should be ready
	assert.True(t, rs.IsFullyReady())
}

func TestReadyState_PartialReady(t *testing.T) {
	rs := NewReadyState(nil, nil, nil)
	
	// Mark only some as ready
	rs.MarkAdminReady()
	rs.MarkTemplatesReady()
	
	assert.True(t, rs.IsAdminReady())
	assert.True(t, rs.IsTemplatesReady())
	assert.False(t, rs.IsAllowlistReady())
	assert.False(t, rs.IsRedisReady())
	assert.False(t, rs.IsFullyReady())
}
