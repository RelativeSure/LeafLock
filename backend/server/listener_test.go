package server

import (
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/require"
)

func supportsIPv6Loopback() bool {
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		return false
	}
	defer func() { _ = ln.Close() }() // Test cleanup

	done := make(chan struct{})
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			_ = conn.Close() // Test cleanup
		}
		close(done)
	}()

	conn, err := net.Dial("tcp6", ln.Addr().String())
	if err != nil {
		return false
	}
	_ = conn.Close() // Test cleanup
	<-done
	return true
}

func acquireRandomPort(t *testing.T) string {
	t.Helper()
	for i := 0; i < 20; i++ {
		candidate := 40000 + rand.IntN(20000)
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", candidate))
		if err != nil {
			continue
		}
		_ = ln.Close() // Test cleanup
		return fmt.Sprintf("%d", candidate)
	}
	t.Fatalf("failed to find available port after multiple attempts")
	return ""
}

func waitForHTTP(t *testing.T, url string, expect int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body) // Test operation
			_ = resp.Body.Close()                  // Test cleanup
			if resp.StatusCode == expect {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s to return %d", url, expect)
}

func waitForTCPDial(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			_ = conn.Close() // Test cleanup
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("timed out dialing %s", addr)
}

func TestListenWithIPv6Fallback_DualStackAcceptsIPv4AndIPv6(t *testing.T) {
	if !supportsIPv6Loopback() {
		t.Skip("skipping: IPv6 loopback not available")
	}

	port := acquireRandomPort(t)

	app := fiber.New()
	app.Get("/health", func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusNoContent)
	})

	errCh := make(chan error, 1)
	go func() {
		errCh <- ListenWithIPv6Fallback(app, port, time.Now())
	}()

	require.NoError(t, waitForTCPDial(fmt.Sprintf("[::1]:%s", port), 5*time.Second))
	waitForHTTP(t, fmt.Sprintf("http://[::1]:%s/health", port), http.StatusNoContent, 5*time.Second)
	waitForHTTP(t, fmt.Sprintf("http://127.0.0.1:%s/health", port), http.StatusNoContent, 5*time.Second)

	require.NoError(t, app.Shutdown())
	require.NoError(t, <-errCh)
}
