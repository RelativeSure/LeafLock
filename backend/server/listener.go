package server

import (
	"context"
	"log"
	"net"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v2"
)

// ListenWithIPv6Fallback attempts to bind the server on IPv6 first, falling back to IPv4 if needed.
// This function implements dual-stack network support optimized for Railway's IPv6-only private network
// while maintaining compatibility with IPv4-only environments.
func ListenWithIPv6Fallback(app *fiber.App, port string, startupStart time.Time) error {
	addrIPv6 := "[::]:" + port
	log.Printf("🔵 [IPv6] Attempting to bind HTTP server on %s", addrIPv6)
	log.Printf("🔍 [NETWORK] Checking IPv6 stack availability...")

	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			if network != "tcp6" {
				return nil
			}

			var sockErr error
			if controlErr := c.Control(func(fd uintptr) {
				sockErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY, 0)
			}); controlErr != nil {
				return controlErr
			}
			return sockErr
		},
	}

	ln6, err := lc.Listen(context.Background(), "tcp6", addrIPv6)
	if err == nil {
		log.Printf("✅ [IPv6] Successfully bound to %s - IPv6 dual-stack available", addrIPv6)
		log.Printf("🌐 [STARTUP] HTTP server listening on %s (Railway IPv6 compatible) - startup time: %v", addrIPv6, time.Since(startupStart))
		return app.Listener(ln6)
	}

	log.Printf("❌ [IPv6] Failed to bind on %s: %v", addrIPv6, err)
	log.Printf("🔄 [FALLBACK] IPv6 binding failed, attempting IPv4 fallback...")

	addrIPv4 := "0.0.0.0:" + port
	log.Printf("🟡 [IPv4] Attempting to bind HTTP server on %s", addrIPv4)
	log.Printf("🌐 [STARTUP] HTTP server starting on %s (IPv4 fallback) - startup time: %v", addrIPv4, time.Since(startupStart))

	ln4, err := net.Listen("tcp4", addrIPv4)
	if err != nil {
		log.Printf("❌ [IPv4] Failed to bind on %s: %v", addrIPv4, err)
		log.Printf("💥 [FATAL] Both IPv6 and IPv4 binding failed - server cannot start")
		return err
	}

	log.Printf("✅ [IPv4] Successfully bound to %s (IPv6 not available)", addrIPv4)
	return app.Listener(ln4)
}
