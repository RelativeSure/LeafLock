package utils

import (
	"net"
	"strings"
	"sync/atomic"

	"github.com/gofiber/fiber/v2"
)

var privateIPBlocks []*net.IPNet

// TrustProxyHeaders is a runtime feature toggle for proxy header trust
var TrustProxyHeaders atomic.Bool

func init() {
	blocks := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	}
	for _, cidr := range blocks {
		if _, block, err := net.ParseCIDR(cidr); err == nil {
			privateIPBlocks = append(privateIPBlocks, block)
		}
	}
}

// ClientIP returns the best-effort client address, honoring common proxy headers
func ClientIP(c *fiber.Ctx) string {
	if !TrustProxyHeaders.Load() {
		return c.IP()
	}
	if cf := strings.TrimSpace(c.Get("CF-Connecting-IP")); cf != "" {
		if ip := net.ParseIP(cf); ip != nil {
			return cf
		}
	}
	if forwarded := c.Get("X-Forwarded-For"); forwarded != "" {
		var fallback string
		for _, part := range strings.Split(forwarded, ",") {
			ip := strings.TrimSpace(part)
			if ip == "" || strings.ToLower(ip) == "unknown" {
				continue
			}
			parsed := net.ParseIP(ip)
			if parsed == nil {
				continue
			}
			if IsPublicIP(parsed) {
				return ip
			}
			if fallback == "" {
				fallback = ip
			}
		}
		if fallback != "" {
			return fallback
		}
	}
	if realIP := strings.TrimSpace(c.Get("X-Real-IP")); realIP != "" {
		if ip := net.ParseIP(realIP); ip != nil {
			return realIP
		}
	}
	if clientIPHeader := strings.TrimSpace(c.Get("X-Client-IP")); clientIPHeader != "" {
		if ip := net.ParseIP(clientIPHeader); ip != nil {
			return clientIPHeader
		}
	}
	return c.IP()
}

// IsPublicIP returns true if the IP is a public IP address
func IsPublicIP(ip net.IP) bool {
	if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
		return false
	}
	for _, block := range privateIPBlocks {
		if block.Contains(ip) {
			return false
		}
	}
	return true
}