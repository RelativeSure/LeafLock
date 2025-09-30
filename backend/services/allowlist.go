package services

import (
	"bufio"
	"bytes"
	"log"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

// adminAllowlist holds the current admin allowlist as an atomic value
var adminAllowlist atomic.Value // holds map[string]struct{}

func init() {
	adminAllowlist.Store(make(map[string]struct{}))
}

// CurrentAllowlist returns the current admin allowlist
func CurrentAllowlist() map[string]struct{} {
	v := adminAllowlist.Load()
	if v == nil {
		return map[string]struct{}{}
	}
	return v.(map[string]struct{})
}

// IsUserInAdminAllowlist checks if a user ID is in the admin allowlist
func IsUserInAdminAllowlist(userID string) bool {
	if _, ok := CurrentAllowlist()[strings.TrimSpace(userID)]; ok {
		return true
	}
	// Backward-compat: also check process env in case watcher not configured
	envAdmins := strings.Split(os.Getenv("ADMIN_USER_IDS"), ",")
	for _, a := range envAdmins {
		if strings.TrimSpace(a) == strings.TrimSpace(userID) {
			return true
		}
	}
	return false
}

// LoadAllowlistFromSources loads the admin allowlist from environment and file sources
func LoadAllowlistFromSources(envList string, filePath string) (map[string]struct{}, string) {
	m := make(map[string]struct{})
	var buf bytes.Buffer
	// include env first
	if envList != "" {
		buf.WriteString("ENV:")
		buf.WriteString(envList)
		buf.WriteString("\n")
		for _, a := range strings.Split(envList, ",") {
			a = strings.TrimSpace(a)
			if a != "" {
				m[a] = struct{}{}
			}
		}
	}
	// include file if present
	if filePath != "" {
		if f, err := os.Open(filePath); err == nil {
			defer f.Close()
			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				if strings.HasPrefix(line, "ADMIN_USER_IDS=") {
					val := strings.TrimSpace(strings.TrimPrefix(line, "ADMIN_USER_IDS="))
					// strip quotes if present
					val = strings.Trim(val, "\"'")
					buf.WriteString("FILE:")
					buf.WriteString(val)
					buf.WriteString("\n")
					for _, a := range strings.Split(val, ",") {
						a = strings.TrimSpace(a)
						if a != "" {
							m[a] = struct{}{}
						}
					}
				}
			}
		}
	}
	return m, buf.String()
}

// StartAdminAllowlistRefresher starts a background goroutine that refreshes the admin allowlist every 5 seconds
func StartAdminAllowlistRefresher() {
	filePath := strings.TrimSpace(os.Getenv("ADMIN_USER_IDS_FILE"))
	// initial load
	m, _ := LoadAllowlistFromSources(os.Getenv("ADMIN_USER_IDS"), filePath)
	adminAllowlist.Store(m)
	go func() {
		var lastSig string
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			m, sig := LoadAllowlistFromSources(os.Getenv("ADMIN_USER_IDS"), filePath)
			if sig != lastSig {
				adminAllowlist.Store(m)
				lastSig = sig
				log.Printf("🔄 Admin allowlist reloaded (%d entries)", len(m))
			}
		}
	}()
}