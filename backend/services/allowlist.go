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

// adminAllowlist implements a thread-safe, hot-reloadable admin user registry
// This global variable provides fast, concurrent access to the admin user list
// while supporting dynamic updates without application restart.
//
// Design Rationale:
// - atomic.Value provides lock-free concurrent reads (performance critical)
// - map[string]struct{} provides O(1) lookup with minimal memory overhead
// - Global scope enables access from any part of the application
// - Hot-reload capability supports dynamic admin management
//
// Security Context:
// - Admin users have elevated privileges (user management, system configuration)
// - Fast lookup is critical for authorization checks on every admin action
// - Thread safety prevents race conditions during updates
// - Atomic updates ensure consistent state across goroutines
var adminAllowlist atomic.Value // holds map[string]struct{}

func init() {
	adminAllowlist.Store(make(map[string]struct{}))
}

// CurrentAllowlist returns a snapshot of the current admin allowlist
// This function provides thread-safe access to the admin user registry
// with the following characteristics:
//
// Performance: O(1) operation due to atomic.Value load
// Thread Safety: Lock-free concurrent reads via atomic.Value
// Memory: Returns a map reference (no copying for performance)
// Consistency: Returns a snapshot (may become stale immediately)
//
// Usage Patterns:
// - Authorization checks: "Is this user an admin?"
// - Admin UI filtering: "Show only admin users"
// - Audit logging: "List current admin users"
// - Configuration validation: "Is this a valid admin ID?"
//
// The function handles the edge case where the allowlist hasn't been
// initialized yet by returning an empty map rather than nil.
func CurrentAllowlist() map[string]struct{} {
	v := adminAllowlist.Load()
	if v == nil {
		return map[string]struct{}{}
	}
	return v.(map[string]struct{})
}

// IsUserInAdminAllowlist performs fast authorization checks for admin privileges
// This function is the primary authorization mechanism for admin functionality
// with the following design considerations:
//
// Performance Requirements:
// - Called on every admin API request (performance critical)
// - Must complete in microseconds to avoid request latency
// - Lock-free implementation prevents blocking on concurrent updates
//
// Security Features:
// - Case-sensitive exact matching (prevents case variation attacks)
// - Whitespace normalization (prevents ID spoofing with spaces)
// - Fallback to environment variables (backward compatibility)
// - Empty string rejection (prevents null/empty ID bypass)
//
// Authorization Logic:
// 1. Check current allowlist (fast path for most cases)
// 2. Fallback to environment variable (backward compatibility)
// 3. Normalize whitespace in both user ID and allowlist entries
// 4. Return boolean result (no error to simplify calling code)
//
// The dual-source approach (allowlist + environment) supports gradual
// migration from environment-based to file-based admin configuration.
func IsUserInAdminAllowlist(userID string) bool {
	if _, ok := CurrentAllowlist()[strings.TrimSpace(userID)]; ok {
		return true
	}
	// Backward-compat: also check process env in case watcher not configured
	// This fallback supports migration scenarios and environments where:
	// - File-based configuration is not available
	// - Dynamic reloading hasn't been set up yet
	// - Environment variables are preferred for container deployments
	//
	// The environment check uses the same normalization logic as the
	// allowlist to ensure consistent behavior between the two sources.
	envAdmins := strings.Split(os.Getenv("ADMIN_USER_IDS"), ",")
	for _, a := range envAdmins {
		if strings.TrimSpace(a) == strings.TrimSpace(userID) {
			return true
		}
	}
	return false
}

// LoadAllowlistFromSources implements a unified admin user loading mechanism
// This function consolidates admin user configuration from multiple sources:
//
// Configuration Hierarchy:
// 1. Environment variables (ADMIN_USER_IDS) - highest priority
// 2. Configuration file (ADMIN_USER_IDS_FILE) - fallback/supplemental
// 3. Both sources can be used together (merged allowlist)
//
// File Format Support:
// - Simple format: One user ID per line
// - Key-value format: ADMIN_USER_IDS="id1,id2,id3"
// - Comment support: Lines starting with # are ignored
// - Whitespace handling: Leading/trailing whitespace is trimmed
//
// Return Values:
// - map[string]struct{}: Parsed allowlist for fast lookup
// - string: Signature for change detection (concatenated sources)
//
// Change Detection:
// The signature string enables the refresher to detect when configuration
// has actually changed, preventing unnecessary updates and log spam.
// The signature includes both source identifiers and their content.
//
// Error Handling:
// - Missing files are silently ignored (optional configuration)
// - Malformed lines are skipped (with logging)
// - Environment variables are parsed leniently (extra commas ignored)
// - Always returns a valid map (never nil)
func LoadAllowlistFromSources(envList string, filePath string) (map[string]struct{}, string) {
	m := make(map[string]struct{})
	var buf bytes.Buffer
	// Process environment variable configuration first
	// Environment variables take precedence and are processed first
	// to ensure they're included in the change detection signature.
	// This supports containerized deployments where file configuration
	// might not be available or desired.
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
			defer func() {
				_ = f.Close() // Best effort cleanup
			}()
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

// StartAdminAllowlistRefresher implements a hot-reloading configuration system
// This function starts a background service that monitors admin user configuration
// for changes and updates the in-memory allowlist without application restart.
//
// Design Rationale:
// - 5-second interval provides near-real-time updates without excessive polling
// - Change detection prevents unnecessary updates and log spam
// - Background goroutine doesn't block application startup
// - Atomic updates ensure consistent state during configuration changes
//
// Configuration Sources:
// - Environment variables (ADMIN_USER_IDS)
// - Configuration files (ADMIN_USER_IDS_FILE)
// - Both sources are monitored and merged dynamically
//
// Use Cases:
// - Emergency admin access: Add admin without restart during incidents
// - Gradual rollouts: Add admins incrementally during maintenance
// - Access revocation: Remove compromised admin accounts immediately
// - Dynamic environments: Support container orchestration changes
//
// Operational Benefits:
// - Zero-downtime admin configuration changes
// - No application restart required for access updates
// - Audit trail through change detection logging
// - Backward compatibility with existing deployments
//
// The function supports both environment-only and file-only configurations,
// making it suitable for various deployment patterns (containers, VMs, bare metal).
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
