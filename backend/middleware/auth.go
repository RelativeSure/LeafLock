package middleware

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"sync/atomic"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Database interface for database operations
type Database interface {
	QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row
	Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error)
	Exec(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error)
	Begin(ctx context.Context) (pgx.Tx, error)
}

// --- Dynamic admin allowlist with hot-reload support ---
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

// LoadAllowlistFromSources loads admin allowlist from environment and file
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
			defer func() {
				_ = f.Close() // Best effort cleanup
			}()
			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line != "" && !strings.HasPrefix(line, "#") {
					m[line] = struct{}{}
					buf.WriteString("FILE:")
					buf.WriteString(line)
					buf.WriteString("\n")
				}
			}
		}
	}
	return m, buf.String()
}

// StoreAllowlist updates the global admin allowlist
func StoreAllowlist(allowlist map[string]struct{}) {
	adminAllowlist.Store(allowlist)
}

// GetUserIDFromToken extracts user ID from JWT token stored in Fiber context
func GetUserIDFromToken(c *fiber.Ctx) (uuid.UUID, error) {
	userID, ok := c.Locals("user_id").(uuid.UUID)
	if !ok {
		return uuid.Nil, fmt.Errorf("user ID not found in context")
	}
	return userID, nil
}

// RequireRole creates a Fiber middleware that checks if the authenticated user has the required role
func RequireRole(db Database, role string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		v := c.Locals("user_id")
		if v == nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
		}
		var uid uuid.UUID
		switch t := v.(type) {
		case uuid.UUID:
			uid = t
		case string:
			parsed, err := uuid.Parse(t)
			if err != nil {
				return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Forbidden"})
			}
			uid = parsed
		default:
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Forbidden"})
		}
		if !HasRole(c.Context(), db, uid, role) {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Forbidden"})
		}
		return c.Next()
	}
}

// HasRole checks if a user has a specific role in the system
// It checks both database roles and the admin allowlist
func HasRole(ctx context.Context, db Database, userID uuid.UUID, role string) bool {
	// Admins always pass
	var isAdmin bool
	if err := db.QueryRow(ctx, "SELECT is_admin FROM users WHERE id = $1", userID).Scan(&isAdmin); err == nil && isAdmin {
		return true
	}
	if strings.ToLower(role) == "admin" {
		if IsUserInAdminAllowlist(userID.String()) {
			return true
		}
	}
	// Check user_roles
	var exists bool
	_ = db.QueryRow(ctx, `
        SELECT EXISTS (
            SELECT 1 FROM user_roles ur
            JOIN roles r ON ur.role_id = r.id
            WHERE ur.user_id = $1 AND r.name = $2
        )`, userID, role).Scan(&exists)
	return exists
}