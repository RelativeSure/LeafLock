package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	miniredis "github.com/alicebob/miniredis/v2"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/redis/go-redis/v9"

	appcrypto "leaflock/crypto"
	"leaflock/services"
)

func TestShareLinkMiddlewareMissingToken(t *testing.T) {
	app := fiber.New()
	crypto := appcrypto.NewCryptoService(make([]byte, 32))
	rdb := redis.NewClient(&redis.Options{Addr: "localhost:0"})

	app.Get("/share", ShareLinkMiddleware(nil, crypto, rdb))

	resp, err := app.Test(httptest.NewRequest("GET", "/share", nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != fiber.StatusBadRequest {
		t.Fatalf("expected 400 for missing token, got %d", resp.StatusCode)
	}
}

func TestShareLinkMiddlewareSuccessWithCache(t *testing.T) {
	minidb := miniredis.RunT(t)
	redisClient := redis.NewClient(&redis.Options{Addr: minidb.Addr()})
	crypto := appcrypto.NewCryptoService(bytesRepeated(32, 'k'))
	ctx := context.Background()

	noteID := uuid.New()
	cache := services.ShareLinkCache{NoteID: noteID.String(), Permission: "read"}
	service := services.NewShareLinkService(redisClient)
	if err := service.CacheShareLink(ctx, "token123", cache); err != nil {
		t.Fatalf("failed to seed cache: %v", err)
	}

	db := &shareLinkStubDB{isActive: true}
	app := fiber.New()
	app.Get("/share/:token", ShareLinkMiddleware(db, crypto, redisClient), func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"note_id":    c.Locals("share_link_note_id").(uuid.UUID).String(),
			"permission": c.Locals("share_link_permission"),
			"is_share":   c.Locals("is_share_link_access"),
			"token":      c.Locals("share_link_token"),
		})
	})

	req := httptest.NewRequest("GET", "/share/token123", nil)
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != fiber.StatusOK {
		t.Fatalf("expected success, got %d", resp.StatusCode)
	}
	var body map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	resp.Body.Close()

	if body["note_id"] != noteID.String() || body["permission"] != "read" || body["is_share"].(bool) != true {
		t.Fatalf("unexpected locals in response: %#v", body)
	}
	if !db.execCalled {
		t.Fatalf("expected update query to be executed")
	}
}

type shareLinkStubDB struct {
	execCalled       bool
	isActive         bool
	passwordHash     *string
	noteID           uuid.UUID
	permission       string
	expiresAt        *time.Time
	maxUses          *int
	useCount         int
	queryErr         error
	execErr          error
	shouldFailUpdate bool // For testing race condition prevention
}

func (db *shareLinkStubDB) QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row {
	switch {
	case strings.Contains(sql, "SELECT is_active") && !strings.Contains(sql, "note_id"):
		return simpleRow{values: []interface{}{db.isActive, db.passwordHash}, err: db.queryErr}
	case strings.Contains(sql, "SELECT note_id"):
		values := []interface{}{db.noteID, db.permission, db.expiresAt, db.maxUses, db.useCount, db.isActive, db.passwordHash}
		return simpleRow{values: values, err: db.queryErr}
	default:
		return simpleRow{err: fmt.Errorf("unexpected query: %s", sql)}
	}
}

func (db *shareLinkStubDB) Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error) {
	return nil, fmt.Errorf("not implemented")
}

func (db *shareLinkStubDB) Exec(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
	if db.execErr != nil {
		return pgconn.CommandTag{}, db.execErr
	}
	db.execCalled = true

	// Simulate race condition: update fails because WHERE clause doesn't match
	if db.shouldFailUpdate {
		return pgconn.NewCommandTag("UPDATE 0"), nil
	}

	return pgconn.NewCommandTag("UPDATE 1"), nil
}

func (db *shareLinkStubDB) Begin(ctx context.Context) (pgx.Tx, error) {
	return nil, fmt.Errorf("not implemented")
}

type simpleRow struct {
	values []interface{}
	err    error
}

func (r simpleRow) Scan(dest ...interface{}) error {
	if r.err != nil {
		return r.err
	}
	for i, val := range r.values {
		switch d := dest[i].(type) {
		case *bool:
			if val == nil {
				*d = false
				continue
			}
			*d = val.(bool)
		case *int:
			switch v := val.(type) {
			case nil:
				*d = 0
			case int:
				*d = v
			case int32:
				*d = int(v)
			case int64:
				*d = int(v)
			default:
				return fmt.Errorf("unsupported int value type %T", v)
			}
		case **int:
			switch v := val.(type) {
			case nil:
				*d = nil
			case *int:
				*d = v
			case int:
				tmp := v
				*d = &tmp
			case int32:
				tmp := int(v)
				*d = &tmp
			case int64:
				tmp := int(v)
				*d = &tmp
			default:
				return fmt.Errorf("unsupported *int value type %T", v)
			}
		case **time.Time:
			switch v := val.(type) {
			case nil:
				*d = nil
			case *time.Time:
				*d = v
			case time.Time:
				tmp := v
				*d = &tmp
			default:
				return fmt.Errorf("unsupported time value type %T", v)
			}
		case *uuid.UUID:
			if v, ok := val.(uuid.UUID); ok {
				*d = v
				continue
			}
			return fmt.Errorf("unsupported uuid value type %T", val)
		case *string:
			if v, ok := val.(string); ok {
				*d = v
				continue
			}
			return fmt.Errorf("unsupported string value type %T", val)
		case **string:
			switch v := val.(type) {
			case nil:
				*d = nil
			case string:
				str := v
				*d = &str
			case *string:
				*d = v
			default:
				return fmt.Errorf("unsupported string value type %T", v)
			}
		default:
			return fmt.Errorf("unsupported scan destination %T", d)
		}
	}
	return nil
}

func TestShareLinkMiddlewarePasswordProtectedSuccess(t *testing.T) {
	minidb := miniredis.RunT(t)
	redisClient := redis.NewClient(&redis.Options{Addr: minidb.Addr()})
	crypto := appcrypto.NewCryptoService(bytesRepeated(32, 's'))

	noteID := uuid.New()
	password := "super-secret"
	hash := appcrypto.HashPassword(password, []byte("0123456789abcdef"))

	db := &shareLinkStubDB{
		isActive:     true,
		passwordHash: &hash,
		noteID:       noteID,
		permission:   "edit",
	}

	app := fiber.New()
	app.Post("/share/:token", ShareLinkMiddleware(db, crypto, redisClient), func(c *fiber.Ctx) error {
		if got := c.Locals("share_link_permission"); got != "edit" {
			t.Fatalf("expected permission edit, got %v", got)
		}
		if got := c.Locals("share_link_note_id").(uuid.UUID); got != noteID {
			t.Fatalf("unexpected note id: %v", got)
		}
		return c.SendStatus(fiber.StatusNoContent)
	})

	req := httptest.NewRequest("POST", "/share/protected", strings.NewReader(fmt.Sprintf(`{"password":"%s"}`, password)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != fiber.StatusNoContent {
		t.Fatalf("expected 204, got %d", resp.StatusCode)
	}
	if !db.execCalled {
		t.Fatalf("expected update query to run for password-protected link")
	}
}

func TestShareLinkMiddlewarePasswordProtectedMissingPassword(t *testing.T) {
	minidb := miniredis.RunT(t)
	redisClient := redis.NewClient(&redis.Options{Addr: minidb.Addr()})
	crypto := appcrypto.NewCryptoService(bytesRepeated(32, 'm'))

	hash := appcrypto.HashPassword("secret", []byte("0123456789abcdef"))
	db := &shareLinkStubDB{
		isActive:     true,
		passwordHash: &hash,
		noteID:       uuid.New(),
		permission:   "read",
	}

	app := fiber.New()
	app.Get("/share/:token", ShareLinkMiddleware(db, crypto, redisClient), func(c *fiber.Ctx) error {
		t.Fatal("handler should not be called when password missing")
		return nil
	})

	resp, err := app.Test(httptest.NewRequest("GET", "/share/needs-password", nil), -1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != fiber.StatusUnauthorized {
		t.Fatalf("expected 401 for missing password, got %d", resp.StatusCode)
	}
	if db.execCalled {
		t.Fatalf("did not expect update query to run when password missing")
	}
}

func TestShareLinkMiddlewareExpired(t *testing.T) {
	minidb := miniredis.RunT(t)
	redisClient := redis.NewClient(&redis.Options{Addr: minidb.Addr()})
	crypto := appcrypto.NewCryptoService(bytesRepeated(32, 'e'))

	past := time.Now().Add(-time.Hour)
	db := &shareLinkStubDB{
		isActive:   true,
		noteID:     uuid.New(),
		permission: "read",
		expiresAt:  &past,
	}

	app := fiber.New()
	app.Get("/share/:token", ShareLinkMiddleware(db, crypto, redisClient), func(c *fiber.Ctx) error {
		t.Fatal("handler should not be called for expired link")
		return nil
	})

	resp, err := app.Test(httptest.NewRequest("GET", "/share/expired", nil), -1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != fiber.StatusForbidden {
		t.Fatalf("expected 403 for expired link, got %d", resp.StatusCode)
	}
	if db.execCalled {
		t.Fatalf("did not expect update query for expired link")
	}
}

func TestShareLinkMiddlewareRevoked(t *testing.T) {
	minidb := miniredis.RunT(t)
	redisClient := redis.NewClient(&redis.Options{Addr: minidb.Addr()})
	crypto := appcrypto.NewCryptoService(bytesRepeated(32, 'r'))

	db := &shareLinkStubDB{
		isActive:   false,
		noteID:     uuid.New(),
		permission: "read",
	}

	app := fiber.New()
	app.Get("/share/:token", ShareLinkMiddleware(db, crypto, redisClient), func(c *fiber.Ctx) error {
		t.Fatal("handler should not run when link revoked")
		return nil
	})

	resp, err := app.Test(httptest.NewRequest("GET", "/share/revoked", nil), -1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != fiber.StatusForbidden {
		t.Fatalf("expected 403 for revoked link, got %d", resp.StatusCode)
	}
	if db.execCalled {
		t.Fatalf("did not expect update query for revoked link")
	}
}

func TestShareLinkMiddlewareUsageLimitReached(t *testing.T) {
	minidb := miniredis.RunT(t)
	redisClient := redis.NewClient(&redis.Options{Addr: minidb.Addr()})
	crypto := appcrypto.NewCryptoService(bytesRepeated(32, 'u'))

	limit := 1
	db := &shareLinkStubDB{
		isActive:   true,
		noteID:     uuid.New(),
		permission: "read",
		maxUses:    &limit,
		useCount:   1,
	}

	app := fiber.New()
	app.Get("/share/:token", ShareLinkMiddleware(db, crypto, redisClient), func(c *fiber.Ctx) error {
		t.Fatal("handler should not run when usage limit reached")
		return nil
	})

	resp, err := app.Test(httptest.NewRequest("GET", "/share/limited", nil), -1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != fiber.StatusForbidden {
		t.Fatalf("expected 403 when usage limit reached, got %d", resp.StatusCode)
	}
	if db.execCalled {
		t.Fatalf("did not expect update query when usage limit reached")
	}
}

func bytesRepeated(n int, b byte) []byte {
	buf := make([]byte, n)
	for i := range buf {
		buf[i] = b
	}
	return buf
}

// TestShareLinkMiddlewareRaceConditionPrevention tests that the atomic update prevents race conditions
func TestShareLinkMiddlewareRaceConditionPrevention(t *testing.T) {
	minidb := miniredis.RunT(t)
	redisClient := redis.NewClient(&redis.Options{Addr: minidb.Addr()})
	crypto := appcrypto.NewCryptoService(bytesRepeated(32, 'z'))

	limit := 5
	db := &shareLinkStubDB{
		isActive:   true,
		noteID:     uuid.New(),
		permission: "read",
		maxUses:    &limit,
		useCount:   4, // One use remaining
	}

	// First request should succeed (use count 4 -> 5)
	app := fiber.New()
	app.Get("/share/:token", ShareLinkMiddleware(db, crypto, redisClient), func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	resp, err := app.Test(httptest.NewRequest("GET", "/share/racing", nil), -1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != fiber.StatusOK {
		t.Fatalf("first request should succeed, got %d", resp.StatusCode)
	}

	// Simulate race condition: second concurrent request with same use_count
	// In a real race condition, both requests would read use_count=4 before either updates
	// Our fix ensures the UPDATE with WHERE clause prevents this
	db.useCount = 5 // Now at limit
	db.shouldFailUpdate = true // Simulate RowsAffected() == 0

	resp2, err := app.Test(httptest.NewRequest("GET", "/share/racing", nil), -1)
	if err != nil {
		t.Fatalf("unexpected error on second request: %v", err)
	}
	if resp2.StatusCode != fiber.StatusForbidden {
		t.Fatalf("second request should fail with 403 when limit reached atomically, got %d", resp2.StatusCode)
	}

	var body map[string]interface{}
	if err := json.NewDecoder(resp2.Body).Decode(&body); err != nil {
		t.Fatalf("failed to parse error response: %v", err)
	}
	resp2.Body.Close()

	if !strings.Contains(body["error"].(string), "usage limit") {
		t.Fatalf("expected usage limit error, got: %v", body["error"])
	}
}
