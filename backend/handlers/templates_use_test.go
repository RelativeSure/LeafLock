package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"leaflock/crypto"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type templatesMockDB struct {
	queryRowFuncs []func(dest ...interface{}) error
	execFuncs     []func(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error)
}

func (m *templatesMockDB) QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row {
	if len(m.queryRowFuncs) == 0 {
		return templatesMockRow{}
	}
	fn := m.queryRowFuncs[0]
	m.queryRowFuncs = m.queryRowFuncs[1:]
	return templatesMockRow{scanFunc: fn}
}

func (m *templatesMockDB) Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error) {
	return nil, nil
}

func (m *templatesMockDB) Exec(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
	if len(m.execFuncs) == 0 {
		return pgconn.NewCommandTag("EXEC 0"), nil
	}
	fn := m.execFuncs[0]
	m.execFuncs = m.execFuncs[1:]
	return fn(ctx, sql, args...)
}

func (m *templatesMockDB) Begin(ctx context.Context) (pgx.Tx, error) {
	return nil, nil
}

type templatesMockRow struct {
	scanFunc func(dest ...interface{}) error
}

func (r templatesMockRow) Scan(dest ...interface{}) error {
	if r.scanFunc != nil {
		return r.scanFunc(dest...)
	}
	return nil
}

func TestUseTemplateCreatesNote(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	cryptoSvc := crypto.NewCryptoService(key)
	userID := uuid.New()
	templateID := uuid.New()

	contentEncrypted, err := cryptoSvc.Encrypt([]byte("Template Content"))
	if err != nil {
		t.Fatalf("failed to encrypt content: %v", err)
	}

	db := &templatesMockDB{
		queryRowFuncs: []func(dest ...interface{}) error{
			// First QueryRow: SELECT content_encrypted FROM templates
			func(dest ...interface{}) error {
				if len(dest) != 1 {
					t.Fatalf("unexpected scan args count for content query: %d", len(dest))
				}
				if v, ok := dest[0].(*[]byte); ok {
					*v = contentEncrypted
				}
				return nil
			},
			// Second QueryRow: SELECT email FROM users
			func(dest ...interface{}) error {
				if len(dest) != 1 {
					t.Fatalf("unexpected scan args count for email query: %d", len(dest))
				}
				if v, ok := dest[0].(*string); ok {
					*v = "user@example.com"
				}
				return nil
			},
		},
		execFuncs: []func(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error){
			// Exec: UPDATE templates SET usage_count = usage_count + 1
			func(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
				return pgconn.NewCommandTag("UPDATE 1"), nil
			},
		},
	}

	handler := NewTemplatesHandler(db, cryptoSvc)
	app := fiber.New()
	app.Post("/:id/use", func(c *fiber.Ctx) error {
		c.Locals("user_id", userID)
		return handler.UseTemplate(c)
	})

	body := map[string]string{"title": "Custom Note"}
	payload, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/"+templateID.String()+"/use", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	// UseTemplate returns 200 with content and tags for client-side E2E encryption
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	// Verify content is returned (decrypted)
	if result["content"] != "Template Content" {
		t.Fatalf("expected content 'Template Content', got %v", result["content"])
	}
}
