package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	appcrypto "leaflock/crypto"
	"leaflock/database"
)

func TestImportNoteHandlerSuccess(t *testing.T) {
	db := &importExportStubDB{
		storageUsed:  1024,
		storageLimit: 1024 * 1024,
		workspaceID:  uuid.New(),
	}
	crypto := appcrypto.NewCryptoService(repeatByte(32, 'i'))
	handler := NewImportExportHandler(db, crypto)

	userID := uuid.New()
	app := fiber.New()
	app.Post("/notes/import", func(c *fiber.Ctx) error {
		c.Locals("user_id", userID)
		return handler.ImportNote(c)
	})

	payload := `{"format":"markdown","content":"# Title\nBody"}`
	req := httptest.NewRequest("POST", "/notes/import", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != fiber.StatusCreated {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}

	var body map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	resp.Body.Close()

	noteID, ok := body["note_id"].(string)
	if !ok || noteID == "" {
		t.Fatalf("expected note_id in response, got %#v", body["note_id"])
	}
	if format := body["format"]; format != "markdown" {
		t.Fatalf("expected format markdown, got %v", format)
	}
	if len(db.execLog) != 2 {
		t.Fatalf("expected two exec calls (insert and update), got %d", len(db.execLog))
	}
	if !strings.Contains(db.execLog[0], "INSERT INTO notes") {
		t.Fatalf("first exec should insert note, got %s", db.execLog[0])
	}
}

func TestImportNoteHandlerStorageLimitExceeded(t *testing.T) {
	db := &importExportStubDB{
		storageUsed:  10,
		storageLimit: 10,
		workspaceID:  uuid.New(),
	}
	crypto := appcrypto.NewCryptoService(repeatByte(32, 'l'))
	handler := NewImportExportHandler(db, crypto)

	userID := uuid.New()
	app := fiber.New()
	app.Post("/notes/import", func(c *fiber.Ctx) error {
		c.Locals("user_id", userID)
		return handler.ImportNote(c)
	})

	payload := `{"format":"markdown","content":"Exceeds"}`
	req := httptest.NewRequest("POST", "/notes/import", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != fiber.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 when storage exceeded, got %d", resp.StatusCode)
	}
	if len(db.execLog) != 0 {
		t.Fatalf("expected no exec calls when storage limit exceeded, got %d", len(db.execLog))
	}
}

func TestBulkImportHandlerMixedResults(t *testing.T) {
	db := &importExportStubDB{
		storageUsed:  0,
		storageLimit: 1024 * 1024,
		workspaceID:  uuid.New(),
	}
	crypto := appcrypto.NewCryptoService(repeatByte(32, 'b'))
	handler := NewImportExportHandler(db, crypto)

	userID := uuid.New()
	app := fiber.New()
	app.Post("/notes/bulk-import", func(c *fiber.Ctx) error {
		c.Locals("user_id", userID)
		return handler.BulkImport(c)
	})

	payload := `{"files":[{"format":"markdown","content":"# Note 1"},{"format":"html","content":"<script>bad</script>"}]}`
	req := httptest.NewRequest("POST", "/notes/bulk-import", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != fiber.StatusCreated {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}

	var body map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	resp.Body.Close()

	if imported := int(body["imported_count"].(float64)); imported != 1 {
		t.Fatalf("expected 1 imported note, got %d", imported)
	}
	if failed := int(body["failed_count"].(float64)); failed != 1 {
		t.Fatalf("expected 1 failed note, got %d", failed)
	}
	if len(db.execLog) != 2 {
		t.Fatalf("expected two exec calls, got %d (%#v)", len(db.execLog), db.execLog)
	}
	if len(db.updateValues) == 0 || db.updateValues[0] <= 0 {
		t.Fatalf("expected storage usage update value recorded, got %#v (types=%#v execLog=%#v)", db.updateValues, db.updateTypes, db.execLog)
	}
}

func TestBulkImportHandlerTooManyFiles(t *testing.T) {
	db := &importExportStubDB{
		storageLimit: 1024 * 1024,
		workspaceID:  uuid.New(),
	}
	crypto := appcrypto.NewCryptoService(repeatByte(32, 'c'))
	handler := NewImportExportHandler(db, crypto)

	userID := uuid.New()
	app := fiber.New()
	app.Post("/notes/bulk-import", func(c *fiber.Ctx) error {
		c.Locals("user_id", userID)
		return handler.BulkImport(c)
	})

	files := make([]string, 0, 51)
	for i := 0; i < 51; i++ {
		files = append(files, `{"format":"markdown","content":"note"}`)
	}
	payload := `{"files":[` + strings.Join(files, ",") + `]}`
	req := httptest.NewRequest("POST", "/notes/bulk-import", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != fiber.StatusBadRequest {
		t.Fatalf("expected 400 for too many files, got %d", resp.StatusCode)
	}
	if len(db.execLog) != 0 {
		t.Fatalf("expected no exec calls when request rejected, got %d", len(db.execLog))
	}
}

var _ database.Database = (*importExportStubDB)(nil)

type importExportStubDB struct {
	storageUsed  int64
	storageLimit int64
	workspaceID  uuid.UUID
	execLog      []string
	updateValues []int64
	updateTypes  []string
}

func (db *importExportStubDB) QueryRow(_ context.Context, sql string, _ ...interface{}) pgx.Row {
	switch {
	case strings.Contains(sql, "storage_used"):
		return rowStub{values: []interface{}{db.storageUsed, db.storageLimit}}
	case strings.Contains(sql, "FROM workspaces"):
		return rowStub{values: []interface{}{db.workspaceID}}
	default:
		return rowStub{err: fmt.Errorf("unexpected query: %s", sql)}
	}
}

func (db *importExportStubDB) Query(context.Context, string, ...interface{}) (pgx.Rows, error) {
	return nil, fmt.Errorf("not implemented")
}

func (db *importExportStubDB) Exec(_ context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
	db.execLog = append(db.execLog, sql)
	if strings.Contains(sql, "storage_used = storage_used + $1") {
		var inc int64
		if len(args) > 0 {
			db.updateTypes = append(db.updateTypes, fmt.Sprintf("%T", args[0]))
			switch v := args[0].(type) {
			case int64:
				inc = v
			case int:
				inc = int64(v)
			case float64:
				inc = int64(v)
			case int32:
				inc = int64(v)
			case uint64:
				inc = int64(v)
			}
		} else {
			db.updateTypes = append(db.updateTypes, "none")
		}
		db.updateValues = append(db.updateValues, inc)
		db.storageUsed += inc
		return pgconn.NewCommandTag("UPDATE 1"), nil
	}
	if strings.Contains(sql, "INSERT INTO notes") {
		return pgconn.NewCommandTag("INSERT 1"), nil
	}
	return pgconn.NewCommandTag("UPDATE 0"), nil
}

func (db *importExportStubDB) Begin(context.Context) (pgx.Tx, error) {
	return nil, fmt.Errorf("not implemented")
}

type rowStub struct {
	values []interface{}
	err    error
}

func (r rowStub) Scan(dest ...interface{}) error {
	if r.err != nil {
		return r.err
	}
	for i, val := range r.values {
		switch d := dest[i].(type) {
		case *int64:
			switch v := val.(type) {
			case int64:
				*d = v
			case int:
				*d = int64(v)
			default:
				return fmt.Errorf("unsupported int64 value type %T", v)
			}
		case *uuid.UUID:
			if id, ok := val.(uuid.UUID); ok {
				*d = id
			} else {
				return fmt.Errorf("unsupported uuid value type %T", val)
			}
		default:
			return fmt.Errorf("unsupported scan destination %T", d)
		}
	}
	return nil
}

func repeatByte(n int, b byte) []byte {
	buf := make([]byte, n)
	for i := range buf {
		buf[i] = b
	}
	return buf
}
