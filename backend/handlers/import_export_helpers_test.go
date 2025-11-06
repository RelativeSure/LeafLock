package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	appcrypto "leaflock/crypto"
)

func TestValidateFileContent(t *testing.T) {
	if err := validateFileContent("# Title\nBody", "markdown"); err != nil {
		t.Fatalf("unexpected error for markdown: %v", err)
	}
	if err := validateFileContent("Plain text", "text"); err != nil {
		t.Fatalf("unexpected error for text: %v", err)
	}
	if err := validateFileContent("{\"title\":\"Note\"}", "json"); err != nil {
		t.Fatalf("unexpected error for json: %v", err)
	}
	if err := validateFileContent("<p>hello</p>", "html"); err != nil {
		t.Fatalf("unexpected error for html: %v", err)
	}

	badInputs := []string{"<script>alert(1)</script>", "javascript:alert(1)", "onload=evil"}
	for _, input := range badInputs {
		if err := validateFileContent(input, "html"); err == nil {
			t.Fatalf("expected error for content %q", input)
		}
	}
}

func TestExtractTitleFromContent(t *testing.T) {
	if got := extractTitleFromContent("# Heading\nBody", "markdown"); got != "Heading" {
		t.Fatalf("expected markdown heading, got %q", got)
	}
	if got := extractTitleFromContent("<h1>Title</h1>", "html"); got != "Title" {
		t.Fatalf("expected html heading, got %q", got)
	}
	if got := extractTitleFromContent("First line\nSecond", "text"); !strings.HasPrefix(got, "First line") {
		t.Fatalf("expected text title, got %q", got)
	}
	jsonContent := `{"title":"JSON Title"}`
	if got := extractTitleFromContent(jsonContent, "json"); got != "JSON Title" {
		t.Fatalf("expected json title, got %q", got)
	}
}

func TestConvertToMarkdown(t *testing.T) {
	cases := []struct {
		format  string
		input   string
		expects string
	}{
		{"markdown", "# Heading", "# Heading"},
		{"text", "Line1\nLine2", "Line1\n\nLine2"},
		{"json", `{"content":"md"}`, "md"},
	}

	for _, tc := range cases {
		got, err := convertToMarkdown(tc.input, tc.format)
		if err != nil {
			t.Fatalf("convertToMarkdown error for %s: %v", tc.format, err)
		}
		if got != tc.expects {
			t.Fatalf("convertToMarkdown got %q want %q", got, tc.expects)
		}
	}

	if _, err := convertToMarkdown("{}", "unknown"); err == nil {
		t.Fatalf("expected error for unsupported format")
	}
}

func TestConvertFromMarkdown(t *testing.T) {
	title := "Test"
	now := time.Now()

	text, mime, err := convertFromMarkdown("**Bold**", "text", title, now, now)
	if err != nil || !strings.Contains(text, "Bold") || mime != "text/plain" {
		t.Fatalf("convertFromMarkdown text failed: %q %s %v", text, mime, err)
	}

	html, mime, err := convertFromMarkdown("# Heading", "html", title, now, now)
	if err != nil || !strings.Contains(html, "<h1>Heading</h1>") || mime != "text/html" {
		t.Fatalf("convertFromMarkdown html failed: %q %s %v", html, mime, err)
	}

	jsonPayload, mime, err := convertFromMarkdown("content", "json", title, now, now)
	if err != nil || mime != "application/json" {
		t.Fatalf("convertFromMarkdown json failed: %s %v", mime, err)
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal([]byte(jsonPayload), &decoded); err != nil {
		t.Fatalf("json output invalid: %v", err)
	}
	if decoded["title"] != title {
		t.Fatalf("expected json title %q, got %v", title, decoded["title"])
	}

	if _, _, err := convertFromMarkdown("", "unsupported", title, now, now); err == nil {
		t.Fatalf("expected error for unsupported format")
	}
}

func TestGenerateFilename(t *testing.T) {
	name := generateFilename("Hello, World!", "markdown")
	if name != "Hello_World.md" {
		t.Fatalf("expected sanitized filename, got %q", name)
	}

	long := strings.Repeat("a", 80)
	if len(generateFilename(long, "text")) > 54 { // 50 chars + extension
		t.Fatalf("expected filename to be truncated")
	}

	if fallback := generateFilename("", "json"); fallback == "" {
		t.Fatalf("expected fallback filename")
	}
}

type scanRow struct {
	values []interface{}
	err    error
}

func (r scanRow) Scan(dest ...interface{}) error {
	if r.err != nil {
		return r.err
	}
	if len(dest) > len(r.values) {
		return fmt.Errorf("not enough values supplied")
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
				return fmt.Errorf("unsupported int64 source %T", v)
			}
		case *uuid.UUID:
			switch v := val.(type) {
			case uuid.UUID:
				*d = v
			case string:
				parsed, err := uuid.Parse(v)
				if err != nil {
					return err
				}
				*d = parsed
			default:
				return fmt.Errorf("unsupported uuid source %T", v)
			}
		case *[]byte:
			switch v := val.(type) {
			case []byte:
				*d = append((*d)[:0], v...)
			case string:
				*d = []byte(v)
			default:
				return fmt.Errorf("unsupported []byte source %T", v)
			}
		case *time.Time:
			*d = val.(time.Time)
		case *bool:
			*d = val.(bool)
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
				return fmt.Errorf("unsupported string pointer source %T", v)
			}
		default:
			return fmt.Errorf("unsupported scan destination %T", d)
		}
	}
	return nil
}

type testDB struct {
	storageUsed  int64
	storageLimit int64
	workspaceID  uuid.UUID
	noteTitleEnc []byte
	noteContent  []byte
	noteCreated  time.Time
	noteUpdated  time.Time
	execCalls    []string
	failExec     bool
}

func (db *testDB) QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row {
	switch {
	case strings.Contains(sql, "storage_used"):
		return scanRow{values: []interface{}{db.storageUsed, db.storageLimit}}
	case strings.Contains(sql, "FROM workspaces"):
		return scanRow{values: []interface{}{db.workspaceID}}
	case strings.Contains(sql, "FROM notes n"):
		return scanRow{values: []interface{}{db.noteTitleEnc, db.noteContent, db.noteCreated, db.noteUpdated}}
	case strings.Contains(sql, "SELECT is_active"):
		return scanRow{values: []interface{}{true, (*string)(nil)}}
	default:
		return scanRow{err: fmt.Errorf("unexpected query: %s", sql)}
	}
}

func (db *testDB) Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error) {
	return nil, fmt.Errorf("unexpected query: %s", sql)
}

func (db *testDB) Exec(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
	if db.failExec {
		return pgconn.NewCommandTag("UPDATE 0"), fmt.Errorf("exec failed")
	}
	db.execCalls = append(db.execCalls, sql)
	return pgconn.NewCommandTag("UPDATE 1"), nil
}

func (db *testDB) Begin(ctx context.Context) (pgx.Tx, error) {
	return nil, fmt.Errorf("not implemented")
}

func TestCheckStorageLimit(t *testing.T) {
	db := &testDB{storageUsed: 100, storageLimit: 500}
	h := &ImportExportHandler{db: db}
	if err := h.checkStorageLimit(uuid.New(), 200); err != nil {
		t.Fatalf("expected storage within limit, got %v", err)
	}

	db.storageUsed = 400
	if err := h.checkStorageLimit(uuid.New(), 200); err == nil {
		t.Fatalf("expected error when exceeding storage limit")
	}
}

func TestUpdateStorageUsage(t *testing.T) {
	db := &testDB{}
	h := &ImportExportHandler{db: db}
	if err := h.updateStorageUsage(uuid.New(), 50); err != nil {
		t.Fatalf("expected update to succeed, got %v", err)
	}

	db.failExec = true
	if err := h.updateStorageUsage(uuid.New(), 10); err == nil {
		t.Fatalf("expected error when exec fails")
	}
}

func TestImportNoteSuccess(t *testing.T) {
	userID := uuid.New()
	db := &testDB{storageLimit: 2048, workspaceID: uuid.New()}
	crypto := appcrypto.NewCryptoService(bytesRepeated(32, 's'))
	h := &ImportExportHandler{db: db, crypto: crypto}

	app := fiber.New()
	app.Post("/notes/import", func(c *fiber.Ctx) error {
		c.Locals("user_id", userID)
		return h.ImportNote(c)
	})

	body := `{"title":"Sample","content":"# Heading","format":"markdown"}`
	req := httptest.NewRequest("POST", "/notes/import", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != fiber.StatusCreated {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}
	require.NoError(t, resp.Body.Close())

	if len(db.execCalls) == 0 {
		t.Fatalf("expected Exec to be called")
	}
}

func TestBulkImportMixed(t *testing.T) {
	userID := uuid.New()
	db := &testDB{storageLimit: 4096, workspaceID: uuid.New()}
	crypto := appcrypto.NewCryptoService(bytesRepeated(32, 'b'))
	h := &ImportExportHandler{db: db, crypto: crypto}

	app := fiber.New()
	app.Post("/bulk", func(c *fiber.Ctx) error {
		c.Locals("user_id", userID)
		return h.BulkImport(c)
	})

	body := `{"files":[{"format":"markdown","content":"# Title","title":"Note"},{"format":"html","content":"<script>alert('x')</script>"}]}`
	req := httptest.NewRequest("POST", "/bulk", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != fiber.StatusCreated {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}
	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	require.NoError(t, resp.Body.Close())

	if result["imported_count"].(float64) != 1 || result["failed_count"].(float64) != 1 {
		t.Fatalf("unexpected bulk import result: %#v", result)
	}
}

func TestExportNoteMarkdown(t *testing.T) {
	userID := uuid.New()
	noteID := uuid.New()
	db := &testDB{storageLimit: 2048, workspaceID: uuid.New(), noteCreated: time.Now().Add(-time.Hour), noteUpdated: time.Now()}
	crypto := appcrypto.NewCryptoService(bytesRepeated(32, 'n'))
	title := "Sample"
	content := "Body"
	db.noteTitleEnc, _ = crypto.Encrypt([]byte(title))
	db.noteContent, _ = crypto.Encrypt([]byte(content))

	h := &ImportExportHandler{db: db, crypto: crypto}
	app := fiber.New()
	app.Post("/notes/:id/export", func(c *fiber.Ctx) error {
		c.Locals("user_id", userID)
		return h.ExportNote(c)
	})

	body := `{"format":"markdown"}`
	req := httptest.NewRequest("POST", fmt.Sprintf("/notes/%s/export", noteID), strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != fiber.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode export response: %v", err)
	}
	require.NoError(t, resp.Body.Close())

	if result["title"] != title {
		t.Fatalf("expected title %q, got %v", title, result["title"])
	}
	if result["content_type"] != "text/markdown" {
		t.Fatalf("unexpected content type: %v", result["content_type"])
	}
}

func bytesRepeated(n int, b byte) []byte {
	buf := make([]byte, n)
	for i := range buf {
		buf[i] = b
	}
	return buf
}
