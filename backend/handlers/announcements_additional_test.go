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
)

type mockAnnouncementsDB struct {
	queryFunc func(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error)
	lastQuery string
}

func (m *mockAnnouncementsDB) Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error) {
	m.lastQuery = sql
	if m.queryFunc != nil {
		return m.queryFunc(ctx, sql, args...)
	}
	return &mockAnnouncementRows{}, nil
}

func (m *mockAnnouncementsDB) QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row {
	return emptyRow{}
}

func (m *mockAnnouncementsDB) Exec(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
	return pgconn.NewCommandTag("SELECT 0"), nil
}

func (m *mockAnnouncementsDB) Begin(ctx context.Context) (pgx.Tx, error) {
	return nil, nil
}

type announcementRecord struct {
	id          string
	title       string
	content     string
	visibility  string
	style       []byte
	active      bool
	dismissible bool
	priority    int
	startDate   *time.Time
	endDate     *time.Time
	createdBy   *string
	createdAt   time.Time
	updatedAt   time.Time
}

type mockAnnouncementRows struct {
	records []announcementRecord
	i       int
	closed  bool
	err     error
}

func (r *mockAnnouncementRows) Close() {
	r.closed = true
}

func (r *mockAnnouncementRows) Err() error {
	return r.err
}

func (r *mockAnnouncementRows) CommandTag() pgconn.CommandTag {
	return pgconn.NewCommandTag("SELECT 0")
}

func (r *mockAnnouncementRows) FieldDescriptions() []pgconn.FieldDescription {
	return nil
}

func (r *mockAnnouncementRows) Next() bool {
	if r.i < len(r.records) {
		r.i++
		return true
	}
	return false
}

func (r *mockAnnouncementRows) current() *announcementRecord {
	if r.i == 0 || r.i > len(r.records) {
		return nil
	}
	return &r.records[r.i-1]
}

func (r *mockAnnouncementRows) Scan(dest ...any) error {
	rec := r.current()
	if rec == nil {
		return pgx.ErrNoRows
	}
	if len(dest) != 13 {
		return fmt.Errorf("unexpected destination count: %d", len(dest))
	}
	if v, ok := dest[0].(*string); ok {
		*v = rec.id
	}
	if v, ok := dest[1].(*string); ok {
		*v = rec.title
	}
	if v, ok := dest[2].(*string); ok {
		*v = rec.content
	}
	if v, ok := dest[3].(*string); ok {
		*v = rec.visibility
	}
	if v, ok := dest[4].(*[]byte); ok {
		*v = rec.style
	}
	if v, ok := dest[5].(*bool); ok {
		*v = rec.active
	}
	if v, ok := dest[6].(*bool); ok {
		*v = rec.dismissible
	}
	if v, ok := dest[7].(*int); ok {
		*v = rec.priority
	}
	if v, ok := dest[8].(**time.Time); ok {
		*v = rec.startDate
	}
	if v, ok := dest[9].(**time.Time); ok {
		*v = rec.endDate
	}
	if v, ok := dest[10].(**string); ok {
		*v = rec.createdBy
	}
	if v, ok := dest[11].(*time.Time); ok {
		*v = rec.createdAt
	}
	if v, ok := dest[12].(*time.Time); ok {
		*v = rec.updatedAt
	}
	return nil
}

func (r *mockAnnouncementRows) Values() ([]any, error) {
	rec := r.current()
	if rec == nil {
		return nil, pgx.ErrNoRows
	}
	return []any{rec.id, rec.title, rec.content, rec.visibility, rec.style, rec.active, rec.dismissible, rec.priority, rec.startDate, rec.endDate, rec.createdBy, rec.createdAt, rec.updatedAt}, nil
}

func (r *mockAnnouncementRows) RawValues() [][]byte {
	return nil
}

func (r *mockAnnouncementRows) Conn() *pgx.Conn {
	return nil
}

type emptyRow struct{}

func (emptyRow) Scan(dest ...any) error {
	return pgx.ErrNoRows
}

func TestGetAnnouncementsAuthenticated(t *testing.T) {
	now := time.Now().UTC()
	creator := uuid.New().String()
	records := []announcementRecord{
		{
			id:          uuid.New().String(),
			title:       "Welcome",
			content:     "Hello",
			visibility:  "logged_in",
			style:       []byte(`{"color":"blue"}`),
			active:      true,
			dismissible: true,
			priority:    10,
			startDate:   &now,
			endDate:     nil,
			createdBy:   &creator,
			createdAt:   now,
			updatedAt:   now,
		},
	}

	db := &mockAnnouncementsDB{
		queryFunc: func(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error) {
			return &mockAnnouncementRows{records: records}, nil
		},
	}

	handler := NewAnnouncementsHandler(db)
	app := fiber.New()
	app.Get("/announcements", func(c *fiber.Ctx) error {
		c.Locals("userID", uuid.New())
		return handler.GetAnnouncements(c)
	})

	resp, err := app.Test(httptest.NewRequest("GET", "/announcements", nil), -1)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var payload []Announcement
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if len(payload) != 1 {
		t.Fatalf("expected 1 announcement, got %d", len(payload))
	}
	if payload[0].Style["color"] != "blue" {
		t.Fatalf("expected style color blue, got %v", payload[0].Style)
	}
	if !strings.Contains(db.lastQuery, "visibility IN ('all', 'logged_in')") {
		t.Fatalf("expected authenticated query to include logged_in visibility, got: %s", db.lastQuery)
	}
}

func TestGetAnnouncementsPublic(t *testing.T) {
	records := []announcementRecord{
		{id: uuid.New().String(), title: "Public", content: "Info", visibility: "all", active: true, dismissible: false, priority: 1, createdAt: time.Now().UTC(), updatedAt: time.Now().UTC()},
	}

	db := &mockAnnouncementsDB{
		queryFunc: func(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error) {
			return &mockAnnouncementRows{records: records}, nil
		},
	}

	handler := NewAnnouncementsHandler(db)
	app := fiber.New()
	app.Get("/announcements", handler.GetAnnouncements)

	resp, err := app.Test(httptest.NewRequest("GET", "/announcements", nil), -1)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if !strings.Contains(db.lastQuery, "visibility = 'all'") {
		t.Fatalf("expected public query to restrict visibility, got: %s", db.lastQuery)
	}
}

func TestGetAllAnnouncements(t *testing.T) {
	records := []announcementRecord{
		{id: uuid.New().String(), title: "System", content: "Maintenance", visibility: "all", active: true, dismissible: true, priority: 5, createdAt: time.Now().UTC(), updatedAt: time.Now().UTC()},
	}

	db := &mockAnnouncementsDB{
		queryFunc: func(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error) {
			return &mockAnnouncementRows{records: records}, nil
		},
	}

	handler := NewAnnouncementsHandler(db)
	app := fiber.New()
	app.Get("/admin/announcements", handler.GetAllAnnouncements)

	resp, err := app.Test(httptest.NewRequest("GET", "/admin/announcements", nil), -1)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var payload []Announcement
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if len(payload) != 1 {
		t.Fatalf("expected 1 announcement, got %d", len(payload))
	}
}
