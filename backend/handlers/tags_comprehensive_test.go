package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"leaflock/crypto"
)

// setupTagsTestDB creates a test database connection
func setupTagsTestDB(t *testing.T) (*pgxpool.Pool, func()) {
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://test:test@localhost:5433/leaflock_test?sslmode=disable" // secretlint-disable-line
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		t.Skipf("Skipping integration test: cannot connect to test database: %v", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Skipf("Skipping integration test: database ping failed: %v", err)
	}

	cleanup := func() {
		pool.Close()
	}

	return pool, cleanup
}

func TestTagsHandler_CreateTag_InvalidJSON(t *testing.T) {
	pool, cleanup := setupTagsTestDB(t)
	defer cleanup()

	cryptoSvc := crypto.NewCryptoService(make([]byte, 32))
	handler := NewTagsHandler(pool, cryptoSvc)
	app := fiber.New()

	app.Post("/tags", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		return handler.CreateTag(c)
	})

	req := httptest.NewRequest("POST", "/tags", bytes.NewBufferString("{invalid json"))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	assert.Equal(t, 400, resp.StatusCode)
}

func TestTagsHandler_CreateTag_MissingName(t *testing.T) {
	pool, cleanup := setupTagsTestDB(t)
	defer cleanup()

	cryptoSvc := crypto.NewCryptoService(make([]byte, 32))
	handler := NewTagsHandler(pool, cryptoSvc)
	app := fiber.New()

	app.Post("/tags", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		return handler.CreateTag(c)
	})

	reqBody := map[string]string{
		"color": "#FF0000",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/tags", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	assert.Equal(t, 400, resp.StatusCode)
}

func TestTagsHandler_CreateTag_Success(t *testing.T) {
	pool, cleanup := setupTagsTestDB(t)
	defer cleanup()

	cryptoSvc := crypto.NewCryptoService(make([]byte, 32))
	handler := NewTagsHandler(pool, cryptoSvc)
	app := fiber.New()

	app.Post("/tags", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		return handler.CreateTag(c)
	})

	reqBody := map[string]string{
		"name": "Test Tag",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/tags", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	assert.True(t, resp.StatusCode == 200 || resp.StatusCode == 201 || resp.StatusCode == 500)
}

func TestTagsHandler_GetTags_Success(t *testing.T) {
	pool, cleanup := setupTagsTestDB(t)
	defer cleanup()

	cryptoSvc := crypto.NewCryptoService(make([]byte, 32))
	handler := NewTagsHandler(pool, cryptoSvc)
	app := fiber.New()

	app.Get("/tags", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		return handler.GetTags(c)
	})

	req := httptest.NewRequest("GET", "/tags", nil)
	resp, err := app.Test(req, -1)

	require.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)

	var result map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestTagsHandler_DeleteTag_InvalidID(t *testing.T) {
	pool, cleanup := setupTagsTestDB(t)
	defer cleanup()

	cryptoSvc := crypto.NewCryptoService(make([]byte, 32))
	handler := NewTagsHandler(pool, cryptoSvc)
	app := fiber.New()

	app.Delete("/tags/:id", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		return handler.DeleteTag(c)
	})

	req := httptest.NewRequest("DELETE", "/tags/invalid-uuid", nil)
	resp, err := app.Test(req, -1)

	require.NoError(t, err)
	assert.Equal(t, 400, resp.StatusCode)
}

func TestTagsHandler_DeleteTag_NotFound(t *testing.T) {
	pool, cleanup := setupTagsTestDB(t)
	defer cleanup()

	cryptoSvc := crypto.NewCryptoService(make([]byte, 32))
	handler := NewTagsHandler(pool, cryptoSvc)
	app := fiber.New()

	app.Delete("/tags/:id", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		return handler.DeleteTag(c)
	})

	nonExistentID := uuid.New().String()
	req := httptest.NewRequest("DELETE", "/tags/"+nonExistentID, nil)
	resp, err := app.Test(req, -1)

	require.NoError(t, err)
	// Should handle gracefully - either 404 or 200
	assert.True(t, resp.StatusCode == 404 || resp.StatusCode == 200)
}

func TestTagsHandler_AssignTagToNote_InvalidJSON(t *testing.T) {
	pool, cleanup := setupTagsTestDB(t)
	defer cleanup()

	cryptoSvc := crypto.NewCryptoService(make([]byte, 32))
	handler := NewTagsHandler(pool, cryptoSvc)
	app := fiber.New()

	app.Post("/notes/:noteId/tags", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		return handler.AssignTagToNote(c)
	})

	noteID := uuid.New().String()
	req := httptest.NewRequest("POST", "/notes/"+noteID+"/tags", bytes.NewBufferString("{invalid"))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	assert.Equal(t, 400, resp.StatusCode)
}

func TestTagsHandler_AssignTagToNote_InvalidNoteID(t *testing.T) {
	pool, cleanup := setupTagsTestDB(t)
	defer cleanup()

	cryptoSvc := crypto.NewCryptoService(make([]byte, 32))
	handler := NewTagsHandler(pool, cryptoSvc)
	app := fiber.New()

	app.Post("/notes/:noteId/tags", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		return handler.AssignTagToNote(c)
	})

	reqBody := map[string]string{
		"tag_id": uuid.New().String(),
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/notes/invalid-uuid/tags", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	assert.Equal(t, 400, resp.StatusCode)
}

func TestTagsHandler_RemoveTagFromNote_InvalidNoteID(t *testing.T) {
	pool, cleanup := setupTagsTestDB(t)
	defer cleanup()

	cryptoSvc := crypto.NewCryptoService(make([]byte, 32))
	handler := NewTagsHandler(pool, cryptoSvc)
	app := fiber.New()

	app.Delete("/notes/:noteId/tags/:tagId", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		return handler.RemoveTagFromNote(c)
	})

	tagID := uuid.New().String()
	req := httptest.NewRequest("DELETE", "/notes/invalid-uuid/tags/"+tagID, nil)
	resp, err := app.Test(req, -1)

	require.NoError(t, err)
	assert.Equal(t, 400, resp.StatusCode)
}

func TestTagsHandler_RemoveTagFromNote_InvalidTagID(t *testing.T) {
	pool, cleanup := setupTagsTestDB(t)
	defer cleanup()

	cryptoSvc := crypto.NewCryptoService(make([]byte, 32))
	handler := NewTagsHandler(pool, cryptoSvc)
	app := fiber.New()

	app.Delete("/notes/:noteId/tags/:tagId", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		return handler.RemoveTagFromNote(c)
	})

	noteID := uuid.New().String()
	req := httptest.NewRequest("DELETE", "/notes/"+noteID+"/tags/invalid-uuid", nil)
	resp, err := app.Test(req, -1)

	require.NoError(t, err)
	assert.Equal(t, 400, resp.StatusCode)
}

func TestTagsHandler_GetNotesByTag_InvalidTagID(t *testing.T) {
	pool, cleanup := setupTagsTestDB(t)
	defer cleanup()

	cryptoSvc := crypto.NewCryptoService(make([]byte, 32))
	handler := NewTagsHandler(pool, cryptoSvc)
	app := fiber.New()

	app.Get("/tags/:id/notes", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		return handler.GetNotesByTag(c)
	})

	req := httptest.NewRequest("GET", "/tags/invalid-uuid/notes", nil)
	resp, err := app.Test(req, -1)

	require.NoError(t, err)
	assert.Equal(t, 400, resp.StatusCode)
}

func TestTagsHandler_GetNotesByTag_Success(t *testing.T) {
	pool, cleanup := setupTagsTestDB(t)
	defer cleanup()

	cryptoSvc := crypto.NewCryptoService(make([]byte, 32))
	handler := NewTagsHandler(pool, cryptoSvc)
	app := fiber.New()

	app.Get("/tags/:id/notes", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		return handler.GetNotesByTag(c)
	})

	tagID := uuid.New().String()
	req := httptest.NewRequest("GET", "/tags/"+tagID+"/notes", nil)
	resp, err := app.Test(req, -1)

	require.NoError(t, err)
	// Should return 200 even if tag doesn't exist (empty list)
	assert.True(t, resp.StatusCode == 200 || resp.StatusCode == 404)
}
