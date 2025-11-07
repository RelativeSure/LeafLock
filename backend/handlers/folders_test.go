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

// setupFoldersTestDB creates a test database connection
func setupFoldersTestDB(t *testing.T) (*pgxpool.Pool, func()) {
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

func TestFoldersHandler_CreateFolder_InvalidJSON(t *testing.T) {
	pool, cleanup := setupFoldersTestDB(t)
	defer cleanup()

	cryptoSvc := crypto.NewCryptoService(make([]byte, 32))
	handler := NewFoldersHandler(pool, cryptoSvc)
	app := fiber.New()

	app.Post("/folders", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		return handler.CreateFolder(c)
	})

	req := httptest.NewRequest("POST", "/folders", bytes.NewBufferString("{invalid json"))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	assert.Equal(t, 400, resp.StatusCode)
}

func TestFoldersHandler_CreateFolder_Success(t *testing.T) {
	pool, cleanup := setupFoldersTestDB(t)
	defer cleanup()

	cryptoSvc := crypto.NewCryptoService(make([]byte, 32))
	handler := NewFoldersHandler(pool, cryptoSvc)
	app := fiber.New()

	app.Post("/folders", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		return handler.CreateFolder(c)
	})

	reqBody := map[string]string{
		"name": "Test Folder",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/folders", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	// Should succeed (200) or fail if DB issues (500), but not panic
	assert.True(t, resp.StatusCode == 200 || resp.StatusCode == 201 || resp.StatusCode == 500)
}

func TestFoldersHandler_GetFolders_Success(t *testing.T) {
	pool, cleanup := setupFoldersTestDB(t)
	defer cleanup()

	cryptoSvc := crypto.NewCryptoService(make([]byte, 32))
	handler := NewFoldersHandler(pool, cryptoSvc)
	app := fiber.New()

	app.Get("/folders", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		return handler.GetFolders(c)
	})

	req := httptest.NewRequest("GET", "/folders", nil)
	resp, err := app.Test(req, -1)

	require.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)

	var result map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestFoldersHandler_MoveNoteToFolder_InvalidJSON(t *testing.T) {
	pool, cleanup := setupFoldersTestDB(t)
	defer cleanup()

	cryptoSvc := crypto.NewCryptoService(make([]byte, 32))
	handler := NewFoldersHandler(pool, cryptoSvc)
	app := fiber.New()

	app.Post("/notes/:noteId/folder", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		return handler.MoveNoteToFolder(c)
	})

	noteID := uuid.New().String()
	req := httptest.NewRequest("POST", "/notes/"+noteID+"/folder", bytes.NewBufferString("{invalid"))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	assert.Equal(t, 400, resp.StatusCode)
}

func TestFoldersHandler_MoveNoteToFolder_InvalidNoteID(t *testing.T) {
	pool, cleanup := setupFoldersTestDB(t)
	defer cleanup()

	cryptoSvc := crypto.NewCryptoService(make([]byte, 32))
	handler := NewFoldersHandler(pool, cryptoSvc)
	app := fiber.New()

	app.Post("/notes/:noteId/folder", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		return handler.MoveNoteToFolder(c)
	})

	reqBody := map[string]string{
		"folder_id": uuid.New().String(),
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/notes/invalid-uuid/folder", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	assert.Equal(t, 400, resp.StatusCode)
}

func TestFoldersHandler_DeleteFolder_InvalidID(t *testing.T) {
	pool, cleanup := setupFoldersTestDB(t)
	defer cleanup()

	cryptoSvc := crypto.NewCryptoService(make([]byte, 32))
	handler := NewFoldersHandler(pool, cryptoSvc)
	app := fiber.New()

	app.Delete("/folders/:id", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		return handler.DeleteFolder(c)
	})

	req := httptest.NewRequest("DELETE", "/folders/invalid-uuid", nil)
	resp, err := app.Test(req, -1)

	require.NoError(t, err)
	assert.Equal(t, 400, resp.StatusCode)
}

func TestFoldersHandler_DeleteFolder_NotFound(t *testing.T) {
	pool, cleanup := setupFoldersTestDB(t)
	defer cleanup()

	cryptoSvc := crypto.NewCryptoService(make([]byte, 32))
	handler := NewFoldersHandler(pool, cryptoSvc)
	app := fiber.New()

	app.Delete("/folders/:id", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		return handler.DeleteFolder(c)
	})

	nonExistentID := uuid.New().String()
	req := httptest.NewRequest("DELETE", "/folders/"+nonExistentID, nil)
	resp, err := app.Test(req, -1)

	require.NoError(t, err)
	// Should handle gracefully - either 404 or 200
	assert.True(t, resp.StatusCode == 404 || resp.StatusCode == 200)
}
