package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"

	miniredis "github.com/alicebob/miniredis/v2"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"leaflock/auth"
)

func TestImportExportFeatures(t *testing.T) {
	// Setup test database
	db, err := SetupTestDatabase()
	if err != nil {
		t.Skipf("Skipping import/export tests: %v", err)
	}
	defer func() {
		if closer, ok := db.(interface{ Close() error }); ok {
			_ = closer.Close() // Test cleanup
		}
	}()

	// Create crypto and auth services
	cfg := LoadConfig()
	testKey := make([]byte, 32) // Test encryption key
	crypto := NewCryptoService(testKey)

	dbPool, ok := db.(*pgxpool.Pool)
	require.True(t, ok, "expected *pgxpool.Pool")

	mr := miniredis.RunT(t)
	defer mr.Close()

	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	authService := auth.NewService(dbPool, rdb, string(cfg.JWTSecret))

	// Create import/export handler
	handler := &ImportExportHandler{
		db:     db,
		crypto: crypto,
	}

	// Create test user and workspace via auth service
	userEmail := fmt.Sprintf("importer+%s@example.com", uuid.NewString())
	ctx := context.Background()

	userResp, err := authService.Register(ctx, userEmail, "TestPass123!@#")
	require.NoError(t, err)

	userID := uuid.MustParse(userResp.UserID)
	workspaceID := uuid.MustParse(userResp.WorkspaceID)

	_, err = db.Exec(ctx, `UPDATE users SET email = $1 WHERE id = $2`, userEmail, userID)
	require.NoError(t, err)

	t.Run("ImportMarkdownNote", func(t *testing.T) {
		app := fiber.New()
		app.Post("/notes/import", func(c *fiber.Ctx) error {
			c.Locals("user_id", userID)
			return handler.ImportNote(c)
		})

		markdownContent := "# Test Note\n\nThis is a test markdown note with **bold** text."
		payload := map[string]string{
			"format":  "markdown",
			"content": markdownContent,
			"title":   "Test Note",
		}
		body, err := json.Marshal(payload)
		require.NoError(t, err)

		req := httptest.NewRequest("POST", "/notes/import", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusCreated, resp.StatusCode)

		var response map[string]interface{}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&response))
		require.NoError(t, resp.Body.Close())

		assert.Equal(t, "Test Note", response["title"])
	})

	t.Run("ExportMarkdownNote", func(t *testing.T) {
		app := fiber.New()
		app.Post("/notes/:id/export", func(c *fiber.Ctx) error {
			c.Locals("user_id", userID)
			return handler.ExportNote(c)
		})

		noteID := uuid.New()
		title := "Export Test Note"
		content := "# Export Test\n\nThis note will be exported."

		encryptedTitle, err := crypto.Encrypt([]byte(title))
		require.NoError(t, err)
		encryptedContent, err := crypto.Encrypt([]byte(content))
		require.NoError(t, err)

		contentHash := sha256.Sum256([]byte(content))
		_, err = db.Exec(ctx, `
			INSERT INTO notes (id, workspace_id, title_encrypted, content_encrypted, content_hash, created_by, is_pinned, pinned_order)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			noteID, workspaceID, encryptedTitle, encryptedContent, contentHash[:], userID, false, 0)
		require.NoError(t, err)

		payload := map[string]string{"format": "markdown"}
		body, err := json.Marshal(payload)
		require.NoError(t, err)

		req := httptest.NewRequest("POST", fmt.Sprintf("/notes/%s/export", noteID), bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)

		var response map[string]interface{}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&response))
		require.NoError(t, resp.Body.Close())
		assert.Equal(t, "markdown", response["format"])
		assert.Contains(t, response["content"], "Export Test")
	})

	t.Run("BulkImportNotes", func(t *testing.T) {
		app := fiber.New()
		app.Post("/notes/bulk-import", func(c *fiber.Ctx) error {
			c.Locals("user_id", userID)
			return handler.BulkImport(c)
		})

		payload := map[string]interface{}{
			"files": []map[string]string{
				{"format": "markdown", "content": "# Note 1\n\nFirst note content.", "title": "Note 1"},
				{"format": "text", "content": "Note 2\n\nSecond note content.", "title": "Note 2"},
			},
		}
		body, err := json.Marshal(payload)
		require.NoError(t, err)

		req := httptest.NewRequest("POST", "/notes/bulk-import", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusCreated, resp.StatusCode)

		var response map[string]interface{}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&response))
		require.NoError(t, resp.Body.Close())

		imported, ok := response["imported"].([]interface{})
		require.True(t, ok)
		assert.Len(t, imported, 2)
	})

	t.Run("ImportUnsupportedFileType", func(t *testing.T) {
		app := fiber.New()
		app.Post("/notes/import", func(c *fiber.Ctx) error {
			c.Locals("user_id", userID)
			return handler.ImportNote(c)
		})

		payload := map[string]string{
			"format":  "pdf",
			"content": "fake pdf content",
			"title":   "Unsupported",
		}
		body, err := json.Marshal(payload)
		require.NoError(t, err)

		req := httptest.NewRequest("POST", "/notes/import", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)
	})
}
