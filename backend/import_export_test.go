package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestImportExportFeatures(t *testing.T) {
	initLogging()

	// Setup test database
	db, err := SetupTestDatabase()
	require.NoError(t, err)
	defer func() {
		if closer, ok := db.(interface{ Close() error }); ok {
			closer.Close()
		}
	}()

	// Create crypto service
	crypto := NewCryptoService([]byte("test-key-32-bytes-long-for-testing"))

	// Create import/export handler
	handler := &ImportExportHandler{
		db:     db,
		crypto: crypto,
	}

	// Create test user and workspace
	userID := uuid.New()
	workspaceID := uuid.New()

	ctx := context.Background()
	_, err = db.Exec(ctx, "TRUNCATE collaborations, note_versions, notes, workspaces, users CASCADE")
	require.NoError(t, err)

	_, err = db.Exec(ctx, `
        INSERT INTO users (
            id, email, email_hash, email_encrypted, email_search_hash,
            password_hash, salt, master_key_encrypted, storage_used, storage_limit
        ) VALUES
            ($1, $2, $3, $4, $5, $6, $7, $8, 0, 10485760)`,
		userID,
		"test@example.com",
		[]byte("hash-test"),
		[]byte("enc-test"),
		[]byte("search-test"),
		"hash",
		[]byte("salt"),
		[]byte("master"))
	require.NoError(t, err)

	_, err = db.Exec(ctx, `
        INSERT INTO workspaces (id, name_encrypted, owner_id, encryption_key_encrypted)
        VALUES ($1, $2, $3, $4)`,
		workspaceID, []byte("workspace"), userID, []byte("workspace-key"))
	require.NoError(t, err)

	t.Run("ImportMarkdownNote", func(t *testing.T) {
		app := fiber.New()
		app.Post("/notes/import", func(c *fiber.Ctx) error {
			c.Locals("user_id", userID)
			return handler.ImportNote(c)
		})

		payload := ImportRequest{
			Format:   "markdown",
			Content:  "# Test Note\n\nThis is a test markdown note with **bold** text.",
			Filename: "test.md",
		}

		body, _ := json.Marshal(payload)
		req := httptest.NewRequest(http.MethodPost, "/notes/import", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, fiber.StatusCreated, resp.StatusCode)

		respBody, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		var response map[string]interface{}
		require.NoError(t, json.Unmarshal(respBody, &response))
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

		_, err = db.Exec(ctx, `
            INSERT INTO notes (id, workspace_id, title_encrypted, content_encrypted, content_hash)
            VALUES ($1, $2, $3, $4, $5)`,
			noteID, workspaceID, encryptedTitle, encryptedContent, []byte("content-hash"))
		require.NoError(t, err)

		reqBody, _ := json.Marshal(ExportRequest{Format: "markdown"})
		req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/notes/%s/export", noteID), bytes.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, fiber.StatusOK, resp.StatusCode)

		respBody, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		var response map[string]interface{}
		require.NoError(t, json.Unmarshal(respBody, &response))

		exportedContent, ok := response["content"].(string)
		require.True(t, ok)
		assert.Contains(t, exportedContent, "# Export Test")
		assert.Contains(t, exportedContent, "This note will be exported.")
	})

	t.Run("BulkImportNotes", func(t *testing.T) {
		app := fiber.New()
		app.Post("/notes/bulk-import", func(c *fiber.Ctx) error {
			c.Locals("user_id", userID)
			return handler.BulkImport(c)
		})

		payload := BulkImportRequest{
			Files: []ImportRequest{
				{Format: "markdown", Content: "# Note 1\n\nFirst note content.", Filename: "note1.md"},
				{Format: "text", Content: "Note 2\n\nSecond note content.", Filename: "note2.txt"},
			},
		}

		body, _ := json.Marshal(payload)
		req := httptest.NewRequest(http.MethodPost, "/notes/bulk-import", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, fiber.StatusCreated, resp.StatusCode)

		respBody, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		var response map[string]interface{}
		require.NoError(t, json.Unmarshal(respBody, &response))

		importedNotes, ok := response["imported"].([]interface{})
		require.True(t, ok)
		assert.Len(t, importedNotes, 2)
	})

	t.Run("ImportUnsupportedFileType", func(t *testing.T) {
		app := fiber.New()
		app.Post("/notes/import", func(c *fiber.Ctx) error {
			c.Locals("user_id", userID)
			return handler.ImportNote(c)
		})

		payload := ImportRequest{
			Format:   "pdf",
			Content:  "fake pdf content",
			Filename: "test.pdf",
		}
		body, _ := json.Marshal(payload)
		req := httptest.NewRequest(http.MethodPost, "/notes/import", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)
	})
}
