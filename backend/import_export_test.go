package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"
)

func TestImportExportFeatures(t *testing.T) {
	// Setup test database
	db, err := SetupTestDatabase()
	if err != nil {
		t.Skipf("Skipping import/export tests: %v", err)
	}
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
	_, err = db.Exec(ctx, `
		INSERT INTO users (id, email, password_hash, workspace_id)
		VALUES ($1, 'test@example.com', 'hash', $2)`,
		userID, workspaceID)
	require.NoError(t, err)

	_, err = db.Exec(ctx, `
		INSERT INTO workspaces (id, name, owner_id)
		VALUES ($1, 'Test Workspace', $2)`,
		workspaceID, userID)
	require.NoError(t, err)

	t.Run("ImportMarkdownNote", func(t *testing.T) {
		app := fiber.New()

		// Create multipart form with markdown file
		var requestBody bytes.Buffer
		writer := multipart.NewWriter(&requestBody)

		fileWriter, err := writer.CreateFormFile("file", "test.md")
		require.NoError(t, err)

		markdownContent := "# Test Note\n\nThis is a test markdown note with **bold** text."
		_, err = fileWriter.Write([]byte(markdownContent))
		require.NoError(t, err)

		err = writer.Close()
		require.NoError(t, err)

		// Create test context
		ctx := &fasthttp.RequestCtx{}
		ctx.Request.SetRequestURI("/notes/import")
		ctx.Request.Header.SetMethod("POST")
		ctx.Request.Header.SetContentType(writer.FormDataContentType())
		ctx.Request.SetBody(requestBody.Bytes())

		c := app.AcquireCtx(ctx)
		defer app.ReleaseCtx(c)
		c.Locals("user_id", userID)

		// Execute handler
		err = handler.ImportNote(c)
		require.NoError(t, err)

		// Check response
		assert.Equal(t, fiber.StatusCreated, c.Response().StatusCode())

		// Parse response
		var response map[string]interface{}
		err = json.Unmarshal(c.Response().Body(), &response)
		require.NoError(t, err)

		note, ok := response["note"].(map[string]interface{})
		require.True(t, ok)
		assert.Equal(t, "Test Note", note["title"])
	})

	t.Run("ExportMarkdownNote", func(t *testing.T) {
		app := fiber.New()

		// Create a test note
		noteID := uuid.New()
		title := "Export Test Note"
		content := "# Export Test\n\nThis note will be exported."

		// Encrypt the note data
		encryptedTitle, err := crypto.Encrypt([]byte(title))
		require.NoError(t, err)
		encryptedContent, err := crypto.Encrypt([]byte(content))
		require.NoError(t, err)

		_, err = db.Exec(ctx, `
			INSERT INTO notes (id, workspace_id, title_encrypted, content_encrypted)
			VALUES ($1, $2, $3, $4)`,
			noteID, workspaceID, encryptedTitle, encryptedContent)
		require.NoError(t, err)

		// Create export request
		exportReq := map[string]string{
			"format": "markdown",
		}
		reqBody, _ := json.Marshal(exportReq)

		// Create test context
		ctx := &fasthttp.RequestCtx{}
		ctx.Request.SetRequestURI(fmt.Sprintf("/notes/%s/export", noteID))
		ctx.Request.Header.SetMethod("POST")
		ctx.Request.Header.SetContentType("application/json")
		ctx.Request.SetBody(reqBody)

		c := app.AcquireCtx(ctx)
		defer app.ReleaseCtx(c)
		c.Locals("user_id", userID)
		c.Params("id", noteID.String())

		// Execute handler
		err = handler.ExportNote(c)
		require.NoError(t, err)

		// Check response
		assert.Equal(t, fiber.StatusOK, c.Response().StatusCode())

		// Parse response
		var response map[string]interface{}
		err = json.Unmarshal(c.Response().Body(), &response)
		require.NoError(t, err)

		exportedContent, ok := response["content"].(string)
		require.True(t, ok)
		assert.Contains(t, exportedContent, "# Export Test")
		assert.Contains(t, exportedContent, "This note will be exported.")
	})

	t.Run("BulkImportNotes", func(t *testing.T) {
		app := fiber.New()

		// Create multipart form with multiple files
		var requestBody bytes.Buffer
		writer := multipart.NewWriter(&requestBody)

		// Add first file
		fileWriter1, err := writer.CreateFormFile("files", "note1.md")
		require.NoError(t, err)
		_, err = fileWriter1.Write([]byte("# Note 1\n\nFirst note content."))
		require.NoError(t, err)

		// Add second file
		fileWriter2, err := writer.CreateFormFile("files", "note2.txt")
		require.NoError(t, err)
		_, err = fileWriter2.Write([]byte("Note 2\n\nSecond note content."))
		require.NoError(t, err)

		err = writer.Close()
		require.NoError(t, err)

		// Create test context
		ctx := &fasthttp.RequestCtx{}
		ctx.Request.SetRequestURI("/notes/bulk-import")
		ctx.Request.Header.SetMethod("POST")
		ctx.Request.Header.SetContentType(writer.FormDataContentType())
		ctx.Request.SetBody(requestBody.Bytes())

		c := app.AcquireCtx(ctx)
		defer app.ReleaseCtx(c)
		c.Locals("user_id", userID)

		// Execute handler
		err = handler.BulkImport(c)
		require.NoError(t, err)

		// Check response
		assert.Equal(t, fiber.StatusCreated, c.Response().StatusCode())

		// Parse response
		var response map[string]interface{}
		err = json.Unmarshal(c.Response().Body(), &response)
		require.NoError(t, err)

		importedNotes, ok := response["imported_notes"].([]interface{})
		require.True(t, ok)
		assert.Len(t, importedNotes, 2)

		// Check first note
		note1 := importedNotes[0].(map[string]interface{})
		assert.Equal(t, "Note 1", note1["title"])

		// Check second note
		note2 := importedNotes[1].(map[string]interface{})
		assert.Equal(t, "Note 2", note2["title"])
	})

	t.Run("ImportUnsupportedFileType", func(t *testing.T) {
		app := fiber.New()

		// Create multipart form with unsupported file
		var requestBody bytes.Buffer
		writer := multipart.NewWriter(&requestBody)

		fileWriter, err := writer.CreateFormFile("file", "test.pdf")
		require.NoError(t, err)
		_, err = fileWriter.Write([]byte("fake pdf content"))
		require.NoError(t, err)

		err = writer.Close()
		require.NoError(t, err)

		// Create test context
		ctx := &fasthttp.RequestCtx{}
		ctx.Request.SetRequestURI("/notes/import")
		ctx.Request.Header.SetMethod("POST")
		ctx.Request.Header.SetContentType(writer.FormDataContentType())
		ctx.Request.SetBody(requestBody.Bytes())

		c := app.AcquireCtx(ctx)
		defer app.ReleaseCtx(c)
		c.Locals("user_id", userID)

		// Execute handler
		err = handler.ImportNote(c)
		require.Error(t, err)
	})
}
