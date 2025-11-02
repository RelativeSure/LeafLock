package handlers

import (
	"bytes"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"leaflock/crypto"
)

// TestNotesHandler_UpdateInvalidJSON tests UpdateNote with invalid JSON
func TestNotesHandler_UpdateInvalidJSON(t *testing.T) {
	cryptoSvc := crypto.NewCryptoService(make([]byte, 32))
	handler := NewNotesHandler(nil, cryptoSvc)
	app := fiber.New()

	noteID := uuid.New()
	app.Put("/notes/:id", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		return handler.UpdateNote(c)
	})

	req := httptest.NewRequest("PUT", "/notes/"+noteID.String(), bytes.NewBufferString("{invalid json"))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	assert.Equal(t, 400, resp.StatusCode)
}

// TestNotesHandler_UpdateInvalidID tests UpdateNote with invalid ID
func TestNotesHandler_UpdateInvalidID(t *testing.T) {
	cryptoSvc := crypto.NewCryptoService(make([]byte, 32))
	handler := NewNotesHandler(nil, cryptoSvc)
	app := fiber.New()

	app.Put("/notes/:id", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		return handler.UpdateNote(c)
	})

	req := httptest.NewRequest("PUT", "/notes/invalid-uuid", bytes.NewBufferString(`{"title":"test"}`))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	assert.Equal(t, 400, resp.StatusCode)
}

// TestNotesHandler_GetVersionsInvalidID tests GetNoteVersions with invalid ID
func TestNotesHandler_GetVersionsInvalidID(t *testing.T) {
	cryptoSvc := crypto.NewCryptoService(make([]byte, 32))
	handler := NewNotesHandler(nil, cryptoSvc)
	app := fiber.New()

	app.Get("/notes/:id/versions", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		return handler.GetNoteVersions(c)
	})

	req := httptest.NewRequest("GET", "/notes/invalid-uuid/versions", nil)
	resp, err := app.Test(req, -1)

	require.NoError(t, err)
	assert.Equal(t, 400, resp.StatusCode)
}

// TestNotesHandler_RestoreVersionInvalidIDs tests RestoreNoteVersion with invalid IDs
func TestNotesHandler_RestoreVersionInvalidIDs(t *testing.T) {
	cryptoSvc := crypto.NewCryptoService(make([]byte, 32))
	handler := NewNotesHandler(nil, cryptoSvc)
	app := fiber.New()

	app.Post("/notes/:id/versions/:versionId/restore", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		return handler.RestoreNoteVersion(c)
	})

	req := httptest.NewRequest("POST", "/notes/invalid-uuid/versions/"+uuid.New().String()+"/restore", nil)
	resp, err := app.Test(req, -1)

	require.NoError(t, err)
	assert.Equal(t, 400, resp.StatusCode)
}

// TestNotesHandler_CompareVersionsInvalidID tests CompareNoteVersions with invalid ID
func TestNotesHandler_CompareVersionsInvalidID(t *testing.T) {
	cryptoSvc := crypto.NewCryptoService(make([]byte, 32))
	handler := NewNotesHandler(nil, cryptoSvc)
	app := fiber.New()

	app.Get("/notes/:id/versions/compare", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		return handler.CompareNoteVersions(c)
	})

	req := httptest.NewRequest("GET", "/notes/invalid-uuid/versions/compare?v1=1&v2=2", nil)
	resp, err := app.Test(req, -1)

	require.NoError(t, err)
	assert.Equal(t, 400, resp.StatusCode)
}

// TestNotesHandler_DeleteVersionInvalidIDs tests DeleteNoteVersion with invalid IDs
func TestNotesHandler_DeleteVersionInvalidIDs(t *testing.T) {
	cryptoSvc := crypto.NewCryptoService(make([]byte, 32))
	handler := NewNotesHandler(nil, cryptoSvc)
	app := fiber.New()

	app.Delete("/notes/:id/versions/:versionId", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		return handler.DeleteNoteVersion(c)
	})

	req := httptest.NewRequest("DELETE", "/notes/invalid-uuid/versions/"+uuid.New().String(), nil)
	resp, err := app.Test(req, -1)

	require.NoError(t, err)
	assert.Equal(t, 400, resp.StatusCode)
}

// TestNotesHandler_UpdateRetentionPolicyInvalidID tests UpdateRetentionPolicy with invalid ID
func TestNotesHandler_UpdateRetentionPolicyInvalidID(t *testing.T) {
	cryptoSvc := crypto.NewCryptoService(make([]byte, 32))
	handler := NewNotesHandler(nil, cryptoSvc)
	app := fiber.New()

	app.Put("/notes/:id/retention", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		return handler.UpdateRetentionPolicy(c)
	})

	req := httptest.NewRequest("PUT", "/notes/invalid-uuid/retention", bytes.NewBufferString(`{"days":30}`))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	assert.Equal(t, 400, resp.StatusCode)
}

// TestNotesHandler_BulkDeleteInvalidJSON tests BulkDeleteNotes with invalid JSON
func TestNotesHandler_BulkDeleteInvalidJSON(t *testing.T) {
	cryptoSvc := crypto.NewCryptoService(make([]byte, 32))
	handler := NewNotesHandler(nil, cryptoSvc)
	app := fiber.New()

	app.Post("/notes/bulk-delete", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		return handler.BulkDeleteNotes(c)
	})

	req := httptest.NewRequest("POST", "/notes/bulk-delete", bytes.NewBufferString("{invalid json"))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	assert.Equal(t, 400, resp.StatusCode)
}

// TestNotesHandler_BulkRestoreInvalidJSON tests BulkRestoreNotes with invalid JSON
func TestNotesHandler_BulkRestoreInvalidJSON(t *testing.T) {
	cryptoSvc := crypto.NewCryptoService(make([]byte, 32))
	handler := NewNotesHandler(nil, cryptoSvc)
	app := fiber.New()

	app.Post("/notes/bulk-restore", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		return handler.BulkRestoreNotes(c)
	})

	req := httptest.NewRequest("POST", "/notes/bulk-restore", bytes.NewBufferString("{invalid json"))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	assert.Equal(t, 400, resp.StatusCode)
}

// TestNotesHandler_PermanentlyDeleteInvalidID tests PermanentlyDeleteNote with invalid ID
func TestNotesHandler_PermanentlyDeleteInvalidID(t *testing.T) {
	cryptoSvc := crypto.NewCryptoService(make([]byte, 32))
	handler := NewNotesHandler(nil, cryptoSvc)
	app := fiber.New()

	app.Delete("/notes/:id/permanent", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		return handler.PermanentlyDeleteNote(c)
	})

	req := httptest.NewRequest("DELETE", "/notes/invalid-uuid/permanent", nil)
	resp, err := app.Test(req, -1)

	require.NoError(t, err)
	assert.Equal(t, 400, resp.StatusCode)
}

// TestNoteLinksHandler_GetBacklinksInvalidID tests GetNoteBacklinks with invalid ID
func TestNoteLinksHandler_GetBacklinksInvalidID(t *testing.T) {
	handler := NewNoteLinksHandler(nil)
	app := fiber.New()

	app.Get("/notes/:id/backlinks", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		return handler.GetNoteBacklinks(c)
	})

	req := httptest.NewRequest("GET", "/notes/invalid-uuid/backlinks", nil)
	resp, err := app.Test(req, -1)

	require.NoError(t, err)
	assert.Equal(t, 400, resp.StatusCode)
}

// TestNoteLinksHandler_DeleteInvalidID tests DeleteNoteLink with invalid ID
func TestNoteLinksHandler_DeleteInvalidID(t *testing.T) {
	handler := NewNoteLinksHandler(nil)
	app := fiber.New()

	app.Delete("/notes/:id/links/:linkId", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		return handler.DeleteNoteLink(c)
	})

	req := httptest.NewRequest("DELETE", "/notes/invalid-uuid/links/"+uuid.New().String(), nil)
	resp, err := app.Test(req, -1)

	require.NoError(t, err)
	assert.Equal(t, 400, resp.StatusCode)
}

// TestNoteLinksHandler_CreateInvalidJSON tests CreateNoteLink with invalid JSON
func TestNoteLinksHandler_CreateInvalidJSON(t *testing.T) {
	handler := NewNoteLinksHandler(nil)
	app := fiber.New()

	noteID := uuid.New()
	app.Post("/notes/:id/links", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		return handler.CreateNoteLink(c)
	})

	req := httptest.NewRequest("POST", "/notes/"+noteID.String()+"/links", bytes.NewBufferString("{invalid json"))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	assert.Equal(t, 400, resp.StatusCode)
}

// TestNoteLinksHandler_CreateInvalidNoteID tests CreateNoteLink with invalid note ID
func TestNoteLinksHandler_CreateInvalidNoteID(t *testing.T) {
	handler := NewNoteLinksHandler(nil)
	app := fiber.New()

	app.Post("/notes/:id/links", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		return handler.CreateNoteLink(c)
	})

	req := httptest.NewRequest("POST", "/notes/invalid-uuid/links", bytes.NewBufferString(`{"target_note_id":"`+uuid.New().String()+`"}`))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	assert.Equal(t, 400, resp.StatusCode)
}

// TestShareLinksHandler_UpdateInvalidID tests UpdateShareLink with invalid ID
func TestShareLinksHandler_UpdateInvalidID(t *testing.T) {
	cryptoSvc := crypto.NewCryptoService(make([]byte, 32))
	handler := NewShareLinksHandler(nil, cryptoSvc, nil)
	app := fiber.New()

	app.Put("/share-links/:id", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		return handler.UpdateShareLink(c)
	})

	req := httptest.NewRequest("PUT", "/share-links/invalid-uuid", bytes.NewBufferString(`{"active":false}`))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	assert.Equal(t, 400, resp.StatusCode)
}

// TestShareLinksHandler_UpdateInvalidJSON tests UpdateShareLink with invalid JSON
func TestShareLinksHandler_UpdateInvalidJSON(t *testing.T) {
	cryptoSvc := crypto.NewCryptoService(make([]byte, 32))
	handler := NewShareLinksHandler(nil, cryptoSvc, nil)
	app := fiber.New()

	linkID := uuid.New()
	app.Put("/share-links/:id", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		return handler.UpdateShareLink(c)
	})

	req := httptest.NewRequest("PUT", "/share-links/"+linkID.String(), bytes.NewBufferString("{invalid json"))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	assert.Equal(t, 400, resp.StatusCode)
}
