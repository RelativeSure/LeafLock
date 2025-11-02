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

// TestCollaborationHandler_Constructor tests NewCollaborationHandler
func TestCollaborationHandler_Constructor(t *testing.T) {
	cryptoSvc := crypto.NewCryptoService(make([]byte, 32))
	handler := NewCollaborationHandler(nil, cryptoSvc)
	require.NotNil(t, handler)
	assert.Nil(t, handler.db)
	assert.NotNil(t, handler.crypto)
}

// TestCollaborationHandler_ShareNoteInvalidID tests ShareNote with invalid ID
func TestCollaborationHandler_ShareNoteInvalidID(t *testing.T) {
	cryptoSvc := crypto.NewCryptoService(make([]byte, 32))
	handler := NewCollaborationHandler(nil, cryptoSvc)
	app := fiber.New()

	app.Post("/notes/:id/share", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		return handler.ShareNote(c)
	})

	req := httptest.NewRequest("POST", "/notes/invalid-uuid/share", bytes.NewBufferString(`{"email":"test@example.com"}`))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	assert.Equal(t, 400, resp.StatusCode)
}

// TestCollaborationHandler_ShareNoteInvalidJSON tests ShareNote with invalid JSON
func TestCollaborationHandler_ShareNoteInvalidJSON(t *testing.T) {
	cryptoSvc := crypto.NewCryptoService(make([]byte, 32))
	handler := NewCollaborationHandler(nil, cryptoSvc)
	app := fiber.New()

	noteID := uuid.New()
	app.Post("/notes/:id/share", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		return handler.ShareNote(c)
	})

	req := httptest.NewRequest("POST", "/notes/"+noteID.String()+"/share", bytes.NewBufferString("{invalid json"))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	assert.Equal(t, 400, resp.StatusCode)
}

// TestCollaborationHandler_GetCollaboratorsInvalidID tests GetCollaborators with invalid ID
func TestCollaborationHandler_GetCollaboratorsInvalidID(t *testing.T) {
	cryptoSvc := crypto.NewCryptoService(make([]byte, 32))
	handler := NewCollaborationHandler(nil, cryptoSvc)
	app := fiber.New()

	app.Get("/notes/:id/collaborators", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		return handler.GetCollaborators(c)
	})

	req := httptest.NewRequest("GET", "/notes/invalid-uuid/collaborators", nil)
	resp, err := app.Test(req, -1)

	require.NoError(t, err)
	assert.Equal(t, 400, resp.StatusCode)
}

// TestCollaborationHandler_RemoveCollaboratorInvalidID tests RemoveCollaborator with invalid ID
func TestCollaborationHandler_RemoveCollaboratorInvalidID(t *testing.T) {
	cryptoSvc := crypto.NewCryptoService(make([]byte, 32))
	handler := NewCollaborationHandler(nil, cryptoSvc)
	app := fiber.New()

	app.Delete("/notes/:id/collaborators/:userId", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		return handler.RemoveCollaborator(c)
	})

	req := httptest.NewRequest("DELETE", "/notes/invalid-uuid/collaborators/"+uuid.New().String(), nil)
	resp, err := app.Test(req, -1)

	require.NoError(t, err)
	assert.Equal(t, 400, resp.StatusCode)
}

// TestCollaborationHandler_RemoveCollaboratorInvalidUserID tests RemoveCollaborator with invalid user ID
func TestCollaborationHandler_RemoveCollaboratorInvalidUserID(t *testing.T) {
	cryptoSvc := crypto.NewCryptoService(make([]byte, 32))
	handler := NewCollaborationHandler(nil, cryptoSvc)
	app := fiber.New()

	noteID := uuid.New()
	app.Delete("/notes/:id/collaborators/:userId", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		return handler.RemoveCollaborator(c)
	})

	req := httptest.NewRequest("DELETE", "/notes/"+noteID.String()+"/collaborators/invalid-uuid", nil)
	resp, err := app.Test(req, -1)

	require.NoError(t, err)
	assert.Equal(t, 400, resp.StatusCode)
}

// TestCollaborationHandler_GetSharedNotesNeedsDB tests that GetSharedNotes requires database
// Note: This handler immediately queries the database, so it cannot be tested without DB connection
func TestCollaborationHandler_GetSharedNotesNeedsDB(t *testing.T) {
	cryptoSvc := crypto.NewCryptoService(make([]byte, 32))
	handler := NewCollaborationHandler(nil, cryptoSvc)
	require.NotNil(t, handler)
	// Handler requires database connection for execution
}
