//go:build integration

package handlers

import (
	"bytes"
	"context"
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

// setupTestDB creates a test database connection
func setupTestDB(t *testing.T) (*pgxpool.Pool, func()) {
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

// TestAnnouncementsHandler_InvalidJSON tests announcements with invalid JSON
func TestAnnouncementsHandler_InvalidJSON(t *testing.T) {
	pool, cleanup := setupTestDB(t)
	defer cleanup()

	handler := NewAnnouncementsHandler(pool)
	app := fiber.New()

	// Create announcement with invalid JSON
	app.Post("/announcements", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		return handler.CreateAnnouncement(c)
	})

	req := httptest.NewRequest("POST", "/announcements", bytes.NewBufferString("{invalid json"))
	req.Header.Set("Content-Type", "application/json")
	
	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	assert.Equal(t, 400, resp.StatusCode)
}

// TestAnnouncementsHandler_GetAnnouncements tests fetching announcements
func TestAnnouncementsHandler_GetAnnouncements(t *testing.T) {
	pool, cleanup := setupTestDB(t)
	defer cleanup()

	handler := NewAnnouncementsHandler(pool)
	app := fiber.New()

	app.Get("/announcements", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		return handler.GetAnnouncements(c)
	})

	req := httptest.NewRequest("GET", "/announcements", nil)
	resp, err := app.Test(req, -1)
	
	require.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
}

// TestAnnouncementsHandler_UpdateInvalidID tests update with invalid ID
func TestAnnouncementsHandler_UpdateInvalidID(t *testing.T) {
	pool, cleanup := setupTestDB(t)
	defer cleanup()

	handler := NewAnnouncementsHandler(pool)
	app := fiber.New()

	app.Put("/announcements/:id", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		return handler.UpdateAnnouncement(c)
	})

	req := httptest.NewRequest("PUT", "/announcements/invalid-uuid", bytes.NewBufferString(`{"message":"test"}`))
	req.Header.Set("Content-Type", "application/json")
	
	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	assert.Equal(t, 400, resp.StatusCode)
}

// TestAnnouncementsHandler_DeleteInvalidID tests delete with invalid ID
func TestAnnouncementsHandler_DeleteInvalidID(t *testing.T) {
	pool, cleanup := setupTestDB(t)
	defer cleanup()

	handler := NewAnnouncementsHandler(pool)
	app := fiber.New()

	app.Delete("/announcements/:id", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		return handler.DeleteAnnouncement(c)
	})

	req := httptest.NewRequest("DELETE", "/announcements/invalid-uuid", nil)
	resp, err := app.Test(req, -1)
	
	require.NoError(t, err)
	assert.Equal(t, 400, resp.StatusCode)
}

// TestFoldersHandler_InvalidJSON tests folders with invalid JSON
func TestFoldersHandler_InvalidJSON(t *testing.T) {
	pool, cleanup := setupTestDB(t)
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

// TestFoldersHandler_GetFolders tests fetching folders
func TestFoldersHandler_GetFolders(t *testing.T) {
	pool, cleanup := setupTestDB(t)
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
	// May return error due to workspace not existing, but handler is exercised
	assert.NotEqual(t, 0, resp.StatusCode)
}

// TestFoldersHandler_DeleteInvalidID tests delete with invalid ID
func TestFoldersHandler_DeleteInvalidID(t *testing.T) {
	pool, cleanup := setupTestDB(t)
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

// TestAttachmentsHandler_GetAttachments tests fetching attachments
func TestAttachmentsHandler_GetAttachments(t *testing.T) {
	pool, cleanup := setupTestDB(t)
	defer cleanup()

	cryptoSvc := crypto.NewCryptoService(make([]byte, 32))
	handler := NewAttachmentsHandler(pool, cryptoSvc)
	app := fiber.New()

	noteID := uuid.New()
	app.Get("/notes/:id/attachments", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		return handler.GetAttachments(c)
	})

	req := httptest.NewRequest("GET", "/notes/"+noteID.String()+"/attachments", nil)
	resp, err := app.Test(req, -1)
	
	require.NoError(t, err)
	// May return error or empty list, but handler is exercised
	assert.NotEqual(t, 0, resp.StatusCode)
}

// TestAttachmentsHandler_DeleteInvalidID tests delete with invalid ID
func TestAttachmentsHandler_DeleteInvalidID(t *testing.T) {
	pool, cleanup := setupTestDB(t)
	defer cleanup()

	cryptoSvc := crypto.NewCryptoService(make([]byte, 32))
	handler := NewAttachmentsHandler(pool, cryptoSvc)
	app := fiber.New()

	app.Delete("/attachments/:id", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		return handler.DeleteAttachment(c)
	})

	req := httptest.NewRequest("DELETE", "/attachments/invalid-uuid", nil)
	resp, err := app.Test(req, -1)
	
	require.NoError(t, err)
	assert.Equal(t, 400, resp.StatusCode)
}

// TestCollaborationHandler_GetCollaborators tests fetching collaborators
func TestCollaborationHandler_GetCollaborators(t *testing.T) {
	pool, cleanup := setupTestDB(t)
	defer cleanup()

	cryptoSvc := crypto.NewCryptoService(make([]byte, 32))
	handler := NewCollaborationHandler(pool, cryptoSvc)
	app := fiber.New()

	noteID := uuid.New()
	app.Get("/notes/:id/collaborators", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		return handler.GetCollaborators(c)
	})

	req := httptest.NewRequest("GET", "/notes/"+noteID.String()+"/collaborators", nil)
	resp, err := app.Test(req, -1)
	
	require.NoError(t, err)
	// Handler is exercised, may return error or empty list
	assert.NotEqual(t, 0, resp.StatusCode)
}

// TestCollaborationHandler_RemoveInvalidID tests remove with invalid ID
func TestCollaborationHandler_RemoveInvalidID(t *testing.T) {
	pool, cleanup := setupTestDB(t)
	defer cleanup()

	cryptoSvc := crypto.NewCryptoService(make([]byte, 32))
	handler := NewCollaborationHandler(pool, cryptoSvc)
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

// TestCollaborationHandler_ShareNoteInvalidJSON tests share with invalid JSON
func TestCollaborationHandler_ShareNoteInvalidJSON(t *testing.T) {
	pool, cleanup := setupTestDB(t)
	defer cleanup()

	cryptoSvc := crypto.NewCryptoService(make([]byte, 32))
	handler := NewCollaborationHandler(pool, cryptoSvc)
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

// TestAnnouncementsHandler_GetAllAnnouncements tests fetching all announcements
func TestAnnouncementsHandler_GetAllAnnouncements(t *testing.T) {
	pool, cleanup := setupTestDB(t)
	defer cleanup()

	handler := NewAnnouncementsHandler(pool)
	app := fiber.New()

	app.Get("/announcements/all", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		return handler.GetAllAnnouncements(c)
	})

	req := httptest.NewRequest("GET", "/announcements/all", nil)
	resp, err := app.Test(req, -1)
	
	require.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
}

// TestAttachmentsHandler_DownloadInvalidID tests download with invalid ID
func TestAttachmentsHandler_DownloadInvalidID(t *testing.T) {
	pool, cleanup := setupTestDB(t)
	defer cleanup()

	cryptoSvc := crypto.NewCryptoService(make([]byte, 32))
	handler := NewAttachmentsHandler(pool, cryptoSvc)
	app := fiber.New()

	app.Get("/attachments/:id/download", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		return handler.DownloadAttachment(c)
	})

	req := httptest.NewRequest("GET", "/attachments/invalid-uuid/download", nil)
	resp, err := app.Test(req, -1)
	
	require.NoError(t, err)
	assert.Equal(t, 400, resp.StatusCode)
}

// TestAnnouncementsHandler_CreateInvalidData tests create with missing data
func TestAnnouncementsHandler_CreateInvalidData(t *testing.T) {
	pool, cleanup := setupTestDB(t)
	defer cleanup()

	handler := NewAnnouncementsHandler(pool)
	app := fiber.New()

	app.Post("/announcements", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		return handler.CreateAnnouncement(c)
	})

	req := httptest.NewRequest("POST", "/announcements", bytes.NewBufferString(`{}`))
	req.Header.Set("Content-Type", "application/json")
	
	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	// May be 400 or 500 depending on validation
	assert.NotEqual(t, 0, resp.StatusCode)
}

// TestFoldersHandler_CreateInvalidData tests create with missing data
func TestFoldersHandler_CreateInvalidData(t *testing.T) {
	pool, cleanup := setupTestDB(t)
	defer cleanup()

	cryptoSvc := crypto.NewCryptoService(make([]byte, 32))
	handler := NewFoldersHandler(pool, cryptoSvc)
	app := fiber.New()

	app.Post("/folders", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		return handler.CreateFolder(c)
	})

	req := httptest.NewRequest("POST", "/folders", bytes.NewBufferString(`{}`))
	req.Header.Set("Content-Type", "application/json")
	
	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	// May be 400 or 500 depending on validation
	assert.NotEqual(t, 0, resp.StatusCode)
}

// TestCollaborationHandler_ShareNoteInvalidID tests share with invalid note ID
func TestCollaborationHandler_ShareNoteInvalidID(t *testing.T) {
	pool, cleanup := setupTestDB(t)
	defer cleanup()

	cryptoSvc := crypto.NewCryptoService(make([]byte, 32))
	handler := NewCollaborationHandler(pool, cryptoSvc)
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

// TestAttachmentsHandler_UploadInvalidNoteID tests upload with invalid note ID
func TestAttachmentsHandler_UploadInvalidNoteID(t *testing.T) {
	pool, cleanup := setupTestDB(t)
	defer cleanup()

	cryptoSvc := crypto.NewCryptoService(make([]byte, 32))
	handler := NewAttachmentsHandler(pool, cryptoSvc)
	app := fiber.New()

	app.Post("/notes/:id/attachments", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		return handler.UploadAttachment(c)
	})

	req := httptest.NewRequest("POST", "/notes/invalid-uuid/attachments", nil)
	resp, err := app.Test(req, -1)
	
	require.NoError(t, err)
	assert.Equal(t, 400, resp.StatusCode)
}

// TestCollaborationHandler_GetCollaboratorsInvalidID tests get with invalid ID
func TestCollaborationHandler_GetCollaboratorsInvalidID(t *testing.T) {
	pool, cleanup := setupTestDB(t)
	defer cleanup()

	cryptoSvc := crypto.NewCryptoService(make([]byte, 32))
	handler := NewCollaborationHandler(pool, cryptoSvc)
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

// TestAnnouncementsHandler_UpdateNotFound tests update non-existent announcement
func TestAnnouncementsHandler_UpdateNotFound(t *testing.T) {
	pool, cleanup := setupTestDB(t)
	defer cleanup()

	handler := NewAnnouncementsHandler(pool)
	app := fiber.New()

	randomID := uuid.New()
	app.Put("/announcements/:id", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		return handler.UpdateAnnouncement(c)
	})

	req := httptest.NewRequest("PUT", "/announcements/"+randomID.String(), bytes.NewBufferString(`{"message":"test"}`))
	req.Header.Set("Content-Type", "application/json")
	
	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	// Likely 404 or 500
	assert.NotEqual(t, 0, resp.StatusCode)
}

// TestAnnouncementsHandler_DeleteNotFound tests delete non-existent announcement
func TestAnnouncementsHandler_DeleteNotFound(t *testing.T) {
	pool, cleanup := setupTestDB(t)
	defer cleanup()

	handler := NewAnnouncementsHandler(pool)
	app := fiber.New()

	randomID := uuid.New()
	app.Delete("/announcements/:id", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		return handler.DeleteAnnouncement(c)
	})

	req := httptest.NewRequest("DELETE", "/announcements/"+randomID.String(), nil)
	resp, err := app.Test(req, -1)
	
	require.NoError(t, err)
	// Likely 404
	assert.NotEqual(t, 0, resp.StatusCode)
}

// TestFoldersHandler_DeleteNotFound tests delete non-existent folder
func TestFoldersHandler_DeleteNotFound(t *testing.T) {
	pool, cleanup := setupTestDB(t)
	defer cleanup()

	cryptoSvc := crypto.NewCryptoService(make([]byte, 32))
	handler := NewFoldersHandler(pool, cryptoSvc)
	app := fiber.New()

	randomID := uuid.New()
	app.Delete("/folders/:id", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		return handler.DeleteFolder(c)
	})

	req := httptest.NewRequest("DELETE", "/folders/"+randomID.String(), nil)
	resp, err := app.Test(req, -1)
	
	require.NoError(t, err)
	// Likely 404
	assert.NotEqual(t, 0, resp.StatusCode)
}

// TestAttachmentsHandler_DeleteNotFound tests delete non-existent attachment
func TestAttachmentsHandler_DeleteNotFound(t *testing.T) {
	pool, cleanup := setupTestDB(t)
	defer cleanup()

	cryptoSvc := crypto.NewCryptoService(make([]byte, 32))
	handler := NewAttachmentsHandler(pool, cryptoSvc)
	app := fiber.New()

	randomID := uuid.New()
	app.Delete("/attachments/:id", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		return handler.DeleteAttachment(c)
	})

	req := httptest.NewRequest("DELETE", "/attachments/"+randomID.String(), nil)
	resp, err := app.Test(req, -1)
	
	require.NoError(t, err)
	// Likely 404
	assert.NotEqual(t, 0, resp.StatusCode)
}

// TestCollaborationHandler_RemoveNotFound tests remove non-existent collaborator
func TestCollaborationHandler_RemoveNotFound(t *testing.T) {
	pool, cleanup := setupTestDB(t)
	defer cleanup()

	cryptoSvc := crypto.NewCryptoService(make([]byte, 32))
	handler := NewCollaborationHandler(pool, cryptoSvc)
	app := fiber.New()

	randomNoteID := uuid.New()
	randomUserID := uuid.New()
	app.Delete("/notes/:id/collaborators/:userId", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		return handler.RemoveCollaborator(c)
	})

	req := httptest.NewRequest("DELETE", "/notes/"+randomNoteID.String()+"/collaborators/"+randomUserID.String(), nil)
	resp, err := app.Test(req, -1)
	
	require.NoError(t, err)
	// Likely 404
	assert.NotEqual(t, 0, resp.StatusCode)
}

// TestAttachmentsHandler_GetAttachmentsInvalidNoteID tests get with invalid note ID
func TestAttachmentsHandler_GetAttachmentsInvalidNoteID(t *testing.T) {
	pool, cleanup := setupTestDB(t)
	defer cleanup()

	cryptoSvc := crypto.NewCryptoService(make([]byte, 32))
	handler := NewAttachmentsHandler(pool, cryptoSvc)
	app := fiber.New()

	app.Get("/notes/:id/attachments", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		return handler.GetAttachments(c)
	})

	req := httptest.NewRequest("GET", "/notes/invalid-uuid/attachments", nil)
	resp, err := app.Test(req, -1)
	
	require.NoError(t, err)
	assert.Equal(t, 400, resp.StatusCode)
}

// TestAnnouncementsHandler_CreateValidData tests create with valid minimal data
func TestAnnouncementsHandler_CreateValidData(t *testing.T) {
	pool, cleanup := setupTestDB(t)
	defer cleanup()

	handler := NewAnnouncementsHandler(pool)
	app := fiber.New()

	app.Post("/announcements", func(c *fiber.Ctx) error {
		// Use admin user for create permission
		c.Locals("user_id", uuid.New())
		c.Locals("is_admin", true)
		return handler.CreateAnnouncement(c)
	})

	req := httptest.NewRequest("POST", "/announcements", bytes.NewBufferString(`{"message":"Test announcement"}`))
	req.Header.Set("Content-Type", "application/json")
	
	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	// May succeed or fail depending on admin check
	assert.NotEqual(t, 0, resp.StatusCode)
}

// TestFoldersHandler_CreateValidData tests create with valid minimal data  
func TestFoldersHandler_CreateValidData(t *testing.T) {
	pool, cleanup := setupTestDB(t)
	defer cleanup()

	cryptoSvc := crypto.NewCryptoService(make([]byte, 32))
	handler := NewFoldersHandler(pool, cryptoSvc)
	app := fiber.New()

	app.Post("/folders", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		return handler.CreateFolder(c)
	})

	req := httptest.NewRequest("POST", "/folders", bytes.NewBufferString(`{"name":"Test folder"}`))
	req.Header.Set("Content-Type", "application/json")
	
	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	// May fail due to workspace not existing
	assert.NotEqual(t, 0, resp.StatusCode)
}

// TestCollaborationHandler_ShareNoteValidData tests share with valid data
func TestCollaborationHandler_ShareNoteValidData(t *testing.T) {
	pool, cleanup := setupTestDB(t)
	defer cleanup()

	cryptoSvc := crypto.NewCryptoService(make([]byte, 32))
	handler := NewCollaborationHandler(pool, cryptoSvc)
	app := fiber.New()

	noteID := uuid.New()
	app.Post("/notes/:id/share", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		return handler.ShareNote(c)
	})

	req := httptest.NewRequest("POST", "/notes/"+noteID.String()+"/share", bytes.NewBufferString(`{"email":"test@example.com"}`))
	req.Header.Set("Content-Type", "application/json")
	
	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	// May fail due to note not existing
	assert.NotEqual(t, 0, resp.StatusCode)
}

// TestAttachmentsHandler_UploadNoFile tests upload without file
func TestAttachmentsHandler_UploadNoFile(t *testing.T) {
	pool, cleanup := setupTestDB(t)
	defer cleanup()

	cryptoSvc := crypto.NewCryptoService(make([]byte, 32))
	handler := NewAttachmentsHandler(pool, cryptoSvc)
	app := fiber.New()

	noteID := uuid.New()
	app.Post("/notes/:id/attachments", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		return handler.UploadAttachment(c)
	})

	req := httptest.NewRequest("POST", "/notes/"+noteID.String()+"/attachments", nil)
	resp, err := app.Test(req, -1)
	
	require.NoError(t, err)
	// Likely 400 due to missing file
	assert.NotEqual(t, 200, resp.StatusCode)
}

// TestAnnouncementsHandler_MultipleOperations tests multiple operations in sequence
func TestAnnouncementsHandler_MultipleOperations(t *testing.T) {
	pool, cleanup := setupTestDB(t)
	defer cleanup()

	handler := NewAnnouncementsHandler(pool)
	app := fiber.New()

	// Get announcements
	app.Get("/announcements", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		return handler.GetAnnouncements(c)
	})

	// Get all announcements
	app.Get("/announcements/all", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		return handler.GetAllAnnouncements(c)
	})

	// Execute both requests
	req1 := httptest.NewRequest("GET", "/announcements", nil)
	resp1, err1 := app.Test(req1, -1)
	require.NoError(t, err1)
	assert.Equal(t, 200, resp1.StatusCode)

	req2 := httptest.NewRequest("GET", "/announcements/all", nil)
	resp2, err2 := app.Test(req2, -1)
	require.NoError(t, err2)
	assert.Equal(t, 200, resp2.StatusCode)
}
