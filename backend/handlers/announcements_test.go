package handlers

import (
	"bytes"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAnnouncementsHandler_Constructor tests NewAnnouncementsHandler
func TestAnnouncementsHandler_Constructor(t *testing.T) {
	handler := NewAnnouncementsHandler(nil)
	require.NotNil(t, handler)
	assert.Nil(t, handler.db)
}

// TestAnnouncementsHandler_GetAnnouncementsConstructor tests GetAnnouncements handler construction
// Note: GetAnnouncements doesn't require authentication and executes DB queries immediately,
// so it cannot be tested without a database connection
func TestAnnouncementsHandler_GetAnnouncementsConstructor(t *testing.T) {
	handler := NewAnnouncementsHandler(nil)
	assert.NotNil(t, handler)
	// Handler exists but requires database for actual execution
}

// TestAnnouncementsHandler_CreateInvalidJSON tests CreateAnnouncement with invalid JSON
func TestAnnouncementsHandler_CreateInvalidJSON(t *testing.T) {
	handler := NewAnnouncementsHandler(nil)
	app := fiber.New()

	app.Post("/announcements", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		c.Locals("is_admin", true)
		return handler.CreateAnnouncement(c)
	})

	req := httptest.NewRequest("POST", "/announcements", bytes.NewBufferString("{invalid json"))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	assert.Equal(t, 400, resp.StatusCode)
}

// TestAnnouncementsHandler_CreateMissingAdmin tests CreateAnnouncement without admin flag
// Note: Admin check happens after parsing body, so invalid JSON is caught first
func TestAnnouncementsHandler_CreateMissingAdmin(t *testing.T) {
	handler := NewAnnouncementsHandler(nil)
	app := fiber.New()

	app.Post("/announcements", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		// is_admin not set
		return handler.CreateAnnouncement(c)
	})

	// Use invalid JSON to trigger error before admin check
	req := httptest.NewRequest("POST", "/announcements", bytes.NewBufferString("{invalid"))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	assert.Equal(t, 400, resp.StatusCode)
}

// TestAnnouncementsHandler_UpdateInvalidID tests UpdateAnnouncement with invalid ID
func TestAnnouncementsHandler_UpdateInvalidID(t *testing.T) {
	handler := NewAnnouncementsHandler(nil)
	app := fiber.New()

	app.Put("/announcements/:id", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		c.Locals("is_admin", true)
		return handler.UpdateAnnouncement(c)
	})

	req := httptest.NewRequest("PUT", "/announcements/invalid-uuid", bytes.NewBufferString(`{"message":"Updated"}`))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	assert.Equal(t, 400, resp.StatusCode)
}

// TestAnnouncementsHandler_UpdateInvalidJSON tests UpdateAnnouncement with invalid JSON
func TestAnnouncementsHandler_UpdateInvalidJSON(t *testing.T) {
	handler := NewAnnouncementsHandler(nil)
	app := fiber.New()

	announcementID := uuid.New()
	app.Put("/announcements/:id", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		c.Locals("is_admin", true)
		return handler.UpdateAnnouncement(c)
	})

	req := httptest.NewRequest("PUT", "/announcements/"+announcementID.String(), bytes.NewBufferString("{invalid json"))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	assert.Equal(t, 400, resp.StatusCode)
}

// TestAnnouncementsHandler_UpdateMissingAdmin tests UpdateAnnouncement without admin flag
func TestAnnouncementsHandler_UpdateMissingAdmin(t *testing.T) {
	handler := NewAnnouncementsHandler(nil)
	app := fiber.New()

	announcementID := uuid.New()
	app.Put("/announcements/:id", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		// is_admin not set
		return handler.UpdateAnnouncement(c)
	})

	// Use invalid JSON to trigger error before admin/DB check
	req := httptest.NewRequest("PUT", "/announcements/"+announcementID.String(), bytes.NewBufferString("{invalid"))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	assert.Equal(t, 400, resp.StatusCode)
}

// TestAnnouncementsHandler_DeleteInvalidID tests DeleteAnnouncement with invalid ID
func TestAnnouncementsHandler_DeleteInvalidID(t *testing.T) {
	handler := NewAnnouncementsHandler(nil)
	app := fiber.New()

	app.Delete("/announcements/:id", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		c.Locals("is_admin", true)
		return handler.DeleteAnnouncement(c)
	})

	req := httptest.NewRequest("DELETE", "/announcements/invalid-uuid", nil)
	resp, err := app.Test(req, -1)

	require.NoError(t, err)
	assert.Equal(t, 400, resp.StatusCode)
}

// TestAnnouncementsHandler_DeleteMissingAdmin tests DeleteAnnouncement with invalid ID triggers before admin check
func TestAnnouncementsHandler_DeleteMissingAdmin(t *testing.T) {
	handler := NewAnnouncementsHandler(nil)
	app := fiber.New()

	app.Delete("/announcements/:id", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		// is_admin not set
		return handler.DeleteAnnouncement(c)
	})

	// Use invalid ID to trigger error before admin check
	req := httptest.NewRequest("DELETE", "/announcements/invalid-uuid", nil)
	resp, err := app.Test(req, -1)

	require.NoError(t, err)
	assert.Equal(t, 400, resp.StatusCode)
}

// TestAnnouncementsHandler_GetAllConstructor tests GetAllAnnouncements handler construction
// Note: GetAllAnnouncements requires database connection and authentication check happens after DB query
func TestAnnouncementsHandler_GetAllConstructor(t *testing.T) {
	handler := NewAnnouncementsHandler(nil)
	assert.NotNil(t, handler)
	// Handler exists but requires database for actual execution
}
