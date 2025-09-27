package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCollaborationFeatures(t *testing.T) {
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

	// Create collaboration handler
	handler := &CollaborationHandler{
		db:     db,
		crypto: crypto,
	}

	// Create test users
	user1ID := uuid.New()
	user2ID := uuid.New()
	user2Email := "user2@example.com"

	ctx := context.Background()
	_, err = db.Exec(ctx, "TRUNCATE collaborations, notes, workspaces, users CASCADE")
	require.NoError(t, err)
	// Insert test users with required encrypted fields
	_, err = db.Exec(ctx, `
        INSERT INTO users (
            id, email, email_hash, email_encrypted, email_search_hash,
            password_hash, salt, master_key_encrypted
        ) VALUES
            ($1, $2, $3, $4, $5, $6, $7, $8),
            ($9, $10, $11, $12, $13, $14, $15, $16)`,
		user1ID,
		"user1@example.com",
		[]byte("hash-user1"),
		[]byte("enc-user1"),
		[]byte("search-user1"),
		"hash1",
		[]byte("salt1"),
		[]byte("master1"),
		user2ID,
		user2Email,
		[]byte("hash-user2"),
		[]byte("enc-user2"),
		[]byte("search-user2"),
		"hash2",
		[]byte("salt2"),
		[]byte("master2"))
	require.NoError(t, err)

	// Create workspace for user1
	workspace1ID := uuid.New()
	_, err = db.Exec(ctx, `
        INSERT INTO workspaces (id, name_encrypted, owner_id, encryption_key_encrypted)
        VALUES ($1, $2, $3, $4)`,
		workspace1ID, []byte("workspace"), user1ID, []byte("workspace-key"))
	require.NoError(t, err)

	// Create test note
	noteID := uuid.New()
	_, err = db.Exec(ctx, `
        INSERT INTO notes (id, workspace_id, title_encrypted, content_encrypted, content_hash)
        VALUES ($1, $2, $3, $4, $5)`,
		noteID, workspace1ID, []byte("encrypted-title"), []byte("encrypted-content"), []byte("content-hash"))
	require.NoError(t, err)

	t.Run("ShareNote", func(t *testing.T) {
		app := fiber.New()
		app.Post("/notes/:id/share", func(c *fiber.Ctx) error {
			c.Locals("user_id", user1ID)
			return handler.ShareNote(c)
		})

		shareReq := ShareNoteRequest{UserEmail: user2Email, Permission: "write"}
		reqBody, _ := json.Marshal(shareReq)
		req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/notes/%s/share", noteID), bytes.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusCreated, resp.StatusCode)

		var count int
		err = db.QueryRow(ctx, `
            SELECT COUNT(*) FROM collaborations
            WHERE note_id = $1 AND user_id = $2 AND permission = $3`,
			noteID, user2ID, "write").Scan(&count)
		require.NoError(t, err)
		assert.Equal(t, 1, count)
	})

	t.Run("GetCollaborators", func(t *testing.T) {
		app := fiber.New()
		app.Get("/notes/:id/collaborators", func(c *fiber.Ctx) error {
			c.Locals("user_id", user1ID)
			return handler.GetCollaborators(c)
		})

		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/notes/%s/collaborators", noteID), nil)
		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)

		var response map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&response)
		require.NoError(t, err)

		collaborators, ok := response["collaborators"].([]interface{})
		require.True(t, ok)
		assert.Len(t, collaborators, 1)

		collab := collaborators[0].(map[string]interface{})
		assert.Equal(t, user2Email, collab["user_email"])
		assert.Equal(t, "write", collab["permission"])
	})

	t.Run("RemoveCollaborator", func(t *testing.T) {
		app := fiber.New()
		app.Delete("/notes/:id/collaborators/:userId", func(c *fiber.Ctx) error {
			c.Locals("user_id", user1ID)
			return handler.RemoveCollaborator(c)
		})

		req := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/notes/%s/collaborators/%s", noteID, user2ID), nil)
		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)

		var count int
		err = db.QueryRow(ctx, `
            SELECT COUNT(*) FROM collaborations
            WHERE note_id = $1 AND user_id = $2`,
			noteID, user2ID).Scan(&count)
		require.NoError(t, err)
		assert.Equal(t, 0, count)
	})
}

func TestWebSocketHub(t *testing.T) {
	t.Run("HubBasicOperations", func(t *testing.T) {
		hub := NewHub()

		// Start hub in goroutine
		go hub.Run()

		// Create test connection
		noteID := uuid.New()
		userID := uuid.New()
		conn := &Connection{
			ID:     uuid.New().String(),
			UserID: userID,
			NoteID: noteID,
			Send:   make(chan []byte, 256),
		}

		// Register connection
		hub.register <- conn

		// Allow some time for processing
		time.Sleep(10 * time.Millisecond)

		// Check connected users
		users := hub.GetConnectedUsers(noteID)
		assert.Len(t, users, 1)
		assert.Equal(t, userID.String(), users[0])

		// Unregister connection
		hub.unregister <- conn

		// Allow some time for processing
		time.Sleep(10 * time.Millisecond)

		// Check connected users after unregister
		users = hub.GetConnectedUsers(noteID)
		assert.Len(t, users, 0)
	})
}

// Helper function to create test database
func SetupTestDatabase() (Database, error) {
	// For testing, we'll use an in-memory database or a test database
	// This is a simplified version - in practice, you'd set up a proper test database
	config := LoadConfig()
	config.DatabaseURL = "postgres://test:test@localhost/leaflock_test?sslmode=disable"

	return SetupDatabase(config.DatabaseURL)
}
