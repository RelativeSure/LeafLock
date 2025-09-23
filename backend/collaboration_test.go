package main

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"
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

	// Insert test users
	ctx := context.Background()
	_, err = db.Exec(ctx, `
		INSERT INTO users (id, email, password_hash, workspace_id)
		VALUES ($1, 'user1@example.com', 'hash1', $2),
			   ($3, $4, 'hash2', $5)`,
		user1ID, uuid.New(), user2ID, user2Email, uuid.New())
	require.NoError(t, err)

	// Create workspace for user1
	workspace1ID := uuid.New()
	_, err = db.Exec(ctx, `
		INSERT INTO workspaces (id, name, owner_id)
		VALUES ($1, 'Test Workspace', $2)`,
		workspace1ID, user1ID)
	require.NoError(t, err)

	// Create test note
	noteID := uuid.New()
	_, err = db.Exec(ctx, `
		INSERT INTO notes (id, workspace_id, title_encrypted, content_encrypted)
		VALUES ($1, $2, 'encrypted-title', 'encrypted-content')`,
		noteID, workspace1ID)
	require.NoError(t, err)

	t.Run("ShareNote", func(t *testing.T) {
		app := fiber.New()

		// Create share request
		shareReq := ShareNoteRequest{
			UserEmail:  user2Email,
			Permission: "write",
		}
		reqBody, _ := json.Marshal(shareReq)

		// Create test context
		ctx := &fasthttp.RequestCtx{}
		ctx.Request.SetRequestURI(fmt.Sprintf("/notes/%s/share", noteID))
		ctx.Request.Header.SetMethod("POST")
		ctx.Request.Header.SetContentType("application/json")
		ctx.Request.SetBody(reqBody)

		c := app.AcquireCtx(ctx)
		defer app.ReleaseCtx(c)
		c.Locals("user_id", user1ID)

		// Set route params
		c.Params("id", noteID.String())

		// Execute handler
		err := handler.ShareNote(c)
		require.NoError(t, err)

		// Check response
		assert.Equal(t, fiber.StatusCreated, c.Response().StatusCode())

		// Verify collaboration was created
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

		// Create test context
		ctx := &fasthttp.RequestCtx{}
		ctx.Request.SetRequestURI(fmt.Sprintf("/notes/%s/collaborators", noteID))
		ctx.Request.Header.SetMethod("GET")

		c := app.AcquireCtx(ctx)
		defer app.ReleaseCtx(c)
		c.Locals("user_id", user1ID)

		// Set route params
		c.Params("id", noteID.String())

		// Execute handler
		err := handler.GetCollaborators(c)
		require.NoError(t, err)

		// Check response
		assert.Equal(t, fiber.StatusOK, c.Response().StatusCode())

		// Parse response
		var response map[string]interface{}
		err = json.Unmarshal(c.Response().Body(), &response)
		require.NoError(t, err)

		collaborators, ok := response["collaborators"].([]interface{})
		require.True(t, ok)
		assert.Len(t, collaborators, 1)

		// Check collaborator details
		collab := collaborators[0].(map[string]interface{})
		assert.Equal(t, user2Email, collab["user_email"])
		assert.Equal(t, "write", collab["permission"])
	})

	t.Run("RemoveCollaborator", func(t *testing.T) {
		app := fiber.New()

		// Create test context
		ctx := &fasthttp.RequestCtx{}
		ctx.Request.SetRequestURI(fmt.Sprintf("/notes/%s/collaborators/%s", noteID, user2ID))
		ctx.Request.Header.SetMethod("DELETE")

		c := app.AcquireCtx(ctx)
		defer app.ReleaseCtx(c)
		c.Locals("user_id", user1ID)

		// Set route params
		c.Params("id", noteID.String())
		c.Params("userId", user2ID.String())

		// Execute handler
		err := handler.RemoveCollaborator(c)
		require.NoError(t, err)

		// Check response
		assert.Equal(t, fiber.StatusOK, c.Response().StatusCode())

		// Verify collaboration was removed
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
		defer func() {
			// Close channels to stop hub
			close(hub.register)
			close(hub.unregister)
		}()

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
