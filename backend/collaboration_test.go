package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	miniredis "github.com/alicebob/miniredis/v2"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"leaflock/auth"
)

func TestCollaborationFeatures(t *testing.T) {
	// Setup test database
	db, err := SetupTestDatabase()
	if err != nil {
		t.Skipf("Skipping collaboration tests: %v", err)
	}
	defer func() {
		if closer, ok := db.(interface{ Close() error }); ok {
			_ = closer.Close() // Test cleanup
		}
	}()

	dbPool, ok := db.(*pgxpool.Pool)
	require.True(t, ok, "expected *pgxpool.Pool")

	cfg := LoadConfig()

	// Create crypto service
	crypto := NewCryptoService(cfg.EncryptionKey)

	// Setup in-memory Redis for auth flows
	mr := miniredis.RunT(t)
	defer mr.Close()

	rdb := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})

	authService := auth.NewService(dbPool, rdb, crypto, string(cfg.JWTSecret))

	// Create collaboration handler
	handler := &CollaborationHandler{
		db:     db,
		crypto: crypto,
	}

	// Create test users
	ctx := context.Background()
	suffix := uuid.NewString()
	user1Email := fmt.Sprintf("user1+%s@example.com", suffix)
	user2Email := fmt.Sprintf("user2+%s@example.com", suffix)

	user1Resp, err := authService.Register(ctx, user1Email, "TestPass123!@#")
	require.NoError(t, err)

	user2Resp, err := authService.Register(ctx, user2Email, "DiffPass456!@#")
	require.NoError(t, err)

	user1ID := uuid.MustParse(user1Resp.UserID)
	user2ID := uuid.MustParse(user2Resp.UserID)
	workspace1ID := uuid.MustParse(user1Resp.WorkspaceID)

	// Keep plaintext email column in sync for handlers relying on it
	_, err = db.Exec(ctx, `UPDATE users SET email = $1 WHERE id = $2`, user1Email, user1ID)
	require.NoError(t, err)
	_, err = db.Exec(ctx, `UPDATE users SET email = $1 WHERE id = $2`, user2Email, user2ID)
	require.NoError(t, err)

	// Create test note
	noteID := uuid.New()
	title := []byte("Collaboration Test Note")
	content := []byte("Encrypted content for collaboration testing.")
	encryptedTitle, err := crypto.Encrypt(title)
	require.NoError(t, err)
	encryptedContent, err := crypto.Encrypt(content)
	require.NoError(t, err)
	contentHash := sha256.Sum256(content)

	_, err = db.Exec(ctx, `
		INSERT INTO notes (id, workspace_id, title_encrypted, content_encrypted, content_hash, created_by)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		noteID, workspace1ID, encryptedTitle, encryptedContent, contentHash[:], user1ID)
	require.NoError(t, err)

	t.Run("ShareNote", func(t *testing.T) {
	app := fiber.New()
	app.Post("/notes/:id/share", func(c *fiber.Ctx) error {
		c.Locals("user_id", user1ID)
		return handler.ShareNote(c)
	})

	shareReq := ShareNoteRequest{
		UserEmail:  user2Email,
		Permission: "write",
	}
	reqBody, _ := json.Marshal(shareReq)

	req := httptest.NewRequest("POST", fmt.Sprintf("/notes/%s/share", noteID), bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusCreated, resp.StatusCode)

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
	app.Get("/notes/:id/collaborators", func(c *fiber.Ctx) error {
		c.Locals("user_id", user1ID)
		return handler.GetCollaborators(c)
	})

	req := httptest.NewRequest("GET", fmt.Sprintf("/notes/%s/collaborators", noteID), nil)
	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	var response map[string]interface{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&response))
	resp.Body.Close()

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
		app.Delete("/notes/:id/collaborators/:userId", func(c *fiber.Ctx) error {
			c.Locals("user_id", user1ID)
			return handler.RemoveCollaborator(c)
		})

		req := httptest.NewRequest("DELETE", fmt.Sprintf("/notes/%s/collaborators/%s", noteID, user2ID), nil)
		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)

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
		defer hub.Close()

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
		hub.RegisterConnection(conn)

		// Allow some time for processing
		time.Sleep(10 * time.Millisecond)

		// Check connected users
		users := hub.GetConnectedUsers(noteID)
		assert.Len(t, users, 1)
		assert.Equal(t, userID.String(), users[0])

		// Unregister connection
		hub.UnregisterConnection(conn)

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
	if override := os.Getenv("TEST_DATABASE_URL"); override != "" {
		config.DatabaseURL = override
	} else {
		config.DatabaseURL = "postgres://test:test@localhost:5433/leaflock_test?sslmode=disable" // secretlint-disable-line
	}

	db, err := SetupDatabase(config.DatabaseURL)
	if err != nil {
		return nil, err
	}

	// Ensure compatibility column exists for tests relying on plaintext email
	ctx := context.Background()
	_, _ = db.Exec(ctx, `ALTER TABLE users ADD COLUMN IF NOT EXISTS email TEXT`)

	return db, nil
}
