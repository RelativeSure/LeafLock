package websocket

import (
	"context"
	"log"

	"github.com/clerk/clerk-sdk-go/v2/jwt"
	"github.com/gofiber/contrib/websocket"
	"github.com/google/uuid"

	"leaflock/config"
	"leaflock/database"
)

// HandleWebSocket handles WebSocket connections for real-time note collaboration
// It authenticates the user, verifies access permissions, and manages the connection lifecycle
func HandleWebSocket(c *websocket.Conn, hub *Hub, db database.Database) {
	defer func() {
		_ = c.Close() // Best effort cleanup
	}()

	// Extract note ID, user ID, and token from query params
	noteIDStr := c.Query("note_id")
	userIDStr := c.Query("user_id")
	tokenStr := c.Query("token")

	// Validate Clerk session token
	if tokenStr == "" {
		log.Printf("WebSocket connection rejected: missing token")
		return
	}

	// Parse and validate Clerk JWT token
	cfg := config.LoadConfig()
	if cfg.ClerkSecretKey == "" {
		log.Printf("WebSocket connection rejected: Clerk not configured")
		return
	}

	// Validate Clerk session token
	claims, err := jwt.Verify(context.Background(), &jwt.VerifyParams{
		Token: tokenStr,
	})
	if err != nil {
		log.Printf("WebSocket connection rejected: invalid Clerk token: %v", err)
		return
	}

	// Extract user ID from Clerk claims
	clerkUserID := claims.Subject
	if clerkUserID == "" {
		log.Printf("WebSocket connection rejected: missing user ID in Clerk claims")
		return
	}

	// Verify the user ID from query matches the Clerk user ID
	if clerkUserID != userIDStr {
		log.Printf("WebSocket connection rejected: user ID mismatch (Clerk: %s, Query: %s)", clerkUserID, userIDStr)
		return
	}

	noteID, err := uuid.Parse(noteIDStr)
	if err != nil {
		log.Printf("Invalid note ID: %v", err)
		return
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		log.Printf("Invalid user ID: %v", err)
		return
	}

	// Verify user has access to the note
	ctx := context.Background()
	var hasAccess bool
	err = db.QueryRow(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM notes n
			JOIN workspaces w ON n.workspace_id = w.id
			WHERE n.id = $1 AND w.owner_id = $2 AND n.deleted_at IS NULL
		) OR EXISTS(
			SELECT 1 FROM collaborations c
			WHERE c.note_id = $1 AND c.user_id = $2
		)`, noteID, userID).Scan(&hasAccess)

	if err != nil || !hasAccess {
		log.Printf("User %s does not have access to note %s", userID, noteID)
		return
	}

	// Create connection
	conn := &Connection{
		ID:     uuid.New().String(),
		UserID: userID,
		NoteID: noteID,
		Conn:   c,
		Send:   make(chan []byte, 256),
	}

	hub.register <- conn

	// Handle outgoing messages
	go func() {
		defer func() {
			hub.unregister <- conn
		}()

		for message := range conn.Send {
			if err := c.WriteMessage(websocket.TextMessage, message); err != nil {
				log.Printf("WebSocket write error: %v", err)
				return
			}
		}
		_ = c.WriteMessage(websocket.CloseMessage, []byte{}) // Best effort close message
	}()

	// Handle incoming messages
	for {
		var msg WSMessage
		err := c.ReadJSON(&msg)
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("WebSocket error: %v", err)
			}
			break
		}

		// Broadcast the message to other users in the same note
		switch msg.Type {
		case "edit":
			// Handle real-time editing
			hub.broadcastToNote(noteID, WSMessage{
				Type:    "edit",
				NoteID:  noteID.String(),
				UserID:  userID.String(),
				Content: msg.Content,
			}, userID)

		case "cursor":
			// Handle cursor position updates
			hub.broadcastToNote(noteID, WSMessage{
				Type:    "cursor",
				NoteID:  noteID.String(),
				UserID:  userID.String(),
				Content: msg.Content,
			}, userID)

		case "presence":
			// Handle presence updates (typing indicators, etc.)
			hub.broadcastToNote(noteID, WSMessage{
				Type:    "presence",
				NoteID:  noteID.String(),
				UserID:  userID.String(),
				Content: msg.Content,
			}, userID)
		}
	}
}
