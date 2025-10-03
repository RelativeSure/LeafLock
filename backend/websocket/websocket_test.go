package websocket

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewHub verifies that NewHub creates a properly initialized Hub
func TestNewHub(t *testing.T) {
	hub := NewHub()

	assert.NotNil(t, hub)
	assert.NotNil(t, hub.connections)
	assert.NotNil(t, hub.noteUsers)
	assert.NotNil(t, hub.register)
	assert.NotNil(t, hub.unregister)
	assert.NotNil(t, hub.broadcast)
	assert.Equal(t, 0, len(hub.connections))
	assert.Equal(t, 0, len(hub.noteUsers))
}

// TestHubRegisterConnection tests registering a new connection
func TestHubRegisterConnection(t *testing.T) {
	hub := NewHub()
	go hub.Run()

	noteID := uuid.New()
	userID := uuid.New()
	conn := &Connection{
		ID:     uuid.New().String(),
		UserID: userID,
		NoteID: noteID,
		Conn:   nil, // Not needed for this test
		Send:   make(chan []byte, 256),
	}

	// Register the connection
	hub.register <- conn

	// Give the goroutine time to process
	time.Sleep(50 * time.Millisecond)

	// Verify the connection was registered
	hub.mu.RLock()
	assert.Equal(t, 1, len(hub.connections))
	assert.Equal(t, 1, len(hub.noteUsers))
	assert.NotNil(t, hub.noteUsers[noteID])
	assert.Equal(t, 1, len(hub.noteUsers[noteID]))
	assert.Equal(t, conn, hub.noteUsers[noteID][userID])
	hub.mu.RUnlock()

	// Clean up
	hub.Stop()
	close(conn.Send)
}

// TestHubUnregisterConnection tests unregistering a connection
func TestHubUnregisterConnection(t *testing.T) {
	hub := NewHub()
	go hub.Run()

	noteID := uuid.New()
	userID := uuid.New()
	conn := &Connection{
		ID:     uuid.New().String(),
		UserID: userID,
		NoteID: noteID,
		Conn:   nil,
		Send:   make(chan []byte, 256),
	}

	// Register then unregister
	hub.register <- conn
	time.Sleep(50 * time.Millisecond)

	hub.unregister <- conn
	time.Sleep(50 * time.Millisecond)

	// Verify the connection was unregistered
	hub.mu.RLock()
	assert.Equal(t, 0, len(hub.connections))
	assert.Equal(t, 0, len(hub.noteUsers))
	hub.mu.RUnlock()

	// Clean up
	close(hub.register)
	close(hub.unregister)
}

// TestHubMultipleUsersPerNote tests multiple users connected to the same note
func TestHubMultipleUsersPerNote(t *testing.T) {
	hub := NewHub()
	go hub.Run()

	noteID := uuid.New()
	user1ID := uuid.New()
	user2ID := uuid.New()

	conn1 := &Connection{
		ID:     uuid.New().String(),
		UserID: user1ID,
		NoteID: noteID,
		Conn:   nil,
		Send:   make(chan []byte, 256),
	}

	conn2 := &Connection{
		ID:     uuid.New().String(),
		UserID: user2ID,
		NoteID: noteID,
		Conn:   nil,
		Send:   make(chan []byte, 256),
	}

	// Register both connections
	hub.register <- conn1
	hub.register <- conn2
	time.Sleep(50 * time.Millisecond)

	// Verify both connections are registered
	hub.mu.RLock()
	assert.Equal(t, 2, len(hub.connections))
	assert.Equal(t, 1, len(hub.noteUsers))
	assert.Equal(t, 2, len(hub.noteUsers[noteID]))
	hub.mu.RUnlock()

	// Clean up
	hub.Stop()
	close(conn1.Send)
	close(conn2.Send)
}

// TestHubMultipleNotes tests users connected to different notes
func TestHubMultipleNotes(t *testing.T) {
	hub := NewHub()
	go hub.Run()

	note1ID := uuid.New()
	note2ID := uuid.New()
	user1ID := uuid.New()
	user2ID := uuid.New()

	conn1 := &Connection{
		ID:     uuid.New().String(),
		UserID: user1ID,
		NoteID: note1ID,
		Conn:   nil,
		Send:   make(chan []byte, 256),
	}

	conn2 := &Connection{
		ID:     uuid.New().String(),
		UserID: user2ID,
		NoteID: note2ID,
		Conn:   nil,
		Send:   make(chan []byte, 256),
	}

	// Register both connections
	hub.register <- conn1
	hub.register <- conn2
	time.Sleep(50 * time.Millisecond)

	// Verify both connections are registered to different notes
	hub.mu.RLock()
	assert.Equal(t, 2, len(hub.connections))
	assert.Equal(t, 2, len(hub.noteUsers))
	assert.Equal(t, 1, len(hub.noteUsers[note1ID]))
	assert.Equal(t, 1, len(hub.noteUsers[note2ID]))
	hub.mu.RUnlock()

	// Clean up
	hub.Stop()
	close(conn1.Send)
	close(conn2.Send)
}

// TestGetConnectedUsers tests retrieving connected users for a note
func TestGetConnectedUsers(t *testing.T) {
	hub := NewHub()
	go hub.Run()

	noteID := uuid.New()
	user1ID := uuid.New()
	user2ID := uuid.New()

	conn1 := &Connection{
		ID:     uuid.New().String(),
		UserID: user1ID,
		NoteID: noteID,
		Conn:   nil,
		Send:   make(chan []byte, 256),
	}

	conn2 := &Connection{
		ID:     uuid.New().String(),
		UserID: user2ID,
		NoteID: noteID,
		Conn:   nil,
		Send:   make(chan []byte, 256),
	}

	// Register connections
	hub.register <- conn1
	hub.register <- conn2
	time.Sleep(50 * time.Millisecond)

	// Get connected users
	users := hub.GetConnectedUsers(noteID)
	assert.Equal(t, 2, len(users))
	assert.Contains(t, users, user1ID.String())
	assert.Contains(t, users, user2ID.String())

	// Test with non-existent note
	emptyNoteID := uuid.New()
	emptyUsers := hub.GetConnectedUsers(emptyNoteID)
	assert.Equal(t, 0, len(emptyUsers))

	// Clean up
	hub.Stop()
	close(conn1.Send)
	close(conn2.Send)
}

// TestBroadcastToNote tests message broadcasting to note users
func TestBroadcastToNote(t *testing.T) {
	hub := NewHub()

	noteID := uuid.New()
	user1ID := uuid.New()
	user2ID := uuid.New()
	senderID := uuid.New()

	conn1 := &Connection{
		ID:     uuid.New().String(),
		UserID: user1ID,
		NoteID: noteID,
		Conn:   nil,
		Send:   make(chan []byte, 256),
	}

	conn2 := &Connection{
		ID:     uuid.New().String(),
		UserID: user2ID,
		NoteID: noteID,
		Conn:   nil,
		Send:   make(chan []byte, 256),
	}

	// Manually add connections (bypass Run() for this test)
	hub.mu.Lock()
	hub.noteUsers[noteID] = map[uuid.UUID]*Connection{
		user1ID: conn1,
		user2ID: conn2,
	}
	hub.mu.Unlock()

	// Broadcast a message
	testMessage := WSMessage{
		Type:    "edit",
		NoteID:  noteID.String(),
		UserID:  senderID.String(),
		Content: "test content",
	}

	hub.broadcastToNote(noteID, testMessage, senderID)

	// Verify both connections received the message
	time.Sleep(50 * time.Millisecond)

	select {
	case msg1 := <-conn1.Send:
		var received WSMessage
		err := json.Unmarshal(msg1, &received)
		require.NoError(t, err)
		assert.Equal(t, "edit", received.Type)
		assert.Equal(t, noteID.String(), received.NoteID)
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Expected to receive message on conn1")
	}

	select {
	case msg2 := <-conn2.Send:
		var received WSMessage
		err := json.Unmarshal(msg2, &received)
		require.NoError(t, err)
		assert.Equal(t, "edit", received.Type)
		assert.Equal(t, noteID.String(), received.NoteID)
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Expected to receive message on conn2")
	}

	// Clean up
	close(conn1.Send)
	close(conn2.Send)
}

// TestBroadcastExcludesSender tests that broadcast excludes the sender
func TestBroadcastExcludesSender(t *testing.T) {
	hub := NewHub()

	noteID := uuid.New()
	senderID := uuid.New()
	receiverID := uuid.New()

	senderConn := &Connection{
		ID:     uuid.New().String(),
		UserID: senderID,
		NoteID: noteID,
		Conn:   nil,
		Send:   make(chan []byte, 256),
	}

	receiverConn := &Connection{
		ID:     uuid.New().String(),
		UserID: receiverID,
		NoteID: noteID,
		Conn:   nil,
		Send:   make(chan []byte, 256),
	}

	// Manually add connections
	hub.mu.Lock()
	hub.noteUsers[noteID] = map[uuid.UUID]*Connection{
		senderID:   senderConn,
		receiverID: receiverConn,
	}
	hub.mu.Unlock()

	// Broadcast a message
	testMessage := WSMessage{
		Type:    "edit",
		NoteID:  noteID.String(),
		UserID:  senderID.String(),
		Content: "test content",
	}

	hub.broadcastToNote(noteID, testMessage, senderID)
	time.Sleep(50 * time.Millisecond)

	// Verify sender did NOT receive the message
	select {
	case <-senderConn.Send:
		t.Fatal("Sender should not receive their own broadcast")
	case <-time.After(100 * time.Millisecond):
		// Expected - sender should not receive message
	}

	// Verify receiver DID receive the message
	select {
	case msg := <-receiverConn.Send:
		var received WSMessage
		err := json.Unmarshal(msg, &received)
		require.NoError(t, err)
		assert.Equal(t, "edit", received.Type)
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Expected receiver to receive message")
	}

	// Clean up
	close(senderConn.Send)
	close(receiverConn.Send)
}

// TestMessageTypes tests different message type structures
func TestMessageTypes(t *testing.T) {
	t.Run("WSMessage", func(t *testing.T) {
		msg := WSMessage{
			Type:    "edit",
			NoteID:  uuid.New().String(),
			UserID:  uuid.New().String(),
			Content: "test content",
		}

		data, err := json.Marshal(msg)
		require.NoError(t, err)

		var decoded WSMessage
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)
		assert.Equal(t, msg.Type, decoded.Type)
		assert.Equal(t, msg.NoteID, decoded.NoteID)
		assert.Equal(t, msg.UserID, decoded.UserID)
	})

	t.Run("PresenceMessage", func(t *testing.T) {
		msg := PresenceMessage{
			UserID:    uuid.New().String(),
			UserEmail: "test@example.com",
			Status:    "online",
		}

		data, err := json.Marshal(msg)
		require.NoError(t, err)

		var decoded PresenceMessage
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)
		assert.Equal(t, msg.UserID, decoded.UserID)
		assert.Equal(t, msg.UserEmail, decoded.UserEmail)
		assert.Equal(t, msg.Status, decoded.Status)
	})

	t.Run("EditMessage", func(t *testing.T) {
		msg := EditMessage{
			Operation: "insert",
			Position:  10,
			Content:   "hello",
			Timestamp: time.Now().Unix(),
		}

		data, err := json.Marshal(msg)
		require.NoError(t, err)

		var decoded EditMessage
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)
		assert.Equal(t, msg.Operation, decoded.Operation)
		assert.Equal(t, msg.Position, decoded.Position)
		assert.Equal(t, msg.Content, decoded.Content)
		assert.Equal(t, msg.Timestamp, decoded.Timestamp)
	})

	t.Run("CursorMessage", func(t *testing.T) {
		msg := CursorMessage{
			UserID:   uuid.New().String(),
			Position: 42,
			Length:   5,
		}

		data, err := json.Marshal(msg)
		require.NoError(t, err)

		var decoded CursorMessage
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)
		assert.Equal(t, msg.UserID, decoded.UserID)
		assert.Equal(t, msg.Position, decoded.Position)
		assert.Equal(t, msg.Length, decoded.Length)
	})
}

// TestConnectionLifecycle tests the full lifecycle of a connection
func TestConnectionLifecycle(t *testing.T) {
	hub := NewHub()
	go hub.Run()

	noteID := uuid.New()
	userID := uuid.New()

	conn := &Connection{
		ID:     uuid.New().String(),
		UserID: userID,
		NoteID: noteID,
		Conn:   nil,
		Send:   make(chan []byte, 256),
	}

	// 1. Register
	hub.register <- conn
	time.Sleep(50 * time.Millisecond)

	hub.mu.RLock()
	assert.Equal(t, 1, len(hub.connections))
	hub.mu.RUnlock()

	// 2. Verify can receive messages
	users := hub.GetConnectedUsers(noteID)
	assert.Equal(t, 1, len(users))
	assert.Contains(t, users, userID.String())

	// 3. Unregister
	hub.unregister <- conn
	time.Sleep(50 * time.Millisecond)

	hub.mu.RLock()
	assert.Equal(t, 0, len(hub.connections))
	hub.mu.RUnlock()

	users = hub.GetConnectedUsers(noteID)
	assert.Equal(t, 0, len(users))

	// Clean up
	hub.Stop()
}

// BenchmarkHubRegister benchmarks connection registration
func BenchmarkHubRegister(b *testing.B) {
	hub := NewHub()
	go hub.Run()

	noteID := uuid.New()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn := &Connection{
			ID:     uuid.New().String(),
			UserID: uuid.New(),
			NoteID: noteID,
			Conn:   nil,
			Send:   make(chan []byte, 256),
		}
		hub.register <- conn
	}
}

// BenchmarkBroadcastToNote benchmarks message broadcasting
func BenchmarkBroadcastToNote(b *testing.B) {
	hub := NewHub()
	noteID := uuid.New()
	userID := uuid.New()

	// Add 10 connections
	hub.mu.Lock()
	hub.noteUsers[noteID] = make(map[uuid.UUID]*Connection)
	for i := 0; i < 10; i++ {
		conn := &Connection{
			ID:     uuid.New().String(),
			UserID: uuid.New(),
			NoteID: noteID,
			Conn:   nil,
			Send:   make(chan []byte, 256),
		}
		hub.noteUsers[noteID][conn.UserID] = conn
	}
	hub.mu.Unlock()

	testMessage := WSMessage{
		Type:    "edit",
		NoteID:  noteID.String(),
		UserID:  userID.String(),
		Content: "test content",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hub.broadcastToNote(noteID, testMessage, userID)
	}
}