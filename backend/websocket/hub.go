package websocket

import (
	"encoding/json"
	"sync"

	"github.com/gofiber/contrib/websocket"
	"github.com/google/uuid"
)

// Connection represents a WebSocket connection for a user collaborating on a note
type Connection struct {
	ID     string
	UserID uuid.UUID
	NoteID uuid.UUID
	Conn   *websocket.Conn
	Send   chan []byte
}

// Hub manages WebSocket connections and message broadcasting for real-time collaboration
type Hub struct {
	connections map[string]*Connection
	noteUsers   map[uuid.UUID]map[uuid.UUID]*Connection // noteID -> userID -> connection
	register    chan *Connection
	unregister  chan *Connection
	broadcast   chan []byte
	mu          sync.RWMutex
	done        chan struct{}
}

// NewHub creates a new Hub instance for managing WebSocket connections
func NewHub() *Hub {
	return &Hub{
		connections: make(map[string]*Connection),
		noteUsers:   make(map[uuid.UUID]map[uuid.UUID]*Connection),
		register:    make(chan *Connection),
		unregister:  make(chan *Connection),
		broadcast:   make(chan []byte),
		done:        make(chan struct{}),
	}
}

// Close gracefully shuts down the hub and releases underlying resources.
func (h *Hub) Close() {
	h.mu.Lock()
	select {
	case <-h.done:
		// already closed
	default:
		close(h.done)
		close(h.register)
		close(h.unregister)
		close(h.broadcast)
	}
	h.mu.Unlock()
}

// RegisterConnection schedules a connection to be added to the hub.
func (h *Hub) RegisterConnection(conn *Connection) {
	h.register <- conn
}

// UnregisterConnection schedules a connection to be removed from the hub.
func (h *Hub) UnregisterConnection(conn *Connection) {
	h.unregister <- conn
}

// Run starts the Hub's main event loop for managing connections and broadcasts
func (h *Hub) Run() {
	for {
		select {
		case <-h.done:
			return
		case conn, ok := <-h.register:
			if !ok {
				return
			}
			h.mu.Lock()
			h.connections[conn.ID] = conn

			if h.noteUsers[conn.NoteID] == nil {
				h.noteUsers[conn.NoteID] = make(map[uuid.UUID]*Connection)
			}
			h.noteUsers[conn.NoteID][conn.UserID] = conn
			h.mu.Unlock()

			// Notify others about new user joining
			h.broadcastToNote(conn.NoteID, WSMessage{
				Type:   "presence",
				NoteID: conn.NoteID.String(),
				Content: PresenceMessage{
					UserID: conn.UserID.String(),
					Status: "online",
				},
			}, conn.UserID)

		case conn, ok := <-h.unregister:
			if !ok {
				return
			}
			h.mu.Lock()
			if _, exists := h.connections[conn.ID]; exists {
				delete(h.connections, conn.ID)
				if noteConns, exists := h.noteUsers[conn.NoteID]; exists {
					delete(noteConns, conn.UserID)
					if len(noteConns) == 0 {
						delete(h.noteUsers, conn.NoteID)
					}
				}
				close(conn.Send)
			}
			h.mu.Unlock()

			// Notify others about user leaving
			h.broadcastToNote(conn.NoteID, WSMessage{
				Type:   "presence",
				NoteID: conn.NoteID.String(),
				Content: PresenceMessage{
					UserID: conn.UserID.String(),
					Status: "offline",
				},
			}, conn.UserID)
		}
	}
}

// broadcastToNote sends a message to all users connected to a specific note,
// excluding the specified user ID
func (h *Hub) broadcastToNote(noteID uuid.UUID, message WSMessage, excludeUserID uuid.UUID) {
	h.mu.RLock()
	noteConns := h.noteUsers[noteID]
	h.mu.RUnlock()

	if noteConns == nil {
		return
	}

	data, err := json.Marshal(message)
	if err != nil {
		return
	}

	for userID, conn := range noteConns {
		if userID != excludeUserID {
			select {
			case conn.Send <- data:
			default:
				close(conn.Send)
				delete(noteConns, userID)
			}
		}
	}
}

// Stop gracefully shuts down the Hub
func (h *Hub) Stop() {
	close(h.done)
}

// GetConnectedUsers returns a list of user IDs currently connected to a specific note
func (h *Hub) GetConnectedUsers(noteID uuid.UUID) []string {
	h.mu.RLock()
	defer h.mu.RUnlock()

	noteConns := h.noteUsers[noteID]
	if noteConns == nil {
		return []string{}
	}

	users := make([]string, 0, len(noteConns))
	for userID := range noteConns {
		users = append(users, userID.String())
	}
	return users
}
