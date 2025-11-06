package websocket

// WSMessage represents a generic WebSocket message structure for real-time collaboration
type WSMessage struct {
	Type    string      `json:"type"`
	NoteID  string      `json:"note_id,omitempty"`
	UserID  string      `json:"user_id,omitempty"`
	Content interface{} `json:"content,omitempty"`
}

// PresenceMessage represents user presence information (online/offline status)
type PresenceMessage struct {
	UserID    string `json:"user_id"`
	UserEmail string `json:"user_email"`
	Status    string `json:"status"` // "online", "offline"
}

// EditMessage represents a text editing operation for collaborative editing
type EditMessage struct {
	Operation string `json:"operation"` // "insert", "delete", "replace"
	Position  int    `json:"position"`
	Content   string `json:"content"`
	Timestamp int64  `json:"timestamp"`
}

// CursorMessage represents cursor position and selection for collaborative editing
type CursorMessage struct {
	UserID   string `json:"user_id"`
	Position int    `json:"position"`
	Length   int    `json:"length"`
}

// NotificationMessage represents a real-time notification
type NotificationMessage struct {
	ID        string                 `json:"id"`
	Type      string                 `json:"type"`
	Title     string                 `json:"title"`
	Message   string                 `json:"message"`
	ActionURL *string                `json:"action_url,omitempty"`
	Metadata  map[string]interface{} `json:"metadata"`
	CreatedAt string                 `json:"created_at"`
}
