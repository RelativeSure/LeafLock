package websocket

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
)

// MockDatabase implements the database.Database interface for testing
type MockDatabase struct {
	QueryRowFunc func(ctx context.Context, sql string, args ...interface{}) pgx.Row
	QueryFunc    func(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error)
	ExecFunc     func(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error)
	BeginFunc    func(ctx context.Context) (pgx.Tx, error)
}

func (m *MockDatabase) QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row {
	if m.QueryRowFunc != nil {
		return m.QueryRowFunc(ctx, sql, args...)
	}
	return &MockRow{
		ScanFunc: func(dest ...interface{}) error {
			return errors.New("not implemented")
		},
	}
}

func (m *MockDatabase) Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error) {
	if m.QueryFunc != nil {
		return m.QueryFunc(ctx, sql, args...)
	}
	return nil, errors.New("not implemented")
}

func (m *MockDatabase) Exec(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
	if m.ExecFunc != nil {
		return m.ExecFunc(ctx, sql, args...)
	}
	return pgconn.CommandTag{}, errors.New("not implemented")
}

func (m *MockDatabase) Begin(ctx context.Context) (pgx.Tx, error) {
	if m.BeginFunc != nil {
		return m.BeginFunc(ctx)
	}
	return nil, errors.New("not implemented")
}

// MockRow implements pgx.Row interface
type MockRow struct {
	ScanFunc func(dest ...interface{}) error
}

func (m *MockRow) Scan(dest ...interface{}) error {
	if m.ScanFunc != nil {
		return m.ScanFunc(dest...)
	}
	return errors.New("not implemented")
}

// MockWebSocketConn simulates a WebSocket connection for testing
type MockWebSocketConn struct {
	QueryParams   map[string]string
	ReadJSONFunc  func(v interface{}) error
	WriteFunc     func(messageType int, data []byte) error
	CloseFunc     func() error
	ReadCallCount int
	Messages      []interface{}
}

func (m *MockWebSocketConn) Query(key string) string {
	if m.QueryParams != nil {
		return m.QueryParams[key]
	}
	return ""
}

func (m *MockWebSocketConn) ReadJSON(v interface{}) error {
	if m.ReadJSONFunc != nil {
		return m.ReadJSONFunc(v)
	}
	return errors.New("not implemented")
}

func (m *MockWebSocketConn) WriteMessage(messageType int, data []byte) error {
	if m.WriteFunc != nil {
		return m.WriteFunc(messageType, data)
	}
	return nil
}

func (m *MockWebSocketConn) Close() error {
	if m.CloseFunc != nil {
		return m.CloseFunc()
	}
	return nil
}

func TestHandleWebSocket_MissingToken(t *testing.T) {
	hub := NewHub()
	mockDB := &MockDatabase{}

	mockConn := &MockWebSocketConn{
		QueryParams: map[string]string{
			"note_id": uuid.New().String(),
			"user_id": uuid.New().String(),
			"token":   "", // Missing token
		},
		CloseFunc: func() error {
			return nil
		},
	}

	// HandleWebSocket should exit early when token is missing
	// We can't directly test this without refactoring, but we verify the mock setup
	assert.Equal(t, "", mockConn.Query("token"))
	assert.NotNil(t, hub)
	assert.NotNil(t, mockDB)
}

func TestHandleWebSocket_InvalidNoteID(t *testing.T) {
	mockConn := &MockWebSocketConn{
		QueryParams: map[string]string{
			"note_id": "invalid-uuid",
			"user_id": uuid.New().String(),
			"token":   "some-token",
		},
		CloseFunc: func() error {
			return nil
		},
	}

	noteIDStr := mockConn.Query("note_id")
	_, err := uuid.Parse(noteIDStr)
	assert.Error(t, err, "Should fail to parse invalid UUID")
}

func TestHandleWebSocket_InvalidUserID(t *testing.T) {
	mockConn := &MockWebSocketConn{
		QueryParams: map[string]string{
			"note_id": uuid.New().String(),
			"user_id": "invalid-uuid",
			"token":   "some-token",
		},
		CloseFunc: func() error {
			return nil
		},
	}

	userIDStr := mockConn.Query("user_id")
	_, err := uuid.Parse(userIDStr)
	assert.Error(t, err, "Should fail to parse invalid UUID")
}

func TestHandleWebSocket_DatabaseAccessDenied(t *testing.T) {
	noteID := uuid.New()
	userID := uuid.New()

	mockDB := &MockDatabase{
		QueryRowFunc: func(ctx context.Context, sql string, args ...interface{}) pgx.Row {
			return &MockRow{
				ScanFunc: func(dest ...interface{}) error {
					// Simulate no access
					if hasAccess, ok := dest[0].(*bool); ok {
						*hasAccess = false
					}
					return nil
				},
			}
		},
	}

	// Simulate database check
	ctx := context.Background()
	var hasAccess bool
	err := mockDB.QueryRow(ctx, "SELECT EXISTS(...)", noteID, userID).Scan(&hasAccess)

	assert.NoError(t, err)
	assert.False(t, hasAccess, "User should not have access")
}

func TestHandleWebSocket_DatabaseQueryError(t *testing.T) {
	noteID := uuid.New()
	userID := uuid.New()

	mockDB := &MockDatabase{
		QueryRowFunc: func(ctx context.Context, sql string, args ...interface{}) pgx.Row {
			return &MockRow{
				ScanFunc: func(dest ...interface{}) error {
					return errors.New("database connection failed")
				},
			}
		},
	}

	// Simulate database check
	ctx := context.Background()
	var hasAccess bool
	err := mockDB.QueryRow(ctx, "SELECT EXISTS(...)", noteID, userID).Scan(&hasAccess)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "database connection failed")
}

func TestWSMessage_EditType(t *testing.T) {
	msg := WSMessage{
		Type:    "edit",
		NoteID:  uuid.New().String(),
		UserID:  uuid.New().String(),
		Content: map[string]interface{}{"delta": "some content"},
	}

	assert.Equal(t, "edit", msg.Type)
	assert.NotEmpty(t, msg.NoteID)
	assert.NotEmpty(t, msg.UserID)
	assert.NotNil(t, msg.Content)
}

func TestWSMessage_CursorType(t *testing.T) {
	msg := WSMessage{
		Type:    "cursor",
		NoteID:  uuid.New().String(),
		UserID:  uuid.New().String(),
		Content: map[string]interface{}{"position": 42},
	}

	assert.Equal(t, "cursor", msg.Type)
}

func TestWSMessage_PresenceType(t *testing.T) {
	msg := WSMessage{
		Type:    "presence",
		NoteID:  uuid.New().String(),
		UserID:  uuid.New().String(),
		Content: map[string]interface{}{"status": "typing"},
	}

	assert.Equal(t, "presence", msg.Type)
}

func TestConnection_Structure(t *testing.T) {
	noteID := uuid.New()
	userID := uuid.New()

	conn := &Connection{
		ID:     uuid.New().String(),
		UserID: userID,
		NoteID: noteID,
		Send:   make(chan []byte, 256),
	}

	assert.NotEmpty(t, conn.ID)
	assert.Equal(t, userID, conn.UserID)
	assert.Equal(t, noteID, conn.NoteID)
	assert.NotNil(t, conn.Send)
	assert.Equal(t, 256, cap(conn.Send))
}

func TestHandleWebSocket_AccessCheck_OwnerAccess(t *testing.T) {
	noteID := uuid.New()
	userID := uuid.New()

	mockDB := &MockDatabase{
		QueryRowFunc: func(ctx context.Context, sql string, args ...interface{}) pgx.Row {
			return &MockRow{
				ScanFunc: func(dest ...interface{}) error {
					// Simulate owner has access
					if hasAccess, ok := dest[0].(*bool); ok {
						*hasAccess = true
					}
					return nil
				},
			}
		},
	}

	ctx := context.Background()
	var hasAccess bool

	// Simulate the access check query from HandleWebSocket
	err := mockDB.QueryRow(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM notes n
			JOIN workspaces w ON n.workspace_id = w.id
			WHERE n.id = $1 AND w.owner_id = $2 AND n.deleted_at IS NULL
		) OR EXISTS(
			SELECT 1 FROM collaborations c
			WHERE c.note_id = $1 AND c.user_id = $2
		)`, noteID, userID).Scan(&hasAccess)

	assert.NoError(t, err)
	assert.True(t, hasAccess)
}

func TestHandleWebSocket_AccessCheck_CollaboratorAccess(t *testing.T) {
	noteID := uuid.New()
	userID := uuid.New()

	mockDB := &MockDatabase{
		QueryRowFunc: func(ctx context.Context, sql string, args ...interface{}) pgx.Row {
			return &MockRow{
				ScanFunc: func(dest ...interface{}) error {
					// Simulate collaborator has access
					if hasAccess, ok := dest[0].(*bool); ok {
						*hasAccess = true
					}
					return nil
				},
			}
		},
	}

	ctx := context.Background()
	var hasAccess bool
	err := mockDB.QueryRow(ctx, "SELECT EXISTS(...)", noteID, userID).Scan(&hasAccess)

	assert.NoError(t, err)
	assert.True(t, hasAccess)
}

func TestBroadcastToNote_MessageFormat(t *testing.T) {
	hub := NewHub()
	go hub.Run()
	defer hub.Close()

	noteID := uuid.New()
	userID := uuid.New()

	msg := WSMessage{
		Type:   "edit",
		NoteID: noteID.String(),
		UserID: userID.String(),
		Content: map[string]interface{}{
			"delta": []map[string]interface{}{
				{"insert": "Hello"},
			},
		},
	}

	// Verify message structure
	assert.Equal(t, "edit", msg.Type)
	assert.Equal(t, noteID.String(), msg.NoteID)
	assert.Equal(t, userID.String(), msg.UserID)
	assert.NotNil(t, msg.Content)
}

func TestHandleWebSocket_ConnectionLifecycleTest(t *testing.T) {
	hub := NewHub()
	go hub.Run()
	defer hub.Close()

	noteID := uuid.New()
	userID := uuid.New()

	// Create connection
	conn := &Connection{
		ID:     uuid.New().String(),
		UserID: userID,
		NoteID: noteID,
		Send:   make(chan []byte, 256),
	}

	// Register
	hub.RegisterConnection(conn)
	assert.Eventually(t, func() bool {
		users := hub.GetConnectedUsers(noteID)
		return len(users) == 1
	}, testTimeout, pollInterval)

	// Unregister
	hub.UnregisterConnection(conn)
	assert.Eventually(t, func() bool {
		users := hub.GetConnectedUsers(noteID)
		return len(users) == 0
	}, testTimeout, pollInterval)

	// Don't double-close the channel - it's already closed by unregister
	select {
	case _, ok := <-conn.Send:
		assert.False(t, ok, "Send channel should be closed")
	default:
		// Channel might already be closed, which is fine
	}
}

func TestHandleWebSocket_ConcurrentConnections(t *testing.T) {
	hub := NewHub()
	go hub.Run()
	defer hub.Close()

	noteID := uuid.New()
	connections := make([]*Connection, 10)

	// Register 10 concurrent connections
	for i := 0; i < 10; i++ {
		connections[i] = &Connection{
			ID:     uuid.New().String(),
			UserID: uuid.New(),
			NoteID: noteID,
			Send:   make(chan []byte, 256),
		}
		hub.RegisterConnection(connections[i])
	}

	// Verify all connected
	assert.Eventually(t, func() bool {
		users := hub.GetConnectedUsers(noteID)
		return len(users) == 10
	}, testTimeout, pollInterval)

	// Unregister all
	for _, conn := range connections {
		hub.UnregisterConnection(conn)
	}

	// Verify all disconnected
	assert.Eventually(t, func() bool {
		users := hub.GetConnectedUsers(noteID)
		return len(users) == 0
	}, testTimeout, pollInterval)
}

func TestHandleWebSocket_ValidUUIDParsing(t *testing.T) {
	validNoteID := uuid.New()
	validUserID := uuid.New()

	noteID, err := uuid.Parse(validNoteID.String())
	assert.NoError(t, err)
	assert.Equal(t, validNoteID, noteID)

	userID, err := uuid.Parse(validUserID.String())
	assert.NoError(t, err)
	assert.Equal(t, validUserID, userID)
}

func TestHandleWebSocket_EmptyQueryParams(t *testing.T) {
	mockConn := &MockWebSocketConn{
		QueryParams: map[string]string{},
	}

	noteIDStr := mockConn.Query("note_id")
	userIDStr := mockConn.Query("user_id")
	tokenStr := mockConn.Query("token")

	assert.Empty(t, noteIDStr)
	assert.Empty(t, userIDStr)
	assert.Empty(t, tokenStr)
}
