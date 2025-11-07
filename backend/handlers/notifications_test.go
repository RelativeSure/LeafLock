package handlers

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"leaflock/websocket"
)

type stubBroadcaster struct {
	payload websocket.WSMessage
	count   int
}

func (s *stubBroadcaster) BroadcastToUser(userID uuid.UUID, message websocket.WSMessage) error {
	s.payload = message
	s.count++
	return nil
}

func TestNotificationsHandler_CreateNotification_Broadcasts(t *testing.T) {
	mockDB := new(MockDB)
	broadcaster := &stubBroadcaster{}
	handler := NewNotificationsHandler(mockDB, broadcaster)

	userID := uuid.New().String()
	row := new(MockRow)
	row.On("Scan", mock.AnythingOfType("*uuid.UUID")).Run(func(args mock.Arguments) {
		*(args[0].(*uuid.UUID)) = uuid.New()
	}).Return(nil).Once()

	mockDB.On("QueryRow",
		mock.Anything,
		mock.MatchedBy(func(query string) bool { return true }),
		userID, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything,
	).Return(row).Once()

	app := fiber.New()
	app.Post("/notifications/:user_id", handler.CreateNotification)

	body, err := json.Marshal(map[string]interface{}{
		"type":    "note_shared",
		"title":   "Shared Note",
		"message": "A note was shared with you",
	})
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/notifications/"+userID, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusCreated, resp.StatusCode)
	assert.Equal(t, 1, broadcaster.count)
	assert.Equal(t, "notification", broadcaster.payload.Type)
}
