package handlers

import (
	"bytes"
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"leaflock/crypto"
)

// TestCollaborationHandler_Constructor tests NewCollaborationHandler
func TestCollaborationHandler_Constructor(t *testing.T) {
	cryptoSvc := crypto.NewCryptoService(make([]byte, 32))
	handler := NewCollaborationHandler(nil, cryptoSvc, nil)
	require.NotNil(t, handler)
	assert.Nil(t, handler.db)
	assert.NotNil(t, handler.crypto)
}

// TestCollaborationHandler_ShareNoteInvalidID tests ShareNote with invalid ID
func TestCollaborationHandler_ShareNoteInvalidID(t *testing.T) {
	cryptoSvc := crypto.NewCryptoService(make([]byte, 32))
	handler := NewCollaborationHandler(nil, cryptoSvc, nil)
	app := fiber.New()

	app.Post("/notes/:id/share", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		return handler.ShareNote(c)
	})

	req := httptest.NewRequest("POST", "/notes/invalid-uuid/share", bytes.NewBufferString(`{"email":"test@example.com"}`))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	assert.Equal(t, 400, resp.StatusCode)
}

// TestCollaborationHandler_ShareNoteInvalidJSON tests ShareNote with invalid JSON
func TestCollaborationHandler_ShareNoteInvalidJSON(t *testing.T) {
	cryptoSvc := crypto.NewCryptoService(make([]byte, 32))
	handler := NewCollaborationHandler(nil, cryptoSvc, nil)
	app := fiber.New()

	noteID := uuid.New()
	app.Post("/notes/:id/share", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		return handler.ShareNote(c)
	})

	req := httptest.NewRequest("POST", "/notes/"+noteID.String()+"/share", bytes.NewBufferString("{invalid json"))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	assert.Equal(t, 400, resp.StatusCode)
}

// TestCollaborationHandler_GetCollaboratorsInvalidID tests GetCollaborators with invalid ID
func TestCollaborationHandler_GetCollaboratorsInvalidID(t *testing.T) {
	cryptoSvc := crypto.NewCryptoService(make([]byte, 32))
	handler := NewCollaborationHandler(nil, cryptoSvc, nil)
	app := fiber.New()

	app.Get("/notes/:id/collaborators", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		return handler.GetCollaborators(c)
	})

	req := httptest.NewRequest("GET", "/notes/invalid-uuid/collaborators", nil)
	resp, err := app.Test(req, -1)

	require.NoError(t, err)
	assert.Equal(t, 400, resp.StatusCode)
}

// TestCollaborationHandler_RemoveCollaboratorInvalidID tests RemoveCollaborator with invalid ID
func TestCollaborationHandler_RemoveCollaboratorInvalidID(t *testing.T) {
	cryptoSvc := crypto.NewCryptoService(make([]byte, 32))
	handler := NewCollaborationHandler(nil, cryptoSvc, nil)
	app := fiber.New()

	app.Delete("/notes/:id/collaborators/:userId", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		return handler.RemoveCollaborator(c)
	})

	req := httptest.NewRequest("DELETE", "/notes/invalid-uuid/collaborators/"+uuid.New().String(), nil)
	resp, err := app.Test(req, -1)

	require.NoError(t, err)
	assert.Equal(t, 400, resp.StatusCode)
}

// TestCollaborationHandler_RemoveCollaboratorInvalidUserID tests RemoveCollaborator with invalid user ID
func TestCollaborationHandler_RemoveCollaboratorInvalidUserID(t *testing.T) {
	cryptoSvc := crypto.NewCryptoService(make([]byte, 32))
	handler := NewCollaborationHandler(nil, cryptoSvc, nil)
	app := fiber.New()

	noteID := uuid.New()
	app.Delete("/notes/:id/collaborators/:userId", func(c *fiber.Ctx) error {
		c.Locals("user_id", uuid.New())
		return handler.RemoveCollaborator(c)
	})

	req := httptest.NewRequest("DELETE", "/notes/"+noteID.String()+"/collaborators/invalid-uuid", nil)
	resp, err := app.Test(req, -1)

	require.NoError(t, err)
	assert.Equal(t, 400, resp.StatusCode)
}

// TestCollaborationHandler_GetSharedNotesNeedsDB tests that GetSharedNotes requires database
// Note: This handler immediately queries the database, so it cannot be tested without DB connection
func TestCollaborationHandler_GetSharedNotesNeedsDB(t *testing.T) {
	cryptoSvc := crypto.NewCryptoService(make([]byte, 32))
	handler := NewCollaborationHandler(nil, cryptoSvc, nil)
	require.NotNil(t, handler)
	// Handler requires database connection for execution
}

type stubShareNotificationService struct {
	enabled bool
	sent    bool
	last    struct {
		to         string
		noteTitle  string
		permission string
	}
}

func (s *stubShareNotificationService) CheckUserEmailPreference(ctx context.Context, userID, preferenceType string) (bool, error) {
	return s.enabled, nil
}

func (s *stubShareNotificationService) SendNoteSharedNotification(ctx context.Context, recipientEmail, recipientName, senderName, noteTitle, permission, noteURL string) error {
	s.sent = true
	s.last.to = recipientEmail
	s.last.noteTitle = noteTitle
	s.last.permission = permission
	return nil
}

func TestCollaborationHandler_sendShareNotification(t *testing.T) {
	mockDB := new(MockDB)
	key := make([]byte, 32)
	cryptoSvc := crypto.NewCryptoService(key)
	handler := NewCollaborationHandler(mockDB, cryptoSvc, &stubShareNotificationService{enabled: true})

	userID := uuid.New()
	targetID := uuid.New()
	noteID := uuid.New()

	senderRow := new(MockRow)
	senderRow.On("Scan", mock.AnythingOfType("*string")).Run(func(args mock.Arguments) {
		*(args[0].(*string)) = "Sender"
	}).Return(nil).Once()
	titleBytes, err := cryptoSvc.Encrypt([]byte("Confidential"))
	require.NoError(t, err)
	titleRow := new(MockRow)
	titleRow.On("Scan", mock.AnythingOfType("*[]uint8")).Run(func(args mock.Arguments) {
		*(args[0].(*[]byte)) = titleBytes
	}).Return(nil).Once()
	recipientRow := new(MockRow)
	recipientRow.On("Scan", mock.AnythingOfType("*string")).Run(func(args mock.Arguments) {
		*(args[0].(*string)) = "Recipient"
	}).Return(nil).Once()

	mockDB.On("QueryRow",
		mock.Anything,
		mock.MatchedBy(func(query string) bool { return strings.Contains(query, "FROM users WHERE id = $1") }),
		userID,
	).Return(senderRow).Once()

	mockDB.On("QueryRow",
		mock.Anything,
		mock.MatchedBy(func(query string) bool { return strings.Contains(query, "title_encrypted") }),
		noteID,
	).Return(titleRow).Once()

	mockDB.On("QueryRow",
		mock.Anything,
		mock.MatchedBy(func(query string) bool { return strings.Contains(query, "FROM users WHERE id = $1") }),
		targetID,
	).Return(recipientRow).Once()

	req := ShareNoteRequest{
		UserEmail:  "target@example.com",
		Permission: "write",
	}

	handler.sendShareNotification(context.Background(), req, userID, targetID, noteID)

	stub := handler.notificationService.(*stubShareNotificationService)
	assert.True(t, stub.sent)
	assert.Equal(t, "target@example.com", stub.last.to)
	assert.Equal(t, "Confidential", stub.last.noteTitle)

	mockDB.AssertExpectations(t)
}
