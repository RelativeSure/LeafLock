package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
)

// TrashHandler Test Suite
type TrashHandlerTestSuite struct {
	suite.Suite
	handler *NotesHandler
	mockDB  *MockDB
	crypto  *CryptoService
	app     *fiber.App
	userID  uuid.UUID
}

func (suite *TrashHandlerTestSuite) SetupTest() {
	suite.mockDB = &MockDB{}
	
	// Generate test encryption key
	key := make([]byte, 32)
	rand.Read(key)
	suite.crypto = NewCryptoService(key)
	
	suite.handler = &NotesHandler{
		db:     suite.mockDB,
		crypto: suite.crypto,
	}

	// Setup test user
	suite.userID = uuid.New()

	// Setup Fiber app with middleware
	suite.app = fiber.New()
	suite.app.Use(func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.userID)
		return c.Next()
	})

	// Register routes
	suite.app.Get("/trash", suite.handler.GetTrash)
	suite.app.Put("/trash/:id/restore", suite.handler.RestoreNote)
	suite.app.Delete("/trash/:id", suite.handler.PermanentlyDeleteNote)
}

func (suite *TrashHandlerTestSuite) TestGetTrashSuccess() {
	workspaceID := uuid.New()
	noteID1 := uuid.New()
	noteID2 := uuid.New()

	// Mock workspace lookup
	mockRow1 := &MockRow{}
	suite.mockDB.On("QueryRow", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "SELECT id FROM workspaces")
	}), suite.userID).Return(mockRow1)
	mockRow1.On("Scan", mock.Anything).Run(func(args mock.Arguments) {
		*args[0].(*uuid.UUID) = workspaceID
	}).Return(nil)

	// Mock trash query
	mockRows := &MockRows{}
	suite.mockDB.On("Query", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "deleted_at IS NOT NULL")
	}), workspaceID).Return(mockRows, nil)

	// Create test encrypted data
	encTitle1, _ := suite.crypto.Encrypt([]byte("Deleted Note 1"))
	encContent1, _ := suite.crypto.Encrypt([]byte("Content 1"))
	encTitle2, _ := suite.crypto.Encrypt([]byte("Deleted Note 2"))
	encContent2, _ := suite.crypto.Encrypt([]byte("Content 2"))

	deletedAt := time.Now().Add(-1 * time.Hour)

	// Mock rows.Next() calls
	mockRows.On("Next").Return(true).Once()
	mockRows.On("Next").Return(true).Once()
	mockRows.On("Next").Return(false).Once()

	// Mock first note scan
	mockRows.On("Scan", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		*args[0].(*uuid.UUID) = noteID1
		*args[1].(*[]byte) = encTitle1
		*args[2].(*[]byte) = encContent1
		*args[3].(*time.Time) = deletedAt
		*args[4].(*time.Time) = time.Now()
	}).Return(nil).Once()

	// Mock second note scan
	mockRows.On("Scan", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		*args[0].(*uuid.UUID) = noteID2
		*args[1].(*[]byte) = encTitle2
		*args[2].(*[]byte) = encContent2
		*args[3].(*time.Time) = deletedAt
		*args[4].(*time.Time) = time.Now()
	}).Return(nil).Once()

	mockRows.On("Close").Return()

	// Make request
	req := httptest.NewRequest("GET", "/trash", nil)
	resp, err := suite.app.Test(req)
	
	suite.NoError(err)
	suite.Equal(200, resp.StatusCode)

	var response map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&response)

	suite.Contains(response, "notes")
	notes := response["notes"].([]interface{})
	suite.Len(notes, 2)
}

func (suite *TrashHandlerTestSuite) TestGetTrashWorkspaceError() {
	// Mock workspace not found
	mockRow1 := &MockRow{}
	suite.mockDB.On("QueryRow", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "SELECT id FROM workspaces")
	}), suite.userID).Return(mockRow1)
	mockRow1.On("Scan", mock.Anything).Return(errors.New("no rows in result set"))

	req := httptest.NewRequest("GET", "/trash", nil)
	resp, err := suite.app.Test(req)
	
	suite.NoError(err)
	suite.Equal(500, resp.StatusCode)
}

func (suite *TrashHandlerTestSuite) TestRestoreNoteSuccess() {
	noteID := uuid.New()
	mockResult := &MockResult{}
	mockResult.On("RowsAffected").Return(int64(1))
	
	suite.mockDB.On("Exec", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "SET deleted_at = NULL")
	}), noteID, suite.userID).Return(mockResult, nil)

	req := httptest.NewRequest("PUT", "/trash/"+noteID.String()+"/restore", nil)
	resp, err := suite.app.Test(req)
	
	suite.NoError(err)
	suite.Equal(200, resp.StatusCode)

	var response map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&response)

	suite.Equal("Note restored successfully", response["message"])
}

func (suite *TrashHandlerTestSuite) TestRestoreNoteNotFound() {
	noteID := uuid.New()
	mockResult := &MockResult{}
	mockResult.On("RowsAffected").Return(int64(0))
	
	suite.mockDB.On("Exec", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "SET deleted_at = NULL")
	}), noteID, suite.userID).Return(mockResult, nil)

	req := httptest.NewRequest("PUT", "/trash/"+noteID.String()+"/restore", nil)
	resp, err := suite.app.Test(req)
	
	suite.NoError(err)
	suite.Equal(404, resp.StatusCode)
}

func (suite *TrashHandlerTestSuite) TestPermanentlyDeleteNoteSuccess() {
	noteID := uuid.New()
	mockResult := &MockResult{}
	mockResult.On("RowsAffected").Return(int64(1))
	
	suite.mockDB.On("Exec", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "DELETE FROM notes")
	}), noteID, suite.userID).Return(mockResult, nil)

	req := httptest.NewRequest("DELETE", "/trash/"+noteID.String(), nil)
	resp, err := suite.app.Test(req)
	
	suite.NoError(err)
	suite.Equal(200, resp.StatusCode)

	var response map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&response)

	suite.Equal("Note permanently deleted successfully", response["message"])
}

func (suite *TrashHandlerTestSuite) TestPermanentlyDeleteNoteNotFound() {
	noteID := uuid.New()
	mockResult := &MockResult{}
	mockResult.On("RowsAffected").Return(int64(0))
	
	suite.mockDB.On("Exec", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "DELETE FROM notes")
	}), noteID, suite.userID).Return(mockResult, nil)

	req := httptest.NewRequest("DELETE", "/trash/"+noteID.String(), nil)
	resp, err := suite.app.Test(req)
	
	suite.NoError(err)
	suite.Equal(404, resp.StatusCode)
}

func (suite *TrashHandlerTestSuite) TestInvalidNoteID() {
	// Test restore with invalid note ID
	req := httptest.NewRequest("PUT", "/trash/invalid-id/restore", nil)
	resp, err := suite.app.Test(req)
	
	suite.NoError(err)
	suite.Equal(400, resp.StatusCode)

	var response map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&response)
	suite.Equal("Invalid note ID", response["error"])
}

// Test cleanup function
func TestCleanupOldDeletedNotes(t *testing.T) {
	// Test the function call structure
	mockDB := &MockDB{}
	
	// Mock both cleanup functions since runCleanupTasks calls both
	mockResult1 := &MockResult{}
	mockResult1.On("RowsAffected").Return(int64(0))
	mockResult2 := &MockResult{}
	mockResult2.On("RowsAffected").Return(int64(0))
	
	ctx := context.Background()
	mockDB.On("Exec", ctx, "SELECT cleanup_expired_sessions()").Return(mockResult1, nil)
	mockDB.On("Exec", ctx, "SELECT cleanup_old_deleted_notes()").Return(mockResult2, nil)
	
	// Mock the count query for deleted notes
	mockRow := &MockRow{}
	mockDB.On("QueryRow", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "COUNT(*)")
	})).Return(mockRow)
	mockRow.On("Scan", mock.Anything).Run(func(args mock.Arguments) {
		*args[0].(*int) = 0
	}).Return(nil)
	
	runCleanupTasks(ctx, mockDB)
	
	// Verify both cleanup functions were called
	mockDB.AssertCalled(t, "Exec", ctx, "SELECT cleanup_expired_sessions()")
	mockDB.AssertCalled(t, "Exec", ctx, "SELECT cleanup_old_deleted_notes()")
}

// Test background cleanup service
func TestBackgroundCleanupService(t *testing.T) {
	mockDB := &MockDB{}
	
	// Mock cleanup calls - setup multiple results since the function calls both cleanup functions
	mockResult1 := &MockResult{}
	mockResult1.On("RowsAffected").Return(int64(0))
	mockResult2 := &MockResult{}
	mockResult2.On("RowsAffected").Return(int64(0))
	
	mockDB.On("Exec", mock.Anything, "SELECT cleanup_expired_sessions()").Return(mockResult1, nil)
	mockDB.On("Exec", mock.Anything, "SELECT cleanup_old_deleted_notes()").Return(mockResult2, nil)
	
	// Mock count query for deleted notes
	mockRow := &MockRow{}
	mockDB.On("QueryRow", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "COUNT(*)")
	})).Return(mockRow)
	mockRow.On("Scan", mock.Anything).Run(func(args mock.Arguments) {
		*args[0].(*int) = 5
	}).Return(nil)

	// Test cleanup task execution
	ctx := context.Background()
	runCleanupTasks(ctx, mockDB)

	// Verify all cleanup functions were called
	mockDB.AssertCalled(t, "Exec", ctx, "SELECT cleanup_expired_sessions()")
	mockDB.AssertCalled(t, "Exec", ctx, "SELECT cleanup_old_deleted_notes()")
}

// Helper function for string matching
func contains(str, substr string) bool {
	return strings.Contains(str, substr)
}

// Run the test suite
func TestTrashHandlerSuite(t *testing.T) {
	suite.Run(t, new(TrashHandlerTestSuite))
}