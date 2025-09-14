package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
)

// TagsHandler Test Suite
type TagsHandlerTestSuite struct {
	suite.Suite
	handler *TagsHandler
	mockDB  *MockDB
	crypto  *CryptoService
	app     *fiber.App
	userID  uuid.UUID
	token   string
}

func (suite *TagsHandlerTestSuite) SetupTest() {
	suite.mockDB = &MockDB{}

	// Generate test encryption key
	key := make([]byte, 32)
	rand.Read(key)
	suite.crypto = NewCryptoService(key)

	suite.handler = &TagsHandler{
		db:     suite.mockDB,
		crypto: suite.crypto,
	}

	// Setup test user and token
	suite.userID = uuid.New()
	suite.token = "test-jwt-token"

	// Setup Fiber app with middleware
	suite.app = fiber.New()
	suite.app.Use(func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.userID)
		return c.Next()
	})

	// Register routes
	suite.app.Get("/tags", suite.handler.GetTags)
	suite.app.Post("/tags", suite.handler.CreateTag)
	suite.app.Delete("/tags/:id", suite.handler.DeleteTag)
	suite.app.Get("/tags/:id/notes", suite.handler.GetNotesByTag)
	suite.app.Post("/notes/:id/tags", suite.handler.AssignTagToNote)
	suite.app.Delete("/notes/:id/tags/:tag_id", suite.handler.RemoveTagFromNote)
}

func (suite *TagsHandlerTestSuite) TestGetTagsSuccess() {
	// Mock database response
	mockRows := &MockRows{}
	suite.mockDB.On("Query", mock.Anything, mock.AnythingOfType("string"), suite.userID).Return(mockRows, nil)

	tagID1 := uuid.New()
	tagID2 := uuid.New()
	encryptedName1, _ := suite.crypto.Encrypt([]byte("Work"))
	encryptedName2, _ := suite.crypto.Encrypt([]byte("Personal"))

	// Mock rows.Next() calls
	mockRows.On("Next").Return(true).Once()
	mockRows.On("Next").Return(true).Once()
	mockRows.On("Next").Return(false).Once()

	// Mock first tag scan
	mockRows.On("Scan", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		*args[0].(*uuid.UUID) = tagID1
		*args[1].(*[]byte) = encryptedName1
		*args[2].(*string) = "#3b82f6"
		*args[3].(*time.Time) = time.Now()
		*args[4].(*time.Time) = time.Now()
	}).Return(nil).Once()

	// Mock second tag scan
	mockRows.On("Scan", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		*args[0].(*uuid.UUID) = tagID2
		*args[1].(*[]byte) = encryptedName2
		*args[2].(*string) = "#ef4444"
		*args[3].(*time.Time) = time.Now()
		*args[4].(*time.Time) = time.Now()
	}).Return(nil).Once()

	mockRows.On("Close").Return()

	// Make request
	req := httptest.NewRequest("GET", "/tags", nil)
	resp, err := suite.app.Test(req)

	suite.NoError(err)
	suite.Equal(200, resp.StatusCode)

	var response map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&response)

	suite.Contains(response, "tags")
	tags := response["tags"].([]interface{})
	suite.Len(tags, 2)
}

func (suite *TagsHandlerTestSuite) TestCreateTagSuccess() {
	mockRow := &MockRow{}
	tagID := uuid.New()

	suite.mockDB.On("QueryRow", mock.Anything, mock.AnythingOfType("string"), suite.userID, mock.Anything, "#3b82f6").Return(mockRow)
	mockRow.On("Scan", mock.Anything).Run(func(args mock.Arguments) {
		*args[0].(*uuid.UUID) = tagID
	}).Return(nil)

	req := CreateTagRequest{
		Name:  "Work",
		Color: "#3b82f6",
	}

	body, _ := json.Marshal(req)
	httpReq := httptest.NewRequest("POST", "/tags", bytes.NewBuffer(body))
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := suite.app.Test(httpReq)

	suite.NoError(err)
	suite.Equal(201, resp.StatusCode)

	var response map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&response)

	suite.Equal("Tag created successfully", response["message"])
	suite.Equal(tagID.String(), response["id"])
}

func (suite *TagsHandlerTestSuite) TestCreateTagDefaultColor() {
	mockRow := &MockRow{}
	tagID := uuid.New()

	// Should use default color when none provided
	suite.mockDB.On("QueryRow", mock.Anything, mock.AnythingOfType("string"), suite.userID, mock.Anything, "#3b82f6").Return(mockRow)
	mockRow.On("Scan", mock.Anything).Run(func(args mock.Arguments) {
		*args[0].(*uuid.UUID) = tagID
	}).Return(nil)

	req := CreateTagRequest{
		Name: "Work",
		// No color specified
	}

	body, _ := json.Marshal(req)
	httpReq := httptest.NewRequest("POST", "/tags", bytes.NewBuffer(body))
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := suite.app.Test(httpReq)

	suite.NoError(err)
	suite.Equal(201, resp.StatusCode)
}

func (suite *TagsHandlerTestSuite) TestCreateTagInvalidColor() {
	req := CreateTagRequest{
		Name:  "Work",
		Color: "invalid-color",
	}

	body, _ := json.Marshal(req)
	httpReq := httptest.NewRequest("POST", "/tags", bytes.NewBuffer(body))
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := suite.app.Test(httpReq)

	suite.NoError(err)
	suite.Equal(400, resp.StatusCode)
}

func (suite *TagsHandlerTestSuite) TestCreateTagDuplicate() {
	mockRow := &MockRow{}

	suite.mockDB.On("QueryRow", mock.Anything, mock.AnythingOfType("string"), suite.userID, mock.Anything, "#3b82f6").Return(mockRow)
	mockRow.On("Scan", mock.Anything).Return(errors.New("duplicate key value violates unique constraint"))

	req := CreateTagRequest{
		Name:  "Work",
		Color: "#3b82f6",
	}

	body, _ := json.Marshal(req)
	httpReq := httptest.NewRequest("POST", "/tags", bytes.NewBuffer(body))
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := suite.app.Test(httpReq)

	suite.NoError(err)
	suite.Equal(409, resp.StatusCode)
}

func (suite *TagsHandlerTestSuite) TestDeleteTagSuccess() {
	tagID := uuid.New()
	mockResult := &MockResult{}
	mockResult.On("RowsAffected").Return(int64(1))

	suite.mockDB.On("Exec", mock.Anything, mock.AnythingOfType("string"), tagID, suite.userID).Return(mockResult, nil)

	req := httptest.NewRequest("DELETE", "/tags/"+tagID.String(), nil)
	resp, err := suite.app.Test(req)

	suite.NoError(err)
	suite.Equal(200, resp.StatusCode)

	var response map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&response)

	suite.Equal("Tag deleted successfully", response["message"])
}

func (suite *TagsHandlerTestSuite) TestDeleteTagNotFound() {
	tagID := uuid.New()
	mockResult := &MockResult{}
	mockResult.On("RowsAffected").Return(int64(0))

	suite.mockDB.On("Exec", mock.Anything, mock.AnythingOfType("string"), tagID, suite.userID).Return(mockResult, nil)

	req := httptest.NewRequest("DELETE", "/tags/"+tagID.String(), nil)
	resp, err := suite.app.Test(req)

	suite.NoError(err)
	suite.Equal(404, resp.StatusCode)
}

func (suite *TagsHandlerTestSuite) TestAssignTagToNoteSuccess() {
	noteID := uuid.New()
	tagID := uuid.New()

	// Mock note existence check
	mockRow1 := &MockRow{}
	suite.mockDB.On("QueryRow", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return strings.Contains(sql, "SELECT true FROM notes")
	}), noteID, suite.userID).Return(mockRow1)
	mockRow1.On("Scan", mock.Anything).Run(func(args mock.Arguments) {
		*args[0].(*bool) = true
	}).Return(nil)

	// Mock tag existence check
	mockRow2 := &MockRow{}
	suite.mockDB.On("QueryRow", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return strings.Contains(sql, "SELECT true FROM tags")
	}), tagID, suite.userID).Return(mockRow2)
	mockRow2.On("Scan", mock.Anything).Run(func(args mock.Arguments) {
		*args[0].(*bool) = true
	}).Return(nil)

	// Mock tag assignment
	mockResult := &MockResult{}
	mockResult.On("RowsAffected").Return(int64(1))
	suite.mockDB.On("Exec", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return strings.Contains(sql, "INSERT INTO note_tags")
	}), noteID, tagID).Return(mockResult, nil)

	req := AssignTagRequest{
		TagID: tagID.String(),
	}

	body, _ := json.Marshal(req)
	httpReq := httptest.NewRequest("POST", "/notes/"+noteID.String()+"/tags", bytes.NewBuffer(body))
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := suite.app.Test(httpReq)

	suite.NoError(err)
	suite.Equal(200, resp.StatusCode)

	var response map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&response)

	suite.Equal("Tag assigned successfully", response["message"])
}

func (suite *TagsHandlerTestSuite) TestAssignTagNoteNotFound() {
	noteID := uuid.New()
	tagID := uuid.New()

	// Mock note not found
	mockRow1 := &MockRow{}
	suite.mockDB.On("QueryRow", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return strings.Contains(sql, "SELECT true FROM notes")
	}), noteID, suite.userID).Return(mockRow1)
	mockRow1.On("Scan", mock.Anything).Return(errors.New("no rows in result set"))

	req := AssignTagRequest{
		TagID: tagID.String(),
	}

	body, _ := json.Marshal(req)
	httpReq := httptest.NewRequest("POST", "/notes/"+noteID.String()+"/tags", bytes.NewBuffer(body))
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := suite.app.Test(httpReq)

	suite.NoError(err)
	suite.Equal(404, resp.StatusCode)
}

func (suite *TagsHandlerTestSuite) TestRemoveTagFromNoteSuccess() {
	noteID := uuid.New()
	tagID := uuid.New()

	mockResult := &MockResult{}
	mockResult.On("RowsAffected").Return(int64(1))

	suite.mockDB.On("Exec", mock.Anything, mock.AnythingOfType("string"), noteID, tagID, suite.userID).Return(mockResult, nil)

	req := httptest.NewRequest("DELETE", "/notes/"+noteID.String()+"/tags/"+tagID.String(), nil)
	resp, err := suite.app.Test(req)

	suite.NoError(err)
	suite.Equal(200, resp.StatusCode)

	var response map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&response)

	suite.Equal("Tag removed successfully", response["message"])
}

func (suite *TagsHandlerTestSuite) TestGetNotesByTagSuccess() {
	tagID := uuid.New()
	noteID1 := uuid.New()
	noteID2 := uuid.New()

	mockRows := &MockRows{}
	suite.mockDB.On("Query", mock.Anything, mock.AnythingOfType("string"), tagID, suite.userID).Return(mockRows, nil)

	// Create mock encrypted data
	encTitle1, _ := suite.crypto.Encrypt([]byte("Note 1"))
	encContent1, _ := suite.crypto.Encrypt([]byte("Content 1"))
	encTitle2, _ := suite.crypto.Encrypt([]byte("Note 2"))
	encContent2, _ := suite.crypto.Encrypt([]byte("Content 2"))

	// Mock rows.Next() calls
	mockRows.On("Next").Return(true).Once()
	mockRows.On("Next").Return(true).Once()
	mockRows.On("Next").Return(false).Once()

	// Mock first note scan
	mockRows.On("Scan", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		*args[0].(*uuid.UUID) = noteID1
		*args[1].(*[]byte) = encTitle1
		*args[2].(*[]byte) = encContent1
		*args[3].(*time.Time) = time.Now()
		*args[4].(*time.Time) = time.Now()
	}).Return(nil).Once()

	// Mock second note scan
	mockRows.On("Scan", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		*args[0].(*uuid.UUID) = noteID2
		*args[1].(*[]byte) = encTitle2
		*args[2].(*[]byte) = encContent2
		*args[3].(*time.Time) = time.Now()
		*args[4].(*time.Time) = time.Now()
	}).Return(nil).Once()

	mockRows.On("Close").Return()

	req := httptest.NewRequest("GET", "/tags/"+tagID.String()+"/notes", nil)
	resp, err := suite.app.Test(req)

	suite.NoError(err)
	suite.Equal(200, resp.StatusCode)

	var response map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&response)

	notes := response["notes"].([]interface{})
	suite.Len(notes, 2)
}

// Test isValidHexColor function
func TestIsValidHexColor(t *testing.T) {
	tests := []struct {
		color    string
		expected bool
	}{
		{"#000000", true},
		{"#FFFFFF", true},
		{"#3b82f6", true},
		{"#3B82F6", true},
		{"#123ABC", true},
		{"000000", false},   // Missing #
		{"#00000", false},   // Too short
		{"#0000000", false}, // Too long
		{"#GGGGGG", false},  // Invalid hex chars
		{"#12345G", false},  // Invalid hex char
		{"", false},         // Empty
		{"red", false},      // Color name
	}

	for _, test := range tests {
		t.Run(test.color, func(t *testing.T) {
			result := isValidHexColor(test.color)
			assert.Equal(t, test.expected, result, "Color: %s", test.color)
		})
	}
}

// Run the test suite
func TestTagsHandlerSuite(t *testing.T) {
	suite.Run(t, new(TagsHandlerTestSuite))
}
