package handlers

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
)

// SettingsHandlerTestSuite tests SettingsHandler
type SettingsHandlerTestSuite struct {
	suite.Suite
	handler *SettingsHandler
	mockDB  *MockDB
	userID  uuid.UUID
}

func (suite *SettingsHandlerTestSuite) SetupTest() {
	suite.mockDB = &MockDB{}
	suite.handler = NewSettingsHandler(suite.mockDB)
	suite.userID = uuid.New()
}

func (suite *SettingsHandlerTestSuite) TestNewSettingsHandler() {
	handler := NewSettingsHandler(suite.mockDB)
	suite.NotNil(handler)
	suite.Equal(suite.mockDB, handler.db)
}

func (suite *SettingsHandlerTestSuite) TestGetSettings_Unauthorized() {
	app := fiber.New()
	app.Get("/settings", suite.handler.GetSettings)

	req := httptest.NewRequest("GET", "/settings", nil)
	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(401, resp.StatusCode)
}

func (suite *SettingsHandlerTestSuite) TestGetSettings_InvalidUserID() {
	app := fiber.New()
	app.Get("/settings", func(c *fiber.Ctx) error {
		c.Locals("user_id", "invalid-uuid")
		return suite.handler.GetSettings(c)
	})

	req := httptest.NewRequest("GET", "/settings", nil)
	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(400, resp.StatusCode)
}

func (suite *SettingsHandlerTestSuite) TestGetSettings_UserNotFound() {
	app := fiber.New()
	app.Get("/settings", func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.userID)
		return suite.handler.GetSettings(c)
	})

	mockRow := &MockRow{}
	suite.mockDB.On("QueryRow", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "SELECT") && contains(sql, "FROM users")
	}), suite.userID).Return(mockRow)

	mockRow.On("Scan", mock.Anything, mock.Anything, mock.Anything, mock.Anything,
		mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything,
		mock.Anything, mock.Anything).Return(sql.ErrNoRows)

	req := httptest.NewRequest("GET", "/settings", nil)
	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(404, resp.StatusCode)
}

func (suite *SettingsHandlerTestSuite) TestGetSettings_Success() {
	app := fiber.New()
	app.Get("/settings", func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.userID)
		return suite.handler.GetSettings(c)
	})

	mockRow := &MockRow{}
	suite.mockDB.On("QueryRow", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "SELECT") && contains(sql, "FROM users")
	}), suite.userID).Return(mockRow)

	mockRow.On("Scan", mock.Anything, mock.Anything, mock.Anything, mock.Anything,
		mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything,
		mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		if theme, ok := args[0].(*string); ok {
			*theme = "dark"
		}
		if autoSave, ok := args[1].(*bool); ok {
			*autoSave = true
		}
		if interval, ok := args[2].(*int); ok {
			*interval = 30
		}
		if view, ok := args[3].(*string); ok {
			*view = "list"
		}
		if notif, ok := args[4].(*bool); ok {
			*notif = true
		}
		if email, ok := args[5].(*bool); ok {
			*email = false
		}
		if enc, ok := args[6].(*bool); ok {
			*enc = true
		}
		if lang, ok := args[7].(*string); ok {
			*lang = "en"
		}
		if behavior, ok := args[8].(*string); ok {
			*behavior = "last-seen"
		}
		if ptype, ok := args[9].(*string); ok {
			*ptype = "gravatar"
		}
		if customURL, ok := args[10].(**string); ok {
			*customURL = nil
		}
	}).Return(nil)

	req := httptest.NewRequest("GET", "/settings", nil)
	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(200, resp.StatusCode)

	var settings UserSettings
	err = json.NewDecoder(resp.Body).Decode(&settings)
	suite.NoError(err)
	suite.Equal("dark", settings.Theme)
	suite.True(settings.AutoSave)
}

func (suite *SettingsHandlerTestSuite) TestUpdateSettings_Unauthorized() {
	app := fiber.New()
	app.Put("/settings", suite.handler.UpdateSettings)

	req := httptest.NewRequest("PUT", "/settings", bytes.NewBufferString(`{}`))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(401, resp.StatusCode)
}

func (suite *SettingsHandlerTestSuite) TestUpdateSettings_InvalidBody() {
	app := fiber.New()
	app.Put("/settings", func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.userID)
		return suite.handler.UpdateSettings(c)
	})

	req := httptest.NewRequest("PUT", "/settings", bytes.NewBufferString(`invalid json`))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(400, resp.StatusCode)
}

func (suite *SettingsHandlerTestSuite) TestUpdateSettings_Success() {
	app := fiber.New()
	app.Put("/settings", func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.userID)
		return suite.handler.UpdateSettings(c)
	})

	theme := "light"
	autoSave := true
	updateReq := map[string]interface{}{
		"theme":    &theme,
		"autoSave": &autoSave,
	}

	reqBody, _ := json.Marshal(updateReq)
	req := httptest.NewRequest("PUT", "/settings", bytes.NewBuffer(reqBody))
	req.Header.Set("Content-Type", "application/json")

	// Mock update query
	suite.mockDB.On("Exec",
		mock.Anything,
		mock.MatchedBy(func(sql string) bool {
			return contains(sql, "UPDATE users") && contains(sql, "SET")
		}),
		mock.AnythingOfType("string"),
		mock.AnythingOfType("bool"),
		mock.AnythingOfType("uuid.UUID"),
	).Return(int64(1), nil)

	// Mock get settings after update
	mockRow := &MockRow{}
	suite.mockDB.On("QueryRow", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return contains(sql, "SELECT") && contains(sql, "FROM users")
	}), suite.userID).Return(mockRow)

	mockRow.On("Scan", mock.Anything, mock.Anything, mock.Anything, mock.Anything,
		mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything,
		mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		if theme, ok := args[0].(*string); ok {
			*theme = "light"
		}
		if autoSave, ok := args[1].(*bool); ok {
			*autoSave = true
		}
		if interval, ok := args[2].(*int); ok {
			*interval = 30
		}
		if view, ok := args[3].(*string); ok {
			*view = "list"
		}
		if notif, ok := args[4].(*bool); ok {
			*notif = true
		}
		if email, ok := args[5].(*bool); ok {
			*email = false
		}
		if enc, ok := args[6].(*bool); ok {
			*enc = true
		}
		if lang, ok := args[7].(*string); ok {
			*lang = "en"
		}
		if behavior, ok := args[8].(*string); ok {
			*behavior = "last-seen"
		}
		if ptype, ok := args[9].(*string); ok {
			*ptype = "gravatar"
		}
		if customURL, ok := args[10].(**string); ok {
			*customURL = nil
		}
	}).Return(nil)

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(200, resp.StatusCode)

	var settings UserSettings
	err = json.NewDecoder(resp.Body).Decode(&settings)
	suite.NoError(err)
	suite.Equal("light", settings.Theme)
}

func (suite *SettingsHandlerTestSuite) TestUpdateSettings_UpdateError() {
	app := fiber.New()
	app.Put("/settings", func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.userID)
		return suite.handler.UpdateSettings(c)
	})

	theme := "light"
	updateReq := map[string]interface{}{
		"theme": &theme,
	}

	reqBody, _ := json.Marshal(updateReq)
	req := httptest.NewRequest("PUT", "/settings", bytes.NewBuffer(reqBody))
	req.Header.Set("Content-Type", "application/json")

	// Mock update query error
	suite.mockDB.On("Exec",
		mock.Anything,
		mock.MatchedBy(func(sql string) bool {
			return contains(sql, "UPDATE users")
		}),
		mock.AnythingOfType("string"),
		mock.AnythingOfType("uuid.UUID"),
	).Return(int64(0), assert.AnError)

	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(500, resp.StatusCode)
}

func TestSettingsHandlerTestSuite(t *testing.T) {
	suite.Run(t, new(SettingsHandlerTestSuite))
}
