package handlers

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/suite"
)

// SearchHandlerTestSuite tests SearchHandler
type SearchHandlerTestSuite struct {
	suite.Suite
	handler *SearchHandler
}

func (suite *SearchHandlerTestSuite) SetupTest() {
	suite.handler = NewSearchHandler(nil)
}

func (suite *SearchHandlerTestSuite) TestNewSearchHandler() {
	handler := NewSearchHandler(nil)
	suite.NotNil(handler)
}

func (suite *SearchHandlerTestSuite) TestSearchNotes_InvalidRequest() {
	app := fiber.New()
	app.Post("/search", func(c *fiber.Ctx) error {
		c.Locals("user_id", "test-user-id")
		return suite.handler.SearchNotes(c)
	})

	req := httptest.NewRequest("POST", "/search", nil)
	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(400, resp.StatusCode) // Bad Request

	var result map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	suite.NoError(err)
	suite.Equal("Invalid request body", result["error"])
}

func TestSearchHandlerTestSuite(t *testing.T) {
	suite.Run(t, new(SearchHandlerTestSuite))
}
