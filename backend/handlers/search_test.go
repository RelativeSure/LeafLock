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
	suite.handler = NewSearchHandler()
}

func (suite *SearchHandlerTestSuite) TestNewSearchHandler() {
	handler := NewSearchHandler()
	suite.NotNil(handler)
}

func (suite *SearchHandlerTestSuite) TestSearchNotes_NotImplemented() {
	app := fiber.New()
	app.Get("/search", suite.handler.SearchNotes)

	req := httptest.NewRequest("GET", "/search", nil)
	resp, err := app.Test(req)
	suite.NoError(err)
	suite.Equal(501, resp.StatusCode) // StatusNotImplemented

	var result map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	suite.NoError(err)
	suite.Equal("SearchDisabled", result["error"])
	suite.Contains(result["message"], "Server-side search is disabled")
}

func TestSearchHandlerTestSuite(t *testing.T) {
	suite.Run(t, new(SearchHandlerTestSuite))
}
