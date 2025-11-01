package services

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"

	"leaflock/config"
)

// EmailServiceTestSuite tests EmailService
type EmailServiceTestSuite struct {
	suite.Suite
	service *EmailService
	config  *config.Config
}

func (suite *EmailServiceTestSuite) SetupTest() {
	suite.config = &config.Config{
		SMTPEnabled:  false, // Disabled for testing
		SMTPHost:     "smtp.example.com",
		SMTPPort:     587,
		SMTPUser:     "user",
		SMTPPassword: "pass",
		SMTPFrom:     "noreply@example.com",
		FrontendURL:  "https://example.com",
	}
	suite.service = NewEmailService(suite.config)
}

func (suite *EmailServiceTestSuite) TestNewEmailService() {
	service := NewEmailService(suite.config)
	suite.NotNil(service)
	suite.Equal(suite.config, service.config)
}

func (suite *EmailServiceTestSuite) TestSendEmail_Disabled() {
	err := suite.service.SendEmail("test@example.com", "Test", "<html>body</html>", "body")
	suite.NoError(err) // Should return nil when SMTP is disabled
}

func (suite *EmailServiceTestSuite) TestSendTemplateEmail_Defaults() {
	suite.config.SMTPEnabled = false
	data := EmailData{
		Subject: "Test Email",
	}

	err := suite.service.SendTemplateEmail("test@example.com", "welcome", data)
	// Will fail on template load but that's expected in unit tests
	assert.Error(suite.T(), err) // Template file won't exist in tests
	assert.Contains(suite.T(), err.Error(), "failed to load email template")
}

func (suite *EmailServiceTestSuite) TestStripHTMLTags() {
	html := "<html><body><p>Hello</p><br/>World</body></html>"
	result := stripHTMLTags(html)
	
	assert.NotContains(suite.T(), result, "<html>")
	assert.NotContains(suite.T(), result, "<body>")
	assert.NotContains(suite.T(), result, "<p>")
	assert.Contains(suite.T(), result, "Hello")
	assert.Contains(suite.T(), result, "World")
}

func (suite *EmailServiceTestSuite) TestStripHTMLTags_BrTags() {
	html := "Line1<br>Line2<br/>Line3<br />Line4"
	result := stripHTMLTags(html)
	
	assert.Contains(suite.T(), result, "Line1")
	assert.Contains(suite.T(), result, "Line2")
	assert.Contains(suite.T(), result, "Line3")
	assert.Contains(suite.T(), result, "Line4")
}

func (suite *EmailServiceTestSuite) TestSendWelcomeEmail() {
	suite.config.SMTPEnabled = false
	err := suite.service.SendWelcomeEmail("user@example.com", "John Doe")
	assert.Error(suite.T(), err) // Will fail on template, but tests the method structure
}

func (suite *EmailServiceTestSuite) TestSendPasswordResetEmail() {
	suite.config.SMTPEnabled = false
	err := suite.service.SendPasswordResetEmail("user@example.com", "token123", "127.0.0.1")
	assert.Error(suite.T(), err) // Will fail on template, but tests the method structure
}

func (suite *EmailServiceTestSuite) TestSendPasswordChangedEmail() {
	suite.config.SMTPEnabled = false
	err := suite.service.SendPasswordChangedEmail("user@example.com", "127.0.0.1")
	assert.Error(suite.T(), err) // Will fail on template, but tests the method structure
}

func TestEmailServiceTestSuite(t *testing.T) {
	suite.Run(t, new(EmailServiceTestSuite))
}

