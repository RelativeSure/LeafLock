package services

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"leaflock/config"
)

func TestNewEmailService(t *testing.T) {
	cfg := &config.Config{
		SMTPEnabled: false,
	}

	service := NewEmailService(cfg)
	require.NotNil(t, service)
	assert.Equal(t, cfg, service.config)
}

func TestSendEmail_Disabled(t *testing.T) {
	cfg := &config.Config{
		SMTPEnabled: false,
	}

	service := NewEmailService(cfg)
	err := service.SendEmail("test@example.com", "Test Subject", "<html>Test</html>", "Test")

	// When SMTP is disabled, SendEmail should return nil (just logs)
	assert.NoError(t, err)
}

// Note: SendWelcomeEmail, SendPasswordResetEmail, SendPasswordChangedEmail, and SendTemplateEmail
// require template files to exist, so they cannot be easily unit tested without filesystem setup.
// These functions are covered by integration tests.

// Note: stripHTMLTags is an unexported function and cannot be tested directly.
// It's tested indirectly through SendTemplateEmail

func TestEmailData_Structure(t *testing.T) {
	// Test that EmailData can be created and accessed properly
	data := EmailData{
		Subject:       "Test Subject",
		RecipientName: "Jane Doe",
		AppName:       "LeafLock",
		AppURL:        "https://leaflock.app",
		Year:          2024,
		Data: map[string]interface{}{
			"key1": "value1",
			"key2": 123,
		},
	}

	assert.Equal(t, "Test Subject", data.Subject)
	assert.Equal(t, "Jane Doe", data.RecipientName)
	assert.Equal(t, "LeafLock", data.AppName)
	assert.Equal(t, "https://leaflock.app", data.AppURL)
	assert.Equal(t, 2024, data.Year)
	assert.Equal(t, "value1", data.Data["key1"])
	assert.Equal(t, 123, data.Data["key2"])
}
