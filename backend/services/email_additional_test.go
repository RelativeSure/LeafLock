package services

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"leaflock/config"
)

// ensureBackendRoot makes the templates directory available to tests that execute template-based emails.
func ensureBackendRoot(t *testing.T) {
	t.Helper()

	cwd, err := os.Getwd()
	require.NoError(t, err)

	backendRoot := filepath.Clean(filepath.Join(cwd, ".."))
	require.NoError(t, os.Chdir(backendRoot))

	t.Cleanup(func() {
		_ = os.Chdir(cwd)
	})
}

// TestSendWelcomeEmail_Disabled tests SendWelcomeEmail when SMTP is disabled
func TestSendWelcomeEmail_Disabled(t *testing.T) {
	ensureBackendRoot(t)

	cfg := &config.Config{
		SMTPEnabled: false,
	}
	service := NewEmailService(cfg)

	err := service.SendWelcomeEmail("test@example.com", "Test User")
	assert.NoError(t, err) // Should succeed (no-op)
}

// TestSendPasswordResetEmail_Disabled tests SendPasswordResetEmail when SMTP is disabled
func TestSendPasswordResetEmail_Disabled(t *testing.T) {
	ensureBackendRoot(t)

	cfg := &config.Config{
		SMTPEnabled: false,
	}
	service := NewEmailService(cfg)

	err := service.SendPasswordResetEmail("test@example.com", "Test User", "https://example.com/reset")
	assert.NoError(t, err) // Should succeed (no-op)
}

// TestSendPasswordChangedEmail_Disabled tests SendPasswordChangedEmail when SMTP is disabled
func TestSendPasswordChangedEmail_Disabled(t *testing.T) {
	ensureBackendRoot(t)

	cfg := &config.Config{
		SMTPEnabled: false,
	}
	service := NewEmailService(cfg)

	err := service.SendPasswordChangedEmail("test@example.com", "Test User")
	assert.NoError(t, err) // Should succeed (no-op)
}

// TestSendTemplateEmail_Disabled tests SendTemplateEmail when SMTP is disabled
func TestSendTemplateEmail_Disabled(t *testing.T) {
	ensureBackendRoot(t)

	cfg := &config.Config{
		SMTPEnabled: false,
	}
	service := NewEmailService(cfg)

	data := EmailData{
		Subject:       "Test Subject",
		RecipientName: "Test User",
	}

	err := service.SendTemplateEmail("test@example.com", "welcome", data)
	assert.NoError(t, err) // Should succeed (no-op)
}

// TestSendEmail_InvalidConfig tests SendEmail with missing config
func TestSendEmail_InvalidConfig(t *testing.T) {
	cfg := &config.Config{
		SMTPEnabled: true,
		SMTPHost:    "", // Empty host
		SMTPPort:    587,
		SMTPFrom:    "test@example.com",
	}
	service := NewEmailService(cfg)

	err := service.SendEmail("to@example.com", "Subject", "Body", "text/plain")
	assert.Error(t, err) // Should fail with invalid config
}

// TestEmailService_Constructor tests NewEmailService
func TestEmailService_Constructor(t *testing.T) {
	cfg := &config.Config{
		SMTPEnabled: true,
		SMTPHost:    "smtp.example.com",
		SMTPPort:    587,
	}
	service := NewEmailService(cfg)

	require.NotNil(t, service)
	assert.Equal(t, cfg, service.config)
}

// TestEmailService_ConstructorNilConfig tests NewEmailService with nil config
func TestEmailService_ConstructorNilConfig(t *testing.T) {
	service := NewEmailService(nil)
	require.NotNil(t, service)
	assert.Nil(t, service.config)
}
