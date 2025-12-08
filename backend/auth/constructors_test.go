package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test constructor functions that are currently at 0% coverage

// MockEmailService is a mock email service for testing
type MockEmailServiceConstructor struct{}

func (m *MockEmailServiceConstructor) SendPasswordResetEmail(toEmail string, resetToken string, ipAddress string) error {
	return nil
}

func TestNewHandler(t *testing.T) {
	// Create a mock service (nil is fine for constructor test)
	var service *Service
	mockEmail := &MockEmailServiceConstructor{}
	config := LoadConfig()

	handler := NewHandler(service, mockEmail, config)

	require.NotNil(t, handler)
	assert.Equal(t, service, handler.service)
	assert.Equal(t, mockEmail, handler.emailService)
	assert.Equal(t, config, handler.config)
}

func TestNewMFAManager(t *testing.T) {
	// Create mocks for dependencies
	// We can pass nil for the test since we're just testing the constructor
	manager := NewMFAManager(nil, nil)

	require.NotNil(t, manager)
	assert.Nil(t, manager.db)
	assert.Nil(t, manager.crypto)
}
