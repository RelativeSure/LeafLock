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

	handler := NewHandler(service, mockEmail)

	require.NotNil(t, handler)
	assert.Equal(t, service, handler.service)
	assert.Equal(t, mockEmail, handler.emailService)
}

func TestNewMFAManager(t *testing.T) {
	// Create mocks for dependencies
	// We can pass nil for the test since we're just testing the constructor
	manager := NewMFAManager(nil, nil)

	require.NotNil(t, manager)
	assert.Nil(t, manager.db)
	assert.Nil(t, manager.crypto)
}
