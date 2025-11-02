package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test constructor functions that are currently at 0% coverage

func TestNewHandler(t *testing.T) {
	// Create a mock service (nil is fine for constructor test)
	var service *Service

	handler := NewHandler(service)

	require.NotNil(t, handler)
	assert.Equal(t, service, handler.service)
}

func TestNewMFAManager(t *testing.T) {
	// Create mocks for dependencies
	// We can pass nil for the test since we're just testing the constructor
	manager := NewMFAManager(nil, nil)

	require.NotNil(t, manager)
	assert.Nil(t, manager.db)
	assert.Nil(t, manager.crypto)
}
