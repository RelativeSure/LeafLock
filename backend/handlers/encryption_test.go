package handlers

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDefaultEncryptionVersion(t *testing.T) {
	assert.Equal(t, 1, defaultEncryptionVersion, "Default encryption version should be 1")
}

