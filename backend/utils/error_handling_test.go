package utils

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestErrorCreation tests error creation and handling
func TestErrorCreation(t *testing.T) {
	t.Run("Create new error", func(t *testing.T) {
		err := errors.New("test error")
		assert.Error(t, err)
		assert.Equal(t, "test error", err.Error())
	})

	t.Run("Nil error", func(t *testing.T) {
		var err error
		assert.NoError(t, err)
		assert.Nil(t, err)
	})

	t.Run("Error wrapping", func(t *testing.T) {
		base := errors.New("base error")
		wrapped := errors.Join(base, errors.New("wrapped"))
		assert.Error(t, wrapped)
		assert.Contains(t, wrapped.Error(), "base error")
	})
}

// TestErrorComparison tests error comparison
func TestErrorComparison(t *testing.T) {
	err1 := errors.New("error 1")
	err2 := errors.New("error 2")

	t.Run("Different errors", func(t *testing.T) {
		assert.NotEqual(t, err1, err2)
	})

	t.Run("Same error instance", func(t *testing.T) {
		assert.Equal(t, err1, err1)
	})

	t.Run("Nil comparison", func(t *testing.T) {
		var err error
		assert.Nil(t, err)
		assert.NotEqual(t, err1, err)
	})
}

// TestErrorMessages tests error message handling
func TestErrorMessages(t *testing.T) {
	tests := []struct {
		name    string
		message string
		empty   bool
	}{
		{"With message", "Something went wrong", false},
		{"Empty message", "", true},
		{"Whitespace only", "   ", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := errors.New(tt.message)
			if tt.empty {
				assert.Equal(t, "", err.Error())
			} else {
				assert.NotEmpty(t, err.Error())
			}
		})
	}
}
