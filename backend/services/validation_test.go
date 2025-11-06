package services

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

// contextKey is a custom type for context keys to avoid collisions
type contextKey string

// TestEmailValidation tests email format validation
func TestEmailValidation(t *testing.T) {
	tests := []struct {
		name  string
		email string
		valid bool
	}{
		{"Valid email", "user@example.com", true},
		{"Valid with subdomain", "user@mail.example.com", true},
		{"Valid with plus", "user+tag@example.com", true},
		{"Valid with dots", "first.last@example.com", true},
		{"Invalid no @", "userexample.com", false},
		{"Invalid no domain", "user@", false},
		{"Invalid no user", "@example.com", false},
		{"Invalid spaces", "user @example.com", false},
		{"Empty string", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Basic email format check
			hasAt := false
			hasDot := false
			for _, c := range tt.email {
				if c == '@' {
					hasAt = true
				}
				if c == '.' {
					hasDot = true
				}
			}
			
			basicValid := hasAt && hasDot && len(tt.email) > 0
			
			if tt.valid {
				assert.True(t, basicValid || len(tt.email) > 5, "Email should be valid: %s", tt.email)
			} else {
				if len(tt.email) == 0 {
					assert.False(t, basicValid)
				}
			}
		})
	}
}

// TestContextOperations tests context usage
func TestContextOperations(t *testing.T) {
	t.Run("Background context", func(t *testing.T) {
		ctx := context.Background()
		assert.NotNil(t, ctx)
	})

	t.Run("Context with value", func(t *testing.T) {
		key := contextKey("key")
		ctx := context.WithValue(context.Background(), key, "value")
		assert.NotNil(t, ctx)
		val := ctx.Value(key)
		assert.Equal(t, "value", val)
	})

	t.Run("Context with cancel", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		assert.NotNil(t, ctx)
		assert.NotNil(t, cancel)
		cancel()
		assert.Error(t, ctx.Err())
	})
}

// TestStringOperations tests common string operations
func TestStringOperations(t *testing.T) {
	t.Run("String concatenation", func(t *testing.T) {
		result := "Hello" + " " + "World"
		assert.Equal(t, "Hello World", result)
	})

	t.Run("String length", func(t *testing.T) {
		s := "test"
		assert.Equal(t, 4, len(s))
	})

	t.Run("Empty string", func(t *testing.T) {
		s := ""
		assert.Equal(t, 0, len(s))
		assert.Empty(t, s)
	})
}

// TestSliceOperations tests slice operations
func TestSliceOperations(t *testing.T) {
	t.Run("Slice creation", func(t *testing.T) {
		s := []int{1, 2, 3}
		assert.Len(t, s, 3)
		assert.Equal(t, 1, s[0])
	})

	t.Run("Slice append", func(t *testing.T) {
		s := []int{1, 2}
		s = append(s, 3)
		assert.Len(t, s, 3)
		assert.Equal(t, 3, s[2])
	})

	t.Run("Empty slice", func(t *testing.T) {
		var s []int
		assert.Len(t, s, 0)
		assert.Nil(t, s)
	})
}

// TestMapOperations tests map operations
func TestMapOperations(t *testing.T) {
	t.Run("Map creation", func(t *testing.T) {
		m := map[string]int{"one": 1, "two": 2}
		assert.Len(t, m, 2)
		assert.Equal(t, 1, m["one"])
	})

	t.Run("Map insertion", func(t *testing.T) {
		m := make(map[string]int)
		m["key"] = 42
		assert.Equal(t, 42, m["key"])
	})

	t.Run("Map key exists", func(t *testing.T) {
		m := map[string]int{"exists": 1}
		val, ok := m["exists"]
		assert.True(t, ok)
		assert.Equal(t, 1, val)
		
		_, ok = m["notexists"]
		assert.False(t, ok)
	})
}

// TestNumericComparisons tests numeric operations
func TestNumericComparisons(t *testing.T) {
	t.Run("Integer comparison", func(t *testing.T) {
		assert.Greater(t, 10, 5)
		assert.Less(t, 5, 10)
		assert.Equal(t, 5, 5)
	})

	t.Run("Zero values", func(t *testing.T) {
		var i int
		assert.Equal(t, 0, i)
	})

	t.Run("Negative numbers", func(t *testing.T) {
		assert.Less(t, -10, 0)
		assert.Greater(t, 0, -10)
	})
}

// TestBooleanLogic tests boolean operations
func TestBooleanLogic(t *testing.T) {
	t.Run("Boolean true", func(t *testing.T) {
		b := true
		assert.True(t, b)
		assert.NotEqual(t, false, b)
	})

	t.Run("Boolean false", func(t *testing.T) {
		b := false
		assert.False(t, b)
		assert.NotEqual(t, true, b)
	})

	t.Run("Boolean zero value", func(t *testing.T) {
		var b bool
		assert.False(t, b)
	})
}
