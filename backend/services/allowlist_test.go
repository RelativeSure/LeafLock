package services

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCurrentAllowlist_New(t *testing.T) {
	allowlist := CurrentAllowlist()
	assert.NotNil(t, allowlist)
	assert.IsType(t, map[string]struct{}{}, allowlist)
}

func TestIsUserInAdminAllowlist_NotInList(t *testing.T) {
	result := IsUserInAdminAllowlist("user-123")
	assert.False(t, result)
}

func TestIsUserInAdminAllowlist_FromEnv(t *testing.T) {
	// Set environment variable
	originalEnv := os.Getenv("ADMIN_USER_IDS")
	defer func() { _ = os.Setenv("ADMIN_USER_IDS", originalEnv) }()

	_ = os.Setenv("ADMIN_USER_IDS", "admin-1,admin-2,admin-3")

	result := IsUserInAdminAllowlist("admin-2")
	assert.True(t, result)

	result = IsUserInAdminAllowlist("admin-4")
	assert.False(t, result)
}

func TestIsUserInAdminAllowlist_TrimmedSpaces(t *testing.T) {
	originalEnv := os.Getenv("ADMIN_USER_IDS")
	defer func() { _ = os.Setenv("ADMIN_USER_IDS", originalEnv) }()

	_ = os.Setenv("ADMIN_USER_IDS", " admin-1 , admin-2 ")

	result := IsUserInAdminAllowlist("admin-1")
	assert.True(t, result)

	result = IsUserInAdminAllowlist("admin-2")
	assert.True(t, result)
}

func TestLoadAllowlistFromSources_EnvOnly(t *testing.T) {
	allowlist, signature := LoadAllowlistFromSources("user1,user2,user3", "")

	assert.Equal(t, 3, len(allowlist))
	assert.Contains(t, allowlist, "user1")
	assert.Contains(t, allowlist, "user2")
	assert.Contains(t, allowlist, "user3")
	assert.Contains(t, signature, "ENV:")
}

func TestLoadAllowlistFromSources_EmptyEnv(t *testing.T) {
	allowlist, _ := LoadAllowlistFromSources("", "")
	assert.Equal(t, 0, len(allowlist))
}

func TestLoadAllowlistFromSources_WithSpaces(t *testing.T) {
	allowlist, _ := LoadAllowlistFromSources(" user1 , user2 , user3 ", "")

	assert.Equal(t, 3, len(allowlist))
	assert.Contains(t, allowlist, "user1")
	assert.Contains(t, allowlist, "user2")
	assert.Contains(t, allowlist, "user3")
}

func TestLoadAllowlistFromSources_EmptyValues(t *testing.T) {
	allowlist, _ := LoadAllowlistFromSources("user1,,user2,", "")

	assert.Equal(t, 2, len(allowlist))
	assert.Contains(t, allowlist, "user1")
	assert.Contains(t, allowlist, "user2")
	assert.NotContains(t, allowlist, "")
}
