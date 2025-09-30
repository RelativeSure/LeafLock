package database

import (
	"testing"
)

func TestDatabaseSchemaNotEmpty(t *testing.T) {
	if DatabaseSchema == "" {
		t.Error("DatabaseSchema should not be empty")
	}

	// Verify schema contains key table definitions
	tables := []string{
		"CREATE TABLE IF NOT EXISTS users",
		"CREATE TABLE IF NOT EXISTS notes",
		"CREATE TABLE IF NOT EXISTS workspaces",
		"CREATE TABLE IF NOT EXISTS audit_log",
		"CREATE TABLE IF NOT EXISTS folders",
		"CREATE TABLE IF NOT EXISTS tags",
		"CREATE TABLE IF NOT EXISTS templates",
	}

	for _, table := range tables {
		if !containsString(DatabaseSchema, table) {
			t.Errorf("DatabaseSchema should contain %s", table)
		}
	}
}

func TestMigrationSchemaVersionFormat(t *testing.T) {
	if MigrationSchemaVersion == "" {
		t.Error("MigrationSchemaVersion should not be empty")
	}

	// Check version format (YYYY.MM.DD.NNN)
	if len(MigrationSchemaVersion) < 10 {
		t.Errorf("MigrationSchemaVersion format unexpected: %s", MigrationSchemaVersion)
	}
}

func TestAdminURLAndDBName(t *testing.T) {
	tests := []struct {
		name           string
		dbURL          string
		expectedDBName string
		shouldContain  string
	}{
		{
			name:           "Standard PostgreSQL URL",
			dbURL:          "postgresql://user:pass@localhost:5432/mydb",
			expectedDBName: "mydb",
			shouldContain:  "/postgres",
		},
		{
			name:           "Postgres database",
			dbURL:          "postgresql://user:pass@localhost:5432/postgres",
			expectedDBName: "postgres",
			shouldContain:  "/postgres",
		},
		{
			name:           "URL with query parameters",
			dbURL:          "postgresql://user:pass@localhost:5432/mydb?sslmode=require",
			expectedDBName: "mydb",
			shouldContain:  "/postgres",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adminURL, dbName := adminURLAndDBName(tt.dbURL)

			if dbName != tt.expectedDBName {
				t.Errorf("Expected dbName %s, got %s", tt.expectedDBName, dbName)
			}

			if !containsString(adminURL, tt.shouldContain) {
				t.Errorf("Expected adminURL to contain %s, got %s", tt.shouldContain, adminURL)
			}
		})
	}
}

func TestSafePgIdent(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "Valid identifier",
			input:    "mydb",
			expected: true,
		},
		{
			name:     "Valid with underscores",
			input:    "my_database_name",
			expected: true,
		},
		{
			name:     "Valid with numbers",
			input:    "db123",
			expected: true,
		},
		{
			name:     "Invalid with dashes",
			input:    "my-database",
			expected: false,
		},
		{
			name:     "Invalid with spaces",
			input:    "my database",
			expected: false,
		},
		{
			name:     "Invalid with special chars",
			input:    "my$database",
			expected: false,
		},
		{
			name:     "SQL injection attempt",
			input:    "mydb; DROP TABLE users;",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, ok := safePgIdent(tt.input)

			if ok != tt.expected {
				t.Errorf("Expected safePgIdent(%s) to return %v, got %v", tt.input, tt.expected, ok)
			}

			if ok && result != tt.input {
				t.Errorf("Expected result %s, got %s", tt.input, result)
			}
		})
	}
}

func TestSchemaContainsIndexes(t *testing.T) {
	indexes := []string{
		"idx_users_email_search_hash",
		"idx_users_count_fast",
		"idx_users_admin_flag",
		"idx_notes_workspace",
		"idx_migrations_version",
		"idx_tags_user",
		"idx_folders_user",
	}

	for _, index := range indexes {
		if !containsString(DatabaseSchema, index) {
			t.Errorf("DatabaseSchema should contain index %s", index)
		}
	}
}

func TestSchemaContainsTriggers(t *testing.T) {
	triggers := []string{
		"update_users_updated_at",
		"update_notes_updated_at",
		"update_workspaces_updated_at",
		"update_tags_updated_at",
		"update_folders_updated_at",
		"update_templates_updated_at",
	}

	for _, trigger := range triggers {
		if !containsString(DatabaseSchema, trigger) {
			t.Errorf("DatabaseSchema should contain trigger %s", trigger)
		}
	}
}

func TestSchemaContainsExtensions(t *testing.T) {
	extensions := []string{
		"uuid-ossp",
		"pgcrypto",
		"pg_trgm",
	}

	for _, ext := range extensions {
		if !containsString(DatabaseSchema, ext) {
			t.Errorf("DatabaseSchema should contain extension %s", ext)
		}
	}
}

// Helper function
func containsString(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 &&
		(s == substr || len(s) >= len(substr) &&
		findSubstring(s, substr))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}