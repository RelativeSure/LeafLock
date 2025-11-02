package database

import "testing"

func TestAdminURLAndDBNameRewrite(t *testing.T) {
	adminURL, dbName := adminURLAndDBName("postgres://user:pass@localhost:5432/appdb?sslmode=disable")
	if dbName != "appdb" {
		t.Fatalf("expected db name appdb, got %s", dbName)
	}
	if adminURL != "postgres://user:pass@localhost:5432/postgres?sslmode=disable" {
		t.Fatalf("unexpected admin URL: %s", adminURL)
	}

}

func TestSafePgIdentValidation(t *testing.T) {
	name, ok := safePgIdent("valid_name123")
	if !ok || name != "valid_name123" {
		t.Fatalf("expected identifier to be valid, got %s, ok=%v", name, ok)
	}

	if _, ok := safePgIdent("invalid-name"); ok {
		t.Fatal("expected identifier with dash to be invalid")
	}
}
