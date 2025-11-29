package auth

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	appcrypto "leaflock/crypto"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

func withDebugEnv(t *testing.T, token string, fn func()) {
	t.Helper()
	original := map[string]string{
		"ENVIRONMENT":         os.Getenv("ENVIRONMENT"),
		"APP_ENV":             os.Getenv("APP_ENV"),
		"RAILWAY_ENVIRONMENT": os.Getenv("RAILWAY_ENVIRONMENT"),
		"NODE_ENV":            os.Getenv("NODE_ENV"),
		"DEBUG_TOKEN":         os.Getenv("DEBUG_TOKEN"),
	}
	for key := range original {
		_ = os.Unsetenv(key)
	}
	if token != "" {
		_ = os.Setenv("DEBUG_TOKEN", token)
	}
	defer func() {
		for key, val := range original {
			if val == "" {
				_ = os.Unsetenv(key)
			} else {
				_ = os.Setenv(key, val)
			}
		}
	}()
	fn()
}

func TestDebugLoginReturnsUserInfo(t *testing.T) {
	withDebugEnv(t, "dev-token", func() {
		email := "user@example.com"
		password := "ValidPass123!"
		crypto := appcrypto.NewCryptoService(make([]byte, 32))
		db := &mockServiceDB{}
		service := &Service{
			db:        db,
			session:   &mockSessionManager{},
			password:  NewPasswordManager(db),
			mfa:       NewMFAManager(db, crypto),
			
		}

		salt, err := service.password.GenerateSalt()
		if err != nil {
			t.Fatalf("failed to generate salt: %v", err)
		}
		passwordHash := service.password.HashPassword(password, salt)
		userID := uuid.New()
		createdAt := time.Now().UTC().Add(-time.Hour)

		db.queryRowFuncs = []func(dest ...interface{}) error{
			func(dest ...interface{}) error {
				if len(dest) != 9 {
					t.Fatalf("unexpected dest count: %d", len(dest))
				}
				if v, ok := dest[0].(*uuid.UUID); ok {
					*v = userID
				}
				if v, ok := dest[1].(*string); ok {
					*v = passwordHash
				}
				if v, ok := dest[2].(*[]byte); ok {
					*v = salt
				}
				if v, ok := dest[3].(*bool); ok {
					*v = false
				}
				if v, ok := dest[4].(*[]byte); ok {
					*v = []byte("secret")
				}
				if v, ok := dest[5].(*int); ok {
					*v = 0
				}
				if v, ok := dest[6].(**time.Time); ok {
					*v = nil
				}
				if v, ok := dest[7].(*bool); ok {
					*v = true
				}
				if v, ok := dest[8].(*time.Time); ok {
					*v = createdAt
				}
				return nil
			},
		}

		handler := NewHandler(service, &MockEmailService{})
		app := fiber.New()
		app.Post("/debug-login", handler.DebugLogin)

		body := AuthRequest{Email: email, Password: password}
		payload, _ := json.Marshal(body)
		req := httptest.NewRequest("POST", "/debug-login", bytes.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Debug-Token", "dev-token")

		resp, err := app.Test(req, -1)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		if resp.StatusCode != 200 {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}

		var debugResp map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&debugResp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		if debugResp["user_found"] != true {
			t.Fatalf("expected user_found true, got %v", debugResp["user_found"])
		}
		if debugResp["password_valid"] != true {
			t.Fatalf("expected password_valid true, got %v", debugResp["password_valid"])
		}
	})
}

func TestDebugAdminInfoDecryptsEmail(t *testing.T) {
	withDebugEnv(t, "dev-token", func() {
		crypto := appcrypto.NewCryptoService(make([]byte, 32))
		db := &mockServiceDB{}
		service := &Service{
			db:        db,
			session:   &mockSessionManager{},
			password:  NewPasswordManager(db),
			mfa:       NewMFAManager(db, crypto),
			
		}

		email := "admin@example.com"
		adminID := uuid.New()
		createdAt := time.Now().UTC().Add(-time.Hour)
		lastLogin := time.Now().UTC()

		db.queryRowFuncs = []func(dest ...interface{}) error{
			func(dest ...interface{}) error {
				if len(dest) != 5 {
					t.Fatalf("unexpected dest count: %d", len(dest))
				}
				if v, ok := dest[0].(*uuid.UUID); ok {
					*v = adminID
				}
				// Zero-knowledge: email_plaintext field is a string (no encryption)
				if v, ok := dest[1].(*string); ok {
					*v = email
				}
				if v, ok := dest[2].(*bool); ok {
					*v = true
				}
				if v, ok := dest[3].(*time.Time); ok {
					*v = createdAt
				}
				if v, ok := dest[4].(**time.Time); ok {
					*v = &lastLogin
				}
				return nil
			},
		}

		handler := NewHandler(service, &MockEmailService{})
		app := fiber.New()
		app.Get("/debug-admin", handler.DebugAdminInfo)

		req := httptest.NewRequest("GET", "/debug-admin", nil)
		req.Header.Set("X-Debug-Token", "dev-token")

		resp, err := app.Test(req, -1)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		if resp.StatusCode != 200 {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}

		var body map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		if body["email"] != email {
			t.Fatalf("expected plaintext email %s, got %v", email, body["email"])
		}
	})
}

func TestDebugEncryptionKeyRoundTrip(t *testing.T) {
	withDebugEnv(t, "dev-token", func() {
		crypto := appcrypto.NewCryptoService(make([]byte, 32))
		service := &Service{
			db:        &mockServiceDB{},
			session:   &mockSessionManager{},
			password:  NewPasswordManager(&mockServiceDB{}),
			mfa:       NewMFAManager(&mockServiceDB{}, crypto),
			
		}
		handler := NewHandler(service, &MockEmailService{})
		app := fiber.New()
		app.Get("/debug-encryption", handler.DebugEncryptionKey)

		req := httptest.NewRequest("GET", "/debug-encryption", nil)
		req.Header.Set("X-Debug-Token", "dev-token")

		resp, err := app.Test(req, -1)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		if resp.StatusCode != 200 {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}

		var body map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		// Zero-knowledge architecture response
		if body["encryption_architecture"] != "zero-knowledge" {
			t.Fatalf("expected zero-knowledge architecture, got %v", body["encryption_architecture"])
		}
		if body["mfa_encryption"] == nil {
			t.Fatalf("expected mfa_encryption field to exist")
		}
	})
}
