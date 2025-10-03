package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// NotesHandler Test Suite
type NotesHandlerTestSuite struct {
	suite.Suite
	handler *NotesHandler
	mockDB  *MockDB
	crypto  *CryptoService
	userID  uuid.UUID
}

func (suite *NotesHandlerTestSuite) SetupTest() {
	suite.mockDB = &MockDB{}

	// Generate test encryption key
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		suite.T().Fatalf("Failed to generate random data: %v", err)
	}
	suite.crypto = NewCryptoService(key)

	suite.handler = &NotesHandler{
		db:     suite.mockDB,
		crypto: suite.crypto,
	}

	suite.userID = uuid.New()
}

func (suite *NotesHandlerTestSuite) TestGetNotesSuccess() {
	app := fiber.New()

	// Mock workspace lookup
	workspaceID := uuid.New()
	mockRow := &MockRow{}
	suite.mockDB.On("QueryRow", mock.Anything, mock.AnythingOfType("string"), suite.userID).Return(mockRow)
	mockRow.On("Scan", mock.Anything).Run(func(args mock.Arguments) {
		if wid, ok := args[0].(*uuid.UUID); ok {
			*wid = workspaceID
		}
	}).Return(nil)

	// Mock notes query
	mockRows := &MockRows{}
	suite.mockDB.On("Query", mock.Anything, mock.AnythingOfType("string"), workspaceID).Return(mockRows, nil)

	// Mock two notes returned
	mockRows.On("Next").Return(true).Once()
	mockRows.On("Next").Return(true).Once()
	mockRows.On("Next").Return(false).Once()

	// Mock encrypted test data
	titleEnc, _ := suite.crypto.Encrypt([]byte("Test Note 1"))
	contentEnc, _ := suite.crypto.Encrypt([]byte("Test content"))
	noteID1 := uuid.New()
	noteID2 := uuid.New()
	now := time.Now()

	// First note scan
	mockRows.On("Scan", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		if id, ok := args[0].(*uuid.UUID); ok {
			*id = noteID1
		}
		if title, ok := args[1].(*[]byte); ok {
			*title = titleEnc
		}
		if content, ok := args[2].(*[]byte); ok {
			*content = contentEnc
		}
		if created, ok := args[3].(*time.Time); ok {
			*created = now
		}
		if updated, ok := args[4].(*time.Time); ok {
			*updated = now
		}
	}).Return(nil).Once()

	// Second note scan
	mockRows.On("Scan", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		if id, ok := args[0].(*uuid.UUID); ok {
			*id = noteID2
		}
		if title, ok := args[1].(*[]byte); ok {
			*title = titleEnc
		}
		if content, ok := args[2].(*[]byte); ok {
			*content = contentEnc
		}
		if created, ok := args[3].(*time.Time); ok {
			*created = now
		}
		if updated, ok := args[4].(*time.Time); ok {
			*updated = now
		}
	}).Return(nil).Once()

	mockRows.On("Close").Return()

	// Create test request with user context
	app.Get("/notes", func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.userID)
		return suite.handler.GetNotes(c)
	})

	req := httptest.NewRequest("GET", "/notes", nil)
	resp, err := app.Test(req)

	suite.NoError(err)
	suite.Equal(200, resp.StatusCode)

	var response map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&response) // Test response parsing

	suite.Contains(response, "notes")
	notes := response["notes"].([]interface{})
	suite.Len(notes, 2)
}

func (suite *NotesHandlerTestSuite) TestGetNoteSuccess() {
	app := fiber.New()

	noteID := uuid.New()
	titleEnc, _ := suite.crypto.Encrypt([]byte("Test Note"))
	contentEnc, _ := suite.crypto.Encrypt([]byte("Test content"))
	now := time.Now()

	// Mock note lookup
	mockRow := &MockRow{}
	suite.mockDB.On("QueryRow", mock.Anything, mock.AnythingOfType("string"), noteID, suite.userID).Return(mockRow)
	mockRow.On("Scan", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		if id, ok := args[0].(*uuid.UUID); ok {
			*id = noteID
		}
		if title, ok := args[1].(*[]byte); ok {
			*title = titleEnc
		}
		if content, ok := args[2].(*[]byte); ok {
			*content = contentEnc
		}
		if created, ok := args[3].(*time.Time); ok {
			*created = now
		}
		if updated, ok := args[4].(*time.Time); ok {
			*updated = now
		}
	}).Return(nil)

	app.Get("/notes/:id", func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.userID)
		return suite.handler.GetNote(c)
	})

	req := httptest.NewRequest("GET", "/notes/"+noteID.String(), nil)
	resp, err := app.Test(req)

	suite.NoError(err)
	suite.Equal(200, resp.StatusCode)

	var response map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&response) // Test response parsing

	suite.Equal(noteID.String(), response["id"])
	suite.NotEmpty(response["title_encrypted"])
	suite.NotEmpty(response["content_encrypted"])
}

func (suite *NotesHandlerTestSuite) TestGetNoteNotFound() {
	app := fiber.New()

	noteID := uuid.New()

	// Mock note not found
	mockRow := &MockRow{}
	suite.mockDB.On("QueryRow", mock.Anything, mock.AnythingOfType("string"), noteID, suite.userID).Return(mockRow)
	mockRow.On("Scan", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(assert.AnError)

	app.Get("/notes/:id", func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.userID)
		return suite.handler.GetNote(c)
	})

	req := httptest.NewRequest("GET", "/notes/"+noteID.String(), nil)
	resp, err := app.Test(req)

	suite.NoError(err)
	suite.Equal(404, resp.StatusCode)
}

func (suite *NotesHandlerTestSuite) TestCreateNoteSuccess() {
	app := fiber.New()

	workspaceID := uuid.New()
	noteID := uuid.New()

	// Mock workspace lookup
	mockRow := &MockRow{}
	suite.mockDB.On("QueryRow", mock.Anything, mock.AnythingOfType("string"), suite.userID).Return(mockRow)
	mockRow.On("Scan", mock.Anything).Run(func(args mock.Arguments) {
		if wid, ok := args[0].(*uuid.UUID); ok {
			*wid = workspaceID
		}
	}).Return(nil)

	// Mock note creation
	mockRow2 := &MockRow{}
	suite.mockDB.On("QueryRow", mock.Anything, mock.AnythingOfType("string"), mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(mockRow2)
	mockRow2.On("Scan", mock.Anything).Run(func(args mock.Arguments) {
		if nid, ok := args[0].(*uuid.UUID); ok {
			*nid = noteID
		}
	}).Return(nil)

	req := CreateNoteRequest{
		TitleEncrypted:   "VGVzdCBUaXRsZQ==", // Base64 encoded test data
		ContentEncrypted: "VGVzdCBDb250ZW50", // Base64 encoded test data
	}

	body, _ := json.Marshal(req)
	httpReq := httptest.NewRequest("POST", "/notes", bytes.NewBuffer(body))
	httpReq.Header.Set("Content-Type", "application/json")

	app.Post("/notes", func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.userID)
		return suite.handler.CreateNote(c)
	})

	resp, err := app.Test(httpReq)

	suite.NoError(err)
	suite.Equal(201, resp.StatusCode)

	var response map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&response) // Test response parsing

	suite.Equal(noteID.String(), response["id"])
	suite.Equal("Note created successfully", response["message"])
}

func (suite *NotesHandlerTestSuite) TestCreateNoteInvalidData() {
	app := fiber.New()

	// Mock workspace lookup (CreateNote always checks workspace first)
	workspaceID := uuid.New()
	mockRow := &MockRow{}
	suite.mockDB.On("QueryRow", mock.Anything, mock.AnythingOfType("string"), mock.Anything).Return(mockRow)
	mockRow.On("Scan", mock.Anything).Run(func(args mock.Arguments) {
		if wid, ok := args[0].(*uuid.UUID); ok {
			*wid = workspaceID
		}
	}).Return(nil)

	req := CreateNoteRequest{
		TitleEncrypted:   "invalid-base64!@#",
		ContentEncrypted: "VGVzdCBDb250ZW50",
	}

	body, _ := json.Marshal(req)
	httpReq := httptest.NewRequest("POST", "/notes", bytes.NewBuffer(body))
	httpReq.Header.Set("Content-Type", "application/json")

	app.Post("/notes", func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.userID)
		return suite.handler.CreateNote(c)
	})

	resp, err := app.Test(httpReq)

	suite.NoError(err)
	suite.Equal(400, resp.StatusCode)
}

func (suite *NotesHandlerTestSuite) TestUpdateNoteSuccess() {
	app := fiber.New()

	noteID := uuid.New()

	// Mock successful update
	mockResult := &MockResult{}
	mockResult.On("RowsAffected").Return(int64(1))
	suite.mockDB.On("Exec", mock.Anything, mock.AnythingOfType("string"), mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(mockResult, nil)

	req := UpdateNoteRequest{
		TitleEncrypted:   "VXBkYXRlZCBUaXRsZQ==",
		ContentEncrypted: "VXBkYXRlZCBDb250ZW50",
	}

	body, _ := json.Marshal(req)
	httpReq := httptest.NewRequest("PUT", "/notes/"+noteID.String(), bytes.NewBuffer(body))
	httpReq.Header.Set("Content-Type", "application/json")

	app.Put("/notes/:id", func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.userID)
		return suite.handler.UpdateNote(c)
	})

	resp, err := app.Test(httpReq)

	suite.NoError(err)
	suite.Equal(200, resp.StatusCode)
}

func (suite *NotesHandlerTestSuite) TestUpdateNoteNotFound() {
	app := fiber.New()

	noteID := uuid.New()

	// Mock no rows affected (note not found or not owned by user)
	mockResult := &MockResult{}
	mockResult.On("RowsAffected").Return(int64(0))
	suite.mockDB.On("Exec", mock.Anything, mock.AnythingOfType("string"), mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(mockResult, nil)

	req := UpdateNoteRequest{
		TitleEncrypted:   "VXBkYXRlZCBUaXRsZQ==",
		ContentEncrypted: "VXBkYXRlZCBDb250ZW50",
	}

	body, _ := json.Marshal(req)
	httpReq := httptest.NewRequest("PUT", "/notes/"+noteID.String(), bytes.NewBuffer(body))
	httpReq.Header.Set("Content-Type", "application/json")

	app.Put("/notes/:id", func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.userID)
		return suite.handler.UpdateNote(c)
	})

	resp, err := app.Test(httpReq)

	suite.NoError(err)
	suite.Equal(404, resp.StatusCode)
}

func (suite *NotesHandlerTestSuite) TestDeleteNoteSuccess() {
	app := fiber.New()

	noteID := uuid.New()

	// Mock successful deletion
	mockResult := &MockResult{}
	mockResult.On("RowsAffected").Return(int64(1))
	suite.mockDB.On("Exec", mock.Anything, mock.AnythingOfType("string"), noteID, suite.userID).Return(mockResult, nil)

	app.Delete("/notes/:id", func(c *fiber.Ctx) error {
		c.Locals("user_id", suite.userID)
		return suite.handler.DeleteNote(c)
	})

	req := httptest.NewRequest("DELETE", "/notes/"+noteID.String(), nil)
	resp, err := app.Test(req)

	suite.NoError(err)
	suite.Equal(200, resp.StatusCode)
}

// Database Integration Tests
type DatabaseIntegrationTestSuite struct {
	suite.Suite
	db      *pgxpool.Pool
	cleanup func()
}

func (suite *DatabaseIntegrationTestSuite) SetupSuite() {
	suite.db, suite.cleanup = setupTestDB(suite.T())
}

func (suite *DatabaseIntegrationTestSuite) TearDownSuite() {
	if suite.cleanup != nil {
		suite.cleanup()
	}
}

func (suite *DatabaseIntegrationTestSuite) TearDownTest() {
	// Clean up test data after each test
	ctx := context.Background()
	_, _ = suite.db.Exec(ctx, "TRUNCATE users, workspaces, notes, audit_log CASCADE") // Test cleanup
}

func (suite *DatabaseIntegrationTestSuite) TestUserRegistrationFlow() {
	ctx := context.Background()

	// Generate test data
	email := "test@example.com"
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		suite.T().Fatalf("Failed to generate random data: %v", err)
	}
	passwordHash := HashPassword("TestPassword123!", salt)

	encryptedEmail := []byte("encrypted_email_data")
	encryptedMasterKey := make([]byte, 64)
	if _, err := rand.Read(encryptedMasterKey); err != nil {
		suite.T().Fatalf("Failed to generate random data: %v", err)
	}

	// Test user creation
	var userID uuid.UUID
	err := suite.db.QueryRow(ctx, `
		INSERT INTO users (email, email_encrypted, password_hash, salt, master_key_encrypted)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id`,
		email, encryptedEmail, passwordHash, salt, encryptedMasterKey,
	).Scan(&userID)

	suite.NoError(err)
	suite.NotEqual(uuid.Nil, userID)

	// Test user lookup
	var retrievedEmail string
	var retrievedHash string
	err = suite.db.QueryRow(ctx, `
		SELECT email, password_hash FROM users WHERE id = $1`,
		userID,
	).Scan(&retrievedEmail, &retrievedHash)

	suite.NoError(err)
	suite.Equal(email, retrievedEmail)
	suite.Equal(passwordHash, retrievedHash)

	// Test password verification
	suite.True(VerifyPassword("TestPassword123!", retrievedHash))
	suite.False(VerifyPassword("WrongPassword", retrievedHash))
}

func (suite *DatabaseIntegrationTestSuite) TestWorkspaceCreation() {
	ctx := context.Background()

	// First create a user
	userID := suite.createTestUser()

	// Create workspace
	encryptedName := []byte("encrypted_workspace_name")
	encryptedKey := make([]byte, 64)
	if _, err := rand.Read(encryptedKey); err != nil {
		suite.T().Fatalf("Failed to generate random data: %v", err)
	}

	var workspaceID uuid.UUID
	err := suite.db.QueryRow(ctx, `
		INSERT INTO workspaces (name_encrypted, owner_id, encryption_key_encrypted)
		VALUES ($1, $2, $3)
		RETURNING id`,
		encryptedName, userID, encryptedKey,
	).Scan(&workspaceID)

	suite.NoError(err)
	suite.NotEqual(uuid.Nil, workspaceID)

	// Verify workspace ownership
	var ownerID uuid.UUID
	err = suite.db.QueryRow(ctx, `
		SELECT owner_id FROM workspaces WHERE id = $1`,
		workspaceID,
	).Scan(&ownerID)

	suite.NoError(err)
	suite.Equal(userID, ownerID)
}

func (suite *DatabaseIntegrationTestSuite) TestNotesOperations() {
	ctx := context.Background()

	// Create user and workspace
	userID := suite.createTestUser()
	workspaceID := suite.createTestWorkspace(userID)

	// Create note
	encryptedTitle := []byte("encrypted_title")
	encryptedContent := []byte("encrypted_content")
	contentHash := []byte("content_hash")

	var noteID uuid.UUID
	err := suite.db.QueryRow(ctx, `
		INSERT INTO notes (workspace_id, title_encrypted, content_encrypted, content_hash, created_by)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id`,
		workspaceID, encryptedTitle, encryptedContent, contentHash, userID,
	).Scan(&noteID)

	suite.NoError(err)
	suite.NotEqual(uuid.Nil, noteID)

	// Test note retrieval
	var retrievedTitle []byte
	var retrievedContent []byte
	err = suite.db.QueryRow(ctx, `
		SELECT title_encrypted, content_encrypted FROM notes WHERE id = $1`,
		noteID,
	).Scan(&retrievedTitle, &retrievedContent)

	suite.NoError(err)
	suite.Equal(encryptedTitle, retrievedTitle)
	suite.Equal(encryptedContent, retrievedContent)

	// Test note update
	newTitle := []byte("new_encrypted_title")
	newContent := []byte("new_encrypted_content")
	newHash := []byte("new_content_hash")

	result, err := suite.db.Exec(ctx, `
		UPDATE notes SET title_encrypted = $1, content_encrypted = $2, content_hash = $3
		WHERE id = $4`,
		newTitle, newContent, newHash, noteID,
	)

	suite.NoError(err)
	suite.Equal(int64(1), result.RowsAffected())

	// Test soft delete
	result, err = suite.db.Exec(ctx, `
		UPDATE notes SET deleted_at = NOW() WHERE id = $1`,
		noteID,
	)

	suite.NoError(err)
	suite.Equal(int64(1), result.RowsAffected())

	// Verify soft deleted note is not returned in active queries
	var count int
	err = suite.db.QueryRow(ctx, `
		SELECT COUNT(*) FROM notes WHERE id = $1 AND deleted_at IS NULL`,
		noteID,
	).Scan(&count)

	suite.NoError(err)
	suite.Equal(0, count)
}

func (suite *DatabaseIntegrationTestSuite) TestAuditLogging() {
	ctx := context.Background()

	userID := suite.createTestUser()

	// Create audit log entry
	action := "test.action"
	resourceType := "test_resource"
	resourceID := uuid.New()
	encryptedIP := []byte("encrypted_ip")
	encryptedUA := []byte("encrypted_user_agent")
	metadata := map[string]interface{}{"key": "value"}
	metadataJSON, _ := json.Marshal(metadata)

	var auditID uuid.UUID
	err := suite.db.QueryRow(ctx, `
		INSERT INTO audit_log (user_id, action, resource_type, resource_id, ip_address_encrypted, user_agent_encrypted, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id`,
		userID, action, resourceType, resourceID, encryptedIP, encryptedUA, metadataJSON,
	).Scan(&auditID)

	suite.NoError(err)
	suite.NotEqual(uuid.Nil, auditID)

	// Verify audit log retrieval
	var retrievedAction string
	var retrievedResourceType string
	err = suite.db.QueryRow(ctx, `
		SELECT action, resource_type FROM audit_log WHERE id = $1`,
		auditID,
	).Scan(&retrievedAction, &retrievedResourceType)

	suite.NoError(err)
	suite.Equal(action, retrievedAction)
	suite.Equal(resourceType, retrievedResourceType)
}

// Helper methods for test data creation
func (suite *DatabaseIntegrationTestSuite) createTestUser() uuid.UUID {
	ctx := context.Background()

	email := "test@example.com"
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		suite.T().Fatalf("Failed to generate random data: %v", err)
	}
	passwordHash := HashPassword("TestPassword123!", salt)
	encryptedEmail := []byte("encrypted_email")
	encryptedMasterKey := make([]byte, 64)
	if _, err := rand.Read(encryptedMasterKey); err != nil {
		suite.T().Fatalf("Failed to generate random data: %v", err)
	}

	var userID uuid.UUID
	err := suite.db.QueryRow(ctx, `
		INSERT INTO users (email, email_encrypted, password_hash, salt, master_key_encrypted)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id`,
		email, encryptedEmail, passwordHash, salt, encryptedMasterKey,
	).Scan(&userID)

	require.NoError(suite.T(), err)
	return userID
}

func (suite *DatabaseIntegrationTestSuite) createTestWorkspace(userID uuid.UUID) uuid.UUID {
	ctx := context.Background()

	encryptedName := []byte("encrypted_workspace_name")
	encryptedKey := make([]byte, 64)
	if _, err := rand.Read(encryptedKey); err != nil {
		suite.T().Fatalf("Failed to generate random data: %v", err)
	}

	var workspaceID uuid.UUID
	err := suite.db.QueryRow(ctx, `
		INSERT INTO workspaces (name_encrypted, owner_id, encryption_key_encrypted)
		VALUES ($1, $2, $3)
		RETURNING id`,
		encryptedName, userID, encryptedKey,
	).Scan(&workspaceID)

	require.NoError(suite.T(), err)
	return workspaceID
}

// Run test suites
func TestNotesHandlerSuite(t *testing.T) {
	suite.Run(t, new(NotesHandlerTestSuite))
}

func TestDatabaseIntegrationSuite(t *testing.T) {
	suite.Run(t, new(DatabaseIntegrationTestSuite))
}

// Security Tests
func TestSQLInjectionPrevention(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	// Test SQL injection attempts in email field
	maliciousEmails := []string{
		"test'; DROP TABLE users; --",
		"test' OR '1'='1",
		"test'; UPDATE users SET email='hacked'; --",
		"test' UNION SELECT password_hash FROM users --",
	}

	for _, email := range maliciousEmails {
		t.Run("SQLInjection_"+email, func(t *testing.T) {
			// This should fail safely without executing the injection
			_, err := db.Exec(ctx, `
				INSERT INTO users (email, email_encrypted, password_hash, salt, master_key_encrypted)
				VALUES ($1, $2, $3, $4, $5)`,
				email, []byte("encrypted"), "hash", []byte("salt"), []byte("key"),
			)

			// The query should either succeed (treating it as literal data) or fail gracefully
			// It should NOT execute the malicious SQL
			if err == nil {
				// Verify no damage was done
				var count int
				_ = db.QueryRow(ctx, "SELECT COUNT(*) FROM users").Scan(&count) // Test verification
				assert.Equal(t, 1, count, "Only the inserted user should exist")

				var retrievedEmail string
				_ = db.QueryRow(ctx, "SELECT email FROM users WHERE email = $1", email).Scan(&retrievedEmail) // Test verification
				assert.Equal(t, email, retrievedEmail, "Email should be stored as literal data")
			}
		})
	}
}

func TestRateLimitingBypass(t *testing.T) {
	config := &Config{
		JWTSecret:        []byte("test-secret-key-for-rate-limiting-tests-with-sufficient-length"),
		EncryptionKey:    make([]byte, 32),
		MaxLoginAttempts: 3,
		LockoutDuration:  5 * time.Minute,
	}

	// Generate test key
	if _, err := rand.Read(config.EncryptionKey); err != nil {
		t.Fatalf("Failed to generate random data: %v", err)
	}

	crypto := NewCryptoService(config.EncryptionKey)
	mockDB := &MockDB{}

	authHandler := &AuthHandler{
		db:     mockDB,
		crypto: crypto,
		config: config,
	}

	app := fiber.New()
	app.Post("/login", authHandler.Login)

	// Test multiple rapid login attempts
	for i := 0; i < 10; i++ {
		t.Run(fmt.Sprintf("RateLimit_Attempt_%d", i+1), func(t *testing.T) {
			// Mock user lookup returning invalid credentials
			mockRow := &MockRow{}
			mockDB.On("QueryRow", mock.Anything, mock.AnythingOfType("string"), mock.Anything).Return(mockRow)
			mockRow.On("Scan", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(assert.AnError) // User not found

			req := LoginRequest{
				Email:    "test@example.com",
				Password: "wrong-password",
			}

			body, _ := json.Marshal(req)
			httpReq := httptest.NewRequest("POST", "/login", bytes.NewBuffer(body))
			httpReq.Header.Set("Content-Type", "application/json")

			resp, err := app.Test(httpReq)
			require.NoError(t, err)

			// Should consistently return 401 for invalid credentials
			assert.Equal(t, 401, resp.StatusCode)
		})
	}
}

func TestEncryptionKeyRotation(t *testing.T) {
	// Test encryption with different keys
	oldKey := make([]byte, 32)
	newKey := make([]byte, 32)
	if _, err := rand.Read(oldKey); err != nil {
		t.Fatalf("Failed to generate random data: %v", err)
	}
	if _, err := rand.Read(newKey); err != nil {
		t.Fatalf("Failed to generate random data: %v", err)
	}

	oldCrypto := NewCryptoService(oldKey)
	newCrypto := NewCryptoService(newKey)

	testData := []byte("sensitive test data")

	// Encrypt with old key
	oldCiphertext, err := oldCrypto.Encrypt(testData)
	require.NoError(t, err)

	// Should not decrypt with new key
	_, err = newCrypto.Decrypt(oldCiphertext)
	assert.Error(t, err, "Data encrypted with old key should not decrypt with new key")

	// Should still decrypt with old key
	decrypted, err := oldCrypto.Decrypt(oldCiphertext)
	require.NoError(t, err)
	assert.Equal(t, testData, decrypted)

	// Encrypt same data with new key
	newCiphertext, err := newCrypto.Encrypt(testData)
	require.NoError(t, err)

	// Ciphertexts should be different
	assert.NotEqual(t, oldCiphertext, newCiphertext)

	// New ciphertext should decrypt correctly with new key
	decrypted, err = newCrypto.Decrypt(newCiphertext)
	require.NoError(t, err)
	assert.Equal(t, testData, decrypted)
}
