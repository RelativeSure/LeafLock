package handlers

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"leaflock/crypto"
)

func TestNotesHandler_GetNotesSuccess(t *testing.T) {
	mockDB := new(MockDB)
	handler := NewNotesHandler(mockDB, crypto.NewCryptoService(make([]byte, 32)))

	userID := uuid.New()
	workspaceID := uuid.New()
	noteID := uuid.New()
	now := time.Now().UTC()

	workspaceRow := new(MockRow)
	workspaceRow.
		On("Scan", mock.AnythingOfType("*uuid.UUID")).
		Run(func(args mock.Arguments) {
			dest := args[0].(*uuid.UUID)
			*dest = workspaceID
		}).
		Return(nil)

	mockDB.
		On("QueryRow",
			mock.Anything,
			"SELECT id FROM workspaces WHERE owner_id = $1 LIMIT 1",
			userID,
		).
		Return(workspaceRow).
		Once()

	mockRows := new(MockRows)
	mockRows.
		On("Next").
		Return(true).
		Once()
	mockRows.
		On("Next").
		Return(false).
		Once()
	mockRows.
		On("Scan",
			mock.AnythingOfType("*uuid.UUID"),
			mock.AnythingOfType("*[]uint8"),
			mock.AnythingOfType("*[]uint8"),
			mock.AnythingOfType("*time.Time"),
			mock.AnythingOfType("*time.Time"),
			mock.AnythingOfType("*bool"),
			mock.AnythingOfType("*bool"),
			mock.AnythingOfType("**uuid.UUID"),
			mock.AnythingOfType("*int"),
		).
		Run(func(args mock.Arguments) {
			*args[0].(*uuid.UUID) = noteID
			*args[1].(*[]byte) = []byte("title-bytes")
			*args[2].(*[]byte) = []byte("content-bytes")
			*args[3].(*time.Time) = now.Add(-time.Hour)
			*args[4].(*time.Time) = now
			*args[5].(*bool) = false
			*args[6].(*bool) = false
			*args[7].(**uuid.UUID) = nil
			*args[8].(*int) = 0
		}).
		Return(nil)

	mockDB.
		On("Query",
			mock.Anything,
			mock.MatchedBy(func(query string) bool {
				return strings.Contains(query, "FROM notes")
			}),
			workspaceID,
		).
		Return(mockRows, nil).
		Once()

	app := fiber.New()
	app.Get("/", func(c *fiber.Ctx) error {
		c.Locals("user_id", userID)
		return handler.GetNotes(c)
	})

	resp, err := app.Test(httptest.NewRequest("GET", "/", nil))
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	var body map[string][]map[string]interface{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	require.Len(t, body["notes"], 1)

	note := body["notes"][0]
	assert.Equal(t, noteID.String(), note["id"].(string))
	assert.Equal(t, base64.StdEncoding.EncodeToString([]byte("title-bytes")), note["title_encrypted"])
	assert.Equal(t, base64.StdEncoding.EncodeToString([]byte("content-bytes")), note["content_encrypted"])

	mockDB.AssertExpectations(t)
	mockRows.AssertExpectations(t)
}

func TestNotesHandler_CreateNote_InvalidTitleEncoding(t *testing.T) {
	mockDB := new(MockDB)
	handler := NewNotesHandler(mockDB, crypto.NewCryptoService(make([]byte, 32)))

	userID := uuid.New()
	workspaceID := uuid.New()

	workspaceRow := new(MockRow)
	workspaceRow.
		On("Scan", mock.AnythingOfType("*uuid.UUID")).
		Run(func(args mock.Arguments) {
			dest := args[0].(*uuid.UUID)
			*dest = workspaceID
		}).
		Return(nil)

	mockDB.
		On("QueryRow",
			mock.Anything,
			"SELECT id FROM workspaces WHERE owner_id = $1 LIMIT 1",
			userID,
		).
		Return(workspaceRow).
		Once()

	app := fiber.New()
	app.Post("/", func(c *fiber.Ctx) error {
		c.Locals("user_id", userID)
		return handler.CreateNote(c)
	})

	payload := map[string]interface{}{
		"title_encrypted":   "!!!notbase64",
		"content_encrypted": base64.StdEncoding.EncodeToString([]byte("content")),
	}
	body, err := json.Marshal(payload)
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)

	mockDB.AssertExpectations(t)
}

func TestNotesHandler_CreateNoteSuccess(t *testing.T) {
	mockDB := new(MockDB)
	handler := NewNotesHandler(mockDB, crypto.NewCryptoService(make([]byte, 32)))

	userID := uuid.New()
	workspaceID := uuid.New()
	noteID := uuid.New()
	createdAt := time.Now().UTC().Add(-2 * time.Hour)
	updatedAt := time.Now().UTC()

	workspaceRow := new(MockRow)
	workspaceRow.
		On("Scan", mock.AnythingOfType("*uuid.UUID")).
		Run(func(args mock.Arguments) {
			dest := args[0].(*uuid.UUID)
			*dest = workspaceID
		}).
		Return(nil)

	mockDB.
		On("QueryRow",
			mock.Anything,
			"SELECT id FROM workspaces WHERE owner_id = $1 LIMIT 1",
			userID,
		).
		Return(workspaceRow).
		Once()

	insertRow := new(MockRow)
	insertRow.
		On("Scan",
			mock.AnythingOfType("*uuid.UUID"),
			mock.AnythingOfType("*time.Time"),
			mock.AnythingOfType("*time.Time"),
		).
		Run(func(args mock.Arguments) {
			*args[0].(*uuid.UUID) = noteID
			*args[1].(*time.Time) = createdAt
			*args[2].(*time.Time) = updatedAt
		}).
		Return(nil)

	mockDB.
		On("QueryRow",
			mock.Anything,
			mock.MatchedBy(func(query string) bool {
				return strings.Contains(query, "INSERT INTO notes")
			}),
			mock.Anything, mock.Anything, mock.Anything, mock.Anything, userID, mock.Anything, mock.Anything,
		).
		Return(insertRow).
		Once()

	app := fiber.New()
	app.Post("/", func(c *fiber.Ctx) error {
		c.Locals("user_id", userID)
		return handler.CreateNote(c)
	})

	payload := map[string]interface{}{
		"title_encrypted":    base64.StdEncoding.EncodeToString([]byte("title")),
		"content_encrypted":  base64.StdEncoding.EncodeToString([]byte("content")),
		"encryption_version": 0,
	}
	body, err := json.Marshal(payload)
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusCreated, resp.StatusCode)

	var response struct {
		Note map[string]interface{} `json:"note"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&response))
	assert.Equal(t, noteID.String(), response.Note["id"])
	assert.Equal(t, base64.StdEncoding.EncodeToString([]byte("title")), response.Note["title_encrypted"])
	assert.Equal(t, base64.StdEncoding.EncodeToString([]byte("content")), response.Note["content_encrypted"])
	assert.EqualValues(t, defaultEncryptionVersion, response.Note["encryption_version"])

	mockDB.AssertExpectations(t)
}

func TestNotesHandler_GetNoteNotFound(t *testing.T) {
	mockDB := new(MockDB)
	handler := NewNotesHandler(mockDB, crypto.NewCryptoService(make([]byte, 32)))

	userID := uuid.New()
	noteID := uuid.New()

	row := new(MockRow)
	row.
		On("Scan",
			mock.AnythingOfType("*uuid.UUID"),
			mock.AnythingOfType("*[]uint8"),
			mock.AnythingOfType("*[]uint8"),
			mock.AnythingOfType("*time.Time"),
			mock.AnythingOfType("*time.Time"),
		).
		Return(pgx.ErrNoRows)

	mockDB.
		On("QueryRow",
			mock.Anything,
			mock.MatchedBy(func(query string) bool {
				return strings.Contains(query, "FROM notes n")
			}),
			noteID,
			userID,
		).
		Return(row).
		Once()

	app := fiber.New()
	app.Get("/:id", func(c *fiber.Ctx) error {
		c.Locals("user_id", userID)
		return handler.GetNote(c)
	})

	req := httptest.NewRequest("GET", "/"+noteID.String(), nil)
	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusNotFound, resp.StatusCode)

	mockDB.AssertExpectations(t)
}

func TestNotesHandler_UpdateNoteNotFound(t *testing.T) {
	mockDB := new(MockDB)
	handler := NewNotesHandler(mockDB, crypto.NewCryptoService(make([]byte, 32)))

	userID := uuid.New()
	noteID := uuid.New()

	tx := new(MockTx)
	row := new(MockRow)

	tx.
		On("QueryRow",
			mock.Anything,
			mock.MatchedBy(func(query string) bool {
				return strings.Contains(query, "SELECT n.version")
			}),
			noteID,
			userID,
		).
		Return(row).
		Once()

	row.
		On("Scan",
			mock.Anything,
			mock.Anything,
			mock.Anything,
			mock.Anything,
			mock.Anything,
			mock.Anything,
		).
		Return(pgx.ErrNoRows)

	tx.
		On("Rollback", mock.Anything).
		Return(nil).
		Once()

	mockDB.
		On("Begin", mock.Anything).
		Return(tx, nil).
		Once()

	app := fiber.New()
	app.Put("/:id", func(c *fiber.Ctx) error {
		c.Locals("user_id", userID)
		return handler.UpdateNote(c)
	})

	payload := map[string]string{
		"title_encrypted":   base64.StdEncoding.EncodeToString([]byte("title")),
		"content_encrypted": base64.StdEncoding.EncodeToString([]byte("content")),
	}
	body, err := json.Marshal(payload)
	require.NoError(t, err)

	req := httptest.NewRequest("PUT", "/"+noteID.String(), bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusNotFound, resp.StatusCode)

	mockDB.AssertExpectations(t)
	tx.AssertExpectations(t)
	row.AssertExpectations(t)
}

func TestNotesHandler_DeleteNoteSuccess(t *testing.T) {
	mockDB := new(MockDB)
	handler := NewNotesHandler(mockDB, crypto.NewCryptoService(make([]byte, 32)))

	userID := uuid.New()
	noteID := uuid.New()

	mockDB.
		On("Exec",
			mock.Anything,
			mock.MatchedBy(func(query string) bool {
				return strings.Contains(query, "UPDATE notes") && strings.Contains(query, "deleted_at = NOW()")
			}),
			noteID,
			userID,
		).
		Return(int64(1), nil).
		Once()

	app := fiber.New()
	app.Delete("/:id", func(c *fiber.Ctx) error {
		c.Locals("user_id", userID)
		return handler.DeleteNote(c)
	})

	req := httptest.NewRequest("DELETE", "/"+noteID.String(), nil)
	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	var body map[string]string
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "Note moved to trash successfully", body["message"])

	mockDB.AssertExpectations(t)
}

func TestNotesHandler_DeleteNoteNotFound(t *testing.T) {
	mockDB := new(MockDB)
	handler := NewNotesHandler(mockDB, crypto.NewCryptoService(make([]byte, 32)))

	userID := uuid.New()
	noteID := uuid.New()

	mockDB.
		On("Exec",
			mock.Anything,
			mock.Anything,
			noteID,
			userID,
		).
		Return(int64(0), nil).
		Once()

	app := fiber.New()
	app.Delete("/:id", func(c *fiber.Ctx) error {
		c.Locals("user_id", userID)
		return handler.DeleteNote(c)
	})

	req := httptest.NewRequest("DELETE", "/"+noteID.String(), nil)
	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusNotFound, resp.StatusCode)

	mockDB.AssertExpectations(t)
}

func TestNotesHandler_GetTrashSuccess(t *testing.T) {
	mockDB := new(MockDB)
	handler := NewNotesHandler(mockDB, crypto.NewCryptoService(make([]byte, 32)))

	userID := uuid.New()
	workspaceID := uuid.New()
	noteID := uuid.New()
	deletedAt := time.Now().UTC().Add(-time.Minute)
	updatedAt := time.Now().UTC()

	workspaceRow := new(MockRow)
	workspaceRow.
		On("Scan", mock.AnythingOfType("*uuid.UUID")).
		Run(func(args mock.Arguments) {
			*args[0].(*uuid.UUID) = workspaceID
		}).
		Return(nil)

	mockDB.
		On("QueryRow",
			mock.Anything,
			"SELECT id FROM workspaces WHERE owner_id = $1 LIMIT 1",
			userID,
		).
		Return(workspaceRow).
		Once()

	trashRows := new(MockRows)
	trashRows.
		On("Next").
		Return(true).
		Once()
	trashRows.
		On("Next").
		Return(false).
		Once()
	trashRows.
		On("Scan",
			mock.AnythingOfType("*uuid.UUID"),
			mock.AnythingOfType("*[]uint8"),
			mock.AnythingOfType("*[]uint8"),
			mock.AnythingOfType("*time.Time"),
			mock.AnythingOfType("*time.Time"),
		).
		Run(func(args mock.Arguments) {
			*args[0].(*uuid.UUID) = noteID
			*args[1].(*[]byte) = []byte("deleted-title")
			*args[2].(*[]byte) = []byte("deleted-content")
			*args[3].(*time.Time) = deletedAt
			*args[4].(*time.Time) = updatedAt
		}).
		Return(nil)

	mockDB.
		On("Query",
			mock.Anything,
			mock.MatchedBy(func(query string) bool {
				return strings.Contains(query, "WHERE workspace_id = $1 AND deleted_at IS NOT NULL")
			}),
			workspaceID,
		).
		Return(trashRows, nil).
		Once()

	app := fiber.New()
	app.Get("/trash", func(c *fiber.Ctx) error {
		c.Locals("user_id", userID)
		return handler.GetTrash(c)
	})

	resp, err := app.Test(httptest.NewRequest("GET", "/trash", nil))
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	var body map[string][]map[string]interface{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	require.Len(t, body["notes"], 1)

	mockDB.AssertExpectations(t)
	trashRows.AssertExpectations(t)
}

func TestNotesHandler_RestoreNoteSuccess(t *testing.T) {
	mockDB := new(MockDB)
	handler := NewNotesHandler(mockDB, crypto.NewCryptoService(make([]byte, 32)))

	userID := uuid.New()
	noteID := uuid.New()

	mockDB.
		On("Exec",
			mock.Anything,
			mock.MatchedBy(func(query string) bool {
				return strings.Contains(query, "SET deleted_at = NULL")
			}),
			noteID,
			userID,
		).
		Return(int64(1), nil).
		Once()

	app := fiber.New()
	app.Post("/:id/restore", func(c *fiber.Ctx) error {
		c.Locals("user_id", userID)
		return handler.RestoreNote(c)
	})

	resp, err := app.Test(httptest.NewRequest("POST", "/"+noteID.String()+"/restore", nil))
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	var body map[string]string
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "Note restored successfully", body["message"])

	mockDB.AssertExpectations(t)
}

func TestNotesHandler_GetNoteVersionsSuccess(t *testing.T) {
	mockDB := new(MockDB)
	handler := NewNotesHandler(mockDB, crypto.NewCryptoService(make([]byte, 32)))

	userID := uuid.New()
	noteID := uuid.New()
	versionID := uuid.New()
	createdAt := time.Now().UTC()

	rows := new(MockRows)
	rows.
		On("Next").
		Return(true).
		Once()
	rows.
		On("Next").
		Return(false).
		Once()
	rows.
		On("Scan",
			mock.AnythingOfType("*uuid.UUID"),
			mock.AnythingOfType("*int"),
			mock.AnythingOfType("*time.Time"),
			mock.AnythingOfType("*string"),
		).
		Run(func(args mock.Arguments) {
			*args[0].(*uuid.UUID) = versionID
			*args[1].(*int) = 3
			*args[2].(*time.Time) = createdAt
			*args[3].(*string) = "test@example.com"
		}).
		Return(nil)

	mockDB.
		On("Query",
			mock.Anything,
			mock.MatchedBy(func(query string) bool {
				return strings.Contains(query, "FROM note_versions")
			}),
			noteID,
			userID,
		).
		Return(rows, nil).
		Once()

	app := fiber.New()
	app.Get("/:id/versions", func(c *fiber.Ctx) error {
		c.Locals("user_id", userID)
		return handler.GetNoteVersions(c)
	})

	req := httptest.NewRequest("GET", "/"+noteID.String()+"/versions", nil)
	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	var body map[string][]map[string]interface{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	require.Len(t, body["versions"], 1)
	assert.Equal(t, "test@example.com", body["versions"][0]["created_by"])

	mockDB.AssertExpectations(t)
	rows.AssertExpectations(t)
}

func TestNotesHandler_RestoreNoteVersionSuccess(t *testing.T) {
	mockDB := new(MockDB)
	handler := NewNotesHandler(mockDB, crypto.NewCryptoService(make([]byte, 32)))

	userID := uuid.New()
	noteID := uuid.New()
	version := 3

	tx := new(MockTx)

	versionRow := new(MockRow)
	versionRow.On("Scan", mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			*(args[0].(*[]byte)) = []byte("title-v3")
			*(args[1].(*[]byte)) = []byte("content-v3")
			*(args[2].(*[]byte)) = []byte("hash3")
		}).Return(nil).Once()

	currentRow := new(MockRow)
	currentRow.On("Scan", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			*(args[0].(*int)) = 2
			*(args[1].(*[]byte)) = []byte("title-current")
			*(args[2].(*[]byte)) = []byte("content-current")
			*(args[3].(*[]byte)) = []byte("hash-current")
		}).Return(nil).Once()

	tx.On("QueryRow", mock.Anything, mock.Anything, noteID, version, userID).Return(versionRow).Once()
	tx.On("QueryRow", mock.Anything, mock.Anything, noteID, userID).Return(currentRow).Once()

	tx.On("Exec", mock.Anything, mock.Anything,
		noteID, mock.AnythingOfType("int"), mock.Anything, mock.Anything, mock.Anything, userID,
	).Return(int64(1), nil).Once()

	tx.On("Exec", mock.Anything, mock.Anything,
		mock.Anything, mock.Anything, mock.Anything, noteID, userID,
	).Return(int64(1), nil).Once()

	tx.On("Commit", mock.Anything).Return(nil).Once()
	tx.On("Rollback", mock.Anything).Return(nil).Once()

	mockDB.On("Begin", mock.Anything).Return(tx, nil).Once()

	app := fiber.New()
	app.Post("/notes/:id/versions/:version/restore", func(c *fiber.Ctx) error {
		c.Locals("user_id", userID)
		return handler.RestoreNoteVersion(c)
	})

	url := "/notes/" + noteID.String() + "/versions/" + strconv.Itoa(version) + "/restore"
	resp, err := app.Test(httptest.NewRequest("POST", url, nil))
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	mockDB.AssertExpectations(t)
	tx.AssertExpectations(t)
	versionRow.AssertExpectations(t)
	currentRow.AssertExpectations(t)
}

func TestNotesHandler_CompareNoteVersionsSuccess(t *testing.T) {
	mockDB := new(MockDB)
	handler := NewNotesHandler(mockDB, crypto.NewCryptoService(make([]byte, 32)))

	userID := uuid.New()
	noteID := uuid.New()

	rows := new(MockRows)
	rows.On("Next").Return(true).Once()
	rows.On("Next").Return(true).Once()
	rows.On("Next").Return(false).Once()
	rows.On("Scan", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			*(args[0].(*int)) = len(rows.Calls) // differentiates entries
			*(args[1].(*[]byte)) = []byte("title")
			*(args[2].(*[]byte)) = []byte("content")
			*(args[3].(*time.Time)) = time.Now().UTC()
			*(args[4].(*string)) = "tester@example.com"
		}).Return(nil).Twice()

	mockDB.On("Query", mock.Anything, mock.Anything, noteID, 1, 2, userID).Return(rows, nil).Once()

	app := fiber.New()
	app.Get("/notes/:id/versions/compare", func(c *fiber.Ctx) error {
		c.Locals("user_id", userID)
		return handler.CompareNoteVersions(c)
	})

	req := httptest.NewRequest("GET", "/notes/"+noteID.String()+"/versions/compare?v1=1&v2=2", nil)
	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	var payload map[string]map[string]interface{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&payload))
	assert.Equal(t, "tester@example.com", payload["v1"]["created_by"])

	mockDB.AssertExpectations(t)
	rows.AssertExpectations(t)
}

func TestNotesHandler_UpdateRetentionPolicySuccess(t *testing.T) {
	mockDB := new(MockDB)
	handler := NewNotesHandler(mockDB, crypto.NewCryptoService(make([]byte, 32)))

	userID := uuid.New()
	noteID := uuid.New()

	mockDB.On("Exec", mock.Anything, mock.Anything, 20, noteID, userID).Return(int64(1), nil).Once()
	mockDB.On("Exec", mock.Anything, mock.Anything, noteID, 20).Return(int64(1), nil).Maybe()

	app := fiber.New()
	app.Put("/notes/:id/retention", func(c *fiber.Ctx) error {
		c.Locals("user_id", userID)
		return handler.UpdateRetentionPolicy(c)
	})

	body := map[string]int{"retention_policy": 20}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest("PUT", "/notes/"+noteID.String()+"/retention", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	mockDB.AssertExpectations(t)
}

func TestNotesHandler_UpdateRetentionPolicyInvalidValue(t *testing.T) {
	handler := NewNotesHandler(new(MockDB), crypto.NewCryptoService(make([]byte, 32)))
	userID := uuid.New()
	noteID := uuid.New()

	app := fiber.New()
	app.Put("/notes/:id/retention", func(c *fiber.Ctx) error {
		c.Locals("user_id", userID)
		return handler.UpdateRetentionPolicy(c)
	})

	body := map[string]int{"retention_policy": 5}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest("PUT", "/notes/"+noteID.String()+"/retention", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)
}

func TestNotesHandler_BulkDeleteNotes(t *testing.T) {
	mockDB := new(MockDB)
	handler := NewNotesHandler(mockDB, crypto.NewCryptoService(make([]byte, 32)))

	userID := uuid.New()
	note1 := uuid.New()
	note2 := uuid.New()

	mockDB.On("Exec", mock.Anything, mock.Anything, note1, userID).Return(int64(1), nil).Once()
	mockDB.On("Exec", mock.Anything, mock.Anything, note2, userID).Return(int64(0), nil).Once()

	app := fiber.New()
	app.Post("/notes/bulk/delete", func(c *fiber.Ctx) error {
		c.Locals("user_id", userID)
		return handler.BulkDeleteNotes(c)
	})

	body := map[string][]string{"note_ids": {note1.String(), "invalid", note2.String()}}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/notes/bulk/delete", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	var payload map[string]interface{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&payload))
	assert.Equal(t, float64(1), payload["successful"])
	assert.Equal(t, float64(2), payload["failed"])

	mockDB.AssertExpectations(t)
}

func TestNotesHandler_BulkDeleteNotesInvalidBody(t *testing.T) {
	handler := NewNotesHandler(new(MockDB), crypto.NewCryptoService(make([]byte, 32)))
	userID := uuid.New()

	app := fiber.New()
	app.Post("/notes/bulk/delete", func(c *fiber.Ctx) error {
		c.Locals("user_id", userID)
		return handler.BulkDeleteNotes(c)
	})

	body := map[string][]string{}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/notes/bulk/delete", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)
}

func TestNotesHandler_BulkRestoreNotes(t *testing.T) {
	mockDB := new(MockDB)
	handler := NewNotesHandler(mockDB, crypto.NewCryptoService(make([]byte, 32)))

	userID := uuid.New()
	note1 := uuid.New()
	note2 := uuid.New()

	mockDB.On("Exec", mock.Anything, mock.Anything, note1, userID).Return(int64(1), nil).Once()
	mockDB.On("Exec", mock.Anything, mock.Anything, note2, userID).Return(int64(0), nil).Once()

	app := fiber.New()
	app.Post("/notes/bulk/restore", func(c *fiber.Ctx) error {
		c.Locals("user_id", userID)
		return handler.BulkRestoreNotes(c)
	})

	body := map[string][]string{"note_ids": {note1.String(), note2.String()}}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/notes/bulk/restore", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	mockDB.AssertExpectations(t)
}

func TestNotesHandler_BulkPermanentlyDeleteNotes(t *testing.T) {
	mockDB := new(MockDB)
	handler := NewNotesHandler(mockDB, crypto.NewCryptoService(make([]byte, 32)))

	userID := uuid.New()
	note1 := uuid.New()
	note2 := uuid.New()

	mockDB.On("Exec", mock.Anything, mock.Anything, note1, userID).Return(int64(1), nil).Once()
	mockDB.On("Exec", mock.Anything, mock.Anything, note2, userID).Return(int64(0), nil).Once()

	app := fiber.New()
	app.Post("/notes/bulk/permanent-delete", func(c *fiber.Ctx) error {
		c.Locals("user_id", userID)
		return handler.BulkPermanentlyDeleteNotes(c)
	})

	body := map[string][]string{"note_ids": {note1.String(), note2.String()}}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/notes/bulk/permanent-delete", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	mockDB.AssertExpectations(t)
}

func TestNotesHandler_DeleteNoteVersionSuccess(t *testing.T) {
	mockDB := new(MockDB)
	handler := NewNotesHandler(mockDB, crypto.NewCryptoService(make([]byte, 32)))

	userID := uuid.New()
	noteID := uuid.New()
	versionID := uuid.New()

	mockDB.On("Exec", mock.Anything, mock.Anything, versionID, noteID, userID).Return(int64(1), nil).Once()

	app := fiber.New()
	app.Delete("/notes/:id/versions/:versionId", func(c *fiber.Ctx) error {
		c.Locals("user_id", userID)
		return handler.DeleteNoteVersion(c)
	})

	resp, err := app.Test(httptest.NewRequest("DELETE", "/notes/"+noteID.String()+"/versions/"+versionID.String(), nil))
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	mockDB.AssertExpectations(t)
}
