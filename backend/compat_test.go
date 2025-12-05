package main

import (
	"context"
	"os"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"leaflock/auth"
	appconfig "leaflock/config"
	appcrypto "leaflock/crypto"
	appdb "leaflock/database"
	"leaflock/handlers"
	"leaflock/services"
	"leaflock/utils"
	websocketpkg "leaflock/websocket"
)

// MockEmailService is a mock email service for testing
type MockEmailServiceCompat struct{}

func (m *MockEmailServiceCompat) SendPasswordResetEmail(toEmail string, resetToken string, ipAddress string) error {
	return nil
}

// Expose configuration and crypto types used across tests.
type Config = appconfig.Config

type CryptoService = appcrypto.CryptoService

var regEnabled = &appconfig.RegEnabled

func NewCryptoService(key []byte) *appcrypto.CryptoService {
	return appcrypto.NewCryptoService(key)
}

// RegisterRequest for backward compatibility with tests
type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// LoginRequest for backward compatibility with tests
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	MFACode  string `json:"mfa_code,omitempty"`
}
type CreateNoteRequest = handlers.CreateNoteRequest
type UpdateNoteRequest = handlers.UpdateNoteRequest
type CreateTagRequest struct {
	Name  string `json:"name"`
	Color string `json:"color,omitempty"`
}

type AssignTagRequest struct {
	TagID string `json:"tag_id"`
}

func HashPassword(password string, salt []byte) string {
	return appcrypto.HashPassword(password, salt)
}

func VerifyPassword(password, encodedHash string) bool {
	return appcrypto.VerifyPassword(password, encodedHash)
}

func seedDefaultAdminUser(db appdb.Database, crypto *appcrypto.CryptoService, cfg *appconfig.Config) error {
	// Admin service removed - admin users must be created manually or via registration
	// See CLAUDE.md for instructions on creating admin users
	return nil
}

func LoadConfig() *appconfig.Config {
	// JWT_SECRET removed - Clerk-only authentication
	// Zero-knowledge: SERVER_ENCRYPTION_KEY no longer used (encryption keys derived from Clerk secret)
	return appconfig.LoadConfig()
}

func SetupDatabase(url string) (*pgxpool.Pool, error) {
	return appdb.SetupDatabase(url)
}



func isValidHexColor(color string) bool {
	return utils.IsValidHexColor(color)
}

func runCleanupTasks(ctx context.Context, db appdb.Database) {
	services.RunCleanupTasks(ctx, db)
}

// AuthHandler compatibility wrapper used by legacy tests.
type AuthHandler struct {
	db     appdb.Database
	redis  *redis.Client
	crypto *appcrypto.CryptoService
	config *appconfig.Config
}

func (h *AuthHandler) handler() *auth.Handler {
	// Type assert database.Database to *pgxpool.Pool for auth.NewService
	db, ok := h.db.(*pgxpool.Pool)
	if !ok {
		panic("AuthHandler requires *pgxpool.Pool, not database.Database interface")
	}
	authService := auth.NewService(db, h.redis, string(h.config.JWTSecret))
	return auth.NewHandler(authService, &MockEmailServiceCompat{})
}

func (h *AuthHandler) Register(c *fiber.Ctx) error {
	// Check if registration is enabled (for backward compatibility with tests)
	if regEnabled.Load() != 1 {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Registration is currently disabled"})
	}
	return h.handler().Register(c)
}

func (h *AuthHandler) Login(c *fiber.Ctx) error {
	return h.handler().Login(c)
}

func (h *AuthHandler) AdminRecovery(c *fiber.Ctx) error {
	// AdminRecovery removed - no longer supported
	return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
		"error": "Admin recovery endpoint no longer available",
	})
}

// NotesHandler compatibility wrapper.
type NotesHandler struct {
	db     appdb.Database
	crypto *appcrypto.CryptoService
}

func (h *NotesHandler) handler() *handlers.NotesHandler {
	return handlers.NewNotesHandler(h.db, h.crypto)
}

func (h *NotesHandler) GetNotes(c *fiber.Ctx) error {
	return h.handler().GetNotes(c)
}

func (h *NotesHandler) GetNote(c *fiber.Ctx) error {
	return h.handler().GetNote(c)
}

func (h *NotesHandler) CreateNote(c *fiber.Ctx) error {
	return h.handler().CreateNote(c)
}

func (h *NotesHandler) UpdateNote(c *fiber.Ctx) error {
	return h.handler().UpdateNote(c)
}

func (h *NotesHandler) DeleteNote(c *fiber.Ctx) error {
	return h.handler().DeleteNote(c)
}

func (h *NotesHandler) GetTrash(c *fiber.Ctx) error {
	return h.handler().GetTrash(c)
}

func (h *NotesHandler) RestoreNote(c *fiber.Ctx) error {
	return h.handler().RestoreNote(c)
}

func (h *NotesHandler) PermanentlyDeleteNote(c *fiber.Ctx) error {
	return h.handler().PermanentlyDeleteNote(c)
}

// TagsHandler compatibility wrapper.
type TagsHandler struct {
	db     appdb.Database
	crypto *appcrypto.CryptoService
}

func (h *TagsHandler) handler() *handlers.TagsHandler {
	return handlers.NewTagsHandler(h.db, h.crypto)
}

func (h *TagsHandler) GetTags(c *fiber.Ctx) error {
	return h.handler().GetTags(c)
}

func (h *TagsHandler) CreateTag(c *fiber.Ctx) error {
	return h.handler().CreateTag(c)
}

func (h *TagsHandler) DeleteTag(c *fiber.Ctx) error {
	return h.handler().DeleteTag(c)
}

func (h *TagsHandler) AssignTagToNote(c *fiber.Ctx) error {
	return h.handler().AssignTagToNote(c)
}

func (h *TagsHandler) RemoveTagFromNote(c *fiber.Ctx) error {
	return h.handler().RemoveTagFromNote(c)
}

func (h *TagsHandler) GetNotesByTag(c *fiber.Ctx) error {
	return h.handler().GetNotesByTag(c)
}

// ImportExportHandler compatibility wrapper.
type ImportExportHandler struct {
	db     appdb.Database
	crypto *appcrypto.CryptoService
}

func (h *ImportExportHandler) handler() *handlers.ImportExportHandler {
	return handlers.NewImportExportHandler(h.db, h.crypto)
}

func (h *ImportExportHandler) GetStorageInfo(c *fiber.Ctx) error {
	return h.handler().GetStorageInfo(c)
}

func (h *ImportExportHandler) ImportNote(c *fiber.Ctx) error {
	return h.handler().ImportNote(c)
}

func (h *ImportExportHandler) ExportNote(c *fiber.Ctx) error {
	return h.handler().ExportNote(c)
}

func (h *ImportExportHandler) BulkImport(c *fiber.Ctx) error {
	return h.handler().BulkImport(c)
}

// Collaboration handler compatibility wrapper.
type CollaborationHandler struct {
	db     appdb.Database
	crypto *appcrypto.CryptoService
}

func (h *CollaborationHandler) handler() *handlers.CollaborationHandler {
	return handlers.NewCollaborationHandler(h.db, h.crypto, nil)
}

func (h *CollaborationHandler) ShareNote(c *fiber.Ctx) error {
	return h.handler().ShareNote(c)
}

func (h *CollaborationHandler) GetCollaborators(c *fiber.Ctx) error {
	return h.handler().GetCollaborators(c)
}

func (h *CollaborationHandler) RemoveCollaborator(c *fiber.Ctx) error {
	return h.handler().RemoveCollaborator(c)
}

func (h *CollaborationHandler) GetSharedNotes(c *fiber.Ctx) error {
	return h.handler().GetSharedNotes(c)
}

type ShareNoteRequest = handlers.ShareNoteRequest

type CollaborationResponse = handlers.CollaborationResponse

func NewHub() *websocketpkg.Hub {
	return websocketpkg.NewHub()
}

type Connection = websocketpkg.Connection
