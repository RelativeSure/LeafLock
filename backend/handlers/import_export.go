package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"leaflock/crypto"
	"leaflock/database"
	"leaflock/utils"
)

// Import/Export Handler
type ImportExportHandler struct {
	db     database.Database
	crypto *crypto.CryptoService
}

// NewImportExportHandler constructs an import/export handler.
func NewImportExportHandler(db database.Database, cryptoService *crypto.CryptoService) *ImportExportHandler {
	return &ImportExportHandler{db: db, crypto: cryptoService}
}

type ImportRequest struct {
	Format   string `json:"format" validate:"required,oneof=markdown text html json"`
	Content  string `json:"content" validate:"required"`
	Title    string `json:"title,omitempty"`
	Filename string `json:"filename,omitempty"`
}

type ExportRequest struct {
	Format string `json:"format" validate:"required,oneof=markdown text html json"`
}

type BulkImportRequest struct {
	Files []ImportRequest `json:"files" validate:"required,min=1,max=50"`
}

// Helper functions for storage management
func (h *ImportExportHandler) checkStorageLimit(userID uuid.UUID, additionalBytes int64) error {
	ctx := context.Background()

	var storageUsed, storageLimit int64
	err := h.db.QueryRow(ctx, `
		SELECT storage_used, storage_limit
		FROM users
		WHERE id = $1
	`, userID).Scan(&storageUsed, &storageLimit)

	if err != nil {
		return fmt.Errorf("failed to check storage: %w", err)
	}

	if storageUsed+additionalBytes > storageLimit {
		return fmt.Errorf("storage limit exceeded: %d bytes used + %d bytes new > %d bytes limit",
			storageUsed, additionalBytes, storageLimit)
	}

	return nil
}

func (h *ImportExportHandler) updateStorageUsage(userID uuid.UUID, additionalBytes int64) error {
	ctx := context.Background()

	_, err := h.db.Exec(ctx, `
		UPDATE users
		SET storage_used = storage_used + $1
		WHERE id = $2
	`, additionalBytes, userID)

	return err
}

func validateFileContent(content, format string) error {
	// Validate file size (max 100KB per file for text content)
	if len(content) > 100*1024 {
		return fmt.Errorf("file too large (max 100KB per file)")
	}

	// Basic content security validation
	lowerContent := strings.ToLower(content)

	// Check for potentially malicious content
	dangerousPatterns := []string{
		"<script", "javascript:", "data:text/html", "data:image/svg+xml",
		"vbscript:", "onload=", "onerror=", "onclick=", "onmouseover=",
		"<iframe", "<object", "<embed", "<applet",
	}

	for _, pattern := range dangerousPatterns {
		if strings.Contains(lowerContent, pattern) {
			return fmt.Errorf("potentially malicious content detected: %s", pattern)
		}
	}

	// Format-specific validation
	switch format {
	case "html":
		// Additional HTML validation
		if strings.Contains(lowerContent, "<meta http-equiv") {
			return fmt.Errorf("meta refresh tags not allowed")
		}
	case "json":
		// Validate JSON structure
		var js interface{}
		if err := json.Unmarshal([]byte(content), &js); err != nil {
			return fmt.Errorf("invalid JSON format: %w", err)
		}
	}

	return nil
}

// GetStorageInfo godoc
// @Summary Get user storage information
// @Description Get current storage usage and limit for the user
// @Tags Import/Export
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "Storage information"
// @Failure 500 {object} map[string]interface{} "Failed to get storage info"
// @Router /user/storage [get]
func (h *ImportExportHandler) GetStorageInfo(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	ctx := context.Background()

	var storageUsed, storageLimit int64
	err := h.db.QueryRow(ctx, `
		SELECT storage_used, storage_limit
		FROM users
		WHERE id = $1
	`, userID).Scan(&storageUsed, &storageLimit)

	if err != nil {
		utils.LogRequestError(c, "GetStorageInfo: failed to get storage info", err, "user_id", userID)
		return c.Status(500).JSON(fiber.Map{"error": "Failed to get storage information"})
	}

	return c.JSON(fiber.Map{
		"storage_used":      storageUsed,
		"storage_limit":     storageLimit,
		"storage_remaining": storageLimit - storageUsed,
		"usage_percentage":  float64(storageUsed) / float64(storageLimit) * 100,
	})
}

// ImportNote godoc
// @Summary Import a note from various formats
// @Description Import a note from markdown, text, HTML, or JSON format
// @Tags Import/Export
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body ImportRequest true "Import data"
// @Success 201 {object} map[string]interface{} "Note imported successfully"
// @Failure 400 {object} map[string]interface{} "Invalid request"
// @Failure 500 {object} map[string]interface{} "Import failed"
// @Router /notes/import [post]
func (h *ImportExportHandler) ImportNote(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	ctx := context.Background()

	var req ImportRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
	}

	// Validate file content and security
	if err := validateFileContent(req.Content, req.Format); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": fmt.Sprintf("Invalid file content: %s", err.Error())})
	}

	// Check storage limit before processing
	contentSize := int64(len(req.Content))
	if err := h.checkStorageLimit(userID, contentSize); err != nil {
		return c.Status(413).JSON(fiber.Map{"error": err.Error()})
	}

	// Extract title from content if not provided
	title := req.Title
	if title == "" {
		title = extractTitleFromContent(req.Content, req.Format)
	}
	if title == "" {
		title = req.Filename
	}
	if title == "" {
		title = "Imported Note"
	}

	// Convert content based on format
	content, err := convertToMarkdown(req.Content, req.Format)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": fmt.Sprintf("Failed to convert %s: %s", req.Format, err.Error())})
	}

	// Get user's default workspace
	var workspaceID uuid.UUID
	err = h.db.QueryRow(ctx, `SELECT id FROM workspaces WHERE owner_id = $1 LIMIT 1`, userID).Scan(&workspaceID)
	if err != nil {
		utils.LogRequestError(c, "ImportNote: failed to get user workspace", err)
		return c.Status(500).JSON(fiber.Map{"error": "Failed to get workspace"})
	}

	// Encrypt title and content
	titleEncrypted, err := h.crypto.Encrypt([]byte(title))
	if err != nil {
		utils.LogRequestError(c, "ImportNote: failed to encrypt title", err, "title_length", len(title))
		return c.Status(500).JSON(fiber.Map{"error": "Failed to encrypt title"})
	}

	contentEncrypted, err := h.crypto.Encrypt([]byte(content))
	if err != nil {
		utils.LogRequestError(c, "ImportNote: failed to encrypt content", err, "content_length", len(content))
		return c.Status(500).JSON(fiber.Map{"error": "Failed to encrypt content"})
	}

	// Insert note
	noteID := uuid.New()
	_, err = h.db.Exec(ctx, `
		INSERT INTO notes (id, workspace_id, title_encrypted, content_encrypted)
		VALUES ($1, $2, $3, $4)`,
		noteID, workspaceID, titleEncrypted, contentEncrypted)

	if err != nil {
		utils.LogRequestError(c, "ImportNote: failed to create note in database", err, "note_id", noteID)
		return c.Status(500).JSON(fiber.Map{"error": "Failed to create note"})
	}

	// Update storage usage
	if err := h.updateStorageUsage(userID, contentSize); err != nil {
		utils.LogRequestError(c, "ImportNote: failed to update storage usage", err, "user_id", userID, "content_size", contentSize)
		// Note: We don't fail the import here as the note was already created
	}

	return c.Status(201).JSON(fiber.Map{
		"message": "Note imported successfully",
		"note_id": noteID,
		"title":   title,
		"format":  req.Format,
	})
}

// ExportNote godoc
// @Summary Export a note in various formats
// @Description Export a note as markdown, text, HTML, or JSON
// @Tags Import/Export
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "Note ID"
// @Param request body ExportRequest true "Export format"
// @Success 200 {object} map[string]interface{} "Note exported successfully"
// @Failure 400 {object} map[string]interface{} "Invalid request"
// @Failure 404 {object} map[string]interface{} "Note not found"
// @Router /notes/{id}/export [post]
func (h *ImportExportHandler) ExportNote(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	noteID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid note ID"})
	}

	ctx := context.Background()

	var req ExportRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
	}

	// Get note with permission check
	var titleEnc, contentEnc []byte
	var createdAt, updatedAt time.Time
	err = h.db.QueryRow(ctx, `
		SELECT n.title_encrypted, n.content_encrypted, n.created_at, n.updated_at
		FROM notes n
		JOIN workspaces w ON n.workspace_id = w.id
		WHERE n.id = $1 AND (w.owner_id = $2 OR EXISTS(
			SELECT 1 FROM collaborations c
			WHERE c.note_id = n.id AND c.user_id = $2
		)) AND n.deleted_at IS NULL`,
		noteID, userID).Scan(&titleEnc, &contentEnc, &createdAt, &updatedAt)

	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Note not found"})
	}

	// Decrypt content
	titleBytes, err := h.crypto.Decrypt(titleEnc)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to decrypt title"})
	}

	contentBytes, err := h.crypto.Decrypt(contentEnc)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to decrypt content"})
	}

	title := string(titleBytes)
	content := string(contentBytes)

	// Convert content to requested format
	exportedContent, contentType, err := convertFromMarkdown(content, req.Format, title, createdAt, updatedAt)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": fmt.Sprintf("Failed to convert to %s: %s", req.Format, err.Error())})
	}

	return c.JSON(fiber.Map{
		"content":      exportedContent,
		"content_type": contentType,
		"title":        title,
		"format":       req.Format,
		"filename":     generateFilename(title, req.Format),
	})
}

// BulkImport godoc
// @Summary Import multiple notes at once
// @Description Import multiple notes from various formats
// @Tags Import/Export
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body BulkImportRequest true "Bulk import data"
// @Success 201 {object} map[string]interface{} "Notes imported successfully"
// @Failure 400 {object} map[string]interface{} "Invalid request"
// @Router /notes/bulk-import [post]
func (h *ImportExportHandler) BulkImport(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	ctx := context.Background()

	var req BulkImportRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
	}

	if len(req.Files) > 50 {
		return c.Status(400).JSON(fiber.Map{"error": "Too many files (max 50)"})
	}

	// Calculate total size and check overall storage limit
	var totalSize int64
	for _, file := range req.Files {
		totalSize += int64(len(file.Content))
	}

	if err := h.checkStorageLimit(userID, totalSize); err != nil {
		return c.Status(413).JSON(fiber.Map{"error": err.Error()})
	}

	// Get user's default workspace
	var workspaceID uuid.UUID
	err := h.db.QueryRow(ctx, `SELECT id FROM workspaces WHERE owner_id = $1 LIMIT 1`, userID).Scan(&workspaceID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to get workspace"})
	}

	var imported []map[string]interface{}
	var failed []map[string]interface{}
	var totalImportedSize int64

	for i, file := range req.Files {
		// Validate file content and security
		if err := validateFileContent(file.Content, file.Format); err != nil {
			failed = append(failed, map[string]interface{}{
				"index": i,
				"title": file.Title,
				"error": fmt.Sprintf("Invalid file content: %s", err.Error()),
			})
			continue
		}

		// Extract title
		title := file.Title
		if title == "" {
			title = extractTitleFromContent(file.Content, file.Format)
		}
		if title == "" {
			title = file.Filename
		}
		if title == "" {
			title = fmt.Sprintf("Imported Note %d", i+1)
		}

		// Convert content
		content, err := convertToMarkdown(file.Content, file.Format)
		if err != nil {
			failed = append(failed, map[string]interface{}{
				"index": i,
				"title": title,
				"error": fmt.Sprintf("Failed to convert %s: %s", file.Format, err.Error()),
			})
			continue
		}

		// Encrypt and save
		titleEncrypted, err := h.crypto.Encrypt([]byte(title))
		if err != nil {
			failed = append(failed, map[string]interface{}{
				"index": i,
				"title": title,
				"error": "Failed to encrypt title",
			})
			continue
		}

		contentEncrypted, err := h.crypto.Encrypt([]byte(content))
		if err != nil {
			failed = append(failed, map[string]interface{}{
				"index": i,
				"title": title,
				"error": "Failed to encrypt content",
			})
			continue
		}

		noteID := uuid.New()
		_, err = h.db.Exec(ctx, `
			INSERT INTO notes (id, workspace_id, title_encrypted, content_encrypted)
			VALUES ($1, $2, $3, $4)`,
			noteID, workspaceID, titleEncrypted, contentEncrypted)

		if err != nil {
			failed = append(failed, map[string]interface{}{
				"index": i,
				"title": title,
				"error": "Failed to save note",
			})
			continue
		}

		// Track successful import size
		totalImportedSize += int64(len(file.Content))

		imported = append(imported, map[string]interface{}{
			"note_id": noteID,
			"title":   title,
			"format":  file.Format,
		})
	}

	// Update storage usage for all successfully imported files
	if totalImportedSize > 0 {
		if err := h.updateStorageUsage(userID, totalImportedSize); err != nil {
			utils.LogRequestError(c, "BulkImport: failed to update storage usage", err, "user_id", userID, "imported_size", totalImportedSize)
			// Note: We don't fail the import here as the notes were already created
		}
	}

	return c.Status(201).JSON(fiber.Map{
		"imported_count": len(imported),
		"failed_count":   len(failed),
		"imported":       imported,
		"failed":         failed,
	})
}

// Helper functions for content conversion
func extractTitleFromContent(content, format string) string {
	switch format {
	case "markdown":
		lines := strings.Split(content, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "# ") {
				return strings.TrimSpace(line[2:])
			}
		}
	case "html":
		// Simple regex to extract title from HTML
		re := regexp.MustCompile(`<title[^>]*>([^<]+)</title>`)
		matches := re.FindStringSubmatch(content)
		if len(matches) > 1 {
			return strings.TrimSpace(matches[1])
		}
		// Try h1 tag
		re = regexp.MustCompile(`<h1[^>]*>([^<]+)</h1>`)
		matches = re.FindStringSubmatch(content)
		if len(matches) > 1 {
			return strings.TrimSpace(matches[1])
		}
	case "text":
		lines := strings.Split(content, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" {
				if len(line) > 50 {
					return line[:50] + "..."
				}
				return line
			}
		}
	case "json":
		var data map[string]interface{}
		if err := json.Unmarshal([]byte(content), &data); err == nil {
			if title, ok := data["title"].(string); ok {
				return title
			}
		}
	}
	return ""
}

func convertToMarkdown(content, format string) (string, error) {
	switch format {
	case "markdown":
		return content, nil
	case "text":
		// Convert plain text to markdown by preserving line breaks
		return strings.ReplaceAll(content, "\n", "\n\n"), nil
	case "html":
		// Basic HTML to Markdown conversion
		// In production, you'd use a proper HTML to Markdown converter
		content = regexp.MustCompile(`<h([1-6])[^>]*>([^<]+)</h[1-6]>`).ReplaceAllString(content, "${1} $2\n")
		content = regexp.MustCompile(`<p[^>]*>([^<]*)</p>`).ReplaceAllString(content, "$1\n\n")
		content = regexp.MustCompile(`<strong[^>]*>([^<]*)</strong>`).ReplaceAllString(content, "**$1**")
		content = regexp.MustCompile(`<em[^>]*>([^<]*)</em>`).ReplaceAllString(content, "*$1*")
		content = regexp.MustCompile(`<br[^>]*>`).ReplaceAllString(content, "\n")
		content = regexp.MustCompile(`<[^>]+>`).ReplaceAllString(content, "")
		return strings.TrimSpace(content), nil
	case "json":
		var data map[string]interface{}
		if err := json.Unmarshal([]byte(content), &data); err != nil {
			return "", err
		}

		if markdownContent, ok := data["content"].(string); ok {
			return markdownContent, nil
		}
		if textContent, ok := data["text"].(string); ok {
			return textContent, nil
		}

		// Convert JSON to markdown representation
		formatted, _ := json.MarshalIndent(data, "", "  ")
		return "```json\n" + string(formatted) + "\n```", nil
	default:
		return "", fmt.Errorf("unsupported format: %s", format)
	}
}

func convertFromMarkdown(content, format, title string, createdAt, updatedAt time.Time) (string, string, error) {
	switch format {
	case "markdown":
		return content, "text/markdown", nil
	case "text":
		// Strip markdown formatting for plain text
		text := content
		text = regexp.MustCompile(`\*\*([^*]+)\*\*`).ReplaceAllString(text, "$1")
		text = regexp.MustCompile(`\*([^*]+)\*`).ReplaceAllString(text, "$1")
		text = regexp.MustCompile(`#{1,6}\s*`).ReplaceAllString(text, "")
		text = regexp.MustCompile(`\[([^\]]+)\]\([^)]+\)`).ReplaceAllString(text, "$1")
		return text, "text/plain", nil
	case "html":
		// Basic markdown to HTML conversion
		html := content
		html = regexp.MustCompile(`^#{6}\s*(.+)$`).ReplaceAllString(html, "<h6>$1</h6>")
		html = regexp.MustCompile(`^#{5}\s*(.+)$`).ReplaceAllString(html, "<h5>$1</h5>")
		html = regexp.MustCompile(`^#{4}\s*(.+)$`).ReplaceAllString(html, "<h4>$1</h4>")
		html = regexp.MustCompile(`^#{3}\s*(.+)$`).ReplaceAllString(html, "<h3>$1</h3>")
		html = regexp.MustCompile(`^#{2}\s*(.+)$`).ReplaceAllString(html, "<h2>$1</h2>")
		html = regexp.MustCompile(`^#{1}\s*(.+)$`).ReplaceAllString(html, "<h1>$1</h1>")
		html = regexp.MustCompile(`\*\*([^*]+)\*\*`).ReplaceAllString(html, "<strong>$1</strong>")
		html = regexp.MustCompile(`\*([^*]+)\*`).ReplaceAllString(html, "<em>$1</em>")
		html = strings.ReplaceAll(html, "\n\n", "</p><p>")
		html = "<p>" + html + "</p>"

		fullHTML := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>%s</title>
    <meta charset="UTF-8">
</head>
<body>
    %s
</body>
</html>`, title, html)

		return fullHTML, "text/html", nil
	case "json":
		data := map[string]interface{}{
			"title":      title,
			"content":    content,
			"created_at": createdAt,
			"updated_at": updatedAt,
			"format":     "markdown",
		}
		jsonBytes, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			return "", "", err
		}
		return string(jsonBytes), "application/json", nil
	default:
		return "", "", fmt.Errorf("unsupported format: %s", format)
	}
}

func generateFilename(title, format string) string {
	// Sanitize title for filename
	filename := regexp.MustCompile(`[^a-zA-Z0-9\-_\s]`).ReplaceAllString(title, "")
	filename = regexp.MustCompile(`\s+`).ReplaceAllString(filename, "_")
	filename = strings.Trim(filename, "_")

	if len(filename) > 50 {
		filename = filename[:50]
	}

	if filename == "" {
		filename = "exported_note"
	}

	switch format {
	case "markdown":
		return filename + ".md"
	case "text":
		return filename + ".txt"
	case "html":
		return filename + ".html"
	case "json":
		return filename + ".json"
	default:
		return filename + ".txt"
	}
}

// WebSocket functionality has been moved to the websocket package (leaflock/websocket)
// To use WebSocket functionality in your routes:
//
// Example route setup:
//   import (
//       "github.com/gofiber/contrib/websocket"
//       ws "leaflock/websocket"
//   )
//
//   hub := ws.NewHub()
//   go hub.Run()
//
//   app.Get("/ws", websocket.New(func(c *websocket.Conn) {
//       ws.HandleWebSocket(c, hub, db)
//   }))

// JWT Middleware
