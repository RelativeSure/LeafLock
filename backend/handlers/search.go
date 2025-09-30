package handlers

import (
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"leaflock/crypto"
	"leaflock/database"
)

// Search Handler
type SearchHandler struct {
	db     database.Database
	crypto *crypto.CryptoService
}

// NewSearchHandler creates a new search handler instance.
func NewSearchHandler(db database.Database, cryptoService *crypto.CryptoService) *SearchHandler {
	return &SearchHandler{db: db, crypto: cryptoService}
}

type SearchRequest struct {
	Query string `json:"query" validate:"required,min=1"`
	Limit int    `json:"limit,omitempty"`
}

type SearchResult struct {
	ID        string `json:"id"`
	Title     string `json:"title"`
	Content   string `json:"content"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
	Snippet   string `json:"snippet"`
}

type SearchResponse struct {
	Results []SearchResult `json:"results"`
	Total   int            `json:"total"`
	Query   string         `json:"query"`
}

// Search notes for the authenticated user
func (h *SearchHandler) SearchNotes(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)

	var req SearchRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
	}

	// Validate request
	if req.Query == "" {
		return c.Status(400).JSON(fiber.Map{"error": "Search query is required"})
	}

	if req.Limit <= 0 {
		req.Limit = 20 // Default limit
	}
	if req.Limit > 100 {
		req.Limit = 100 // Max limit
	}

	// Search in notes (decrypt and search - in production you'd want indexed search)
	query := `
		SELECT id, title_encrypted, content_encrypted, created_at, updated_at
		FROM notes
		WHERE created_by = $1 AND deleted_at IS NULL
		ORDER BY updated_at DESC
		LIMIT $2`

	rows, err := h.db.Query(c.Context(), query, userID, req.Limit*2) // Get more to account for filtering
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to search notes"})
	}
	defer rows.Close()

	var results []SearchResult
	searchQuery := strings.ToLower(strings.TrimSpace(req.Query))

	for rows.Next() {
		var id uuid.UUID
		var titleEncrypted, contentEncrypted []byte
		var createdAt, updatedAt time.Time

		err := rows.Scan(&id, &titleEncrypted, &contentEncrypted, &createdAt, &updatedAt)
		if err != nil {
			continue
		}

		// Decrypt title and content
		titleBytes, err := h.crypto.Decrypt(titleEncrypted)
		if err != nil {
			continue
		}

		contentBytes, err := h.crypto.Decrypt(contentEncrypted)
		if err != nil {
			continue
		}

		title := string(titleBytes)
		content := string(contentBytes)

		// Perform case-insensitive search
		titleLower := strings.ToLower(title)
		contentLower := strings.ToLower(content)

		if strings.Contains(titleLower, searchQuery) || strings.Contains(contentLower, searchQuery) {
			// Create snippet showing context around the match
			snippet := createSearchSnippet(content, searchQuery, 150)

			results = append(results, SearchResult{
				ID:        id.String(),
				Title:     title,
				Content:   content,
				CreatedAt: createdAt.Format(time.RFC3339),
				UpdatedAt: updatedAt.Format(time.RFC3339),
				Snippet:   snippet,
			})

			// Stop when we have enough results
			if len(results) >= req.Limit {
				break
			}
		}
	}

	return c.JSON(SearchResponse{
		Results: results,
		Total:   len(results),
		Query:   req.Query,
	})
}

// Create a snippet showing context around the search term
func createSearchSnippet(content, query string, maxLength int) string {
	contentLower := strings.ToLower(content)
	queryLower := strings.ToLower(query)

	index := strings.Index(contentLower, queryLower)
	if index == -1 {
		// If query not found in content, return beginning
		if len(content) <= maxLength {
			return content
		}
		return content[:maxLength] + "..."
	}

	// Calculate snippet bounds
	start := index - 50
	if start < 0 {
		start = 0
	}

	end := index + len(query) + 50
	if end > len(content) {
		end = len(content)
	}

	snippet := content[start:end]

	// Add ellipsis if needed
	if start > 0 {
		snippet = "..." + snippet
	}
	if end < len(content) {
		snippet = snippet + "..."
	}

	return snippet
}
