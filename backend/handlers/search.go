package handlers

import "github.com/gofiber/fiber/v2"

// SearchHandler intentionally avoids accessing encrypted note content on the
// server. All search functionality is handled client-side after decryption in
// the browser to preserve end-to-end privacy guarantees.
type SearchHandler struct{}

// NewSearchHandler creates a new search handler instance.
func NewSearchHandler() *SearchHandler {
	return &SearchHandler{}
}

// SearchNotes returns a not-implemented response to signal that search must be
// performed locally by the client once notes are decrypted.
func (h *SearchHandler) SearchNotes(c *fiber.Ctx) error {
	return c.Status(fiber.StatusNotImplemented).JSON(fiber.Map{
		"error":   "SearchDisabled",
		"message": "Server-side search is disabled to preserve end-to-end encryption. Please perform search locally after unlocking your notes.",
	})
}
