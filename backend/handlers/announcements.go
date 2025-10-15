package handlers

import (
	"context"
	"encoding/json"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type AnnouncementsHandler struct {
	db *pgxpool.Pool
}

type Announcement struct {
	ID          string                 `json:"id"`
	Title       string                 `json:"title"`
	Content     string                 `json:"content"`
	Visibility  string                 `json:"visibility"` // 'all' or 'logged_in'
	Style       map[string]interface{} `json:"style"`
	Active      bool                   `json:"active"`
	Dismissible bool                   `json:"dismissible"`
	Priority    int                    `json:"priority"`
	StartDate   *time.Time             `json:"start_date,omitempty"`
	EndDate     *time.Time             `json:"end_date,omitempty"`
	CreatedBy   *string                `json:"created_by,omitempty"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

type CreateAnnouncementRequest struct {
	Title       string                 `json:"title" validate:"required"`
	Content     string                 `json:"content" validate:"required"`
	Visibility  string                 `json:"visibility" validate:"required,oneof=all logged_in"`
	Style       map[string]interface{} `json:"style"`
	Active      bool                   `json:"active"`
	Dismissible bool                   `json:"dismissible"`
	Priority    int                    `json:"priority"`
	StartDate   *time.Time             `json:"start_date"`
	EndDate     *time.Time             `json:"end_date"`
}

type UpdateAnnouncementRequest struct {
	Title       *string                `json:"title"`
	Content     *string                `json:"content"`
	Visibility  *string                `json:"visibility" validate:"omitempty,oneof=all logged_in"`
	Style       map[string]interface{} `json:"style"`
	Active      *bool                  `json:"active"`
	Dismissible *bool                  `json:"dismissible"`
	Priority    *int                   `json:"priority"`
	StartDate   *time.Time             `json:"start_date"`
	EndDate     *time.Time             `json:"end_date"`
}

func NewAnnouncementsHandler(db *pgxpool.Pool) *AnnouncementsHandler {
	return &AnnouncementsHandler{db: db}
}

// GetAnnouncements returns active announcements (public endpoint)
// @Summary Get active announcements
// @Description Get all active announcements visible to the current user
// @Tags announcements
// @Accept json
// @Produce json
// @Success 200 {array} Announcement
// @Failure 500 {object} map[string]string
// @Router /api/v1/announcements [get]
func (h *AnnouncementsHandler) GetAnnouncements(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Check if user is authenticated (optional)
	userID := c.Locals("userID")
	isAuthenticated := userID != nil

	// Build query based on authentication status
	var query string
	now := time.Now()

	if isAuthenticated {
		// Show both 'all' and 'logged_in' announcements
		query = `
			SELECT id, title, content, visibility, COALESCE(style, '{}'::jsonb),
			       active, dismissible, priority, start_date, end_date,
			       created_by, created_at, updated_at
			FROM announcements
			WHERE active = true
			  AND (start_date IS NULL OR start_date <= $1)
			  AND (end_date IS NULL OR end_date >= $1)
			  AND visibility IN ('all', 'logged_in')
			ORDER BY priority DESC, created_at DESC
		`
	} else {
		// Show only 'all' announcements
		query = `
			SELECT id, title, content, visibility, COALESCE(style, '{}'::jsonb),
			       active, dismissible, priority, start_date, end_date,
			       created_by, created_at, updated_at
			FROM announcements
			WHERE active = true
			  AND (start_date IS NULL OR start_date <= $1)
			  AND (end_date IS NULL OR end_date >= $1)
			  AND visibility = 'all'
			ORDER BY priority DESC, created_at DESC
		`
	}

	rows, err := h.db.Query(ctx, query, now)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to fetch announcements",
		})
	}
	defer rows.Close()

	announcements := []Announcement{}
	for rows.Next() {
		var a Announcement
		var styleJSON []byte

		if err := rows.Scan(
			&a.ID, &a.Title, &a.Content, &a.Visibility, &styleJSON,
			&a.Active, &a.Dismissible, &a.Priority, &a.StartDate, &a.EndDate,
			&a.CreatedBy, &a.CreatedAt, &a.UpdatedAt,
		); err != nil {
			continue
		}

		// Parse style JSON if present; default to empty map on error or absence.
		if len(styleJSON) > 0 {
			if err := json.Unmarshal(styleJSON, &a.Style); err != nil {
				a.Style = map[string]interface{}{}
			}
		} else {
			a.Style = map[string]interface{}{}
		}

		announcements = append(announcements, a)
	}

	return c.JSON(announcements)
}

// CreateAnnouncement creates a new announcement (admin only)
// @Summary Create announcement
// @Description Create a new system announcement
// @Tags announcements
// @Accept json
// @Produce json
// @Param announcement body CreateAnnouncementRequest true "Announcement data"
// @Success 201 {object} Announcement
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Security BearerAuth
// @Router /api/v1/admin/announcements [post]
func (h *AnnouncementsHandler) CreateAnnouncement(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var req CreateAnnouncementRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	// Validate visibility
	if req.Visibility != "all" && req.Visibility != "logged_in" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Visibility must be 'all' or 'logged_in'",
		})
	}

	userID := c.Locals("userID").(string)

	var announcementID string
	err := h.db.QueryRow(ctx, `
		INSERT INTO announcements (
			title, content, visibility, style, active, dismissible,
			priority, start_date, end_date, created_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING id
	`, req.Title, req.Content, req.Visibility, req.Style, req.Active,
		req.Dismissible, req.Priority, req.StartDate, req.EndDate, userID).Scan(&announcementID)

	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to create announcement",
		})
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"id":      announcementID,
		"message": "Announcement created successfully",
	})
}

// UpdateAnnouncement updates an existing announcement (admin only)
// @Summary Update announcement
// @Description Update an existing announcement
// @Tags announcements
// @Accept json
// @Produce json
// @Param id path string true "Announcement ID"
// @Param announcement body UpdateAnnouncementRequest true "Updated announcement data"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Security BearerAuth
// @Router /api/v1/admin/announcements/{id} [put]
func (h *AnnouncementsHandler) UpdateAnnouncement(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	announcementID := c.Params("id")
	if _, err := uuid.Parse(announcementID); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid announcement ID",
		})
	}

	var req UpdateAnnouncementRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	// Build dynamic update query
	query := `UPDATE announcements SET updated_at = NOW()`
	args := []interface{}{}
	argPos := 1

	if req.Title != nil {
		query += `, title = $` + strconv.Itoa(argPos)
		args = append(args, *req.Title)
		argPos++
	}
	if req.Content != nil {
		query += `, content = $` + strconv.Itoa(argPos)
		args = append(args, *req.Content)
		argPos++
	}
	if req.Visibility != nil {
		if *req.Visibility != "all" && *req.Visibility != "logged_in" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Visibility must be 'all' or 'logged_in'",
			})
		}
		query += `, visibility = $` + strconv.Itoa(argPos)
		args = append(args, *req.Visibility)
		argPos++
	}
	if req.Style != nil {
		query += `, style = $` + strconv.Itoa(argPos)
		args = append(args, req.Style)
		argPos++
	}
	if req.Active != nil {
		query += `, active = $` + strconv.Itoa(argPos)
		args = append(args, *req.Active)
		argPos++
	}
	if req.Dismissible != nil {
		query += `, dismissible = $` + strconv.Itoa(argPos)
		args = append(args, *req.Dismissible)
		argPos++
	}
	if req.Priority != nil {
		query += `, priority = $` + strconv.Itoa(argPos)
		args = append(args, *req.Priority)
		argPos++
	}
	if req.StartDate != nil {
		query += `, start_date = $` + strconv.Itoa(argPos)
		args = append(args, *req.StartDate)
		argPos++
	}
	if req.EndDate != nil {
		query += `, end_date = $` + strconv.Itoa(argPos)
		args = append(args, *req.EndDate)
		argPos++
	}

	query += ` WHERE id = $` + strconv.Itoa(argPos)
	args = append(args, announcementID)

	result, err := h.db.Exec(ctx, query, args...)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to update announcement",
		})
	}

	if result.RowsAffected() == 0 {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "Announcement not found",
		})
	}

	return c.JSON(fiber.Map{
		"message": "Announcement updated successfully",
	})
}

// DeleteAnnouncement deletes an announcement (admin only)
// @Summary Delete announcement
// @Description Delete an announcement
// @Tags announcements
// @Accept json
// @Produce json
// @Param id path string true "Announcement ID"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Security BearerAuth
// @Router /api/v1/admin/announcements/{id} [delete]
func (h *AnnouncementsHandler) DeleteAnnouncement(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	announcementID := c.Params("id")
	if _, err := uuid.Parse(announcementID); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid announcement ID",
		})
	}

	result, err := h.db.Exec(ctx, `
		DELETE FROM announcements WHERE id = $1
	`, announcementID)

	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to delete announcement",
		})
	}

	if result.RowsAffected() == 0 {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "Announcement not found",
		})
	}

	return c.JSON(fiber.Map{
		"message": "Announcement deleted successfully",
	})
}

// GetAllAnnouncements returns all announcements for admin management (admin only)
// @Summary Get all announcements
// @Description Get all announcements including inactive ones for management
// @Tags announcements
// @Accept json
// @Produce json
// @Success 200 {array} Announcement
// @Failure 401 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Security BearerAuth
// @Router /api/v1/admin/announcements [get]
func (h *AnnouncementsHandler) GetAllAnnouncements(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rows, err := h.db.Query(ctx, `
		SELECT id, title, content, visibility, COALESCE(style, '{}'::jsonb),
		       active, dismissible, priority, start_date, end_date,
		       created_by, created_at, updated_at
		FROM announcements
		ORDER BY priority DESC, created_at DESC
	`)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to fetch announcements",
		})
	}
	defer rows.Close()

	announcements := []Announcement{}
	for rows.Next() {
		var a Announcement
		var styleJSON []byte

		if err := rows.Scan(
			&a.ID, &a.Title, &a.Content, &a.Visibility, &styleJSON,
			&a.Active, &a.Dismissible, &a.Priority, &a.StartDate, &a.EndDate,
			&a.CreatedBy, &a.CreatedAt, &a.UpdatedAt,
		); err != nil {
			continue
		}

		// Parse style JSON if present; default to empty map on error or absence.
		if len(styleJSON) > 0 {
			if err := json.Unmarshal(styleJSON, &a.Style); err != nil {
				a.Style = map[string]interface{}{}
			}
		} else {
			a.Style = map[string]interface{}{}
		}

		announcements = append(announcements, a)
	}

	return c.JSON(announcements)
}
