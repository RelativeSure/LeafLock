package handlers

import (
	"context"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"leaflock/database"
)

// AnalyticsHandler handles analytics and reporting operations
type AnalyticsHandler struct {
	db database.Database
}

// NewAnalyticsHandler creates a new analytics handler
func NewAnalyticsHandler(db database.Database) *AnalyticsHandler {
	return &AnalyticsHandler{db: db}
}

// UserStats represents user analytics data
type UserStats struct {
	TotalNotes          int                   `json:"total_notes"`
	TotalFolders        int                   `json:"total_folders"`
	TotalTags           int                   `json:"total_tags"`
	TotalCollaborations int                   `json:"total_collaborations"`
	NotesCreatedToday   int                   `json:"notes_created_today"`
	NotesCreatedWeek    int                   `json:"notes_created_week"`
	NotesCreatedMonth   int                   `json:"notes_created_month"`
	ActivityByDay       []ActivityData        `json:"activity_by_day"`
	NotesByFolder       []CountData           `json:"notes_by_folder"`
	NotesByTag          []CountData           `json:"notes_by_tag"`
	RecentActivity      []RecentActivityEntry `json:"recent_activity"`
}

// ActivityData represents daily activity count
type ActivityData struct {
	Date  string `json:"date"`
	Count int    `json:"count"`
}

// CountData represents count by category
type CountData struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// RecentActivityEntry represents a recent activity item
type RecentActivityEntry struct {
	Type      string `json:"type"`
	Message   string `json:"message"`
	Timestamp string `json:"timestamp"`
}

// GetUserAnalytics returns analytics data for the current user
// @Summary Get user analytics
// @Description Get analytics and statistics for the authenticated user
// @Tags Analytics
// @Produce json
// @Success 200 {object} UserStats
// @Failure 500 {object} map[string]string
// @Router /api/v1/analytics [get]
func (h *AnalyticsHandler) GetUserAnalytics(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)
	ctx := context.Background()

	stats := UserStats{}

	// Get total notes
	err := h.db.QueryRow(ctx, `
		SELECT COUNT(*) FROM notes n
		JOIN workspaces w ON n.workspace_id = w.id
		WHERE w.owner_id = $1 AND n.deleted_at IS NULL`,
		userID).Scan(&stats.TotalNotes)
	if err != nil {
		stats.TotalNotes = 0
	}

	// Get total folders
	err = h.db.QueryRow(ctx, `
		SELECT COUNT(*) FROM folders
		WHERE user_id = $1`,
		userID).Scan(&stats.TotalFolders)
	if err != nil {
		stats.TotalFolders = 0
	}

	// Get total tags
	err = h.db.QueryRow(ctx, `
		SELECT COUNT(*) FROM tags
		WHERE user_id = $1`,
		userID).Scan(&stats.TotalTags)
	if err != nil {
		stats.TotalTags = 0
	}

	// Get total collaborations (notes shared with user)
	err = h.db.QueryRow(ctx, `
		SELECT COUNT(*) FROM collaborations
		WHERE user_id = $1`,
		userID).Scan(&stats.TotalCollaborations)
	if err != nil {
		stats.TotalCollaborations = 0
	}

	// Notes created today
	err = h.db.QueryRow(ctx, `
		SELECT COUNT(*) FROM notes n
		JOIN workspaces w ON n.workspace_id = w.id
		WHERE w.owner_id = $1 AND n.deleted_at IS NULL
		AND n.created_at >= CURRENT_DATE`,
		userID).Scan(&stats.NotesCreatedToday)
	if err != nil {
		stats.NotesCreatedToday = 0
	}

	// Notes created this week
	err = h.db.QueryRow(ctx, `
		SELECT COUNT(*) FROM notes n
		JOIN workspaces w ON n.workspace_id = w.id
		WHERE w.owner_id = $1 AND n.deleted_at IS NULL
		AND n.created_at >= CURRENT_DATE - INTERVAL '7 days'`,
		userID).Scan(&stats.NotesCreatedWeek)
	if err != nil {
		stats.NotesCreatedWeek = 0
	}

	// Notes created this month
	err = h.db.QueryRow(ctx, `
		SELECT COUNT(*) FROM notes n
		JOIN workspaces w ON n.workspace_id = w.id
		WHERE w.owner_id = $1 AND n.deleted_at IS NULL
		AND n.created_at >= CURRENT_DATE - INTERVAL '30 days'`,
		userID).Scan(&stats.NotesCreatedMonth)
	if err != nil {
		stats.NotesCreatedMonth = 0
	}

	// Activity by day (last 30 days)
	rows, err := h.db.Query(ctx, `
		SELECT DATE(n.created_at) as date, COUNT(*) as count
		FROM notes n
		JOIN workspaces w ON n.workspace_id = w.id
		WHERE w.owner_id = $1
		AND n.created_at >= CURRENT_DATE - INTERVAL '30 days'
		GROUP BY DATE(n.created_at)
		ORDER BY date DESC`,
		userID)

	if err == nil {
		defer rows.Close()
		stats.ActivityByDay = []ActivityData{}
		for rows.Next() {
			var activity ActivityData
			var date time.Time
			if err := rows.Scan(&date, &activity.Count); err != nil {
				continue
			}
			activity.Date = date.Format("2006-01-02")
			stats.ActivityByDay = append(stats.ActivityByDay, activity)
		}
	}

	// Notes by folder
	rows, err = h.db.Query(ctx, `
		SELECT COALESCE(f.name_encrypted::text, 'Uncategorized') as folder, COUNT(*) as count
		FROM notes n
		JOIN workspaces w ON n.workspace_id = w.id
		LEFT JOIN folders f ON n.folder_id = f.id
		WHERE w.owner_id = $1 AND n.deleted_at IS NULL
		GROUP BY f.name_encrypted
		ORDER BY count DESC
		LIMIT 10`,
		userID)

	if err == nil {
		defer rows.Close()
		stats.NotesByFolder = []CountData{}
		for rows.Next() {
			var data CountData
			if err := rows.Scan(&data.Name, &data.Count); err != nil {
				continue
			}
			stats.NotesByFolder = append(stats.NotesByFolder, data)
		}
	}

	// Notes by tag
	rows, err = h.db.Query(ctx, `
		SELECT t.name_encrypted::text as tag, COUNT(DISTINCT nt.note_id) as count
		FROM tags t
		JOIN note_tags nt ON t.id = nt.tag_id
		WHERE t.user_id = $1
		GROUP BY t.name_encrypted
		ORDER BY count DESC
		LIMIT 10`,
		userID)

	if err == nil {
		defer rows.Close()
		stats.NotesByTag = []CountData{}
		for rows.Next() {
			var data CountData
			if err := rows.Scan(&data.Name, &data.Count); err != nil {
				continue
			}
			stats.NotesByTag = append(stats.NotesByTag, data)
		}
	}

	// Recent activity from audit log
	rows, err = h.db.Query(ctx, `
		SELECT action, metadata, created_at
		FROM audit_log
		WHERE user_id = $1
		ORDER BY created_at DESC
		LIMIT 20`,
		userID)

	if err == nil {
		defer rows.Close()
		stats.RecentActivity = []RecentActivityEntry{}
		for rows.Next() {
			var action string
			var metadata interface{}
			var createdAt time.Time
			if err := rows.Scan(&action, &metadata, &createdAt); err != nil {
				continue
			}

			entry := RecentActivityEntry{
				Type:      action,
				Message:   action,
				Timestamp: createdAt.Format(time.RFC3339),
			}
			stats.RecentActivity = append(stats.RecentActivity, entry)
		}
	}

	return c.JSON(stats)
}

// GetAdminAnalytics returns system-wide analytics (admin only)
// @Summary Get admin analytics
// @Description Get system-wide analytics and statistics (admin only)
// @Tags Analytics
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Failure 403 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/v1/admin/analytics [get]
func (h *AnalyticsHandler) GetAdminAnalytics(c *fiber.Ctx) error {
	ctx := context.Background()

	stats := make(map[string]interface{})

	// Total users
	var totalUsers int
	_ = h.db.QueryRow(ctx, `SELECT COUNT(*) FROM users WHERE deleted_at IS NULL`).Scan(&totalUsers)
	stats["total_users"] = totalUsers

	// Total notes
	var totalNotes int
	_ = h.db.QueryRow(ctx, `SELECT COUNT(*) FROM notes WHERE deleted_at IS NULL`).Scan(&totalNotes)
	stats["total_notes"] = totalNotes

	// Total workspaces
	var totalWorkspaces int
	_ = h.db.QueryRow(ctx, `SELECT COUNT(*) FROM workspaces`).Scan(&totalWorkspaces)
	stats["total_workspaces"] = totalWorkspaces

	// Active users (logged in last 30 days)
	var activeUsers int
	_ = h.db.QueryRow(ctx, `
		SELECT COUNT(*) FROM users
		WHERE last_login >= CURRENT_DATE - INTERVAL '30 days'
		AND deleted_at IS NULL`).Scan(&activeUsers)
	stats["active_users"] = activeUsers

	// User growth (last 30 days by day)
	rows, err := h.db.Query(ctx, `
		SELECT DATE(created_at) as date, COUNT(*) as count
		FROM users
		WHERE created_at >= CURRENT_DATE - INTERVAL '30 days'
		GROUP BY DATE(created_at)
		ORDER BY date DESC`)

	if err == nil {
		defer rows.Close()
		userGrowth := []ActivityData{}
		for rows.Next() {
			var activity ActivityData
			var date time.Time
			if err := rows.Scan(&date, &activity.Count); err != nil {
				continue
			}
			activity.Date = date.Format("2006-01-02")
			userGrowth = append(userGrowth, activity)
		}
		stats["user_growth"] = userGrowth
	}

	// Note creation over time
	rows, err = h.db.Query(ctx, `
		SELECT DATE(created_at) as date, COUNT(*) as count
		FROM notes
		WHERE created_at >= CURRENT_DATE - INTERVAL '30 days'
		GROUP BY DATE(created_at)
		ORDER BY date DESC`)

	if err == nil {
		defer rows.Close()
		noteGrowth := []ActivityData{}
		for rows.Next() {
			var activity ActivityData
			var date time.Time
			if err := rows.Scan(&date, &activity.Count); err != nil {
				continue
			}
			activity.Date = date.Format("2006-01-02")
			noteGrowth = append(noteGrowth, activity)
		}
		stats["note_growth"] = noteGrowth
	}

	return c.JSON(stats)
}
