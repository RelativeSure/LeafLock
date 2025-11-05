package handlers

import (
	"context"
	"encoding/json"
	"strconv"
	"time"

	"leaflock/database"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

// AuditLogHandler handles audit log operations
type AuditLogHandler struct {
	db database.Database
}

// NewAuditLogHandler creates a new audit log handler
func NewAuditLogHandler(db database.Database) *AuditLogHandler {
	return &AuditLogHandler{db: db}
}

// AuditLogEntry represents an audit log entry
type AuditLogEntry struct {
	ID           string                 `json:"id"`
	UserID       *string                `json:"user_id"`
	UserEmail    *string                `json:"user_email,omitempty"` // Joined from users table
	Action       string                 `json:"action"`
	ResourceType *string                `json:"resource_type"`
	ResourceID   *string                `json:"resource_id"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt    time.Time              `json:"created_at"`
}

// GetAuditLogsRequest represents the query parameters for fetching audit logs
type GetAuditLogsRequest struct {
	UserID       string `query:"user_id"`
	Action       string `query:"action"`
	ResourceType string `query:"resource_type"`
	StartDate    string `query:"start_date"`
	EndDate      string `query:"end_date"`
	Limit        int    `query:"limit"`
	Offset       int    `query:"offset"`
}

// GetAuditLogsResponse represents the response for audit logs
type GetAuditLogsResponse struct {
	Logs       []AuditLogEntry `json:"logs"`
	Total      int             `json:"total"`
	Limit      int             `json:"limit"`
	Offset     int             `json:"offset"`
	HasMore    bool            `json:"has_more"`
}

// GetAuditLogs returns audit logs with pagination and filtering (admin only)
// @Summary Get audit logs
// @Description Retrieve audit logs with optional filtering by user, action, resource type, and date range
// @Tags Admin
// @Accept json
// @Produce json
// @Param user_id query string false "Filter by user ID"
// @Param action query string false "Filter by action"
// @Param resource_type query string false "Filter by resource type"
// @Param start_date query string false "Start date (ISO 8601)"
// @Param end_date query string false "End date (ISO 8601)"
// @Param limit query int false "Limit" default(50)
// @Param offset query int false "Offset" default(0)
// @Success 200 {object} GetAuditLogsResponse
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/v1/admin/audit-logs [get]
func (h *AuditLogHandler) GetAuditLogs(c *fiber.Ctx) error {
	var req GetAuditLogsRequest
	if err := c.QueryParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid query parameters",
		})
	}

	// Set defaults
	if req.Limit <= 0 || req.Limit > 1000 {
		req.Limit = 50
	}
	if req.Offset < 0 {
		req.Offset = 0
	}

	ctx := context.Background()

	// Build query with filters
	query := `
		SELECT
			a.id,
			a.user_id,
			u.email_plaintext as user_email,
			a.action,
			a.resource_type,
			a.resource_id,
			a.metadata,
			a.created_at
		FROM audit_log a
		LEFT JOIN users u ON a.user_id = u.id
		WHERE 1=1
	`
	args := []interface{}{}
	argIndex := 1

	// Add filters
	if req.UserID != "" {
		query += " AND a.user_id = $" + strconv.Itoa(argIndex)
		args = append(args, req.UserID)
		argIndex++
	}
	if req.Action != "" {
		query += " AND a.action = $" + strconv.Itoa(argIndex)
		args = append(args, req.Action)
		argIndex++
	}
	if req.ResourceType != "" {
		query += " AND a.resource_type = $" + strconv.Itoa(argIndex)
		args = append(args, req.ResourceType)
		argIndex++
	}
	if req.StartDate != "" {
		startDate, err := time.Parse(time.RFC3339, req.StartDate)
		if err == nil {
			query += " AND a.created_at >= $" + strconv.Itoa(argIndex)
			args = append(args, startDate)
			argIndex++
		}
	}
	if req.EndDate != "" {
		endDate, err := time.Parse(time.RFC3339, req.EndDate)
		if err == nil {
			query += " AND a.created_at <= $" + strconv.Itoa(argIndex)
			args = append(args, endDate)
			argIndex++
		}
	}

	// Get total count
	countQuery := "SELECT COUNT(*) FROM audit_log a WHERE 1=1"
	if req.UserID != "" {
		countQuery += " AND a.user_id = '" + req.UserID + "'"
	}
	if req.Action != "" {
		countQuery += " AND a.action = '" + req.Action + "'"
	}
	if req.ResourceType != "" {
		countQuery += " AND a.resource_type = '" + req.ResourceType + "'"
	}

	var total int
	err := h.db.QueryRow(ctx, countQuery).Scan(&total)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to count audit logs",
		})
	}

	// Add ordering and pagination
	query += " ORDER BY a.created_at DESC LIMIT $" + strconv.Itoa(argIndex) + " OFFSET $" + strconv.Itoa(argIndex+1)
	args = append(args, req.Limit, req.Offset)

	// Execute query
	rows, err := h.db.Query(ctx, query, args...)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to fetch audit logs",
		})
	}
	defer rows.Close()

	// Parse results
	logs := []AuditLogEntry{}
	for rows.Next() {
		var log AuditLogEntry
		var userID *uuid.UUID
		var userEmail *string
		var resourceType, resourceID *uuid.UUID
		var metadataJSON []byte

		err := rows.Scan(
			&log.ID,
			&userID,
			&userEmail,
			&log.Action,
			&resourceType,
			&resourceID,
			&metadataJSON,
			&log.CreatedAt,
		)
		if err != nil {
			continue
		}

		// Convert UUIDs to strings
		if userID != nil {
			userIDStr := userID.String()
			log.UserID = &userIDStr
		}
		if userEmail != nil {
			log.UserEmail = userEmail
		}
		if resourceType != nil {
			resTypeStr := resourceType.String()
			log.ResourceType = &resTypeStr
		}
		if resourceID != nil {
			resIDStr := resourceID.String()
			log.ResourceID = &resIDStr
		}

		// Parse metadata JSON
		if metadataJSON != nil {
			var metadata map[string]interface{}
			if err := json.Unmarshal(metadataJSON, &metadata); err == nil {
				log.Metadata = metadata
			}
		}

		logs = append(logs, log)
	}

	return c.JSON(GetAuditLogsResponse{
		Logs:    logs,
		Total:   total,
		Limit:   req.Limit,
		Offset:  req.Offset,
		HasMore: req.Offset+req.Limit < total,
	})
}

// GetUserAuditLogs returns audit logs for the authenticated user
// @Summary Get user's own audit logs
// @Description Retrieve audit logs for the authenticated user
// @Tags Audit Logs
// @Accept json
// @Produce json
// @Param limit query int false "Limit" default(50)
// @Param offset query int false "Offset" default(0)
// @Success 200 {object} GetAuditLogsResponse
// @Failure 401 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/v1/audit-logs [get]
func (h *AuditLogHandler) GetUserAuditLogs(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(string)

	limitStr := c.Query("limit", "50")
	offsetStr := c.Query("offset", "0")

	limit, _ := strconv.Atoi(limitStr)
	offset, _ := strconv.Atoi(offsetStr)

	if limit <= 0 || limit > 1000 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	ctx := context.Background()

	// Get total count
	var total int
	countQuery := "SELECT COUNT(*) FROM audit_log WHERE user_id = $1"
	err := h.db.QueryRow(ctx, countQuery, userID).Scan(&total)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to count audit logs",
		})
	}

	// Fetch logs
	query := `
		SELECT
			id,
			user_id,
			action,
			resource_type,
			resource_id,
			metadata,
			created_at
		FROM audit_log
		WHERE user_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`

	rows, err := h.db.Query(ctx, query, userID, limit, offset)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to fetch audit logs",
		})
	}
	defer rows.Close()

	logs := []AuditLogEntry{}
	for rows.Next() {
		var log AuditLogEntry
		var userIDUUID, resourceType, resourceID *uuid.UUID
		var metadataJSON []byte

		err := rows.Scan(
			&log.ID,
			&userIDUUID,
			&log.Action,
			&resourceType,
			&resourceID,
			&metadataJSON,
			&log.CreatedAt,
		)
		if err != nil {
			continue
		}

		if userIDUUID != nil {
			uid := userIDUUID.String()
			log.UserID = &uid
		}
		if resourceType != nil {
			rt := resourceType.String()
			log.ResourceType = &rt
		}
		if resourceID != nil {
			rid := resourceID.String()
			log.ResourceID = &rid
		}

		if metadataJSON != nil {
			var metadata map[string]interface{}
			if err := json.Unmarshal(metadataJSON, &metadata); err == nil {
				log.Metadata = metadata
			}
		}

		logs = append(logs, log)
	}

	return c.JSON(GetAuditLogsResponse{
		Logs:    logs,
		Total:   total,
		Limit:   limit,
		Offset:  offset,
		HasMore: offset+limit < total,
	})
}
