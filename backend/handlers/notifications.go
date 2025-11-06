package handlers

import (
	"context"
	"time"

	"leaflock/database"
	"leaflock/websocket"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

// NotificationsHandler handles notification operations
type NotificationsHandler struct {
	db  database.Database
	hub *websocket.Hub
}

// NewNotificationsHandler creates a new notifications handler
func NewNotificationsHandler(db database.Database, hub *websocket.Hub) *NotificationsHandler {
	return &NotificationsHandler{
		db:  db,
		hub: hub,
	}
}

// Notification represents an in-app notification
type Notification struct {
	ID        string                 `json:"id"`
	UserID    string                 `json:"user_id"`
	Type      string                 `json:"type"`
	Title     string                 `json:"title"`
	Message   string                 `json:"message"`
	ActionURL *string                `json:"action_url,omitempty"`
	Metadata  map[string]interface{} `json:"metadata"`
	IsRead    bool                   `json:"is_read"`
	CreatedAt time.Time              `json:"created_at"`
	ReadAt    *time.Time             `json:"read_at,omitempty"`
}

// CreateNotificationRequest represents request to create a notification
type CreateNotificationRequest struct {
	Type      string                 `json:"type" validate:"required"`
	Title     string                 `json:"title" validate:"required"`
	Message   string                 `json:"message" validate:"required"`
	ActionURL *string                `json:"action_url,omitempty"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// GetNotifications returns all notifications for the current user
// @Summary Get user notifications
// @Description Retrieve all notifications for the authenticated user
// @Tags Notifications
// @Accept json
// @Produce json
// @Param limit query int false "Limit" default(50)
// @Param offset query int false "Offset" default(0)
// @Param unread_only query bool false "Only unread notifications" default(false)
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/v1/notifications [get]
func (h *NotificationsHandler) GetNotifications(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(string)
	ctx := context.Background()

	// Parse query parameters
	limit := c.QueryInt("limit", 50)
	if limit > 100 {
		limit = 100
	}
	offset := c.QueryInt("offset", 0)
	unreadOnly := c.QueryBool("unread_only", false)

	// Build query
	query := `
		SELECT id, user_id, type, title, message, action_url, metadata, is_read, created_at, read_at
		FROM notifications
		WHERE user_id = $1
	`
	args := []interface{}{userID}

	if unreadOnly {
		query += " AND is_read = false"
	}

	query += " ORDER BY created_at DESC LIMIT $2 OFFSET $3"
	args = append(args, limit, offset)

	rows, err := h.db.Query(ctx, query, args...)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to fetch notifications",
		})
	}
	defer rows.Close()

	notifications := []Notification{}
	for rows.Next() {
		var notification Notification
		var actionURL *string
		var metadata interface{}
		var readAt *time.Time

		err := rows.Scan(
			&notification.ID,
			&notification.UserID,
			&notification.Type,
			&notification.Title,
			&notification.Message,
			&actionURL,
			&metadata,
			&notification.IsRead,
			&notification.CreatedAt,
			&readAt,
		)
		if err != nil {
			continue
		}

		notification.ActionURL = actionURL
		notification.ReadAt = readAt

		// Parse metadata if it exists
		if metadata != nil {
			if m, ok := metadata.(map[string]interface{}); ok {
				notification.Metadata = m
			}
		}
		if notification.Metadata == nil {
			notification.Metadata = make(map[string]interface{})
		}

		notifications = append(notifications, notification)
	}

	// Get unread count
	var unreadCount int
	err = h.db.QueryRow(ctx, `
		SELECT COUNT(*) FROM notifications
		WHERE user_id = $1 AND is_read = false
	`, userID).Scan(&unreadCount)
	if err != nil {
		unreadCount = 0
	}

	return c.JSON(fiber.Map{
		"notifications": notifications,
		"unread_count":  unreadCount,
		"limit":         limit,
		"offset":        offset,
	})
}

// CreateNotification creates a new notification for a user
// @Summary Create notification
// @Description Create a new notification for a specific user
// @Tags Notifications
// @Accept json
// @Produce json
// @Param user_id path string true "User ID"
// @Param notification body CreateNotificationRequest true "Notification data"
// @Success 201 {object} Notification
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/v1/notifications/{user_id} [post]
func (h *NotificationsHandler) CreateNotification(c *fiber.Ctx) error {
	targetUserID := c.Params("user_id")
	ctx := context.Background()

	var req CreateNotificationRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	// Validate notification type
	validTypes := map[string]bool{
		"note_shared":          true,
		"note_commented":       true,
		"folder_shared":        true,
		"mention":              true,
		"system":               true,
		"collaboration_invite": true,
	}
	if !validTypes[req.Type] {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid notification type",
		})
	}

	var notificationID uuid.UUID
	err := h.db.QueryRow(ctx, `
		INSERT INTO notifications (user_id, type, title, message, action_url, metadata)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id`,
		targetUserID, req.Type, req.Title, req.Message, req.ActionURL, req.Metadata).Scan(&notificationID)

	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to create notification",
		})
	}

	notification := Notification{
		ID:        notificationID.String(),
		UserID:    targetUserID,
		Type:      req.Type,
		Title:     req.Title,
		Message:   req.Message,
		ActionURL: req.ActionURL,
		Metadata:  req.Metadata,
		IsRead:    false,
		CreatedAt: time.Now(),
	}

	// Broadcast notification via WebSocket if user is connected
	if h.hub != nil {
		targetUUID, err := uuid.Parse(targetUserID)
		if err == nil {
			wsMessage := websocket.WSMessage{
				Type:   "notification",
				UserID: targetUserID,
				Content: websocket.NotificationMessage{
					ID:        notification.ID,
					Type:      notification.Type,
					Title:     notification.Title,
					Message:   notification.Message,
					ActionURL: notification.ActionURL,
					Metadata:  notification.Metadata,
					CreatedAt: notification.CreatedAt.Format(time.RFC3339),
				},
			}
			_ = h.hub.BroadcastToUser(targetUUID, wsMessage)
		}
	}

	return c.Status(fiber.StatusCreated).JSON(notification)
}

// MarkAsRead marks a notification as read
// @Summary Mark notification as read
// @Description Mark a specific notification as read
// @Tags Notifications
// @Accept json
// @Produce json
// @Param id path string true "Notification ID"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/v1/notifications/{id}/read [post]
func (h *NotificationsHandler) MarkAsRead(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(string)
	notificationID := c.Params("id")
	ctx := context.Background()

	result, err := h.db.Exec(ctx, `
		UPDATE notifications
		SET is_read = true, read_at = NOW()
		WHERE id = $1 AND user_id = $2`,
		notificationID, userID)

	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to mark notification as read",
		})
	}

	if result.RowsAffected() == 0 {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "Notification not found",
		})
	}

	return c.JSON(fiber.Map{
		"message": "Notification marked as read",
	})
}

// MarkAllAsRead marks all notifications as read for the current user
// @Summary Mark all notifications as read
// @Description Mark all notifications as read for the authenticated user
// @Tags Notifications
// @Accept json
// @Produce json
// @Success 200 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/v1/notifications/read-all [post]
func (h *NotificationsHandler) MarkAllAsRead(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(string)
	ctx := context.Background()

	_, err := h.db.Exec(ctx, `
		UPDATE notifications
		SET is_read = true, read_at = NOW()
		WHERE user_id = $1 AND is_read = false`,
		userID)

	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to mark all notifications as read",
		})
	}

	return c.JSON(fiber.Map{
		"message": "All notifications marked as read",
	})
}

// DeleteNotification deletes a specific notification
// @Summary Delete notification
// @Description Delete a specific notification
// @Tags Notifications
// @Accept json
// @Produce json
// @Param id path string true "Notification ID"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/v1/notifications/{id} [delete]
func (h *NotificationsHandler) DeleteNotification(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(string)
	notificationID := c.Params("id")
	ctx := context.Background()

	result, err := h.db.Exec(ctx, `
		DELETE FROM notifications
		WHERE id = $1 AND user_id = $2`,
		notificationID, userID)

	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to delete notification",
		})
	}

	if result.RowsAffected() == 0 {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "Notification not found",
		})
	}

	return c.JSON(fiber.Map{
		"message": "Notification deleted successfully",
	})
}

// GetUnreadCount returns the count of unread notifications
// @Summary Get unread notification count
// @Description Get the count of unread notifications for the authenticated user
// @Tags Notifications
// @Accept json
// @Produce json
// @Success 200 {object} map[string]int
// @Failure 500 {object} map[string]string
// @Router /api/v1/notifications/unread-count [get]
func (h *NotificationsHandler) GetUnreadCount(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(string)
	ctx := context.Background()

	var unreadCount int
	err := h.db.QueryRow(ctx, `
		SELECT COUNT(*) FROM notifications
		WHERE user_id = $1 AND is_read = false
	`, userID).Scan(&unreadCount)

	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to get unread count",
		})
	}

	return c.JSON(fiber.Map{
		"unread_count": unreadCount,
	})
}
