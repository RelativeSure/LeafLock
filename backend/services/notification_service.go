package services

import (
	"context"
	"strings"

	"leaflock/database"
)

// NotificationService handles email notifications based on database templates
type NotificationService struct {
	db           database.Database
	emailService *EmailService
}

// NewNotificationService creates a new notification service
func NewNotificationService(db database.Database, emailService *EmailService) *NotificationService {
	return &NotificationService{
		db:           db,
		emailService: emailService,
	}
}

// EmailTemplate represents an email template from the database
type EmailTemplate struct {
	Name      string
	Subject   string
	BodyHTML  string
	BodyText  string
	Variables []string
}

// GetTemplate retrieves an email template from the database
func (s *NotificationService) GetTemplate(ctx context.Context, name string) (*EmailTemplate, error) {
	var template EmailTemplate
	err := s.db.QueryRow(ctx, `
		SELECT name, subject, body_html, body_text
		FROM email_templates
		WHERE name = $1`,
		name).Scan(&template.Name, &template.Subject, &template.BodyHTML, &template.BodyText)

	if err != nil {
		return nil, err
	}

	return &template, nil
}

// RenderTemplate replaces variables in template with actual values
func (s *NotificationService) RenderTemplate(template *EmailTemplate, variables map[string]string) (subject, htmlBody, textBody string) {
	subject = template.Subject
	htmlBody = template.BodyHTML
	textBody = template.BodyText

	// Replace all variables
	for key, value := range variables {
		placeholder := "{{" + key + "}}"
		subject = strings.ReplaceAll(subject, placeholder, value)
		htmlBody = strings.ReplaceAll(htmlBody, placeholder, value)
		textBody = strings.ReplaceAll(textBody, placeholder, value)
	}

	return subject, htmlBody, textBody
}

// SendNotificationEmail sends a notification email using a template
func (s *NotificationService) SendNotificationEmail(ctx context.Context, to, templateName string, variables map[string]string) error {
	// Get template from database
	template, err := s.GetTemplate(ctx, templateName)
	if err != nil {
		return err
	}

	// Render template with variables
	subject, htmlBody, textBody := s.RenderTemplate(template, variables)

	// Send email
	return s.emailService.SendEmail(to, subject, htmlBody, textBody)
}

// SendNoteSharedNotification sends a notification when a note is shared
func (s *NotificationService) SendNoteSharedNotification(ctx context.Context, recipientEmail, recipientName, senderName, noteTitle, permission, noteURL string) error {
	variables := map[string]string{
		"recipient_name": recipientName,
		"sender_name":    senderName,
		"note_title":     noteTitle,
		"permission":     permission,
		"note_url":       noteURL,
	}
	return s.SendNotificationEmail(ctx, recipientEmail, "note_shared", variables)
}

// SendCollaborationInvite sends a notification when invited to collaborate
func (s *NotificationService) SendCollaborationInvite(ctx context.Context, recipientEmail, recipientName, senderName, noteTitle, noteURL string) error {
	variables := map[string]string{
		"recipient_name": recipientName,
		"sender_name":    senderName,
		"note_title":     noteTitle,
		"note_url":       noteURL,
	}
	return s.SendNotificationEmail(ctx, recipientEmail, "collaboration_invite", variables)
}

// SendPasswordResetEmail sends a password reset email
func (s *NotificationService) SendPasswordResetEmail(ctx context.Context, userEmail, userName, resetURL string) error {
	variables := map[string]string{
		"user_name":  userName,
		"reset_url":  resetURL,
	}
	return s.SendNotificationEmail(ctx, userEmail, "password_reset", variables)
}

// CheckUserEmailPreference checks if user has enabled email notifications for a specific event
func (s *NotificationService) CheckUserEmailPreference(ctx context.Context, userID, preferenceType string) (bool, error) {
	var enabled bool
	query := `SELECT COALESCE(email_notifications, false) FROM users WHERE id = $1`

	// Adjust query based on preference type
	switch preferenceType {
	case "note_shared":
		query = `SELECT COALESCE(email_on_note_shared, true) FROM users WHERE id = $1`
	case "collaboration":
		query = `SELECT COALESCE(email_on_collaboration, true) FROM users WHERE id = $1`
	case "mention":
		query = `SELECT COALESCE(email_on_mention, true) FROM users WHERE id = $1`
	}

	err := s.db.QueryRow(ctx, query, userID).Scan(&enabled)
	if err != nil {
		return false, err
	}

	return enabled, nil
}
