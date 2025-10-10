package services

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"html/template"
	"log"
	"net/smtp"
	"path/filepath"
	"strings"
	"time"

	"github.com/jordan-wright/email"
	"leaflock/config"
)

// EmailService handles email sending operations
type EmailService struct {
	config *config.Config
}

// NewEmailService creates a new email service
func NewEmailService(cfg *config.Config) *EmailService {
	return &EmailService{
		config: cfg,
	}
}

// EmailData represents data for email templates
type EmailData struct {
	Subject       string
	RecipientName string
	AppName       string
	AppURL        string
	Year          int
	// Additional template-specific fields
	Data map[string]interface{}
}

// SendEmail sends an email using the configured SMTP server
func (s *EmailService) SendEmail(to string, subject string, htmlBody string, textBody string) error {
	if !s.config.SMTPEnabled {
		log.Printf("📧 [EMAIL-DISABLED] Would send email to: %s, Subject: %s", to, subject)
		log.Printf("📧 [EMAIL-PREVIEW] HTML Length: %d bytes, Text Length: %d bytes", len(htmlBody), len(textBody))
		return nil
	}

	e := email.NewEmail()
	e.From = s.config.SMTPFrom
	e.To = []string{to}
	e.Subject = subject
	e.HTML = []byte(htmlBody)
	e.Text = []byte(textBody)

	// Setup TLS config
	var tlsConfig *tls.Config
	if s.config.SMTPInsecure {
		tlsConfig = &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         s.config.SMTPHost,
		}
	} else {
		tlsConfig = &tls.Config{
			ServerName: s.config.SMTPHost,
		}
	}

	// Send email with retry logic
	var lastErr error
	for i := 0; i < 3; i++ {
		if i > 0 {
			time.Sleep(time.Duration(i) * time.Second)
		}

		var err error
		if s.config.SMTPUseTLS {
			auth := smtp.PlainAuth("", s.config.SMTPUser, s.config.SMTPPassword, s.config.SMTPHost)
			addr := fmt.Sprintf("%s:%d", s.config.SMTPHost, s.config.SMTPPort)
			err = e.SendWithTLS(addr, auth, tlsConfig)
		} else {
			addr := fmt.Sprintf("%s:%d", s.config.SMTPHost, s.config.SMTPPort)
			err = e.Send(addr, nil)
		}

		if err == nil {
			log.Printf("✅ Email sent successfully to: %s, Subject: %s", to, subject)
			return nil
		}
		lastErr = err
		log.Printf("⚠️  Email send attempt %d failed: %v", i+1, err)
	}

	log.Printf("❌ Failed to send email to %s after 3 attempts: %v", to, lastErr)
	return fmt.Errorf("failed to send email: %w", lastErr)
}

// SendTemplateEmail sends an email using a template
func (s *EmailService) SendTemplateEmail(to string, templateName string, data EmailData) error {
	// Set default values
	if data.AppName == "" {
		data.AppName = "LeafLock"
	}
	if data.AppURL == "" {
		data.AppURL = "https://leaflock.app" // Update with your actual URL
	}
	if data.Year == 0 {
		data.Year = time.Now().Year()
	}

	// Load and parse template
	htmlPath := filepath.Join("templates", "emails", templateName+".html")
	htmlTmpl, err := template.ParseFiles(htmlPath)
	if err != nil {
		return fmt.Errorf("failed to load email template %s: %w", templateName, err)
	}

	// Render HTML
	var htmlBuffer bytes.Buffer
	if err := htmlTmpl.Execute(&htmlBuffer, data); err != nil {
		return fmt.Errorf("failed to render email template %s: %w", templateName, err)
	}

	// Generate plain text version (strip HTML tags)
	textBody := stripHTMLTags(htmlBuffer.String())

	return s.SendEmail(to, data.Subject, htmlBuffer.String(), textBody)
}

// stripHTMLTags is a simple HTML tag stripper for plain text emails
func stripHTMLTags(html string) string {
	// Remove HTML tags using simple string replacement
	text := html
	text = strings.ReplaceAll(text, "<br>", "\n")
	text = strings.ReplaceAll(text, "<br/>", "\n")
	text = strings.ReplaceAll(text, "<br />", "\n")
	text = strings.ReplaceAll(text, "</p>", "\n\n")
	text = strings.ReplaceAll(text, "</div>", "\n")
	text = strings.ReplaceAll(text, "</li>", "\n")

	// Remove all remaining HTML tags
	var result strings.Builder
	inTag := false
	for _, char := range text {
		if char == '<' {
			inTag = true
		} else if char == '>' {
			inTag = false
		} else if !inTag {
			result.WriteRune(char)
		}
	}

	// Clean up multiple newlines
	cleaned := strings.ReplaceAll(result.String(), "\n\n\n", "\n\n")
	cleaned = strings.TrimSpace(cleaned)

	return cleaned
}

// SendWelcomeEmail sends welcome email to new users
func (s *EmailService) SendWelcomeEmail(toEmail string, userName string) error {
	data := EmailData{
		Subject:       "Welcome to LeafLock! 🔒",
		RecipientName: userName,
		Data: map[string]interface{}{
			"getting_started_url": "https://docs.leaflock.app/getting-started",
			"docs_url":            "https://docs.leaflock.app",
		},
	}
	return s.SendTemplateEmail(toEmail, "welcome", data)
}

// SendPasswordResetEmail sends password reset email
func (s *EmailService) SendPasswordResetEmail(toEmail string, resetToken string, ipAddress string) error {
	resetURL := fmt.Sprintf("%s/reset-password?token=%s", s.config.FrontendURL, resetToken)

	data := EmailData{
		Subject: "LeafLock Password Reset Request",
		Data: map[string]interface{}{
			"reset_url":    resetURL,
			"expires_in":   "1 hour",
			"ip_address":   ipAddress,
			"request_time": time.Now().Format("2006-01-02 15:04:05 MST"),
		},
	}
	return s.SendTemplateEmail(toEmail, "password_reset", data)
}

// SendPasswordChangedEmail sends confirmation that password was changed
func (s *EmailService) SendPasswordChangedEmail(toEmail string, ipAddress string) error {
	data := EmailData{
		Subject: "Your LeafLock Password Was Changed",
		Data: map[string]interface{}{
			"change_time": time.Now().Format("2006-01-02 15:04:05 MST"),
			"ip_address":  ipAddress,
		},
	}
	return s.SendTemplateEmail(toEmail, "password_changed", data)
}
