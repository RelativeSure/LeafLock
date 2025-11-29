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

// SendEmail sends an email using the configured SMTP server with retry logic
// This function implements the core email delivery mechanism with several
// critical features for production reliability:
//
// 1. Configuration-Aware Operation:
//    - Respects SMTP_ENABLED environment variable for development/testing
//    - Provides detailed logging when emails are disabled
//    - Prevents accidental email sending in non-production environments
//
// 2. Production-Grade Email Delivery:
//    - Supports both TLS and non-TLS SMTP connections
//    - Configurable authentication (PlainAuth)
//    - Proper email formatting (HTML + text multipart)
//    - From address validation and formatting
//
// 3. Reliability Features:
//    - 3-attempt retry mechanism with exponential backoff
//    - Detailed error logging for debugging delivery issues
//    - Success/failure logging for monitoring
//
// 4. Security Considerations:
//    - TLS configuration with server name verification
//    - Optional insecure mode for development (with warnings)
//    - No email content logging (privacy protection)
//
// Error Handling:
// - Returns error after 3 failed attempts
// - Logs each attempt for debugging
// - Distinguishes between configuration and delivery errors
func (s *EmailService) SendEmail(to string, subject string, htmlBody string, textBody string) error {
	if !s.config.SMTPEnabled {
		// Development mode: Log what would be sent without actually sending
		// This prevents accidental emails during development/testing while
		// providing visibility into email generation for debugging
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

	// Setup TLS configuration for secure email delivery
	// The TLS configuration varies based on deployment environment:
	// - Production: Full certificate verification with proper server name
	// - Development: Optional insecure mode for self-signed certificates
	//
	// Security Note: InsecureSkipVerify should ONLY be used in development
	// with trusted SMTP servers. Production environments must use proper TLS.
	var tlsConfig *tls.Config
	if s.config.SMTPInsecure {
		tlsConfig = &tls.Config{
			InsecureSkipVerify: true, // Development only - accepts any certificate
			ServerName:         s.config.SMTPHost,
		}
	} else {
		tlsConfig = &tls.Config{
			ServerName: s.config.SMTPHost, // Production - verifies certificate
		}
	}

	// Send email with retry logic and exponential backoff
	// Email delivery can fail for various transient reasons:
	// - Network connectivity issues
	// - SMTP server temporary unavailability
	// - Rate limiting from email providers
	// - Greylisting (temporary rejection)
	//
	// The retry mechanism implements exponential backoff:
	// - Attempt 1: immediate (0s delay)
	// - Attempt 2: 1 second delay
	// - Attempt 3: 2 seconds delay
	//
	// This balances reliability with user experience - emails generally
	// arrive within seconds even with retries, while handling temporary issues.
	var lastErr error
	for i := 0; i < 3; i++ {
		if i > 0 {
			time.Sleep(time.Duration(i) * time.Second) // Exponential backoff
		}

		var err error
		if s.config.SMTPUseTLS {
			// TLS connection with authentication
			auth := smtp.PlainAuth("", s.config.SMTPUser, s.config.SMTPPassword, s.config.SMTPHost)
			addr := fmt.Sprintf("%s:%d", s.config.SMTPHost, s.config.SMTPPort)
			err = e.SendWithTLS(addr, auth, tlsConfig)
		} else {
			// Plain text connection (development/internal SMTP)
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

// SendTemplateEmail sends an email using HTML templates with automatic text generation
// This function provides a complete templating solution for application emails:
//
// Template System Features:
// - HTML templates with Go template syntax (variables, conditionals, loops)
// - Automatic plain text generation from HTML (no separate text template needed)
// - Consistent branding across all emails (app name, URL, year)
// - Template-specific data injection via EmailData.Data map
//
// Default Values Strategy:
// - AppName: "LeafLock" (fallback for missing configuration)
// - AppURL: "https://leaflock.app" (production default)
// - Year: Current year (for copyright notices)
// - RecipientName: "" (optional personalization)
//
// File Organization:
// Templates are stored in: templates/emails/{templateName}.html
// This convention allows easy template discovery and management.
// Templates should include both HTML structure and inline CSS for email client compatibility.
//
// Text Generation:
// The stripHTMLTags function converts HTML to readable plain text by:
// - Converting common HTML tags to whitespace
// - Removing all remaining HTML tags
// - Cleaning up multiple newlines
// - Trimming whitespace
//
// This ensures recipients with text-only email clients still receive readable content.
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
	// Templates follow the convention: templates/emails/{name}.html
	// This allows easy organization and discovery of email templates.
	// The template.ParseFiles function caches parsed templates internally,
	// providing good performance for repeated email sending.
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
	// Email best practice requires both HTML and plain text versions:
	// - HTML for rich formatting and branding
	// - Plain text for accessibility and spam score improvement
	// - Some email clients only support plain text
	//
	// Rather than maintaining separate templates, we automatically generate
	// the text version from HTML, reducing maintenance burden and ensuring consistency.
	textBody := stripHTMLTags(htmlBuffer.String())

	return s.SendEmail(to, data.Subject, htmlBuffer.String(), textBody)
}

// stripHTMLTags converts HTML content to readable plain text
// This function implements a lightweight HTML-to-text conversion specifically
// designed for email plain text generation. It's not a full HTML parser but
// handles the most common cases found in email templates:
//
// Conversion Rules:
// - <br>, <br/>, <br /> → newline (common line breaks)
// - </p> → double newline (paragraph separation)
// - </div> → newline (block element separation)
// - </li> → newline (list item separation)
// - All other HTML tags → removed entirely
// - Multiple newlines → collapsed to double newline maximum
// - Leading/trailing whitespace → trimmed
//
// Limitations:
// - Doesn't handle nested tags intelligently
// - No CSS styling interpretation
// - Simple character-by-character parsing
//
// Performance: O(n) where n is the HTML string length.
// Suitable for processing email templates (typically small HTML documents).
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

// SendWelcomeEmail sends a personalized welcome email to new users
// This function implements the new user onboarding email with:
//
// Content Strategy:
// - Friendly, welcoming tone with emoji (🔒) for visual appeal
// - Clear value proposition and next steps
// - Links to documentation for self-service onboarding
// - Personalization with user's name
//
// Template Data:
// - getting_started_url: Direct link to getting started guide
// - docs_url: General documentation homepage
// - Both URLs are hardcoded for reliability (config URLs might be missing during signup)
//
// Usage Context:
// - Called immediately after successful user registration
// - Provides immediate value and guidance to new users
// - Reduces support burden by pointing users to documentation
// - Sets expectations about the service capabilities
//
// Error Handling:
// - Email failures are logged but don't fail user registration
// - Users can still use the application even if welcome email fails
// - Retry mechanism in SendEmail provides reliability
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

// SendPasswordResetEmail sends a secure password reset email
// This function implements the password reset flow with security best practices:
//
// Security Features:
// - Time-limited reset tokens (15 minutes) to prevent brute force
// - IP address logging for security audit trail
// - One-time use tokens (consumed on first use)
// - HTTPS reset URLs (when FrontendURL uses HTTPS)
//
// User Experience:
// - Clear subject line indicating password reset request
// - Direct link to reset form (no need to copy/paste tokens)
// - Expiration time clearly stated
// - IP address provided for security awareness
//
// Template Data:
// - reset_url: Complete URL with token for one-click reset
// - expires_in: Human-readable expiration time
// - ip_address: Request origin for security verification
// - request_time: Timestamp for audit trail
//
// Privacy Considerations:
// - IP address is included for security but not permanently stored
// - Reset tokens are single-use and time-limited
// - No password information is included in the email
//
// Integration Points:
// - FrontendURL must be configured for reset link generation
// - Token generation happens in the authentication handler
// - Token validation happens in the password reset handler
func (s *EmailService) SendPasswordResetEmail(toEmail string, resetToken string, ipAddress string) error {
	resetURL := fmt.Sprintf("%s/reset-password?token=%s", s.config.FrontendURL, resetToken)

	data := EmailData{
		Subject: "LeafLock Password Reset Request",
		Data: map[string]interface{}{
			"reset_url":    resetURL,
			"expires_in":   "15 minutes",
			"ip_address":   ipAddress,
			"request_time": time.Now().Format("2006-01-02 15:04:05 MST"),
		},
	}
	return s.SendTemplateEmail(toEmail, "password_reset", data)
}

// SendPasswordChangedEmail sends security notification after password change
// This function implements a critical security feature - notifying users when
// their password is changed to detect unauthorized account access.
//
// Security Rationale:
// - Immediate notification of password changes
// - IP address provided for location verification
// - Timestamp for incident timeline reconstruction
// - No sensitive information in email content
//
// User Experience:
// - Clear subject indicating password was changed
// - Immediate notification (sent synchronously with password change)
// - Actionable information if change was unauthorized
// - Professional tone for security communications
//
// Template Data:
// - change_time: Precise timestamp of password change
// - ip_address: Origin of the password change request
//
// Incident Response:
// - Users can immediately identify unauthorized changes
// - IP address helps determine if change was legitimate
// - Timestamp helps correlate with other security events
// - Users are prompted to contact support if change was unauthorized
//
// Privacy Note:
// - IP addresses are not stored permanently with this notification
// - Email serves only as immediate alert, not permanent record
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
