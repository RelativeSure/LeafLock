# SMTP Integration Implementation Guide for LeafLock

**Status**: Planning Complete - Ready for Implementation
**Estimated Effort**: 30 hours
**Priority**: High (Password reset is a critical security feature)

---

## 📋 Implementation Checklist

### Phase 1: SMTP Infrastructure ⚙️ ✅ COMPLETE

- [x] Add SMTP configuration to `backend/config/config.go`
- [x] Update `.env.example` with SMTP variables
- [x] Create `backend/services/email_service.go`
- [x] Add Go dependencies: `go get github.com/jordan-wright/email`
- [x] Create email templates directory: `backend/templates/emails/`
- [x] Test SMTP connection and basic email sending

### Phase 2: Password Reset 🔑 ✅ COMPLETE

- [x] Add `password_reset_tokens` table to `backend/database/schema.go`
- [x] Bump `MigrationSchemaVersion` in `backend/database/database.go` (2025.10.09.001)
- [x] Create password reset handlers in `backend/handlers/auth.go`:
  - [x] `RequestPasswordReset` - POST `/api/v1/auth/password/reset-request`
  - [x] `VerifyResetToken` - GET `/api/v1/auth/password/reset-verify`
  - [x] `ConfirmPasswordReset` - POST `/api/v1/auth/password/reset-confirm`
- [x] Create email templates:
  - [x] `backend/templates/emails/password_reset.html`
  - [x] `backend/templates/emails/password_changed.html`
- [x] Add routes to `backend/routes.go`
- [ ] Write tests: `backend/handlers/password_reset_test.go`

### Phase 3: Welcome Emails 📧 ✅ COMPLETE

- [x] Create `backend/templates/emails/welcome.html`
- [x] Add welcome email to registration flow in `backend/handlers/auth.go:Register()` (line 331)
- [x] Test welcome email delivery (non-blocking implementation)

### Phase 4: Frontend Password Reset 💻 ✅ COMPLETE

- [x] Create `frontend/src/features/auth/ForgotPasswordView.tsx` (123 lines)
- [x] Create `frontend/src/features/auth/ResetPasswordView.tsx` (309 lines)
- [x] Add password reset views to `frontend/src/features/app/LeafLockApp.tsx`
  - [x] Import ForgotPasswordView and ResetPasswordView components
  - [x] Add state for `showForgotPassword` and `resetToken`
  - [x] Add URL parameter check for reset token
  - [x] Add password reset routing logic
- [x] Add "Forgot Password?" link to `frontend/src/features/auth/LoginView.tsx` (line 279-289)
- [x] Add API integration to `frontend/src/services/secureApi.ts`:
  - [x] `requestPasswordReset(email)` - line 208
  - [x] `verifyResetToken(token)` - line 215
  - [x] `confirmPasswordReset(token, newPassword)` - line 219
- [ ] Write tests:
  - [ ] `frontend/src/features/auth/ForgotPasswordView.test.tsx`
  - [ ] `frontend/src/features/auth/ResetPasswordView.test.tsx`

### Phase 5: Testing & Documentation 🧪

- [ ] Manual testing of password reset flow
- [ ] Manual testing of welcome email
- [ ] Run all backend tests: `cd backend && go test -v ./...`
- [ ] Run all frontend tests: `cd frontend && pnpm test`
- [ ] Update `CLAUDE.md` with SMTP configuration notes
- [ ] Update README with email setup instructions

---

## 🔧 Detailed Implementation Steps

### Step 1: Add SMTP Configuration to `backend/config/config.go`

**Location**: After line 35 (after `DefaultAdminPassword string`)

```go
// Email/SMTP configuration
SMTPEnabled    bool
SMTPHost       string
SMTPPort       int
SMTPUser       string
SMTPPassword   string
SMTPFrom       string
SMTPUseTLS     bool
SMTPInsecure   bool // Skip TLS verification (dev only)
```

**Location**: In `LoadConfig()` function, after line 156 (after admin configuration)

```go
return &Config{
    // ... existing fields ...
    DefaultAdminPassword: adminPassword,

    // SMTP configuration
    SMTPEnabled:  GetEnvAsBool("SMTP_ENABLED", false),
    SMTPHost:     GetEnvOrDefault("SMTP_HOST", "localhost"),
    SMTPPort:     GetEnvAsInt("SMTP_PORT", 587),
    SMTPUser:     GetEnvOrDefault("SMTP_USER", ""),
    SMTPPassword: GetEnvOrDefault("SMTP_PASSWORD", ""),
    SMTPFrom:     GetEnvOrDefault("SMTP_FROM", "LeafLock <noreply@leaflock.app>"),
    SMTPUseTLS:   GetEnvAsBool("SMTP_USE_TLS", true),
    SMTPInsecure: GetEnvAsBool("SMTP_INSECURE", false),
}
```

---

### Step 2: Update `.env.example`

**Location**: After line 24 (after `ENABLE_METRICS=true`)

```bash
# ==========================================
# SMTP/Email Configuration
# ==========================================
# Enable SMTP email sending (set to false to disable all emails)
SMTP_ENABLED=false

# SMTP server settings
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=noreply@leaflock.app
SMTP_PASSWORD=your_app_password_here

# Email sender information
SMTP_FROM="LeafLock <noreply@leaflock.app>"

# TLS/SSL settings
SMTP_USE_TLS=true
SMTP_INSECURE=false  # Set to true only for self-signed certs in development

# Common SMTP Providers:
# Gmail: smtp.gmail.com:587 (requires app password)
# Outlook: smtp-mail.outlook.com:587
# SendGrid: smtp.sendgrid.net:587
# Mailgun: smtp.mailgun.org:587
# AWS SES: email-smtp.us-east-1.amazonaws.com:587
```

---

### Step 3: Create `backend/services/email_service.go`

```go
package services

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"html/template"
	"log"
	"net/smtp"
	"path/filepath"
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
	Subject      string
	RecipientName string
	AppName      string
	AppURL       string
	Year         int
	// Additional template-specific fields
	Data map[string]interface{}
}

// SendEmail sends an email using the configured SMTP server
func (s *EmailService) SendEmail(to string, subject string, htmlBody string, textBody string) error {
	if !s.config.SMTPEnabled {
		log.Printf("📧 [EMAIL-DISABLED] Would send email to: %s, Subject: %s", to, subject)
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
			log.Printf("✅ Email sent to: %s, Subject: %s", to, subject)
			return nil
		}
		lastErr = err
		log.Printf("⚠️ Email send attempt %d failed: %v", i+1, err)
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
		return fmt.Errorf("failed to load email template: %w", err)
	}

	// Render HTML
	var htmlBuffer bytes.Buffer
	if err := htmlTmpl.Execute(&htmlBuffer, data); err != nil {
		return fmt.Errorf("failed to render email template: %w", err)
	}

	// Generate plain text version (strip HTML tags for now)
	textBody := stripHTMLTags(htmlBuffer.String())

	return s.SendEmail(to, data.Subject, htmlBuffer.String(), textBody)
}

// stripHTMLTags is a simple HTML tag stripper for plain text emails
// For production, consider using a proper HTML-to-text library
func stripHTMLTags(html string) string {
	// Simple implementation - replace with proper library for production
	// This is just a placeholder
	return html
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
	resetURL := fmt.Sprintf("https://yourapp.com/reset-password?token=%s", resetToken)

	data := EmailData{
		Subject: "LeafLock Password Reset Request",
		Data: map[string]interface{}{
			"reset_url":   resetURL,
			"expires_in":  "1 hour",
			"ip_address":  ipAddress,
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
```

---

### Step 4: Add Password Reset Table to `backend/database/schema.go`

**Location**: After the `share_links` table (after line 401)

```sql
-- Password reset tokens table for secure password recovery
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    token_hash BYTEA NOT NULL UNIQUE, -- Argon2id hash of the reset token
    expires_at TIMESTAMPTZ NOT NULL, -- Tokens expire after 1 hour
    used BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    ip_address_encrypted BYTEA, -- Track who requested the reset
    user_agent_encrypted BYTEA  -- Track request origin for security
);

-- Indexes for password reset tokens
CREATE INDEX IF NOT EXISTS idx_password_reset_user ON password_reset_tokens(user_id, used, expires_at);
CREATE INDEX IF NOT EXISTS idx_password_reset_hash ON password_reset_tokens(token_hash) WHERE used = false;
CREATE INDEX IF NOT EXISTS idx_password_reset_expires ON password_reset_tokens(expires_at) WHERE used = false;
```

---

### Step 5: Bump Migration Version in `backend/database/database.go`

**Location**: Line 21

**Current**: `const MigrationSchemaVersion = "2025.10.04.001"`
**Update to**: `const MigrationSchemaVersion = "2025.10.09.001"`

**Why**: Ensures the password_reset_tokens table is created on existing deployments.

---

### Step 6: Create Email Templates

#### File: `backend/templates/emails/welcome.html`

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Welcome to {{.AppName}}</title>
</head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
        <h1 style="color: white; margin: 0;">🔒 Welcome to {{.AppName}}!</h1>
    </div>

    <div style="background: #f9fafb; padding: 30px; border-radius: 0 0 10px 10px; border: 1px solid #e5e7eb;">
        <p style="font-size: 16px;">Hi {{.RecipientName}},</p>

        <p style="font-size: 16px;">Thank you for creating your {{.AppName}} account! Your notes are now protected with end-to-end encryption.</p>

        <h2 style="color: #667eea; margin-top: 30px;">Quick Start Guide</h2>
        <ul style="font-size: 14px; line-height: 2;">
            <li><strong>Create your first note</strong> - Click the "New Note" button</li>
            <li><strong>Enable Two-Factor Authentication</strong> - Go to Settings → Security</li>
            <li><strong>Organize with folders and tags</strong> - Keep your notes structured</li>
            <li><strong>Share securely</strong> - Collaborate with others using encrypted sharing</li>
        </ul>

        <div style="text-align: center; margin: 30px 0;">
            <a href="{{.Data.getting_started_url}}" style="display: inline-block; background: #667eea; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; font-weight: bold;">Get Started</a>
        </div>

        <h2 style="color: #667eea; margin-top: 30px;">Security Tips</h2>
        <ul style="font-size: 14px; line-height: 2;">
            <li>Use a strong, unique password (at least 12 characters)</li>
            <li>Enable MFA for an extra layer of security</li>
            <li>Never share your password with anyone</li>
            <li>Keep your backup codes in a safe place</li>
        </ul>

        <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #e5e7eb; font-size: 12px; color: #6b7280;">
            <p>Need help? Visit our <a href="{{.Data.docs_url}}" style="color: #667eea;">documentation</a> or contact support.</p>
            <p>&copy; {{.Year}} {{.AppName}}. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
```

#### File: `backend/templates/emails/password_reset.html`

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Password Reset Request</title>
</head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
        <h1 style="color: white; margin: 0;">🔑 Password Reset Request</h1>
    </div>

    <div style="background: #f9fafb; padding: 30px; border-radius: 0 0 10px 10px; border: 1px solid #e5e7eb;">
        <p style="font-size: 16px;">Hello,</p>

        <p style="font-size: 16px;">We received a request to reset your {{.AppName}} password. Click the button below to create a new password:</p>

        <div style="text-align: center; margin: 30px 0;">
            <a href="{{.Data.reset_url}}" style="display: inline-block; background: #667eea; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; font-weight: bold;">Reset Password</a>
        </div>

        <p style="font-size: 14px; color: #6b7280;">Or copy and paste this link into your browser:</p>
        <p style="font-size: 12px; background: #fff; padding: 10px; border: 1px solid #e5e7eb; border-radius: 5px; word-break: break-all;">{{.Data.reset_url}}</p>

        <div style="margin-top: 30px; padding: 15px; background: #fef3c7; border-left: 4px solid #f59e0b; border-radius: 5px;">
            <p style="margin: 0; font-size: 14px; color: #92400e;"><strong>⚠️ Security Notice</strong></p>
            <ul style="font-size: 13px; color: #92400e; margin: 10px 0;">
                <li>This link expires in <strong>{{.Data.expires_in}}</strong></li>
                <li>Request initiated from IP: <code>{{.Data.ip_address}}</code></li>
                <li>Request time: {{.Data.request_time}}</li>
            </ul>
        </div>

        <p style="font-size: 14px; margin-top: 20px;">If you didn't request this password reset, you can safely ignore this email. Your password will remain unchanged.</p>

        <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #e5e7eb; font-size: 12px; color: #6b7280;">
            <p>&copy; {{.Year}} {{.AppName}}. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
```

#### File: `backend/templates/emails/password_changed.html`

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Password Changed</title>
</head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: linear-gradient(135deg, #10b981 0%, #059669 100%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
        <h1 style="color: white; margin: 0;">✅ Password Changed Successfully</h1>
    </div>

    <div style="background: #f9fafb; padding: 30px; border-radius: 0 0 10px 10px; border: 1px solid #e5e7eb;">
        <p style="font-size: 16px;">Hello,</p>

        <p style="font-size: 16px;">Your {{.AppName}} password was successfully changed.</p>

        <div style="margin: 20px 0; padding: 15px; background: #ecfdf5; border-left: 4px solid #10b981; border-radius: 5px;">
            <p style="margin: 0; font-size: 14px;"><strong>Change Details:</strong></p>
            <ul style="font-size: 13px; margin: 10px 0;">
                <li>Time: {{.Data.change_time}}</li>
                <li>IP Address: <code>{{.Data.ip_address}}</code></li>
            </ul>
        </div>

        <div style="margin-top: 30px; padding: 15px; background: #fee2e2; border-left: 4px solid #ef4444; border-radius: 5px;">
            <p style="margin: 0; font-size: 14px; color: #991b1b;"><strong>⚠️ Didn't make this change?</strong></p>
            <p style="font-size: 13px; color: #991b1b; margin: 10px 0;">If you did not change your password, your account may be compromised. Please contact support immediately.</p>
        </div>

        <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #e5e7eb; font-size: 12px; color: #6b7280;">
            <p>&copy; {{.Year}} {{.AppName}}. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
```

---

## 🔐 Security Implementation Notes

### Password Reset Token Security

**Token Generation**:
```go
// Generate cryptographically secure random token (32 bytes = 256 bits)
token := make([]byte, 32)
if _, err := rand.Read(token); err != nil {
    return err
}
tokenString := hex.EncodeToString(token) // 64 character hex string
```

**Token Storage**:
```go
// Hash token with Argon2id before storing in database
salt := make([]byte, 16)
rand.Read(salt)
tokenHash := argon2.IDKey([]byte(tokenString), salt, 1, 64*1024, 4, 32)

// Store in database
INSERT INTO password_reset_tokens (user_id, token_hash, expires_at, ip_address_encrypted)
VALUES ($1, $2, NOW() + INTERVAL '1 hour', $3)
```

**Token Validation**:
```go
// Verify token hasn't been used and hasn't expired
SELECT user_id FROM password_reset_tokens
WHERE token_hash = $1 AND used = false AND expires_at > NOW()
```

### Rate Limiting (Already Configured!)

Your existing rate limiter in `backend/middleware/rate_limit.go` already handles password reset endpoints:

- **Tier 1 - Auth Endpoints**: 5 requests/15 min
- Applies to `/auth/password/reset-request`
- Prevents email bombing and brute force attacks

---

## 📚 Additional Email Use Cases (Future)

### Security Emails
- New device login notification
- MFA enabled/disabled confirmation
- Account locked notification
- Admin privileges changed

### Collaboration Emails
- Note shared with you
- Share permission changed
- Share revoked
- Comment added to shared note

### System Emails
- Maintenance notifications
- Security advisories
- Feature announcements
- Account deletion confirmation

---

## 🧪 Testing Checklist

### Manual Testing

1. **SMTP Connection**:
   ```bash
   # Test SMTP connection with your provider
   curl -v --url "smtp://smtp.gmail.com:587" \
        --mail-from "noreply@leaflock.app" \
        --mail-rcpt "test@example.com" \
        --user "noreply@leaflock.app:your_password"
   ```

2. **Welcome Email**:
   - Register new account
   - Check email inbox
   - Verify formatting and links

3. **Password Reset Flow**:
   - Request password reset
   - Check email inbox
   - Click reset link
   - Verify token is valid
   - Change password
   - Check confirmation email
   - Try logging in with new password

4. **Security Tests**:
   - Try using expired token (after 1 hour)
   - Try using same token twice
   - Try invalid token
   - Verify rate limiting works
   - Check audit logs

### Automated Tests

```bash
# Backend tests
cd backend
go test -v ./handlers/... -run TestPasswordReset
go test -v ./services/... -run TestEmailService

# Frontend tests
cd frontend
pnpm test ForgotPasswordView
pnpm test ResetPasswordView
```

---

## 📖 Documentation Updates

### Update `CLAUDE.md`

Add SMTP section after the "Environment Setup" section:

```markdown
## SMTP/Email Configuration

LeafLock uses SMTP for transactional emails (password reset, welcome emails, etc.).

**Environment Variables** (`.env`):
```bash
SMTP_ENABLED=true
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=noreply@yourapp.com
SMTP_PASSWORD=your_app_password
SMTP_FROM="LeafLock <noreply@yourapp.com>"
SMTP_USE_TLS=true
```

**Common Providers**:
- Gmail: Requires app-specific password (not your regular password)
- SendGrid: Free tier includes 100 emails/day
- Mailgun: Free tier includes 5,000 emails/month
- AWS SES: Pay-as-you-go pricing

**Testing**: Set `SMTP_ENABLED=false` to log emails instead of sending them.
```

---

## ⚡ Quick Start Commands

```bash
# Install email library
cd backend
go get github.com/jordan-wright/email

# Create templates directory
mkdir -p backend/templates/emails

# Run migrations (will create password_reset_tokens table)
# Start backend - migrations run automatically on startup
cd backend && go run main.go

# Test email service
cd backend && go test -v ./services/email_service_test.go
```

---

## 🎯 Success Criteria

✅ Users can request password reset via email
✅ Reset links expire after 1 hour
✅ Tokens are single-use only
✅ All password changes send confirmation emails
✅ Welcome emails sent to new users
✅ Rate limiting prevents abuse
✅ SMTP can be disabled for testing
✅ Email templates are mobile-responsive
✅ Audit logs track all password resets
✅ All tests passing

---

## 📞 Support & Resources

- **Go Email Library**: https://github.com/jordan-wright/email
- **Email Template Best Practices**: https://www.campaignmonitor.com/dev-resources/guides/coding-html-emails/
- **SMTP Testing Tool**: https://mailtrap.io (dev environment)
- **Email Deliverability Checker**: https://www.mail-tester.com

---

**Last Updated**: 2025-10-09
**Implemented By**: TBD
**Reviewed By**: TBD
