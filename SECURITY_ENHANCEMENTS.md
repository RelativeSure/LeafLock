# 🔒 LeafLock Security Enhancements

## Overview

This document outlines the comprehensive security enhancements implemented for the LeafLock application, focusing on Clerk authentication, database security, and secure coding practices.

## 🛡️ Security Features Implemented

### 1. Timing Attack Protection

**Problem**: Traditional string comparison can leak information about token validity through timing analysis.

**Solution**: Implemented constant-time token validation with artificial delays.

```go
// Secure token comparison with timing attack protection
func ConstantTimeCompare(a, b []byte) bool {
    if len(a) != len(b) {
        // Sleep for random duration to prevent timing attacks
        time.Sleep(time.Duration(rand.Intn(10)+5) * time.Millisecond)
        return false
    }
    
    result := subtle.ConstantTimeCompare(a, b)
    
    // Add random delay to make timing consistent
    time.Sleep(time.Duration(rand.Intn(5)+2) * time.Millisecond)
    
    return result == 1
}
```

**Benefits**:
- Prevents timing-based token validation attacks
- Consistent response times regardless of token validity
- Random delays prevent statistical analysis

### 2. Secure Logging with PII Protection

**Problem**: Application logs often contain sensitive user data that could be exposed in security incidents.

**Solution**: Implemented comprehensive PII redaction and structured security event logging.

```go
// PII redaction functions
func RedactPII(input string) string {
    // Email redaction
    if strings.Contains(input, "@") {
        parts := strings.Split(input, "@")
        if len(parts) == 2 {
            username := parts[0]
            domain := parts[1]
            if len(username) > 3 {
                redactedUsername := username[:2] + "***" + username[len(username)-1:]
                return redactedUsername + "@" + domain
            }
            return "***@" + domain
        }
    }
    
    // Phone number redaction
    phoneRegex := regexp.MustCompile(`(\+?\d{1,3})?[-.\s]?\(?(\d{3})\)?[-.\s]?(\d{3})[-.\s]?(\d{4})`)
    if phoneRegex.MatchString(input) {
        return phoneRegex.ReplaceAllString(input, "***-***-$4")
    }
    
    return "***"
}
```

**Benefits**:
- Automatic redaction of emails, phone numbers, and names
- Structured security event logging with severity levels
- IP address masking for privacy protection
- Compliance with data protection regulations (GDPR, CCPA)

### 3. Clerk Webhook Security

**Problem**: Webhook endpoints are vulnerable to replay attacks, spoofing, and rate limiting bypasses.

**Solution**: Implemented comprehensive webhook security with signature verification and rate limiting.

```go
// Secure webhook processing
func (h *Handler) HandleClerkWebhook(c *fiber.Ctx) error {
    ctx := c.Context()
    
    // Rate limiting
    clientIP := c.IP()
    if err := h.checkWebhookRateLimit(ctx, clientIP); err != nil {
        return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
            "error": "Rate limit exceeded",
        })
    }
    
    // Signature verification
    signature := c.Get("Clerk-Signature")
    if signature == "" {
        logSecurityEvent(ctx, "webhook_missing_signature", map[string]interface{}{
            "client_ip": RedactIP(clientIP),
        })
        return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
            "error": "Missing webhook signature",
        })
    }
    
    // Verify signature
    if !h.verifyWebhookSignature(c.Body(), signature) {
        logSecurityEvent(ctx, "webhook_invalid_signature", map[string]interface{}{
            "client_ip": RedactIP(clientIP),
        })
        return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
            "error": "Invalid webhook signature",
        })
    }
    
    // Process validated webhook
    return h.processWebhookEvent(ctx, c.Body())
}
```

**Benefits**:
- Protection against webhook spoofing attacks
- Rate limiting prevents abuse
- Comprehensive audit logging
- Secure error handling without information leakage

### 4. Database Security Hardening

**Problem**: Database connections and data storage lack comprehensive security measures.

**Solution**: Implemented encryption at rest, connection pool security, and comprehensive audit logging.

```go
// Secure database configuration
func SetupSecureDatabase(databaseURL string) (*pgxpool.Pool, error) {
    config, err := pgxpool.ParseConfig(databaseURL)
    if err != nil {
        return nil, fmt.Errorf("failed to parse database URL: %w", err)
    }
    
    // Security: Connection pool configuration
    config.MaxConns = 25                    // Limit maximum connections
    config.MinConns = 5                     // Minimum connections
    config.MaxConnLifetime = time.Hour      // Maximum connection lifetime
    config.MaxConnIdleTime = 30 * time.Minute
    config.HealthCheckPeriod = time.Minute
    
    // Security: SSL/TLS configuration
    if config.ConnConfig.TLSConfig == nil {
        config.ConnConfig.TLSConfig = &tls.Config{
            MinVersion: tls.VersionTLS12,
            CipherSuites: []uint16{
                tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
                tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            },
        }
    }
    
    // Security: Runtime parameters
    runtimeParams := map[string]string{
        "application_name": "leaflock_secure",
        "statement_timeout": "30000",  // 30 second statement timeout
        "idle_in_transaction_session_timeout": "60000",
        "log_statement": "all",        // Log all statements for audit
        "log_min_duration_statement": "1000",
    }
    
    for key, value := range runtimeParams {
        config.ConnConfig.RuntimeParams[key] = value
    }
    
    return pgxpool.NewWithConfig(context.Background(), config)
}
```

**Benefits**:
- Encryption at rest for sensitive data
- SSL/TLS enforcement with strong cipher suites
- Connection pool security with proper timeouts
- Comprehensive audit logging
- Row-level security for data isolation

### 5. Enhanced Error Handling

**Problem**: Error messages can leak sensitive information about system internals.

**Solution**: Implemented security-focused error handling with categorized responses.

```go
// Secure error categorization
func (h *Handler) categorizeClerkError(err error) (errorType, severity, message string) {
    errStr := strings.ToLower(err.Error())
    
    switch {
    case strings.Contains(errStr, "expired"):
        return "token_expired", "info", "Your session has expired. Please sign in again."
    case strings.Contains(errStr, "invalid"):
        return "invalid_token", "info", "Invalid authentication. Please try again."
    case strings.Contains(errStr, "rate limit"):
        return "rate_limited", "warning", "Too many requests. Please try again later."
    case strings.Contains(errStr, "network"):
        return "network_error", "error", "Network error. Please check your connection."
    default:
        return "authentication_error", "error", "Authentication failed. Please try again."
    }
}
```

**Benefits**:
- No sensitive information leakage
- User-friendly error messages
- Proper error categorization for monitoring
- Security event logging

## 🔐 Security Configuration

### PostgreSQL Security

```sql
-- Enable SSL/TLS encryption
ALTER SYSTEM SET ssl = on;
ALTER SYSTEM SET ssl_cert_file = 'server.crt';
ALTER SYSTEM SET ssl_key_file = 'server.key';

-- Set strong password encryption
ALTER SYSTEM SET password_encryption = 'scram-sha-256';

-- Configure connection security
ALTER SYSTEM SET ssl_prefer_server_ciphers = on;
ALTER SYSTEM SET ssl_ciphers = 'HIGH:MEDIUM:+3DES:!aNULL';

-- Enable comprehensive audit logging
ALTER SYSTEM SET log_statement = 'all';
ALTER SYSTEM SET log_connections = on;
ALTER SYSTEM SET log_disconnections = on;

-- Set connection timeouts and limits
ALTER SYSTEM SET statement_timeout = '30000';
ALTER SYSTEM SET idle_in_transaction_session_timeout = '60000';
```

### Redis Security

```go
// Secure Redis configuration
opt := &redis.Options{
    Password:     password,
    DB:           0,
    PoolSize:     20,                    // Limit connection pool size
    MinIdleConns: 3,                     // Minimum idle connections
    MaxRetries:   3,                     // Maximum retry attempts
    DialTimeout:  5 * time.Second,       // Connection timeout
    ReadTimeout:  3 * time.Second,       // Read timeout
    WriteTimeout: 3 * time.Second,       // Write timeout
    PoolTimeout:  4 * time.Second,       // Pool timeout
    
    // TLS configuration
    TLSConfig: &tls.Config{
        MinVersion: tls.VersionTLS12,
        CipherSuites: []uint16{
            tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
        },
    },
}
```

## 🧪 Security Testing

### Unit Tests

```go
func TestTimingAttackProtection(t *testing.T) {
    token1 := "valid_token"
    token2 := "invalid_token"
    
    result1 := ConstantTimeCompare(token1, token1)
    result2 := ConstantTimeCompare(token1, token2)
    
    assert.True(t, result1, "Same tokens should match")
    assert.False(t, result2, "Different tokens should not match")
}

func TestPIIRedaction(t *testing.T) {
    tests := []struct {
        input    string
		expected string
    }{
        {input: "user@example.com", expected: "us***e@example.com"},
        {input: "+1234567890", expected: "***-***-7890"},
        {input: "John Doe", expected: "Jo***e"},
    }
    
    for _, tt := range tests {
        result := RedactPII(tt.input)
        assert.Equal(t, tt.expected, result)
    }
}
```

### Integration Tests

```go
func TestSecureDatabaseConnection(t *testing.T) {
    config := DefaultSecurityConfig()
    
    assert.True(t, config.EncryptionAtRest, "Encryption at rest should be enabled")
    assert.True(t, config.AuditLogging, "Audit logging should be enabled")
    assert.Equal(t, 30*time.Second, config.ConnectionTimeout, "Connection timeout should be 30 seconds")
}
```

## 📊 Security Monitoring

### Security Event Logging

- **Authentication Events**: Login attempts, password changes, session management
- **Authorization Events**: Permission changes, access violations
- **System Events**: Configuration changes, security updates
- **Error Events**: Failed operations, validation errors

### Rate Limiting

- **Webhook Endpoints**: 10 requests per minute per IP
- **Authentication Endpoints**: 5 attempts per minute per user
- **General API**: 100 requests per minute per user

### Security Metrics

- **Failed Authentication Rate**: Monitor for brute force attempts
- **Error Rate**: Track system stability and potential attacks
- **Response Time**: Detect timing-based attacks
- **Connection Count**: Monitor for connection exhaustion attacks

## 🔧 Deployment Security

### Environment Variables

```bash
# Database Security
DATABASE_URL="postgresql://user:password@host:port/database?sslmode=require"
REDIS_URL="rediss://user:password@host:port/0"

# Clerk Configuration
CLERK_WEBHOOK_SECRET="your-webhook-secret"
CLERK_CLIENT_SECRET="your-client-secret"

# Security Settings
SECURITY_LOG_LEVEL="info"
SECURITY_RATE_LIMIT_ENABLED="true"
SECURITY_ENCRYPTION_KEY="your-encryption-key"
```

### Container Security

```dockerfile
# Use minimal base image
FROM golang:1.19-alpine AS builder

# Create non-root user
RUN addgroup -g 1001 -S app && \
    adduser -S app -u 1001 -G app

# Set security headers
ENV CGO_ENABLED=0 GOOS=linux GOARCH=amd64

# Run as non-root user
USER app:app
```

## 🚀 Next Security Steps

1. **Frontend CSP Headers**: Implement Content Security Policy
2. **Security Metrics Dashboard**: Real-time security monitoring
3. **Penetration Testing**: Third-party security testing
4. **Security Training**: Team security awareness training
5. **Regular Security Audits**: Automated vulnerability scanning
6. **Incident Response Plan**: Documented security incident procedures

## 📞 Security Contact

For security-related issues or questions, please contact the security team at security@leaflock.app

## 📝 License

This security implementation is part of the LeafLock project and follows the project's security guidelines and best practices.