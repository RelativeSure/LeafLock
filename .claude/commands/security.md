# Security Commands

Security analysis, testing, and hardening commands for Secure Notes application.

## Quick Security Commands

```bash
# Full security audit
./security-audit.sh

# Vulnerability scan
make security-scan

# Check for secrets in code
./check-secrets.sh
```

## Vulnerability Scanning

### Backend Security (Go)
```bash
cd backend

# Go vulnerability check
go install golang.org/x/vuln/cmd/govulncheck@latest
govulncheck ./...

# Security linting
go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest
gosec ./...

# Dependency audit
go list -json -deps ./... | nancy sleuth
```

### Frontend Security (Node.js)
```bash
cd frontend

# NPM audit
npm audit

# High-severity vulnerabilities only
npm audit --audit-level=high

# Fix vulnerabilities
npm audit fix

# Audit production dependencies only
npm audit --production
```

### Container Security
```bash
# Scan container images
podman build --security-opt label=disable -t secure-notes-backend .
podman image scan secure-notes-backend

# With trivy
trivy image secure-notes-backend:latest

# With docker scout (if using Docker)
docker scout cves secure-notes-backend:latest
```

## Secret Detection

### Scan for Hardcoded Secrets
```bash
# Install detect-secrets
pip install detect-secrets

# Scan for secrets
detect-secrets scan --all-files --baseline .secrets.baseline

# Audit baseline
detect-secrets audit .secrets.baseline

# Check specific files
detect-secrets scan backend/main.go frontend/src/
```

### Environment Security
```bash
# Check .env file permissions
ls -la .env

# Ensure .env is not in git
git ls-files | grep -E "\.env$" && echo "WARNING: .env file in git!"

# Check for exposed secrets in history
git log -p | grep -i "password\|secret\|key" | head -20
```

### API Key Security
```bash
# Check for API keys in code
grep -r "api[_-]key" --include="*.go" --include="*.js" --include="*.ts" .
grep -r "secret[_-]key" --include="*.go" --include="*.js" --include="*.ts" .
grep -r "access[_-]token" --include="*.go" --include="*.js" --include="*.ts" .
```

## Authentication & Authorization Testing

### JWT Token Security
```bash
# Decode JWT token (replace $TOKEN)
echo $TOKEN | cut -d. -f2 | base64 -d | jq .

# Test token expiration
curl -H "Authorization: Bearer expired_token" http://localhost:8080/api/v1/notes

# Test malformed tokens
curl -H "Authorization: Bearer invalid.token.here" http://localhost:8080/api/v1/notes
```

### Session Security
```bash
# Check Redis session storage
podman exec -it secure-notes-redis redis-cli keys "session:*"

# Test session timeout
# (Login, wait for timeout, try to access protected resource)

# Test session invalidation
curl -X POST http://localhost:8080/api/v1/auth/logout \
     -H "Authorization: Bearer $TOKEN"
```

### Password Security
```bash
# Test password hashing in backend
cd backend
go test -run TestPasswordHashing -v

# Test password strength requirements
curl -X POST http://localhost:8080/api/v1/auth/register \
     -H "Content-Type: application/json" \
     -d '{"email":"test@example.com","password":"weak"}'
```

## Encryption Testing

### Client-Side Encryption
```bash
cd frontend

# Test encryption/decryption
npm test -- --run encryption

# Test key derivation
npm test -- --run key-derivation

# Verify zero-knowledge architecture
npm test -- --run zero-knowledge
```

### Backend Encryption
```bash
cd backend

# Test server-side encryption
go test -run TestServerEncryption -v

# Test encryption key rotation
go test -run TestKeyRotation -v

# Verify encrypted data storage
go test -run TestEncryptedStorage -v
```

## Network Security

### TLS/SSL Testing
```bash
# Test SSL configuration
sslscan your-domain.com

# Test SSL certificate
openssl s_client -connect your-domain.com:443 -servername your-domain.com

# Check certificate expiration
echo | openssl s_client -connect your-domain.com:443 2>/dev/null | openssl x509 -noout -dates
```

### CORS Security
```bash
# Test CORS configuration
curl -H "Origin: https://malicious-site.com" \
     -H "Access-Control-Request-Method: POST" \
     -X OPTIONS \
     http://localhost:8080/api/v1/notes

# Test CORS bypass attempts
curl -H "Origin: null" http://localhost:8080/api/v1/notes
curl -H "Origin: localhost:3000" http://localhost:8080/api/v1/notes
```

### Header Security
```bash
# Check security headers
curl -I http://localhost:8080/

# Required security headers:
# X-Content-Type-Options: nosniff
# X-Frame-Options: DENY
# X-XSS-Protection: 1; mode=block
# Strict-Transport-Security: max-age=31536000
```

## Input Validation & Injection Testing

### SQL Injection Testing
```bash
# Test SQL injection in API endpoints
curl -X POST http://localhost:8080/api/v1/notes \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer $TOKEN" \
     -d '{"title":"test","content":"'"'"'; DROP TABLE notes; --"}'

# Test SQL injection in authentication
curl -X POST http://localhost:8080/api/v1/auth/login \
     -H "Content-Type: application/json" \
     -d '{"email":"admin'"'"'; --","password":"anything"}'
```

### XSS Testing
```bash
# Test XSS in API responses
curl -X POST http://localhost:8080/api/v1/notes \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer $TOKEN" \
     -d '{"title":"<script>alert('"'"'xss'"'"')</script>","content":"test"}'

# Check if HTML is properly escaped in responses
curl http://localhost:8080/api/v1/notes | grep -o "<script>"
```

### Command Injection Testing
```bash
# Test command injection (if file upload exists)
curl -X POST http://localhost:8080/api/v1/upload \
     -F "file=@test.txt;filename=test.txt; rm -rf /" \
     -H "Authorization: Bearer $TOKEN"
```

## Access Control Testing

### Authorization Bypass
```bash
# Test accessing other users' data
USER1_TOKEN=$TOKEN1
USER2_TOKEN=$TOKEN2

# Create note as user 1
NOTE_ID=$(curl -X POST http://localhost:8080/api/v1/notes \
          -H "Authorization: Bearer $USER1_TOKEN" \
          -H "Content-Type: application/json" \
          -d '{"title":"Private Note","content":"Secret"}' | jq -r .id)

# Try to access as user 2
curl -H "Authorization: Bearer $USER2_TOKEN" \
     http://localhost:8080/api/v1/notes/$NOTE_ID
```

### Privilege Escalation
```bash
# Test admin endpoint access with regular user token
curl -H "Authorization: Bearer $REGULAR_USER_TOKEN" \
     http://localhost:8080/api/v1/admin/users

# Test role modification
curl -X PUT http://localhost:8080/api/v1/users/profile \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"role":"admin"}'
```

## Rate Limiting & DoS Protection

### Rate Limiting Tests
```bash
# Test API rate limits
for i in {1..100}; do
  curl -s http://localhost:8080/api/v1/auth/login \
       -H "Content-Type: application/json" \
       -d '{"email":"test@example.com","password":"wrongpassword"}' &
done
wait

# Test rate limit headers
curl -I http://localhost:8080/api/v1/auth/login
```

### Load Testing for DoS
```bash
# Install artillery if not available
npm install -g artillery

# Simple load test
artillery quick --count 100 --num 10 http://localhost:8080/api/v1/health

# Sustained load test
cat > load-test.yml << EOF
config:
  target: 'http://localhost:8080'
  phases:
    - duration: 60
      arrivalRate: 10
scenarios:
  - name: 'Health Check'
    requests:
      - get:
          url: '/api/v1/health'
EOF

artillery run load-test.yml
```

## Database Security

### Database Connection Security
```bash
# Test database connection with wrong credentials
PGPASSWORD=wrongpassword psql -h localhost -U postgres -d notes

# Check database SSL configuration
psql -h localhost -U postgres -d notes -c "SHOW ssl;"

# Test database user permissions
psql -h localhost -U postgres -d notes -c "SELECT * FROM pg_user;"
```

### Data Encryption at Rest
```bash
# Check if database files are encrypted
file /var/lib/postgresql/data/*

# Test encrypted column access
psql -h localhost -U postgres -d notes -c "SELECT encrypted_content FROM notes LIMIT 1;"
```

## Compliance & Audit

### GDPR Compliance Testing
```bash
# Test data deletion
curl -X DELETE http://localhost:8080/api/v1/users/account \
     -H "Authorization: Bearer $TOKEN"

# Test data export
curl http://localhost:8080/api/v1/users/data \
     -H "Authorization: Bearer $TOKEN"
```

### Security Audit Log
```bash
# Check audit logs
grep -E "(login|logout|failed|unauthorized)" /var/log/secure-notes/audit.log

# Test audit log generation
curl -X POST http://localhost:8080/api/v1/auth/login \
     -H "Content-Type: application/json" \
     -d '{"email":"test@example.com","password":"wrongpassword"}'

tail /var/log/secure-notes/audit.log
```

## Security Monitoring

### Real-time Security Monitoring
```bash
# Monitor failed login attempts
tail -f /var/log/secure-notes/audit.log | grep "failed_login"

# Monitor suspicious API calls
tail -f /var/log/secure-notes/access.log | grep -E "(SELECT|DROP|INSERT|UPDATE)" -i
```

### Intrusion Detection
```bash
# Monitor unusual access patterns
awk '{print $1}' /var/log/secure-notes/access.log | sort | uniq -c | sort -nr | head -20

# Check for port scanning
netstat -an | grep LISTEN | wc -l
ss -tuln | grep LISTEN
```

## Incident Response

### Security Incident Checklist
```bash
# 1. Isolate affected systems
docker-compose down

# 2. Preserve logs
cp -r /var/log/secure-notes /security-incident-$(date +%Y%m%d)/

# 3. Reset credentials
./rotate-all-secrets.sh

# 4. Patch vulnerabilities
./update-dependencies.sh

# 5. Restore from clean backup
./restore-from-backup.sh
```

### Forensic Analysis
```bash
# Analyze access logs
grep "$(date +%Y-%m-%d)" /var/log/secure-notes/access.log | \
awk '{print $1, $7}' | sort | uniq -c | sort -nr

# Check for unusual database queries
grep -E "(DROP|DELETE|ALTER)" /var/log/postgresql/postgresql.log

# Analyze authentication patterns
grep "auth" /var/log/secure-notes/audit.log | \
awk '{print $3}' | sort | uniq -c
```

## Security Tools Installation

### Essential Security Tools
```bash
# Go security tools
go install golang.org/x/vuln/cmd/govulncheck@latest
go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest

# General security tools
pip install detect-secrets
npm install -g audit-ci

# Container security
curl -sSfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -

# SSL/TLS testing
git clone https://github.com/rbsec/sslscan.git
cd sslscan && make
```

### Security Automation Scripts
```bash
# Create automated security check
cat > security-check.sh << 'EOF'
#!/bin/bash
echo "🔍 Running security audit..."

# Backend security
cd backend && govulncheck ./... && gosec ./...

# Frontend security
cd ../frontend && npm audit --audit-level=high

# Container security
cd .. && make security-scan

# Secret detection
detect-secrets scan --all-files

echo "✅ Security audit complete"
EOF

chmod +x security-check.sh
```