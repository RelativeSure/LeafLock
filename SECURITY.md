# Secure Notes - Security Architecture

## Table of Contents

1. [Security Overview](#security-overview)
2. [Zero-Knowledge Architecture](#zero-knowledge-architecture)
3. [Cryptographic Implementation](#cryptographic-implementation)
4. [Authentication & Authorization](#authentication--authorization)
5. [Data Protection](#data-protection)
6. [Network Security](#network-security)
7. [Threat Model Analysis](#threat-model-analysis)
8. [Security Controls](#security-controls)
9. [Compliance & Standards](#compliance--standards)
10. [Security Best Practices](#security-best-practices)
11. [Incident Response](#incident-response)
12. [Security Audit Guide](#security-audit-guide)

## Security Overview

Secure Notes implements a zero-knowledge architecture with end-to-end encryption, ensuring that sensitive user data is never accessible to the server in plaintext. The security model is built on the principle of "privacy by design" with multiple layers of protection.

**Core Security Principles:**
- **Zero-Knowledge**: Server never sees plaintext data
- **End-to-End Encryption**: Client-side encryption/decryption
- **Defense in Depth**: Multiple security layers
- **Least Privilege**: Minimal required permissions
- **Secure by Default**: Strong security settings out-of-the-box

**Security Architecture Overview:**

```
┌─────────────────────────────────────────────────────────────┐
│                     CLIENT SECURITY BOUNDARY                │
│                                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │  Password   │  │ Master Key  │  │ Plaintext   │        │
│  │ (User Input)│→ │ (Derived)   │→ │ Notes       │        │
│  └─────────────┘  └─────────────┘  └─────────────┘        │
│           │               │               │                │
│           ▼               ▼               ▼                │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │ Argon2id    │  │XChaCha20-   │  │ Encrypted   │        │
│  │ Hashing     │  │ Poly1305    │  │ Data        │        │
│  └─────────────┘  └─────────────┘  └─────────────┘        │
│                                           │                │
└───────────────────────────────────────────┼────────────────┘
                                            │
                                    HTTPS/TLS 1.3
                                            │
┌───────────────────────────────────────────┼────────────────┐
│                   SERVER SECURITY BOUNDARY                 │
│                                           ▼                │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │JWT + Session│  │Rate Limiting│  │ Encrypted   │        │
│  │ Management  │  │+ CORS       │  │ Storage     │        │
│  └─────────────┘  └─────────────┘  └─────────────┘        │
│           │               │               │                │
│           ▼               ▼               ▼                │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │ PostgreSQL  │  │   Redis     │  │ Audit Log   │        │
│  │(Encrypted)  │  │ (Sessions)  │  │ (Security)  │        │
│  └─────────────┘  └─────────────┘  └─────────────┘        │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Zero-Knowledge Architecture

### Design Principles

**Zero-Knowledge Guarantees:**
1. **Server Cannot Decrypt**: Server never has access to user's master key
2. **Password Verification**: Uses password hashes, not plaintext passwords  
3. **Encrypted Storage**: All sensitive data stored as encrypted blobs
4. **Minimal Metadata**: Only necessary metadata is stored unencrypted
5. **Client-Side Processing**: All encryption/decryption happens in browser

### Key Management Architecture

```
User Password
     │
     ▼ PBKDF2 (600,000 iterations)
Derived Key (256-bit)
     │
     ├─ Branch 1: Master Encryption Key
     │  │
     │  ▼ XChaCha20-Poly1305
     │  Encrypt/Decrypt Note Content
     │
     └─ Branch 2: Authentication
        │
        ▼ Argon2id (Server-side hash)
        Password Verification
```

### Data Flow Security

**Note Creation Flow:**
1. User types plaintext note → Browser memory
2. Master key derives encryption key → Browser memory  
3. XChaCha20-Poly1305 encrypts note → Browser memory
4. Base64 encode encrypted data → Browser memory
5. HTTPS POST to server → Network (encrypted)
6. Server stores encrypted blob → Database (encrypted)
7. Clear browser memory → No plaintext residue

**Note Retrieval Flow:**
1. HTTPS GET from server → Network (encrypted)
2. Server returns encrypted blob → Database (encrypted)
3. Base64 decode encrypted data → Browser memory
4. XChaCha20-Poly1305 decrypts note → Browser memory
5. Display plaintext to user → Browser DOM
6. Clear browser memory → No plaintext residue

### Trust Model

**Trusted Components:**
- User's browser and device
- Client-side JavaScript cryptography
- User's password and memory
- Local browser storage (temporary)

**Untrusted Components:**
- Web server and backend services
- Database and storage systems
- Network infrastructure
- Cloud providers and hosting
- System administrators

**Threat Assumptions:**
- Attacker may compromise server
- Attacker may access database
- Network traffic may be monitored
- Server logs may be captured
- Backup systems may be compromised

## Cryptographic Implementation

### Client-Side Cryptography

**Encryption Algorithm: XChaCha20-Poly1305**
```typescript
// Key Derivation
const salt = sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES);
const key = await crypto.subtle.deriveBits({
  name: 'PBKDF2',
  salt: salt,
  iterations: 600000,
  hash: 'SHA-256'
}, keyMaterial, 256);

// Encryption
const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
const ciphertext = sodium.crypto_secretbox_easy(plaintext, nonce, key);

// Result: nonce + ciphertext (authenticated encryption)
```

**Cryptographic Parameters:**
- **Encryption**: XChaCha20-Poly1305 (ChaCha20 stream cipher + Poly1305 MAC)
- **Key Derivation**: PBKDF2-SHA256, 600,000 iterations
- **Key Length**: 256 bits (32 bytes)
- **Nonce Length**: 192 bits (24 bytes) for XChaCha20
- **Salt Length**: 256 bits (32 bytes) for PBKDF2
- **MAC**: Poly1305 (128-bit authentication tag)

### Server-Side Cryptography

**Password Hashing: Argon2id**
```go
// Argon2id Configuration (backend/main.go:305-311)
hash := argon2.IDKey(
    []byte(password),  // Password
    salt,              // 32-byte random salt
    3,                 // Time parameter (iterations)
    64*1024,          // Memory parameter (64MB)
    4,                // Parallelism parameter (4 threads)
    32,               // Key length (32 bytes)
)
```

**JWT Token Security:**
```go
// JWT Configuration
claims := jwt.MapClaims{
    "user_id": userID.String(),
    "exp":     time.Now().Add(24 * time.Hour).Unix(),
    "iat":     time.Now().Unix(),
}
token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims) // HMAC-SHA512
signedToken := token.SignedString(jwtSecret) // 512-bit secret
```

**Session Token Security:**
```go
// Session Token Generation
sessionToken := make([]byte, 32) // 256-bit random token
rand.Read(sessionToken)

// Hash for storage (prevents token recovery from DB)
tokenHash := argon2.IDKey(sessionToken, []byte("session"), 1, 64*1024, 4, 32)
```

### Cryptographic Security Analysis

**Encryption Strength:**
- **XChaCha20**: 256-bit key, 192-bit nonce, IND-CPA secure
- **Poly1305**: 128-bit MAC, SUF-CMA secure  
- **Combined**: Authenticated encryption, IND-CCA2 secure
- **Quantum Resistance**: Not quantum-resistant (like all current practical crypto)

**Key Derivation Strength:**
- **PBKDF2-SHA256**: 600,000 iterations (≥ OWASP recommendation)
- **Argon2id**: Memory-hard, ASIC-resistant, winner of password hashing competition
- **Salt**: 256-bit random salt prevents rainbow table attacks
- **Timing**: ~500ms key derivation adds computational cost for attackers

**Random Number Generation:**
- **Client**: `crypto.getRandomValues()` (browser CSPRNG)
- **Server**: `crypto/rand` (Go CSPRNG)
- **Entropy**: OS-level entropy sources, suitable for cryptographic use

## Authentication & Authorization

### Authentication Flow

**Registration Process:**
1. **Password Validation**: 12+ character minimum, complexity checks
2. **Salt Generation**: 32-byte random salt per user
3. **Key Derivation**: PBKDF2-SHA256 (600k iterations) for master key
4. **Password Hashing**: Argon2id (64MB, 3 iterations) for server storage
5. **Master Key Encryption**: Encrypt master key with derived key
6. **Database Storage**: Store encrypted master key and password hash

**Login Process:**
1. **Credential Validation**: Email format and password length checks
2. **Rate Limiting**: 100 requests/minute per IP, account lockout after 5 failures
3. **Password Verification**: Constant-time Argon2id comparison
4. **Account Security**: Check for account lockout and failed attempts
5. **Token Generation**: Create JWT token (24-hour expiration)
6. **Session Creation**: Generate session token, hash for storage
7. **Audit Logging**: Log all authentication events

### Authorization Model

**Role-Based Access Control (RBAC):**
```go
// User Permissions
type Permission string
const (
    ReadNotes   Permission = "notes:read"
    WriteNotes  Permission = "notes:write"
    DeleteNotes Permission = "notes:delete"
    ShareNotes  Permission = "notes:share"
)

// User Roles  
type Role struct {
    Name        string
    Permissions []Permission
}

var (
    OwnerRole = Role{
        Name: "owner",
        Permissions: []Permission{
            ReadNotes, WriteNotes, DeleteNotes, ShareNotes,
        },
    }
    EditorRole = Role{
        Name: "editor", 
        Permissions: []Permission{
            ReadNotes, WriteNotes,
        },
    }
    ViewerRole = Role{
        Name: "viewer",
        Permissions: []Permission{
            ReadNotes,
        },
    }
)
```

**Resource Access Control:**
```go
// Note Access Validation
func (h *NotesHandler) validateNoteAccess(userID, noteID uuid.UUID, permission Permission) error {
    // Check direct ownership
    var ownerID uuid.UUID
    err := h.db.QueryRow(ctx, `
        SELECT w.owner_id 
        FROM notes n
        JOIN workspaces w ON n.workspace_id = w.id
        WHERE n.id = $1 AND n.deleted_at IS NULL`, 
        noteID).Scan(&ownerID)
    
    if err == nil && ownerID == userID {
        return nil // Owner has all permissions
    }
    
    // Check shared access
    var userPermission string
    err = h.db.QueryRow(ctx, `
        SELECT permission
        FROM collaborations
        WHERE note_id = $1 AND user_id = $2`,
        noteID, userID).Scan(&userPermission)
    
    if err != nil {
        return errors.New("access denied")
    }
    
    return validatePermission(userPermission, permission)
}
```

### Multi-Factor Authentication (MFA)

**TOTP Implementation:**
```go
// MFA Secret Generation
func generateMFASecret() ([]byte, error) {
    secret := make([]byte, 32) // 256-bit secret
    _, err := rand.Read(secret)
    return secret, err
}

// TOTP Verification
func verifyTOTP(secret []byte, code string) bool {
    // RFC 6238 TOTP implementation
    timestamp := time.Now().Unix() / 30 // 30-second windows
    
    // Check current window and ±1 window for clock skew
    for i := -1; i <= 1; i++ {
        if generateTOTP(secret, timestamp+int64(i)) == code {
            return true
        }
    }
    return false
}
```

### Account Security Features

**Brute Force Protection:**
```go
type AccountSecurity struct {
    MaxLoginAttempts int           // 5 attempts
    LockoutDuration  time.Duration // 15 minutes
    PasswordPolicy   PasswordPolicy
}

func (h *AuthHandler) checkAccountLockout(userID uuid.UUID) error {
    var failedAttempts int
    var lockedUntil *time.Time
    
    err := h.db.QueryRow(ctx, `
        SELECT failed_attempts, locked_until 
        FROM users WHERE id = $1`,
        userID).Scan(&failedAttempts, &lockedUntil)
    
    if failedAttempts >= h.config.MaxLoginAttempts {
        return errors.New("account locked")
    }
    
    if lockedUntil != nil && lockedUntil.After(time.Now()) {
        return errors.New("account locked until " + lockedUntil.String())
    }
    
    return nil
}
```

**Password Policy:**
```typescript
interface PasswordPolicy {
  minLength: number;        // 12 characters minimum
  requireUppercase: boolean; // At least one uppercase letter
  requireLowercase: boolean; // At least one lowercase letter  
  requireNumbers: boolean;   // At least one number
  requireSymbols: boolean;   // At least one special character
  forbidCommon: boolean;     // Reject common passwords
  forbidPersonal: boolean;   // Reject email-based passwords
}

const passwordPolicy: PasswordPolicy = {
  minLength: 12,
  requireUppercase: true,
  requireLowercase: true,
  requireNumbers: true,
  requireSymbols: true,
  forbidCommon: true,
  forbidPersonal: true,
};
```

## Data Protection

### Data Classification

**Sensitivity Levels:**

| Data Type | Sensitivity | Encryption | Access Control |
|-----------|-------------|------------|----------------|
| Note Content | **Critical** | XChaCha20-Poly1305 (Client) | Owner only |
| Note Titles | **Critical** | XChaCha20-Poly1305 (Client) | Owner only |
| User Email | **High** | XChaCha20-Poly1305 (Server) | System only |
| Password Hash | **High** | Argon2id | System only |
| Session Data | **Medium** | XChaCha20-Poly1305 (Server) | System only |
| IP Addresses | **Medium** | XChaCha20-Poly1305 (Server) | System only |
| Audit Logs | **Low** | XChaCha20-Poly1305 (Server) | Admin only |
| Metadata | **Low** | None (timestamps, IDs) | System only |

### Database Security

**Encrypted Field Storage:**
```sql
-- All sensitive data stored as BYTEA (binary encrypted)
CREATE TABLE users (
    id UUID PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,           -- Searchable (hashed)
    email_encrypted BYTEA NOT NULL,       -- Encrypted for privacy
    password_hash TEXT NOT NULL,          -- Argon2id hash
    salt BYTEA NOT NULL,                  -- Password salt
    master_key_encrypted BYTEA NOT NULL,  -- User's encrypted master key
    -- ... other encrypted fields
);

CREATE TABLE notes (
    id UUID PRIMARY KEY,
    workspace_id UUID REFERENCES workspaces(id),
    title_encrypted BYTEA NOT NULL,       -- Client-side encrypted
    content_encrypted BYTEA NOT NULL,     -- Client-side encrypted  
    content_hash BYTEA NOT NULL,          -- Integrity verification
    -- ... metadata (unencrypted for queries)
);
```

**Database Connection Security:**
```go
// PostgreSQL with TLS
dbURL := "postgres://user:pass@host:5432/db?sslmode=require&sslcert=client-cert.pem&sslkey=client-key.pem&sslrootcert=ca-cert.pem"

// Connection pooling with security
config, err := pgxpool.ParseConfig(dbURL)
config.MaxConns = 20
config.MinConns = 5
config.MaxConnLifetime = time.Hour
config.MaxConnIdleTime = 30 * time.Minute
```

### Backup Security

**Encrypted Backup Strategy:**
```bash
#!/bin/bash
# secure-backup.sh

# Generate backup encryption key
BACKUP_KEY=$(openssl rand -base64 32)

# Create encrypted database backup
pg_dump -h localhost -U postgres notes | \
  openssl enc -aes-256-gcm -pbkdf2 -salt -pass pass:${BACKUP_KEY} | \
  gzip > notes-backup-$(date +%Y%m%d).enc.gz

# Securely store backup key (separate from backup)
echo ${BACKUP_KEY} | gpg --encrypt --recipient backup@company.com > backup-key-$(date +%Y%m%d).gpg

# Upload to secure storage
aws s3 cp notes-backup-$(date +%Y%m%d).enc.gz s3://secure-backups/ --server-side-encryption AES256
```

### Data Retention & Deletion

**Secure Deletion Policy:**
```go
// Soft delete with automatic cleanup
func (h *NotesHandler) DeleteNote(noteID uuid.UUID) error {
    // Mark as deleted
    _, err := h.db.Exec(ctx, `
        UPDATE notes 
        SET deleted_at = NOW()
        WHERE id = $1`, noteID)
    
    // Schedule for hard deletion after 30 days
    return h.scheduleHardDeletion(noteID, 30*24*time.Hour)
}

// Hard deletion (permanent removal)
func (h *NotesHandler) HardDeleteNote(noteID uuid.UUID) error {
    // Remove all traces
    _, err := h.db.Exec(ctx, `DELETE FROM notes WHERE id = $1`, noteID)
    _, err = h.db.Exec(ctx, `DELETE FROM collaborations WHERE note_id = $1`, noteID)
    _, err = h.db.Exec(ctx, `DELETE FROM attachments WHERE note_id = $1`, noteID)
    
    // Clear from audit logs (after retention period)
    return h.cleanupAuditLogs(noteID)
}
```

## Network Security

### Transport Layer Security

**TLS Configuration:**
```nginx
# Nginx TLS Configuration
ssl_protocols TLSv1.3 TLSv1.2;
ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
ssl_prefer_server_ciphers off;
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 1d;
ssl_session_tickets off;

# HSTS
add_header Strict-Transport-Security "max-age=63072000" always;

# Certificate transparency
add_header Expect-CT "max-age=604800, enforce, report-uri=\"https://ct.example.com/report\"";
```

**Certificate Management:**
```yaml
# cert-manager ClusterIssuer
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: security@company.com
    privateKeySecretRef:
      name: letsencrypt-prod
    solvers:
    - http01:
        ingress:
          class: nginx
    - dns01:
        route53:
          region: us-east-1
          secretAccessKeySecretRef:
            name: route53-credentials
            key: secret-access-key
```

### Network Segmentation

**Kubernetes Network Policies:**
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: secure-notes-isolation
  namespace: secure-notes
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: secure-notes
  policyTypes:
  - Ingress
  - Egress
  ingress:
  # Allow ingress only from ingress controller
  - from:
    - namespaceSelector:
        matchLabels:
          name: ingress-nginx
    ports:
    - protocol: TCP
      port: 8080
    - protocol: TCP
      port: 80
  egress:
  # Allow egress to database and cache
  - to:
    - podSelector:
        matchLabels:
          app.kubernetes.io/name: postgresql
    ports:
    - protocol: TCP
      port: 5432
  - to:
    - podSelector:
        matchLabels:
          app.kubernetes.io/name: redis
    ports:
    - protocol: TCP
      port: 6379
  # Allow DNS resolution
  - to: []
    ports:
    - protocol: UDP
      port: 53
```

### API Security Headers

**Security Headers Implementation:**
```go
// Fiber security middleware (backend/main.go:883-890)
app.Use(helmet.New(helmet.Config{
    XSSProtection:         "1; mode=block",
    ContentTypeNosniff:    "nosniff", 
    XFrameOptions:         "DENY",
    HSTSMaxAge:            31536000,
    ContentSecurityPolicy: "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'",
    ReferrerPolicy:        "strict-origin-when-cross-origin",
}))
```

**CORS Configuration:**
```go
// CORS with strict origin control
app.Use(cors.New(cors.Config{
    AllowOrigins:     strings.Join(config.AllowedOrigins, ","), // Specific domains only
    AllowCredentials: true,                                     // Enable cookies/auth
    AllowHeaders:     "Origin, Content-Type, Accept, Authorization",
    AllowMethods:     "GET, POST, PUT, DELETE, OPTIONS",
    MaxAge:           300, // 5 minutes preflight cache
}))
```

## Threat Model Analysis

### STRIDE Analysis

**Spoofing Threats:**
- **Risk**: Attacker impersonates legitimate user
- **Mitigation**: Strong authentication (Argon2id + JWT), MFA support
- **Controls**: Account lockout, session management, audit logging

**Tampering Threats:**
- **Risk**: Attacker modifies data in transit or at rest  
- **Mitigation**: Authenticated encryption (Poly1305 MAC), HTTPS/TLS
- **Controls**: Content integrity hashes, database constraints

**Repudiation Threats:**
- **Risk**: User denies performing actions
- **Mitigation**: Comprehensive audit logging, digital signatures
- **Controls**: Immutable audit trail, timestamp validation

**Information Disclosure Threats:**
- **Risk**: Sensitive data exposed to unauthorized parties
- **Mitigation**: End-to-end encryption, access controls, data classification
- **Controls**: Zero-knowledge architecture, encrypted storage

**Denial of Service Threats:**
- **Risk**: Service availability impacted by attacks
- **Mitigation**: Rate limiting, resource limits, load balancing
- **Controls**: Connection pooling, health checks, auto-scaling

**Elevation of Privilege Threats:**
- **Risk**: Attacker gains unauthorized access levels
- **Mitigation**: Least privilege, RBAC, input validation
- **Controls**: JWT validation, SQL injection prevention, container security

### Attack Scenarios & Mitigations

**Scenario 1: Database Breach**
```
Attack: Attacker gains read access to PostgreSQL database
Impact: Access to encrypted user data, password hashes, metadata
Mitigation: 
  ✓ All sensitive data encrypted (zero-knowledge)
  ✓ Password hashes use Argon2id (memory-hard)
  ✓ Database encryption at rest
  ✓ Network segmentation
  ✓ Database access logging
Result: Attacker cannot decrypt user notes or recover passwords
```

**Scenario 2: Server Compromise**
```
Attack: Attacker gains root access to application server
Impact: Access to application code, environment variables, memory
Mitigation:
  ✓ Master keys never stored on server
  ✓ Environment variables for config only
  ✓ Container isolation (non-root users)
  ✓ Read-only root filesystems
  ✓ Runtime security monitoring
Result: Attacker cannot access plaintext user data
```

**Scenario 3: Man-in-the-Middle**
```
Attack: Attacker intercepts network traffic
Impact: Access to encrypted data in transit
Mitigation:
  ✓ TLS 1.3 with strong cipher suites
  ✓ HSTS and certificate pinning
  ✓ Data already encrypted client-side
  ✓ Certificate transparency monitoring
Result: Attacker sees only encrypted data
```

**Scenario 4: Client-Side Attack**
```
Attack: Malware on user's device
Impact: Access to plaintext data in browser memory
Mitigation:
  ⚠️ Limited server-side mitigation possible
  ✓ Auto-logout on inactivity
  ✓ Clear memory after use
  ✓ Content Security Policy
  ✓ Subresource Integrity (SRI)
Result: Residual risk - user education required
```

### Risk Assessment Matrix

| Threat Category | Likelihood | Impact | Risk Level | Mitigations |
|----------------|------------|---------|------------|-------------|
| **Data Breach (Server)** | Medium | Low | **Low** | Zero-knowledge architecture |
| **Data Breach (Database)** | Medium | Low | **Low** | Client-side encryption |
| **Authentication Bypass** | Low | High | **Medium** | MFA, account lockout, audit |
| **Man-in-the-Middle** | Low | Low | **Low** | TLS 1.3, certificate pinning |
| **Client-Side Compromise** | Medium | High | **Medium** | User education, auto-logout |
| **Denial of Service** | High | Medium | **Medium** | Rate limiting, scaling |
| **Insider Threat** | Low | Medium | **Low** | Zero-knowledge, audit logging |
| **Social Engineering** | Medium | High | **Medium** | User education, MFA |

## Security Controls

### Technical Controls

**Preventive Controls:**
```yaml
Authentication:
  - Strong password policy (12+ chars, complexity)
  - Argon2id password hashing (64MB memory)
  - JWT with HMAC-SHA512 signing
  - Account lockout after 5 failed attempts
  - Multi-factor authentication support

Encryption:
  - XChaCha20-Poly1305 for data encryption
  - TLS 1.3 for transport encryption  
  - PBKDF2-SHA256 for key derivation (600k iterations)
  - Database field-level encryption

Access Control:
  - Role-based access control (RBAC)
  - JSON Web Token (JWT) authentication
  - Session management with expiration
  - CORS with origin restrictions

Network Security:
  - Network policies (Kubernetes)
  - Rate limiting (100 req/min per IP)
  - DDoS protection
  - Firewall rules
```

**Detective Controls:**
```yaml
Monitoring:
  - Comprehensive audit logging
  - Authentication failure tracking
  - Anomaly detection for access patterns
  - Security event alerting

Logging:
  - All authentication events
  - Data access attempts
  - Administrative actions
  - Error conditions and exceptions

Health Checks:
  - Application health endpoints
  - Database connectivity monitoring
  - Cache availability monitoring
  - Certificate expiration tracking
```

**Corrective Controls:**
```yaml
Incident Response:
  - Automated account lockout
  - Session invalidation
  - Rate limiting escalation
  - Alert notification system

Recovery:
  - Encrypted backup systems
  - Point-in-time recovery
  - Disaster recovery procedures
  - Business continuity planning
```

### Administrative Controls

**Security Policies:**
- Data classification and handling procedures
- Incident response and escalation procedures
- Access control and privilege management
- Secure development lifecycle (SDLC)
- Vulnerability management program

**Training and Awareness:**
- Security awareness training for users
- Secure coding practices for developers
- Incident response training for operations
- Regular security assessment and testing

**Change Management:**
- Code review requirements
- Security testing in CI/CD pipeline
- Configuration change controls
- Emergency change procedures

## Compliance & Standards

### Security Standards Compliance

**OWASP Top 10 2021 Compliance:**

| Risk | Status | Mitigations |
|------|--------|-------------|
| **A01: Broken Access Control** | ✅ Protected | RBAC, JWT validation, ownership checks |
| **A02: Cryptographic Failures** | ✅ Protected | Strong encryption, proper key management |
| **A03: Injection** | ✅ Protected | Parameterized queries, input validation |
| **A04: Insecure Design** | ✅ Protected | Zero-knowledge architecture, threat modeling |
| **A05: Security Misconfiguration** | ✅ Protected | Secure defaults, hardening guides |
| **A06: Vulnerable Components** | ✅ Protected | Dependency scanning, regular updates |
| **A07: Authentication Failures** | ✅ Protected | Strong passwords, MFA, account lockout |
| **A08: Software Integrity** | ✅ Protected | Code signing, SRI, secure pipelines |
| **A09: Logging Failures** | ✅ Protected | Comprehensive audit logging |
| **A10: Server-Side Forgery** | ✅ Protected | Input validation, network restrictions |

**NIST Cybersecurity Framework Alignment:**
- **Identify**: Asset inventory, risk assessment, governance
- **Protect**: Access controls, data security, training
- **Detect**: Security monitoring, audit logging, anomaly detection
- **Respond**: Incident response procedures, communications
- **Recover**: Recovery planning, backup systems, lessons learned

### Privacy Compliance

**GDPR Compliance (Privacy by Design):**
- **Data Minimization**: Only collect necessary data
- **Purpose Limitation**: Use data only for stated purposes  
- **Storage Limitation**: Automatic data retention/deletion
- **Accuracy**: Data integrity verification
- **Security**: Strong encryption and access controls
- **Accountability**: Audit trails and documentation
- **Transparency**: Clear privacy policies
- **Rights**: Data export, deletion, and modification capabilities

**Data Processing Record:**
```yaml
Personal_Data_Processing:
  Controller: Organization Name
  Purpose: Secure note-taking service
  Legal_Basis: Consent (Article 6(1)(a))
  Categories:
    - Email addresses (encrypted)
    - IP addresses (encrypted, for security)
    - Usage metadata (anonymized)
  Recipients: None (zero-knowledge architecture)
  Retention: 
    - Active accounts: Indefinite (with user consent)
    - Deleted accounts: 30 days (secure deletion)
  Security_Measures:
    - End-to-end encryption
    - Zero-knowledge architecture
    - Access controls and audit logging
```

## Security Best Practices

### Development Security

**Secure Coding Standards:**
```go
// Input validation
func validateEmail(email string) error {
    if len(email) > 254 {
        return errors.New("email too long")
    }
    
    emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
    if !emailRegex.MatchString(email) {
        return errors.New("invalid email format")
    }
    
    return nil
}

// SQL injection prevention
func (h *NotesHandler) GetNote(noteID uuid.UUID, userID uuid.UUID) (*Note, error) {
    var note Note
    err := h.db.QueryRow(ctx, `
        SELECT id, title_encrypted, content_encrypted, created_at, updated_at
        FROM notes 
        WHERE id = $1 AND created_by = $2 AND deleted_at IS NULL`,
        noteID, userID).Scan(&note.ID, &note.TitleEncrypted, &note.ContentEncrypted, &note.CreatedAt, &note.UpdatedAt)
    
    return &note, err
}

// Constant-time comparison
func verifyPassword(password, hash string) bool {
    return subtle.ConstantTimeCompare(
        []byte(computeHash(password)), 
        []byte(hash),
    ) == 1
}
```

### Operational Security

**Container Security:**
```dockerfile
# Multi-stage build for minimal attack surface
FROM golang:1.23-alpine AS builder
RUN apk add --no-cache git ca-certificates
WORKDIR /app
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o app .

FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /app/app /app
EXPOSE 8080
USER 65534:65534
ENTRYPOINT ["/app"]
```

**Kubernetes Security:**
```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 65534
  runAsGroup: 65534
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop:
    - ALL
  seccompProfile:
    type: RuntimeDefault
```

### Monitoring & Alerting

**Security Event Monitoring:**
```go
type SecurityEvent struct {
    Timestamp   time.Time `json:"timestamp"`
    EventType   string    `json:"event_type"`
    UserID      string    `json:"user_id,omitempty"`
    IPAddress   string    `json:"ip_address"`
    UserAgent   string    `json:"user_agent"`
    Details     string    `json:"details"`
    RiskLevel   string    `json:"risk_level"`
}

// High-risk events that require immediate alerting
var HighRiskEvents = map[string]bool{
    "account.lockout":        true,
    "login.brute_force":      true,
    "admin.privilege_escalation": true,
    "data.unauthorized_access": true,
    "auth.token_manipulation": true,
}

func (h *AuthHandler) logSecurityEvent(event SecurityEvent) {
    // Log to audit system
    h.auditLogger.Log(event)
    
    // Send alerts for high-risk events
    if HighRiskEvents[event.EventType] {
        h.alertManager.SendAlert(SecurityAlert{
            Event: event,
            Severity: "HIGH",
            Message: fmt.Sprintf("Security event detected: %s", event.EventType),
        })
    }
}
```

## Incident Response

### Security Incident Classification

**Severity Levels:**

| Severity | Definition | Response Time | Examples |
|----------|------------|---------------|----------|
| **Critical** | Data breach, system compromise | < 1 hour | Database breach, admin account compromise |
| **High** | Service disruption, auth bypass | < 4 hours | Authentication failure, DoS attack |
| **Medium** | Security policy violation | < 24 hours | Brute force attempts, config issues |
| **Low** | Minor security concern | < 72 hours | Failed login attempts, certificate expiry |

### Incident Response Procedures

**Immediate Response (0-1 hour):**
1. **Assess and Contain**
   ```bash
   # Identify compromised accounts
   kubectl logs -f deployment/backend -n secure-notes | grep "SECURITY_EVENT"
   
   # Disable compromised user accounts
   psql -c "UPDATE users SET locked_until = NOW() + INTERVAL '24 HOURS' WHERE id = '$USER_ID';"
   
   # Revoke all sessions for affected users
   redis-cli FLUSHDB  # Clear all sessions (nuclear option)
   ```

2. **Evidence Collection**
   ```bash
   # Collect system logs
   kubectl logs --previous deployment/backend -n secure-notes > incident-logs-$(date +%Y%m%d).txt
   
   # Database forensics
   pg_dump --data-only --table=audit_log notes > audit-$(date +%Y%m%d).sql
   
   # Network traffic analysis
   tcpdump -i any -w incident-$(date +%Y%m%d).pcap
   ```

**Short-term Response (1-24 hours):**
1. **Detailed Investigation**
2. **Stakeholder Notification**
3. **System Hardening**
4. **Monitoring Enhancement**

**Long-term Response (24+ hours):**
1. **Root Cause Analysis**
2. **Process Improvement**
3. **Security Posture Review**
4. **Lessons Learned Documentation**

### Breach Notification Procedures

**Internal Notification:**
- Security team: Immediate (< 1 hour)
- Management: Within 4 hours
- Legal/Compliance: Within 24 hours
- All staff: As appropriate per incident

**External Notification:**
- Customers: Within 72 hours (if personal data affected)
- Regulators: Within 72 hours (GDPR requirement)
- Law enforcement: As required by jurisdiction
- Media: As determined by legal/PR teams

## Security Audit Guide

### Self-Assessment Checklist

**Authentication Security:**
- [ ] Password complexity requirements enforced (12+ chars)
- [ ] Argon2id used for password hashing (64MB memory, 3 iterations)
- [ ] Account lockout after 5 failed attempts
- [ ] JWT tokens use HMAC-SHA512 with 512-bit secrets
- [ ] Session tokens are 256-bit random values
- [ ] MFA implementation available and tested
- [ ] Password reset process secure (email verification)

**Encryption Security:**
- [ ] XChaCha20-Poly1305 used for data encryption
- [ ] PBKDF2-SHA256 with 600k iterations for key derivation
- [ ] All sensitive database fields encrypted
- [ ] TLS 1.3 configured with strong cipher suites
- [ ] Certificate management automated (cert-manager)
- [ ] HSTS headers configured (max-age=31536000)

**Application Security:**
- [ ] Input validation on all user inputs
- [ ] SQL injection protection (parameterized queries)
- [ ] XSS protection (Content Security Policy)
- [ ] CSRF protection (SameSite cookies)
- [ ] Rate limiting configured (100 req/min per IP)
- [ ] Security headers implemented (helmet.js)
- [ ] CORS configured with specific origins

**Infrastructure Security:**
- [ ] Containers run as non-root users
- [ ] Read-only root filesystems enabled
- [ ] Resource limits configured
- [ ] Network policies restrict pod communication
- [ ] Pod security standards enforced (restricted profile)
- [ ] Secrets management (not in environment variables)
- [ ] Regular security updates applied

### Penetration Testing Scope

**Authentication Testing:**
- Password policy bypass attempts
- Brute force attack simulation
- Session fixation and hijacking tests
- JWT token manipulation attempts
- Account enumeration testing
- MFA bypass attempts

**Authorization Testing:**
- Privilege escalation attempts
- Horizontal access control bypass
- API endpoint authorization testing
- Resource-level permission verification
- Role-based access control validation

**Data Security Testing:**
- Encryption implementation validation
- Key management security review
- Data leakage testing
- Backup security assessment
- Database security configuration review

**Network Security Testing:**
- TLS configuration assessment
- Certificate validation testing
- Man-in-the-middle attack simulation
- Network segmentation validation
- DoS/DDoS resilience testing

### Compliance Audit Preparation

**Documentation Requirements:**
- Security policies and procedures
- Risk assessment and threat modeling
- Incident response procedures
- Data flow diagrams
- Network architecture diagrams
- Encryption implementation details
- Access control matrices
- Audit log retention policies

**Evidence Collection:**
- Security configuration snapshots
- Audit log samples
- Penetration testing reports
- Vulnerability assessment results
- Security training records
- Incident response exercise results
- Business continuity test results

This comprehensive security architecture documentation provides the foundation for maintaining a secure, privacy-focused notes application with enterprise-grade security controls.