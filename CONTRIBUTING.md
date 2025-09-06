# Contributing to Secure Notes

## Table of Contents

1. [Getting Started](#getting-started)
2. [Development Environment](#development-environment)
3. [Code Standards](#code-standards)
4. [Security Guidelines](#security-guidelines)
5. [Testing Requirements](#testing-requirements)
6. [Submission Process](#submission-process)
7. [Code Review Process](#code-review-process)
8. [Documentation Requirements](#documentation-requirements)
9. [Release Process](#release-process)
10. [Community Guidelines](#community-guidelines)

## Getting Started

We welcome contributions to Secure Notes! This guide will help you understand our development process, coding standards, and how to submit your contributions effectively.

**Before You Start:**
- Read the [ARCHITECTURE.md](ARCHITECTURE.md) to understand the system design
- Review the [SECURITY.md](SECURITY.md) for security requirements
- Set up your development environment using [GETTING_STARTED.md](GETTING_STARTED.md)
- Check existing [Issues](https://github.com/secure-notes/secure-notes/issues) and [Pull Requests](https://github.com/secure-notes/secure-notes/pulls)

### Ways to Contribute

**Code Contributions:**
- Bug fixes and security improvements
- New features and enhancements
- Performance optimizations
- Documentation improvements

**Non-Code Contributions:**
- Bug reports with detailed reproduction steps
- Feature requests with clear use cases
- Documentation improvements and translations
- Security vulnerability reports (see [Security Policy](#security-vulnerability-reporting))

### Project Structure

```
secure-notes/
├── backend/                 # Go backend service
│   ├── main.go             # Main application entry point
│   ├── go.mod              # Go module dependencies
│   └── Dockerfile          # Backend container image
├── frontend/               # React frontend application  
│   ├── src/
│   │   └── App.jsx        # Main React application
│   ├── package.json       # Node.js dependencies
│   └── Dockerfile         # Frontend container image
├── helm/                  # Kubernetes Helm charts
│   └── secure-notes/      # Helm chart for deployment
├── .github/              # GitHub workflows and templates
│   └── workflows/        # CI/CD pipelines
├── docs/                 # Additional documentation
├── docker-compose.yml    # Docker Compose configuration
├── Makefile             # Development automation
└── *.md                 # Documentation files
```

## Development Environment

### Prerequisites

**Required Software:**
- **Go 1.23+** for backend development
- **Node.js 20+** and **npm** for frontend development
- **Docker or Podman** for containerized development
- **Git** for version control
- **Make** for automation scripts

**Recommended Tools:**
- **VS Code** with Go and TypeScript extensions
- **Postman** or **curl** for API testing
- **kubectl** and **helm** for Kubernetes development
- **jq** for JSON processing in scripts

### Setup Instructions

```bash
# 1. Fork and clone the repository
git clone https://github.com/your-username/secure-notes.git
cd secure-notes

# 2. Set up environment configuration
cp .env.example .env
# Edit .env with secure values (see GETTING_STARTED.md)

# 3. Start development environment
make up

# 4. Verify setup
curl http://localhost:8080/api/v1/health
curl http://localhost:3000

# 5. Run tests to ensure everything works
make test
```

### Development Workflow

**Branch Strategy:**
```bash
# Create feature branch from main
git checkout main
git pull origin main
git checkout -b feature/your-feature-name

# Make changes and commit
git add .
git commit -m "feat: add new feature description"

# Push branch and create pull request
git push origin feature/your-feature-name
```

**Daily Development:**
```bash
# Start development services
make up

# Run backend tests
cd backend && go test -v ./...

# Run frontend tests  
cd frontend && npm test

# View logs during development
make logs

# Stop services when done
make down
```

## Code Standards

### Go Backend Standards

**Code Formatting:**
```bash
# Use gofmt for formatting
gofmt -w .

# Use golangci-lint for linting
golangci-lint run

# Use goimports for imports
goimports -w .
```

**Go Code Style:**
```go
// Package documentation
// Package main implements the Secure Notes backend API server.
package main

// Function documentation
// HashPassword creates an Argon2id hash of the given password using the provided salt.
// It returns a formatted hash string suitable for storage.
func HashPassword(password string, salt []byte) string {
    // Implementation with clear variable names
    hash := argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, 32)
    b64Salt := base64.RawStdEncoding.EncodeToString(salt)
    b64Hash := base64.RawStdEncoding.EncodeToString(hash)
    
    return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
        argon2.Version, 64*1024, 3, 4, b64Salt, b64Hash)
}

// Error handling
func (h *AuthHandler) Register(c *fiber.Ctx) error {
    var req RegisterRequest
    if err := c.BodyParser(&req); err != nil {
        return c.Status(400).JSON(fiber.Map{
            "error": "Invalid request",
            "code":  "INVALID_JSON",
        })
    }
    
    // Validate input
    if err := validateRegisterRequest(req); err != nil {
        return c.Status(400).JSON(fiber.Map{
            "error": err.Error(),
            "code":  "VALIDATION_FAILED",
        })
    }
    
    // ... implementation
}
```

**Security Requirements:**
```go
// Always use parameterized queries
func (h *NotesHandler) GetNote(noteID uuid.UUID, userID uuid.UUID) (*Note, error) {
    var note Note
    err := h.db.QueryRow(ctx, `
        SELECT id, title_encrypted, content_encrypted, created_at, updated_at
        FROM notes 
        WHERE id = $1 AND created_by = $2 AND deleted_at IS NULL`,
        noteID, userID).Scan(&note.ID, &note.TitleEncrypted, &note.ContentEncrypted, &note.CreatedAt, &note.UpdatedAt)
    
    return &note, err
}

// Use constant-time comparisons for sensitive data
func verifyPassword(password, hash string) bool {
    computedHash := computePasswordHash(password)
    return subtle.ConstantTimeCompare([]byte(hash), []byte(computedHash)) == 1
}

// Always validate user authorization
func (h *NotesHandler) requireNoteAccess(userID, noteID uuid.UUID) error {
    var ownerID uuid.UUID
    err := h.db.QueryRow(ctx, `
        SELECT w.owner_id 
        FROM notes n
        JOIN workspaces w ON n.workspace_id = w.id
        WHERE n.id = $1`, 
        noteID).Scan(&ownerID)
    
    if err != nil || ownerID != userID {
        return errors.New("access denied")
    }
    
    return nil
}
```

### React Frontend Standards

**TypeScript/JavaScript Style:**
```typescript
// Use TypeScript interfaces for type safety
interface Note {
  id: string;
  title: string;
  content: string;
  createdAt: string;
  updatedAt: string;
}

interface CryptoService {
  encryptData(plaintext: string): Promise<string>;
  decryptData(ciphertext: string): Promise<string>;
  setMasterKey(key: Uint8Array): Promise<void>;
}

// Component with proper error handling
const NotesEditor: React.FC = () => {
  const [note, setNote] = useState<Note | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSave = async () => {
    try {
      setLoading(true);
      setError(null);
      
      await api.updateNote(note.id, note.title, note.content);
      
      // Success feedback
      setLastSaved(new Date());
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Save failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="notes-editor">
      {error && (
        <div className="error-banner" role="alert">
          {error}
        </div>
      )}
      {/* Component JSX */}
    </div>
  );
};
```

**Security Requirements:**
```typescript
// Always encrypt data before sending to server
class SecureAPI {
  async createNote(title: string, content: string): Promise<Note> {
    // Encrypt client-side before transmission
    const encryptedTitle = await cryptoService.encryptData(title);
    const encryptedContent = await cryptoService.encryptData(JSON.stringify(content));
    
    return this.request('/notes', {
      method: 'POST',
      body: JSON.stringify({
        title_encrypted: encryptedTitle,
        content_encrypted: encryptedContent,
      }),
    });
  }

  // Always validate API responses
  async request(endpoint: string, options: RequestInit = {}): Promise<any> {
    const response = await fetch(`${this.baseURL}${endpoint}`, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...options.headers,
      },
    });

    if (!response.ok) {
      // Don't expose sensitive error details
      throw new Error(`Request failed: ${response.status}`);
    }

    const data = await response.json();
    
    // Validate response structure
    if (!data || typeof data !== 'object') {
      throw new Error('Invalid response format');
    }

    return data;
  }
}

// Clear sensitive data from memory
const clearSensitiveData = (obj: any) => {
  if (obj && typeof obj === 'object') {
    for (const key in obj) {
      if (obj.hasOwnProperty(key)) {
        obj[key] = null;
      }
    }
  }
};
```

### Database Standards

**Migration Scripts:**
```sql
-- migrations/001_create_users.sql
-- Create users table with proper constraints and indexes

BEGIN;

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email TEXT UNIQUE NOT NULL CHECK (email ~ '^[^@]+@[^@]+\.[^@]+$'),
    email_encrypted BYTEA NOT NULL,
    password_hash TEXT NOT NULL CHECK (password_hash LIKE '$argon2id$%'),
    salt BYTEA NOT NULL CHECK (length(salt) = 32),
    master_key_encrypted BYTEA NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    failed_attempts INTEGER DEFAULT 0 CHECK (failed_attempts >= 0),
    locked_until TIMESTAMPTZ,
    
    CONSTRAINT valid_lock_state CHECK (
        (failed_attempts < 5 AND locked_until IS NULL) OR
        (failed_attempts >= 5 AND locked_until IS NOT NULL)
    )
);

-- Indexes for performance
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_locked ON users(locked_until) WHERE locked_until IS NOT NULL;

-- Trigger for updated_at
CREATE TRIGGER update_users_updated_at 
    BEFORE UPDATE ON users 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

COMMIT;
```

## Security Guidelines

### Security-First Development

**All code must follow security best practices:**

1. **Input Validation**
   ```go
   // Validate all user inputs
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
   ```

2. **SQL Injection Prevention**
   ```go
   // Always use parameterized queries
   // GOOD:
   rows, err := db.Query("SELECT * FROM users WHERE id = $1", userID)
   
   // BAD:
   rows, err := db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = '%s'", userID))
   ```

3. **Authentication & Authorization**
   ```go
   // Always check user permissions
   func (h *Handler) requireAuth(c *fiber.Ctx) error {
       userID := c.Locals("user_id")
       if userID == nil {
           return c.Status(401).JSON(fiber.Map{"error": "Authentication required"})
       }
       return c.Next()
   }
   ```

4. **Encryption Requirements**
   ```typescript
   // All sensitive data must be encrypted client-side
   const encryptedData = await cryptoService.encryptData(sensitiveData);
   // Never send plaintext sensitive data to server
   ```

### Security Vulnerability Reporting

**For security vulnerabilities, do NOT create a public issue.**

Instead, email security@secure-notes.com with:
- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Suggested fix (if known)

We will respond within 24 hours and work with you on coordinated disclosure.

## Testing Requirements

### Test Coverage Requirements

**Minimum Coverage:**
- Backend: 80% test coverage
- Frontend: 70% test coverage
- Critical security functions: 100% coverage

### Backend Testing

**Unit Tests:**
```go
// backend/auth_test.go
func TestHashPassword(t *testing.T) {
    tests := []struct {
        name     string
        password string
        salt     []byte
        wantErr  bool
    }{
        {
            name:     "valid password",
            password: "SecurePassword123!",
            salt:     make([]byte, 32),
            wantErr:  false,
        },
        {
            name:     "empty password",
            password: "",
            salt:     make([]byte, 32),
            wantErr:  true,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Fill salt with test data
            for i := range tt.salt {
                tt.salt[i] = byte(i)
            }
            
            hash := HashPassword(tt.password, tt.salt)
            
            if tt.wantErr {
                assert.Empty(t, hash)
            } else {
                assert.NotEmpty(t, hash)
                assert.Contains(t, hash, "$argon2id$")
                
                // Verify password can be verified
                assert.True(t, VerifyPassword(tt.password, hash))
            }
        })
    }
}

// Integration test
func TestCreateNote(t *testing.T) {
    // Setup test database
    db := setupTestDB(t)
    defer cleanupTestDB(t, db)
    
    // Create test user
    userID := createTestUser(t, db)
    
    // Test note creation
    noteID, err := CreateNote(db, userID, "encrypted_title", "encrypted_content")
    assert.NoError(t, err)
    assert.NotEmpty(t, noteID)
    
    // Verify note was created
    var count int
    err = db.QueryRow("SELECT COUNT(*) FROM notes WHERE id = $1", noteID).Scan(&count)
    assert.NoError(t, err)
    assert.Equal(t, 1, count)
}
```

**Security Tests:**
```go
func TestPasswordHashingTime(t *testing.T) {
    // Test that password hashing takes appropriate time
    start := time.Now()
    salt := make([]byte, 32)
    HashPassword("testpassword", salt)
    duration := time.Since(start)
    
    // Should take at least 100ms (prevents timing attacks)
    assert.True(t, duration > 100*time.Millisecond)
    assert.True(t, duration < 2*time.Second) // But not too long
}

func TestConstantTimeComparison(t *testing.T) {
    correctHash := HashPassword("password123", []byte("salt"))
    
    // Time comparison with correct password
    start1 := time.Now()
    result1 := VerifyPassword("password123", correctHash)
    time1 := time.Since(start1)
    
    // Time comparison with incorrect password
    start2 := time.Now()
    result2 := VerifyPassword("wrongpassword", correctHash)
    time2 := time.Since(start2)
    
    assert.True(t, result1)
    assert.False(t, result2)
    
    // Times should be similar (constant time)
    diff := time1 - time2
    if diff < 0 {
        diff = -diff
    }
    assert.True(t, diff < 10*time.Millisecond) // Allow some variance
}
```

### Frontend Testing

**Component Tests:**
```typescript
// frontend/src/__tests__/LoginView.test.tsx
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import LoginView from '../LoginView';

describe('LoginView', () => {
  test('validates password strength', async () => {
    render(<LoginView />);
    
    const passwordInput = screen.getByLabelText(/password/i);
    const submitButton = screen.getByRole('button', { name: /login/i });
    
    // Test weak password
    fireEvent.change(passwordInput, { target: { value: '123' } });
    fireEvent.click(submitButton);
    
    await waitFor(() => {
      expect(screen.getByText(/password must be at least 12 characters/i)).toBeInTheDocument();
    });
  });

  test('encrypts data before submission', async () => {
    const mockEncrypt = jest.fn().mockResolvedValue('encrypted_data');
    const mockAPI = {
      login: jest.fn().mockResolvedValue({ token: 'test_token' })
    };
    
    // Mock crypto service
    jest.doMock('../crypto', () => ({
      encryptData: mockEncrypt
    }));
    
    render(<LoginView api={mockAPI} />);
    
    // Fill form and submit
    fireEvent.change(screen.getByLabelText(/email/i), { 
      target: { value: 'test@example.com' } 
    });
    fireEvent.change(screen.getByLabelText(/password/i), { 
      target: { value: 'SecurePassword123!' } 
    });
    fireEvent.click(screen.getByRole('button', { name: /login/i }));
    
    await waitFor(() => {
      expect(mockEncrypt).toHaveBeenCalled();
      expect(mockAPI.login).toHaveBeenCalledWith('test@example.com', 'SecurePassword123!');
    });
  });
});
```

**Encryption Tests:**
```typescript
// frontend/src/__tests__/crypto.test.ts
import { CryptoService } from '../crypto';

describe('CryptoService', () => {
  let cryptoService: CryptoService;

  beforeEach(async () => {
    cryptoService = new CryptoService();
    await cryptoService.initSodium();
    
    // Set test key
    const testKey = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      testKey[i] = i;
    }
    await cryptoService.setMasterKey(testKey);
  });

  test('encrypts and decrypts data correctly', async () => {
    const plaintext = 'This is a test message';
    
    const encrypted = await cryptoService.encryptData(plaintext);
    expect(encrypted).toBeTruthy();
    expect(encrypted).not.toEqual(plaintext);
    
    const decrypted = await cryptoService.decryptData(encrypted);
    expect(decrypted).toEqual(plaintext);
  });

  test('encryption produces different output each time', async () => {
    const plaintext = 'Same message';
    
    const encrypted1 = await cryptoService.encryptData(plaintext);
    const encrypted2 = await cryptoService.encryptData(plaintext);
    
    expect(encrypted1).not.toEqual(encrypted2); // Different nonces
    
    const decrypted1 = await cryptoService.decryptData(encrypted1);
    const decrypted2 = await cryptoService.decryptData(encrypted2);
    
    expect(decrypted1).toEqual(plaintext);
    expect(decrypted2).toEqual(plaintext);
  });

  test('fails gracefully with invalid data', async () => {
    await expect(cryptoService.decryptData('invalid_data')).rejects.toThrow();
  });
});
```

### Running Tests

```bash
# Backend tests
cd backend
go test -v ./...                    # Run all tests
go test -v ./... -cover            # With coverage
go test -v ./... -race             # With race detection
go test -bench=.                   # Benchmark tests

# Frontend tests  
cd frontend
npm test                           # Interactive mode
npm test -- --coverage            # With coverage
npm test -- --watchAll=false      # Single run
npm run test:e2e                   # End-to-end tests

# Integration tests
make test                          # Run all tests
docker compose -f docker-compose.test.yml up --abort-on-container-exit
```

## Submission Process

### Pull Request Process

1. **Before Creating PR:**
   ```bash
   # Ensure your branch is up to date
   git checkout main
   git pull origin main
   git checkout your-branch
   git rebase main
   
   # Run tests locally
   make test
   
   # Run linting
   make lint
   ```

2. **PR Requirements:**
   - Clear, descriptive title
   - Comprehensive description of changes
   - Link to related issues
   - Screenshots for UI changes
   - Test coverage maintained or improved
   - Documentation updated if needed

3. **PR Template:**
   ```markdown
   ## Description
   Brief description of the changes and their purpose.
   
   ## Type of Change
   - [ ] Bug fix (non-breaking change)
   - [ ] New feature (non-breaking change)
   - [ ] Breaking change (fix or feature causing existing functionality to not work)
   - [ ] Documentation update
   - [ ] Security improvement
   
   ## Testing
   - [ ] Unit tests added/updated
   - [ ] Integration tests pass
   - [ ] Manual testing completed
   - [ ] Security testing performed
   
   ## Checklist
   - [ ] Code follows project style guidelines
   - [ ] Self-review completed
   - [ ] Code comments added for complex logic
   - [ ] Documentation updated
   - [ ] No new warnings introduced
   ```

### Commit Message Standards

**Format:**
```
type(scope): short description

Longer description if needed

Closes #issue-number
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code formatting changes
- `refactor`: Code refactoring
- `test`: Test additions/modifications
- `security`: Security improvements
- `perf`: Performance improvements

**Examples:**
```bash
feat(auth): add multi-factor authentication support

Implements TOTP-based MFA using RFC 6238 standard.
Adds QR code generation for easy setup.
Includes backup codes for account recovery.

Closes #123

fix(encryption): resolve key derivation timing issue

Addresses potential timing attack in PBKDF2 implementation
by using constant-time comparison for derived keys.

Security impact: Low - requires local access

docs(api): update authentication endpoint documentation

Adds examples for MFA login flow and error responses.
Includes rate limiting information.
```

## Code Review Process

### Review Guidelines

**For Reviewers:**

1. **Security First**
   - Verify all security requirements are met
   - Check for potential vulnerabilities
   - Ensure encryption is properly implemented
   - Review authentication and authorization logic

2. **Code Quality**
   - Readable and maintainable code
   - Proper error handling
   - Adequate test coverage
   - Performance considerations

3. **Architecture Consistency**
   - Follows established patterns
   - Maintains separation of concerns
   - Uses appropriate abstractions

**Review Checklist:**
```markdown
## Security Review
- [ ] Input validation implemented
- [ ] SQL injection protection verified
- [ ] Authentication/authorization checks present
- [ ] Sensitive data properly encrypted
- [ ] No hardcoded secrets or credentials
- [ ] Error messages don't leak sensitive information

## Code Quality Review  
- [ ] Code is readable and well-documented
- [ ] Error handling is appropriate
- [ ] Tests provide adequate coverage
- [ ] Performance impact considered
- [ ] No code duplication
- [ ] Follows established patterns

## Documentation Review
- [ ] API documentation updated if needed
- [ ] README updated for new features
- [ ] Configuration changes documented
- [ ] Database schema changes documented
```

### Approval Process

**Required Approvals:**
- At least **2 approvals** from maintainers for features
- At least **1 approval** from security team for security changes
- **Lead maintainer approval** for breaking changes

**Automated Checks Must Pass:**
- All tests (unit, integration, security)
- Code quality gates (linting, coverage)
- Security scanning (SAST, dependency check)
- Build verification

## Documentation Requirements

### Code Documentation

**Go Documentation:**
```go
// Package auth provides authentication and authorization functionality
// for the Secure Notes application.
//
// This package implements JWT-based authentication with Argon2id password
// hashing and optional multi-factor authentication using TOTP.
package auth

// AuthHandler handles HTTP requests for authentication endpoints.
// It provides user registration, login, logout, and password reset functionality.
type AuthHandler struct {
    db     *pgxpool.Pool    // Database connection pool
    crypto *CryptoService   // Encryption service
    config *Config          // Application configuration
}

// Register creates a new user account with encrypted master key.
// 
// The registration process:
// 1. Validates email format and password strength
// 2. Generates cryptographic salt and derives encryption key
// 3. Creates encrypted master key for user's data encryption
// 4. Stores user record with Argon2id password hash
// 5. Creates default workspace for the user
// 6. Returns JWT token for immediate authentication
//
// Security considerations:
// - Password must meet complexity requirements (12+ chars)
// - Email addresses are stored both as plaintext (for login) and encrypted (for privacy)
// - Master key is encrypted with user's password-derived key (zero-knowledge)
func (h *AuthHandler) Register(c *fiber.Ctx) error {
    // Implementation...
}
```

**TypeScript Documentation:**
```typescript
/**
 * CryptoService provides client-side encryption and decryption functionality
 * using the libsodium library. All encryption is performed in the browser
 * to maintain zero-knowledge architecture.
 * 
 * @example
 * ```typescript
 * const crypto = new CryptoService();
 * await crypto.initSodium();
 * await crypto.setMasterKey(derivedKey);
 * 
 * const encrypted = await crypto.encryptData("sensitive data");
 * const decrypted = await crypto.decryptData(encrypted);
 * ```
 */
class CryptoService {
  private masterKey: Uint8Array | null = null;
  private sodiumReady: boolean = false;

  /**
   * Encrypts plaintext data using XChaCha20-Poly1305 authenticated encryption.
   * 
   * @param plaintext - The data to encrypt
   * @returns Promise resolving to base64-encoded encrypted data (nonce + ciphertext)
   * @throws Error if master key is not set or encryption fails
   * 
   * @security The nonce is randomly generated for each encryption operation
   * to ensure semantic security. The resulting ciphertext includes both the
   * nonce and the authenticated ciphertext.
   */
  async encryptData(plaintext: string): Promise<string> {
    // Implementation...
  }
}
```

### API Documentation

**All API changes require documentation updates in [API_DOCUMENTATION.md](API_DOCUMENTATION.md):**

```markdown
### Create Encrypted Note

**Endpoint:** `POST /api/v1/notes`

**Authentication:** Required (Bearer token)

**Request Body:**
```json
{
  "title_encrypted": "base64-encoded-encrypted-title",
  "content_encrypted": "base64-encoded-encrypted-content"
}
```

**Security Notes:**
- All data must be encrypted client-side before transmission
- Server never sees plaintext note content
- Content integrity is verified using Argon2id hash
```

## Release Process

### Version Numbering

We use [Semantic Versioning](https://semver.org/):
- **MAJOR**: Breaking changes to API or security model
- **MINOR**: New features, backward compatible
- **PATCH**: Bug fixes, security patches

### Release Checklist

**Pre-Release:**
- [ ] All tests passing
- [ ] Security review completed
- [ ] Documentation updated
- [ ] Performance benchmarks run
- [ ] Database migration scripts tested
- [ ] Changelog updated

**Release Process:**
```bash
# 1. Create release branch
git checkout main
git pull origin main
git checkout -b release/v1.2.0

# 2. Update version files
# Update version in package.json, go.mod, helm charts

# 3. Run final tests
make test
make security-scan

# 4. Create release PR
git add .
git commit -m "chore: prepare release v1.2.0"
git push origin release/v1.2.0

# 5. After approval, tag release
git checkout main
git tag v1.2.0
git push origin v1.2.0

# 6. Deploy to staging for final verification
# 7. Deploy to production
# 8. Monitor deployment
```

**Post-Release:**
- Monitor error rates and performance metrics
- Respond to any critical issues within 24 hours
- Update documentation site
- Announce release in community channels

## Community Guidelines

### Code of Conduct

We are committed to providing a friendly, safe, and welcoming environment for all contributors, regardless of level of experience, gender identity and expression, sexual orientation, disability, personal appearance, body size, race, ethnicity, age, religion, nationality, or other similar characteristic.

**Expected Behavior:**
- Use welcoming and inclusive language
- Be respectful of differing viewpoints and experiences
- Gracefully accept constructive criticism
- Focus on what is best for the community
- Show empathy towards other community members

**Unacceptable Behavior:**
- Trolling, insulting/derogatory comments, and personal or political attacks
- Public or private harassment
- Publishing others' private information without explicit permission
- Other conduct which could reasonably be considered inappropriate

### Getting Help

**For Development Questions:**
- Create a [Discussion](https://github.com/secure-notes/secure-notes/discussions)
- Join our community chat (link in README)
- Check existing documentation and issues

**For Bug Reports:**
- Search existing issues first
- Use the bug report template
- Include reproduction steps and environment details
- Add relevant logs and screenshots

**For Feature Requests:**
- Search existing issues and discussions
- Use the feature request template
- Explain the use case and business value
- Consider implementation complexity

### Recognition

We recognize and celebrate contributions through:
- Contributor mentions in release notes
- GitHub contributor statistics
- Community spotlight features
- Maintainer recognition program

Thank you for contributing to Secure Notes! Your efforts help make secure, private note-taking accessible to everyone.