# Secure Notes API Documentation

## Table of Contents

1. [API Overview](#api-overview)
2. [Authentication](#authentication)
3. [Error Handling](#error-handling)
4. [Rate Limiting](#rate-limiting)
5. [Authentication Endpoints](#authentication-endpoints)
6. [Notes Management Endpoints](#notes-management-endpoints)
7. [Health Check Endpoints](#health-check-endpoints)
8. [Request/Response Examples](#requestresponse-examples)
9. [Client Libraries](#client-libraries)
10. [Security Considerations](#security-considerations)

## API Overview

The Secure Notes API is a RESTful API that provides secure, encrypted note management with zero-knowledge architecture. All sensitive data is encrypted client-side before transmission to the server.

**Base URL:** `http://localhost:8080/api/v1` (development)  
**Production URL:** `https://your-domain.com/api/v1`

**API Characteristics:**
- RESTful design with standard HTTP methods
- JSON request/response format
- JWT-based authentication
- Client-side encryption (zero-knowledge)
- Comprehensive error handling
- Rate limiting protection
- CORS-enabled for cross-origin requests

**Content Type:**
```
Content-Type: application/json
Accept: application/json
```

## Authentication

### Authentication Method

The API uses JWT (JSON Web Token) authentication with Bearer token authorization:

```http
Authorization: Bearer <jwt_token>
```

### Token Lifecycle

1. **Obtain Token**: Login or register to receive JWT token
2. **Token Storage**: Store token securely (localStorage/sessionStorage)
3. **Token Usage**: Include in Authorization header for protected endpoints
4. **Token Expiration**: Tokens expire after 24 hours
5. **Token Refresh**: Re-authenticate when token expires

### Authentication Flow

```
Client                          Server
  |                               |
  |  POST /auth/login             |
  |  (email, password)            |
  |------------------------------>|
  |                               |
  |  200 OK                       |
  |  { token: "jwt_token" }       |
  |<------------------------------|
  |                               |
  |  GET /notes                   |
  |  Authorization: Bearer token  |
  |------------------------------>|
  |                               |
  |  200 OK                       |
  |  { notes: [...] }             |
  |<------------------------------|
```

## Error Handling

### Standard Error Response

All API errors follow a consistent format:

```json
{
  "error": "Human-readable error message",
  "code": "ERROR_CODE",
  "details": "Additional error details (optional)"
}
```

### HTTP Status Codes

| Status Code | Meaning | Usage |
|-------------|---------|-------|
| `200` | OK | Successful request |
| `201` | Created | Resource created successfully |
| `400` | Bad Request | Invalid request data |
| `401` | Unauthorized | Authentication required/failed |
| `403` | Forbidden | Access denied |
| `404` | Not Found | Resource not found |
| `409` | Conflict | Resource already exists |
| `429` | Too Many Requests | Rate limit exceeded |
| `500` | Internal Server Error | Server error |
| `503` | Service Unavailable | Service temporarily unavailable |

### Common Error Scenarios

**Invalid JSON:**
```json
HTTP/1.1 400 Bad Request
{
  "error": "Invalid request",
  "code": "INVALID_JSON"
}
```

**Authentication Required:**
```json
HTTP/1.1 401 Unauthorized  
{
  "error": "Missing authorization",
  "code": "MISSING_TOKEN"
}
```

**Invalid Token:**
```json
HTTP/1.1 401 Unauthorized
{
  "error": "Invalid token", 
  "code": "INVALID_TOKEN"
}
```

**Rate Limited:**
```json
HTTP/1.1 429 Too Many Requests
{
  "error": "Rate limit exceeded",
  "code": "RATE_LIMITED",
  "retry_after": 60
}
```

## Rate Limiting

**Limits:**
- **100 requests per minute** per IP address
- **Additional limits** may apply to specific endpoints
- **Burst allowance** for legitimate usage spikes

**Rate Limit Headers:**
```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 87
X-RateLimit-Reset: 1640995200
```

**Exceeded Rate Limit:**
```http
HTTP/1.1 429 Too Many Requests
Retry-After: 60

{
  "error": "Rate limit exceeded",
  "retry_after": 60
}
```

## Authentication Endpoints

### Register New User

Create a new user account with encrypted workspace.

**Endpoint:** `POST /auth/register`

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!"
}
```

**Request Validation:**
- Email: Valid email format, unique
- Password: Minimum 12 characters, complexity requirements

**Response (Success):**
```json
HTTP/1.1 201 Created

{
  "message": "Registration successful",
  "token": "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9...",
  "user_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "workspace_id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
}
```

**Response (Error - Email Exists):**
```json
HTTP/1.1 409 Conflict

{
  "error": "Email already registered",
  "code": "EMAIL_EXISTS"
}
```

**Response (Error - Weak Password):**
```json
HTTP/1.1 400 Bad Request

{
  "error": "Password must be at least 12 characters",
  "code": "WEAK_PASSWORD"
}
```

**Curl Example:**
```bash
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "MySecurePassword123!"
  }'
```

### User Login

Authenticate existing user and obtain JWT token.

**Endpoint:** `POST /auth/login`

**Request Body:**
```json
{
  "email": "user@example.com", 
  "password": "SecurePassword123!",
  "mfa_code": "123456"
}
```

**Request Fields:**
- `email`: User's email address (required)
- `password`: User's password (required)
- `mfa_code`: TOTP code if MFA is enabled (optional)

**Response (Success):**
```json
HTTP/1.1 200 OK

{
  "token": "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9...",
  "session": "a1b2c3d4e5f6789...",
  "user_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479", 
  "workspace_id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
}
```

**Response (MFA Required):**
```json
HTTP/1.1 200 OK

{
  "mfa_required": true,
  "message": "MFA code required"
}
```

**Response (Error - Invalid Credentials):**
```json
HTTP/1.1 401 Unauthorized

{
  "error": "Invalid credentials",
  "code": "INVALID_CREDENTIALS"
}
```

**Response (Error - Account Locked):**
```json
HTTP/1.1 403 Forbidden

{
  "error": "Account locked. Try again later.",
  "code": "ACCOUNT_LOCKED",
  "retry_after": 900
}
```

**Curl Example:**
```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "MySecurePassword123!"
  }'
```

## Notes Management Endpoints

### Get All Notes

Retrieve all encrypted notes for the authenticated user.

**Endpoint:** `GET /notes`

**Authentication:** Required (Bearer token)

**Query Parameters:**
- `limit`: Maximum number of notes (optional, default: no limit)
- `offset`: Number of notes to skip (optional, default: 0)
- `workspace_id`: Filter by workspace (optional)

**Response (Success):**
```json
HTTP/1.1 200 OK

{
  "notes": [
    {
      "id": "note-uuid-1",
      "title_encrypted": "base64-encoded-encrypted-title",
      "content_encrypted": "base64-encoded-encrypted-content", 
      "created_at": "2024-01-15T10:30:00Z",
      "updated_at": "2024-01-15T14:22:00Z"
    },
    {
      "id": "note-uuid-2", 
      "title_encrypted": "base64-encoded-encrypted-title-2",
      "content_encrypted": "base64-encoded-encrypted-content-2",
      "created_at": "2024-01-14T09:15:00Z",
      "updated_at": "2024-01-14T16:45:00Z"
    }
  ]
}
```

**Note Fields:**
- `id`: Unique note identifier
- `title_encrypted`: Base64-encoded encrypted title
- `content_encrypted`: Base64-encoded encrypted content
- `created_at`: ISO 8601 timestamp of creation
- `updated_at`: ISO 8601 timestamp of last modification

**Curl Example:**
```bash
curl -X GET http://localhost:8080/api/v1/notes \
  -H "Authorization: Bearer <your-jwt-token>"
```

### Get Specific Note

Retrieve a specific encrypted note by ID.

**Endpoint:** `GET /notes/{id}`

**Authentication:** Required (Bearer token)

**Path Parameters:**
- `id`: Note UUID (required)

**Response (Success):**
```json
HTTP/1.1 200 OK

{
  "id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "title_encrypted": "base64-encoded-encrypted-title",
  "content_encrypted": "base64-encoded-encrypted-content",
  "created_at": "2024-01-15T10:30:00Z",
  "updated_at": "2024-01-15T14:22:00Z"
}
```

**Response (Error - Not Found):**
```json
HTTP/1.1 404 Not Found

{
  "error": "Note not found",
  "code": "NOTE_NOT_FOUND"
}
```

**Curl Example:**
```bash
curl -X GET http://localhost:8080/api/v1/notes/f47ac10b-58cc-4372-a567-0e02b2c3d479 \
  -H "Authorization: Bearer <your-jwt-token>"
```

### Create New Note

Create a new encrypted note.

**Endpoint:** `POST /notes`

**Authentication:** Required (Bearer token)

**Request Body:**
```json
{
  "title_encrypted": "base64-encoded-encrypted-title",
  "content_encrypted": "base64-encoded-encrypted-content"
}
```

**Request Validation:**
- Both fields are required
- Must be valid base64-encoded encrypted data
- Encrypted content must decrypt to valid JSON on client

**Response (Success):**
```json
HTTP/1.1 201 Created

{
  "id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "message": "Note created successfully"
}
```

**Response (Error - Invalid Encryption):**
```json
HTTP/1.1 400 Bad Request

{
  "error": "Invalid title encryption",
  "code": "INVALID_ENCRYPTION"
}
```

**Curl Example:**
```bash
curl -X POST http://localhost:8080/api/v1/notes \
  -H "Authorization: Bearer <your-jwt-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "title_encrypted": "base64-encrypted-data-here",
    "content_encrypted": "base64-encrypted-content-here"
  }'
```

### Update Existing Note

Update an existing encrypted note.

**Endpoint:** `PUT /notes/{id}`

**Authentication:** Required (Bearer token)

**Path Parameters:**
- `id`: Note UUID (required)

**Request Body:**
```json
{
  "title_encrypted": "base64-encoded-encrypted-title-updated",
  "content_encrypted": "base64-encoded-encrypted-content-updated"
}
```

**Response (Success):**
```json
HTTP/1.1 200 OK

{
  "message": "Note updated successfully"
}
```

**Response (Error - Not Found):**
```json
HTTP/1.1 404 Not Found

{
  "error": "Note not found",
  "code": "NOTE_NOT_FOUND"
}
```

**Curl Example:**
```bash
curl -X PUT http://localhost:8080/api/v1/notes/f47ac10b-58cc-4372-a567-0e02b2c3d479 \
  -H "Authorization: Bearer <your-jwt-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "title_encrypted": "updated-base64-encrypted-title",
    "content_encrypted": "updated-base64-encrypted-content"
  }'
```

### Delete Note

Soft delete an existing note (sets deleted_at timestamp).

**Endpoint:** `DELETE /notes/{id}`

**Authentication:** Required (Bearer token)

**Path Parameters:**
- `id`: Note UUID (required)

**Response (Success):**
```json
HTTP/1.1 200 OK

{
  "message": "Note deleted successfully"
}
```

**Response (Error - Not Found):**
```json
HTTP/1.1 404 Not Found

{
  "error": "Note not found", 
  "code": "NOTE_NOT_FOUND"
}
```

**Curl Example:**
```bash
curl -X DELETE http://localhost:8080/api/v1/notes/f47ac10b-58cc-4372-a567-0e02b2c3d479 \
  -H "Authorization: Bearer <your-jwt-token>"
```

## Health Check Endpoints

### Basic Health Check

Check if the API service is running and responding.

**Endpoint:** `GET /health`

**Authentication:** Not required

**Response (Success):**
```json
HTTP/1.1 200 OK

{
  "status": "healthy",
  "encryption": "enabled"
}
```

**Curl Example:**
```bash
curl http://localhost:8080/api/v1/health
```

### Readiness Check

Comprehensive check including database and Redis connectivity.

**Endpoint:** `GET /ready`

**Authentication:** Not required

**Response (Success):**
```json
HTTP/1.1 200 OK

{
  "status": "ready",
  "db": "connected",
  "redis": "connected", 
  "encryption": "active"
}
```

**Response (Service Unavailable):**
```json
HTTP/1.1 503 Service Unavailable

{
  "status": "not ready",
  "db": "down",
  "redis": "connected",
  "encryption": "active"
}
```

**Curl Example:**
```bash
curl http://localhost:8080/api/v1/ready
```

## Request/Response Examples

### Complete Registration and Note Creation Workflow

**1. Register New User:**
```bash
# Register
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "alice@example.com",
    "password": "MyVerySecurePassword123!"
  }'

# Response
{
  "message": "Registration successful",
  "token": "eyJhbGciOiJIUzUxMiJ9...",
  "user_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "workspace_id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
}
```

**2. Create First Note:**
```bash
# Note: In practice, title and content would be encrypted client-side
curl -X POST http://localhost:8080/api/v1/notes \
  -H "Authorization: Bearer eyJhbGciOiJIUzUxMiJ9..." \
  -H "Content-Type: application/json" \
  -d '{
    "title_encrypted": "SGVsbG8gV29ybGQ=",
    "content_encrypted": "VGhpcyBpcyBteSBmaXJzdCBzZWN1cmUgbm90ZSE="
  }'

# Response  
{
  "id": "a1b2c3d4-e5f6-7890-1234-567890abcdef",
  "message": "Note created successfully"
}
```

**3. Retrieve All Notes:**
```bash
curl -X GET http://localhost:8080/api/v1/notes \
  -H "Authorization: Bearer eyJhbGciOiJIUzUxMiJ9..."

# Response
{
  "notes": [
    {
      "id": "a1b2c3d4-e5f6-7890-1234-567890abcdef",
      "title_encrypted": "SGVsbG8gV29ybGQ=", 
      "content_encrypted": "VGhpcyBpcyBteSBmaXJzdCBzZWN1cmUgbm90ZSE=",
      "created_at": "2024-01-15T10:30:00Z",
      "updated_at": "2024-01-15T10:30:00Z"
    }
  ]
}
```

### JavaScript/TypeScript Client Example

```typescript
class SecureNotesAPI {
  private baseUrl = 'http://localhost:8080/api/v1';
  private token: string | null = null;

  async register(email: string, password: string) {
    const response = await fetch(`${this.baseUrl}/auth/register`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ email, password }),
    });

    if (!response.ok) {
      throw new Error(`Registration failed: ${response.statusText}`);
    }

    const data = await response.json();
    this.token = data.token;
    return data;
  }

  async login(email: string, password: string) {
    const response = await fetch(`${this.baseUrl}/auth/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ email, password }),
    });

    if (!response.ok) {
      throw new Error(`Login failed: ${response.statusText}`);
    }

    const data = await response.json();
    this.token = data.token;
    return data;
  }

  async getNotes() {
    if (!this.token) throw new Error('Not authenticated');

    const response = await fetch(`${this.baseUrl}/notes`, {
      headers: {
        'Authorization': `Bearer ${this.token}`,
      },
    });

    if (!response.ok) {
      throw new Error(`Failed to fetch notes: ${response.statusText}`);
    }

    return await response.json();
  }

  async createNote(titleEncrypted: string, contentEncrypted: string) {
    if (!this.token) throw new Error('Not authenticated');

    const response = await fetch(`${this.baseUrl}/notes`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${this.token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        title_encrypted: titleEncrypted,
        content_encrypted: contentEncrypted,
      }),
    });

    if (!response.ok) {
      throw new Error(`Failed to create note: ${response.statusText}`);
    }

    return await response.json();
  }
}
```

### Python Client Example

```python
import requests
import json
from typing import Optional, Dict, Any

class SecureNotesAPI:
    def __init__(self, base_url: str = "http://localhost:8080/api/v1"):
        self.base_url = base_url
        self.token: Optional[str] = None

    def register(self, email: str, password: str) -> Dict[Any, Any]:
        response = requests.post(
            f"{self.base_url}/auth/register",
            json={"email": email, "password": password}
        )
        response.raise_for_status()
        
        data = response.json()
        self.token = data["token"]
        return data

    def login(self, email: str, password: str) -> Dict[Any, Any]:
        response = requests.post(
            f"{self.base_url}/auth/login", 
            json={"email": email, "password": password}
        )
        response.raise_for_status()
        
        data = response.json()
        self.token = data["token"]
        return data

    def get_notes(self) -> Dict[Any, Any]:
        if not self.token:
            raise ValueError("Not authenticated")
            
        response = requests.get(
            f"{self.base_url}/notes",
            headers={"Authorization": f"Bearer {self.token}"}
        )
        response.raise_for_status()
        return response.json()

    def create_note(self, title_encrypted: str, content_encrypted: str) -> Dict[Any, Any]:
        if not self.token:
            raise ValueError("Not authenticated")
            
        response = requests.post(
            f"{self.base_url}/notes",
            json={
                "title_encrypted": title_encrypted,
                "content_encrypted": content_encrypted
            },
            headers={"Authorization": f"Bearer {self.token}"}
        )
        response.raise_for_status()
        return response.json()
```

## Client Libraries

### Official JavaScript/TypeScript SDK

```bash
npm install @secure-notes/js-sdk
```

```typescript
import { SecureNotesClient } from '@secure-notes/js-sdk';

const client = new SecureNotesClient('http://localhost:8080/api/v1');
await client.register('user@example.com', 'password123');
const notes = await client.getNotes();
```

### Go SDK

```go
import "github.com/secure-notes/go-sdk"

client := securenotes.NewClient("http://localhost:8080/api/v1")
err := client.Register("user@example.com", "password123")
notes, err := client.GetNotes()
```

## Security Considerations

### Client-Side Encryption Requirements

**All sensitive data must be encrypted client-side before transmission:**

1. **Key Derivation**: Use PBKDF2 with 600,000+ iterations
2. **Encryption Algorithm**: XChaCha20-Poly1305 or equivalent
3. **Nonce**: Generate random nonce for each encryption
4. **Encoding**: Base64 encode encrypted data for transmission

### API Security Best Practices

**Token Management:**
- Store JWT tokens securely (HTTPOnly cookies preferred)
- Implement token refresh mechanism
- Clear tokens on logout
- Never log tokens in client-side code

**Request Security:**
- Always use HTTPS in production
- Validate all server responses
- Implement request timeouts
- Handle rate limiting gracefully

**Error Handling:**
- Don't expose sensitive information in error messages
- Implement proper error recovery
- Log security events appropriately
- Handle network failures gracefully

### HTTPS/TLS Requirements

**Production Requirements:**
- TLS 1.3 minimum
- Strong cipher suites only
- HSTS headers enabled
- Certificate pinning recommended

**Development:**
```bash
# Generate self-signed certificates
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes

# Start server with HTTPS
./secure-notes-backend --tls --cert=cert.pem --key=key.pem
```

This API documentation provides complete information for integrating with the Secure Notes API while maintaining the zero-knowledge security model.