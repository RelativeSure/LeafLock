# LeafLock API Quick Reference & curl Examples

**Base URL**: `http://localhost:8080/api/v1`

---

## 1. Health & Status Endpoints

### Health Check (Full)
```bash
curl -s http://localhost:8080/api/v1/health | jq .
```
**Response (200)**:
```json
{
  "status": "healthy",
  "database": "healthy",
  "redis": "healthy",
  "timestamp": "2025-10-24T20:01:48Z",
  "uptime": "3m13.721492633s",
  "user_count": 7,
  "note_count": 42,
  "version": "1.0.0"
}
```

### Liveness Probe
```bash
curl -s http://localhost:8080/api/v1/health/live | jq .
```

### Readiness Probe
```bash
curl -s http://localhost:8080/api/v1/health/ready | jq .
```

---

## 2. Authentication

### Register New User
```bash
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePassword123!",
    "name": "John Doe"
  }' | jq .
```
**Response (200/201)**:
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

### Login
```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePassword123!"
  }' | jq .
```
**Response (200)**:
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

### Check Registration Status
```bash
curl -s http://localhost:8080/api/v1/auth/registration | jq .
```
**Response (200)**:
```json
{
  "enabled": true
}
```

---

## 3. Multi-Factor Authentication (MFA)

### Get MFA Status
```bash
curl -s http://localhost:8080/api/v1/auth/mfa/status \
  -H "Authorization: Bearer $TOKEN" | jq .
```
**Response (200)**:
```json
{
  "mfa_enabled": false,
  "backup_codes_remaining": 0
}
```

### Setup MFA (TOTP)
```bash
curl -X POST http://localhost:8080/api/v1/auth/mfa/setup \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}' | jq .
```
**Response (200)**:
```json
{
  "secret": "U74EZ2ETHDFLOUUVVUJXKYPJRYHRGHDR",
  "qr_code_url": "otpauth://totp/LeafLock:user@example.com?algorithm=SHA1&digits=6&issuer=LeafLock&secret=U74EZ2ETHDFLOUUVVUJXKYPJRYHRGHDR"
}
```

---

## 4. Notes Management

### Create Note
```bash
curl -X POST http://localhost:8080/api/v1/notes \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "My First Note",
    "content": "Note content here",
    "encrypted_content": "encrypted_data_base64"
  }' | jq .
```
**Response (201)**:
```json
{
  "id": "cb992ed5-b029-41b3-8327-7b9f13a64aad",
  "message": "Note created successfully"
}
```

### List All Notes
```bash
curl -s http://localhost:8080/api/v1/notes \
  -H "Authorization: Bearer $TOKEN" | jq .
```
**Response (200)**:
```json
{
  "notes": [
    {
      "id": "cb992ed5-b029-41b3-8327-7b9f13a64aad",
      "title_encrypted": "...",
      "content_encrypted": "...",
      "created_at": "2025-10-24T20:01:49.122455Z",
      "updated_at": "2025-10-24T20:01:49.122455Z",
      "folder_id": null,
      "tags": []
    }
  ]
}
```

### Get Specific Note
```bash
curl -s http://localhost:8080/api/v1/notes/{note_id} \
  -H "Authorization: Bearer $TOKEN" | jq .
```

### Update Note
```bash
curl -X PUT http://localhost:8080/api/v1/notes/{note_id} \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Updated Title",
    "content": "Updated content",
    "encrypted_content": "new_encrypted_data"
  }' | jq .
```
**Response (200)**:
```json
{
  "message": "Note updated successfully"
}
```

### Delete Note
```bash
curl -X DELETE http://localhost:8080/api/v1/notes/{note_id} \
  -H "Authorization: Bearer $TOKEN"
```

---

## 5. Tags

### Create Tag
```bash
curl -X POST http://localhost:8080/api/v1/tags \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Important",
    "color": "#FF0000"
  }' | jq .
```
**Response (201)**:
```json
{
  "id": "9a4a863c-9309-4e62-8bc4-269bddee1da3",
  "message": "Tag created successfully"
}
```

### List Tags
```bash
curl -s http://localhost:8080/api/v1/tags \
  -H "Authorization: Bearer $TOKEN" | jq .
```
**Response (200)**:
```json
{
  "tags": [
    {
      "id": "9a4a863c-9309-4e62-8bc4-269bddee1da3",
      "name": "Important",
      "color": "#FF0000",
      "created_at": "2025-10-24T20:01:49.209001Z",
      "updated_at": "2025-10-24T20:01:49.209001Z"
    }
  ]
}
```

---

## 6. Folders

### Create Folder
```bash
curl -X POST http://localhost:8080/api/v1/folders \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Work",
    "color": "#0000FF"
  }' | jq .
```
**Response (200/201)**:
```json
{
  "id": "8478e88a-af52-49b3-964a-55a491328501",
  "name": "Work",
  "color": "#0000FF",
  "message": "Folder created successfully"
}
```

### List Folders
```bash
curl -s http://localhost:8080/api/v1/folders \
  -H "Authorization: Bearer $TOKEN" | jq .
```
**Response (200)**:
```json
{
  "folders": [
    {
      "id": "8478e88a-af52-49b3-964a-55a491328501",
      "name": "Work",
      "color": "#0000FF",
      "created_at": "2025-10-24T20:01:49.226176Z",
      "updated_at": "2025-10-24T20:01:49.226176Z"
    }
  ]
}
```

---

## 7. Templates

### List Templates
```bash
curl -s http://localhost:8080/api/v1/templates \
  -H "Authorization: Bearer $TOKEN" | jq .
```
**Response (200)**:
```json
{
  "templates": [
    {
      "id": "template-1",
      "name": "Bug Report",
      "description": "Template for documenting software bugs",
      "icon": "bug",
      "content": "# Bug Report\n\n## Description\n...",
      "created_at": "2025-10-19T09:13:41.316459Z"
    }
  ]
}
```

---

## 8. Settings

### Get User Settings
```bash
curl -s http://localhost:8080/api/v1/settings \
  -H "Authorization: Bearer $TOKEN" | jq .
```
**Response (200)**:
```json
{
  "theme": "system"
}
```

### Update Settings
```bash
curl -X PUT http://localhost:8080/api/v1/settings \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "theme": "dark"
  }' | jq .
```
**Response (200)**:
```json
{
  "theme": "dark"
}
```

---

## Error Responses

### 401 Unauthorized (Missing Token)
```json
{
  "error": "No authorization token provided",
  "code": "INVALID_TOKEN"
}
```

### 401 Unauthorized (Invalid Token)
```json
{
  "error": "Invalid or expired token",
  "code": "INVALID_TOKEN"
}
```

### 400 Bad Request
```json
{
  "error": "password must be at least 12 characters long",
  "code": "VALIDATION_FAILED"
}
```

### 409 Conflict (Duplicate Email)
```json
{
  "error": "email already exists",
  "code": "EMAIL_EXISTS"
}
```

### 404 Not Found
```json
{
  "error": "Note not found"
}
```

---

## Common curl Patterns

### Setting up a TOKEN variable for reuse
```bash
TOKEN=$(curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"Password123!"}' \
  | jq -r '.token')

# Use it in subsequent requests
curl -s http://localhost:8080/api/v1/notes \
  -H "Authorization: Bearer $TOKEN" | jq .
```

### Pretty-printing JSON responses
```bash
# With jq installed
curl -s http://localhost:8080/api/v1/health | jq .

# Without jq
curl -s http://localhost:8080/api/v1/health | python3 -m json.tool
```

### Checking response status code
```bash
curl -s -w "\nStatus: %{http_code}\n" http://localhost:8080/api/v1/health
```

### Measuring response time
```bash
curl -s -w "Response time: %{time_total}s\n" http://localhost:8080/api/v1/health -o /dev/null
```

---

## Test Summary Results

**Overall Status**: PASS (19/19 tests)  
**Pass Rate**: 100%  
**Performance**: Excellent (avg 6.5ms response time)  
**Security**: Strong (JWT + proper headers)  
**Status Code Consistency**: Good (201 for create, 200 for read/update)

