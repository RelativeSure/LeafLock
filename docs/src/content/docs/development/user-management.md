# User Management Guide

This guide provides instructions for managing users in LeafLock, including database operations and admin tasks.

## Default Admin Account

### Automatic Creation

LeafLock automatically creates a default admin user when:
1. The application starts
2. No users exist in the database
3. `ENABLE_DEFAULT_ADMIN=true` (default)

### Configuration

Configure the default admin account via environment variables:

```bash
# Enable/disable default admin creation
ENABLE_DEFAULT_ADMIN=true

# Default admin credentials
DEFAULT_ADMIN_EMAIL=admin@leaflock.app
DEFAULT_ADMIN_PASSWORD=AdminPass123!
```

### Security Best Practices

⚠️ **CRITICAL**: Change the default password immediately after first login!

1. **Login with default credentials**
2. **Go to Settings → Change Password**
3. **Use a strong, unique password**
4. **Consider enabling MFA**

## Database User Management

For direct database operations, you can manage users through SQL commands.

### Prerequisites

Access the PostgreSQL database:

```bash
# Using Docker Compose
docker compose exec postgres psql -U postgres -d notes

# Using Podman
podman exec -it leaflock-postgres psql -U postgres -d notes
```

### View Existing Users

```sql
-- List all users with basic info
SELECT
    id,
    is_admin,
    mfa_enabled,
    failed_attempts,
    locked_until,
    created_at,
    last_login
FROM users
ORDER BY created_at DESC;

-- Count total users
SELECT COUNT(*) as total_users FROM users;

-- Count admin users
SELECT COUNT(*) as admin_users FROM users WHERE is_admin = true;
```

### Create New User

**Note**: Due to end-to-end encryption, users should be created through the application's registration endpoint, not directly in the database. However, you can create basic user records:

```sql
-- This creates a user record but they won't be able to login
-- They need to complete registration through the application
INSERT INTO users (
    email_hash,
    email_encrypted,
    email_search_hash,
    password_hash,
    salt,
    master_key_encrypted,
    is_admin,
    mfa_enabled
) VALUES (
    -- These would need to be properly encrypted values
    -- Use the application's registration endpoint instead
);
```

**Recommended**: Use the API registration endpoint or admin panel instead.

### Modify User Permissions

```sql
-- Make a user an admin
UPDATE users
SET is_admin = true
WHERE id = 'user-uuid-here';

-- Remove admin privileges
UPDATE users
SET is_admin = false
WHERE id = 'user-uuid-here';

-- Enable MFA for a user
UPDATE users
SET mfa_enabled = true
WHERE id = 'user-uuid-here';

-- Disable MFA for a user
UPDATE users
SET mfa_enabled = false,
    mfa_secret_encrypted = NULL
WHERE id = 'user-uuid-here';
```

### Reset Failed Login Attempts

```sql
-- Reset failed attempts and unlock account
UPDATE users
SET failed_attempts = 0,
    locked_until = NULL
WHERE id = 'user-uuid-here';

-- Unlock all locked accounts
UPDATE users
SET failed_attempts = 0,
    locked_until = NULL
WHERE locked_until IS NOT NULL;
```

### Find User by Email

Since emails are encrypted, you need to search by email hash:

```sql
-- You'll need the email to generate the hash
-- This requires application-level functions
SELECT id, is_admin, created_at, last_login
FROM users
WHERE email_search_hash = encode(
    sha256(lower('user@example.com')::bytea),
    'hex'
)::bytea;
```

### Delete User

⚠️ **Warning**: This will permanently delete all user data including notes!

```sql
-- Delete a user and all their data
DELETE FROM users WHERE id = 'user-uuid-here';

-- The foreign key constraints will cascade delete:
-- - User's notes
-- - User's workspaces
-- - User's sessions
-- - User's audit logs
-- - User's collaborations
```

### User Storage Information

```sql
-- Check user storage usage
SELECT
    id,
    storage_used,
    storage_limit,
    ROUND((storage_used::float / storage_limit * 100), 2) as usage_percent
FROM users
WHERE storage_used > 0
ORDER BY usage_percent DESC;

-- Update user storage limit (in bytes)
UPDATE users
SET storage_limit = 10485760  -- 10MB
WHERE id = 'user-uuid-here';
```

## Admin Panel Operations

### Access Requirements

- Must be logged in as admin user (`is_admin = true`)
- Access admin endpoints at `/api/v1/admin/*`

### Available Admin Functions

1. **User Management**
   - View all users
   - Modify user permissions
   - Reset user passwords (generates reset tokens)
   - Lock/unlock accounts

2. **System Settings**
   - View application settings
   - Modify global configurations
   - Manage announcements

3. **Audit Logs**
   - View user activity
   - Security event monitoring
   - Login attempt tracking

## API User Management

### Create User (Registration)

```bash
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "newuser@example.com",
    "password": "SecurePassword123!"
  }'
```

### Admin: List Users

```bash
curl -X GET http://localhost:8080/api/v1/admin/users \
  -H "Authorization: Bearer your-admin-jwt-token"
```

### Admin: Modify User

```bash
curl -X PATCH http://localhost:8080/api/v1/admin/users/user-id \
  -H "Authorization: Bearer your-admin-jwt-token" \
  -H "Content-Type: application/json" \
  -d '{
    "is_admin": true
  }'
```

## Troubleshooting

### User Cannot Login

1. **Check account lock status**:
   ```sql
   SELECT id, failed_attempts, locked_until
   FROM users
   WHERE email_search_hash = 'search-hash';
   ```

2. **Reset failed attempts**:
   ```sql
   UPDATE users
   SET failed_attempts = 0, locked_until = NULL
   WHERE id = 'user-id';
   ```

### Admin Access Lost

1. **Make existing user admin**:
   ```sql
   UPDATE users
   SET is_admin = true
   WHERE id = 'user-id';
   ```

2. **Or enable default admin creation**:
   ```bash
   # Set in .env file
   ENABLE_DEFAULT_ADMIN=true
   DEFAULT_ADMIN_EMAIL=recovery@yourdomain.com
   DEFAULT_ADMIN_PASSWORD=TempRecoveryPass123!

   # Restart application
   make down && make up
   ```

### Reset All User Data

⚠️ **DANGER**: This will delete ALL users and data!

```sql
-- Clear all user data (irreversible!)
TRUNCATE users CASCADE;

-- This will also clear:
-- - All notes and workspaces
-- - All sessions
-- - All audit logs
-- - All collaborations
-- - All attachments
```

## Security Considerations

1. **Encryption**: All user emails and sensitive data are encrypted at rest
2. **Password Hashing**: Uses Argon2id with high memory cost
3. **Session Management**: JWT tokens with Redis-backed refresh rotation
4. **Audit Logging**: All user actions are logged for security monitoring
5. **MFA Support**: TOTP-based multi-factor authentication available

## Backup Considerations

When backing up user data, ensure you also backup:
- Database encryption keys
- JWT secrets
- User master keys (encrypted)
- Redis session data (if needed for active sessions)

Without the proper encryption keys, backed up data cannot be decrypted.