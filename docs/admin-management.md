# Admin Management Guide

## Overview

This secure notes application is designed with end-to-end encryption where each user manages their own encrypted workspace. Currently, the system does not have built-in super admin functionality due to the zero-knowledge architecture. However, this guide explains how to add admin capabilities and manage users at the database level.

## Current System Architecture

The application uses:
- **Zero-knowledge encryption**: Server never sees plaintext data
- **User workspaces**: Each user has their own encrypted workspace
- **Note-level permissions**: Users can share notes with `read`, `write`, or `admin` permissions
- **PostgreSQL database**: User data stored in encrypted format

## Database Schema

### Users Table Structure

```sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email TEXT UNIQUE NOT NULL,
    email_encrypted BYTEA NOT NULL,
    password_hash TEXT NOT NULL,
    salt BYTEA NOT NULL,
    master_key_encrypted BYTEA NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    last_login TIMESTAMPTZ,
    failed_attempts INT DEFAULT 0,
    locked_until TIMESTAMPTZ
);
```

## Adding Admin Role Support

Since there's no admin role currently, you'll need to modify the database schema:

### 1. Add Admin Column to Users Table

```sql
-- Connect to your PostgreSQL database
psql -U postgres -d notes

-- Add admin role column
ALTER TABLE users ADD COLUMN is_admin BOOLEAN DEFAULT false;

-- Create an index for faster admin queries
CREATE INDEX idx_users_is_admin ON users(is_admin);
```

### 2. Make a User Admin

To grant admin access to a user, update their record in the database:

```sql
-- Make a specific user admin by email
UPDATE users 
SET is_admin = true 
WHERE email = 'admin@example.com';

-- Or by user ID
UPDATE users 
SET is_admin = true 
WHERE id = 'your-user-uuid-here';
```

### 3. Remove Admin Access

```sql
-- Remove admin access from a user
UPDATE users 
SET is_admin = false 
WHERE email = 'user@example.com';
```

## Database User Management Tasks

### View All Users

```sql
-- List all users with basic info
SELECT 
    id,
    email,
    COALESCE(is_admin, false) as is_admin,
    created_at,
    last_login,
    failed_attempts
FROM users 
ORDER BY created_at DESC;
```

### Find Admin Users

```sql
-- List all admin users
SELECT 
    id,
    email,
    created_at,
    last_login
FROM users 
WHERE is_admin = true;
```

### User Activity Monitoring

```sql
-- Find inactive users (haven't logged in recently)
SELECT 
    id,
    email,
    created_at,
    last_login,
    (NOW() - last_login) as inactive_period
FROM users 
WHERE last_login < NOW() - INTERVAL '30 days'
   OR last_login IS NULL;
```

### Account Security Management

```sql
-- Check users with too many failed attempts
SELECT 
    id,
    email,
    failed_attempts,
    locked_until
FROM users 
WHERE failed_attempts > 5;

-- Unlock a locked user account
UPDATE users 
SET failed_attempts = 0, 
    locked_until = NULL 
WHERE email = 'user@example.com';
```

### User Statistics

```sql
-- Count total users
SELECT COUNT(*) as total_users FROM users;

-- Count active users (logged in last 30 days)
SELECT COUNT(*) as active_users 
FROM users 
WHERE last_login > NOW() - INTERVAL '30 days';

-- Count notes per user
SELECT 
    u.email,
    COUNT(n.id) as note_count
FROM users u
LEFT JOIN workspaces w ON u.id = w.owner_id
LEFT JOIN notes n ON w.id = n.workspace_id 
WHERE n.deleted_at IS NULL
GROUP BY u.id, u.email
ORDER BY note_count DESC;
```

## Backend Code Modifications Needed

To implement admin functionality, you would need to modify the Go backend:

### 1. Add Admin Middleware

```go
func AdminRequired(c *fiber.Ctx) error {
    userID := c.Locals("userID").(string)
    
    // Query database to check if user is admin
    var isAdmin bool
    err := db.QueryRow(context.Background(), 
        "SELECT COALESCE(is_admin, false) FROM users WHERE id = $1", 
        userID).Scan(&isAdmin)
    
    if err != nil || !isAdmin {
        return c.Status(403).JSON(fiber.Map{
            "error": "Admin access required",
        })
    }
    
    return c.Next()
}
```

### 2. Add Admin Routes

```go
// Admin routes
adminGroup := app.Group("/api/v1/admin", AuthRequired, AdminRequired)

adminGroup.Get("/users", listUsers)
adminGroup.Put("/users/:id/admin", toggleAdminStatus)
adminGroup.Delete("/users/:id", deleteUser)
adminGroup.Get("/stats", getSystemStats)
```

## Security Considerations

### Zero-Knowledge Limitations

Due to the zero-knowledge architecture:
- **Admins cannot read user notes**: All content is encrypted with user keys
- **Password resets**: Must be handled carefully to maintain encryption
- **User data**: Only metadata (email, timestamps) is visible to admins

### Recommended Admin Capabilities

Safe admin operations that preserve encryption:
- ✅ View user list and metadata
- ✅ Monitor login attempts and security events
- ✅ Disable/enable user accounts
- ✅ View system statistics and usage
- ✅ Manage system-wide settings
- ❌ Read user notes or content
- ❌ Reset passwords without user involvement

## Environment Setup for Admin Access

### Database Connection

Admins need direct database access for user management:

```bash
# Using PostgreSQL command line
export PGPASSWORD="your-postgres-password"
psql -h localhost -U postgres -d notes

# Or using a database admin tool
# Connect to: postgresql://postgres:password@localhost:5432/notes
```

### Backup User Data

Before making changes, always backup:

```bash
# Backup users table
pg_dump -h localhost -U postgres -d notes -t users > users_backup.sql

# Full database backup
pg_dump -h localhost -U postgres -d notes > full_backup.sql
```

## Common Admin Tasks

### 1. Creating the First Admin

```sql
-- After first user registers, make them admin
UPDATE users 
SET is_admin = true 
WHERE email = (
    SELECT email FROM users 
    ORDER BY created_at ASC 
    LIMIT 1
);
```

### 2. Emergency Account Recovery

```sql
-- If admin is locked out, unlock manually
UPDATE users 
SET failed_attempts = 0, 
    locked_until = NULL 
WHERE is_admin = true;
```

### 3. System Maintenance

```sql
-- Clean up old deleted notes (after 30 days)
DELETE FROM notes 
WHERE deleted_at IS NOT NULL 
  AND deleted_at < NOW() - INTERVAL '30 days';

-- Clean up inactive sessions (implement session cleanup)
-- This would depend on your session storage implementation
```

## Monitoring and Logging

For production admin management:

1. **Enable PostgreSQL logging** for audit trails
2. **Monitor authentication failures** for security
3. **Set up alerts** for suspicious activity
4. **Regular backups** of user data

## Frontend Admin Panel (Future Enhancement)

To add admin UI to the application, you would need:

1. **Admin route protection** in React
2. **Admin dashboard component** showing user statistics
3. **User management interface** for admin actions
4. **System health monitoring** displays

This would require updating the frontend with admin-specific components and routes that only render for users with `is_admin = true`.

---

**Note**: This guide assumes you want to add admin functionality to an existing zero-knowledge encrypted system. All admin operations should respect the encryption model and user privacy principles of the application.