# LeafLock Feature Implementation Roadmap

This document outlines missing/incomplete features identified in the codebase and provides implementation guidance.

**Status**: Generated 2025-11-05
**Related commits**: 5c753f0 (audit log viewer backend)

---

## ✅ COMPLETED

### 1. Audit Log Viewer (Backend)
**Status**: ✅ Backend complete, ⚠️ Frontend pending
**Commits**: 5c753f0

**Backend implementation**:
- `handlers/audit_logs.go` - Complete
- Routes: `GET /api/v1/audit-logs`, `GET /api/v1/admin/audit-logs`
- Features: Filtering, pagination, user email joins

**Frontend TODO**:
```typescript
// Create: frontend/src/stores/auditLogStore.ts
// Create: frontend/src/components/admin/AuditLogViewer.tsx
// Create: frontend/src/components/settings/ActivityLog.tsx
// API client: Add to frontend/src/services/api/adminService.ts
```

---

## 🔨 IMPLEMENTATION REQUIRED

### 2. User Profiles & Avatars
**Priority**: HIGH
**Complexity**: Medium
**Impact**: High (basic missing feature)

**Database**: Already exists
```sql
-- users table columns (existing):
profile_picture_type VARCHAR(20) DEFAULT 'gravatar'
profile_picture_custom_url TEXT
```

**Backend TODO**:
```go
// File: backend/handlers/profile.go
type ProfileHandler struct {
    db database.Database
    crypto *crypto.CryptoService
}

// Endpoints needed:
// GET /api/v1/profile
// PUT /api/v1/profile (name, bio)
// POST /api/v1/profile/avatar (upload)
// DELETE /api/v1/profile/avatar

// Add columns to users table:
ALTER TABLE users ADD COLUMN IF NOT EXISTS display_name TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS bio TEXT;
```

**Frontend TODO**:
```typescript
// Create: frontend/src/components/settings/ProfileTab.tsx
// Update: frontend/src/stores/authStore.ts (add profile fields)
// Avatar upload with image cropping
// Gravatar integration
```

---

### 3. Nested Folders
**Priority**: HIGH
**Complexity**: Medium-High
**Impact**: Very High (major UX improvement)

**Database migration**:
```sql
-- File: backend/database/schema.go
ALTER TABLE folders ADD COLUMN IF NOT EXISTS parent_id UUID REFERENCES folders(id) ON DELETE CASCADE;
ALTER TABLE folders ADD COLUMN IF NOT EXISTS depth INT DEFAULT 0;
ALTER TABLE folders ADD COLUMN IF NOT EXISTS path TEXT; -- /parent/child/grandchild

-- Index for tree queries
CREATE INDEX IF NOT EXISTS idx_folders_parent_id ON folders(parent_id);
CREATE INDEX IF NOT EXISTS idx_folders_path ON folders USING gin(path gin_trgm_ops);
```

**Backend changes**:
```go
// File: backend/handlers/folders.go
// Update CreateFolder to accept parent_id
// Add GetFolderTree (recursive tree structure)
// Add MoveFolderToParent
// Prevent circular references
// Update depth on move operations

// New endpoints:
// POST /api/v1/folders/:id/move (move to new parent)
// GET /api/v1/folders/tree (get full tree structure)
```

**Frontend changes**:
```typescript
// Update: frontend/src/components/sidebar/FolderTree.tsx
// Implement collapsible tree view
// Drag-and-drop folder reordering
// Breadcrumb navigation for deep folders
```

---

### 4. Advanced Search Filters
**Priority**: HIGH
**Complexity**: Medium
**Impact**: High

**Backend changes**:
```go
// File: backend/handlers/search.go
type SearchRequest struct {
    Query        string   `json:"query"`
    Tags         []string `json:"tags"`          // NEW
    FolderIDs    []string `json:"folder_ids"`    // NEW
    StartDate    string   `json:"start_date"`    // NEW
    EndDate      string   `json:"end_date"`      // NEW
    CreatedBy    string   `json:"created_by"`    // NEW
    IsPinned     *bool    `json:"is_pinned"`     // NEW
    IsLocked     *bool    `json:"is_locked"`     // NEW
    SearchIn     string   `json:"search_in"`     // "title"|"content"|"both"
    SortBy       string   `json:"sort_by"`       // "created_at"|"updated_at"|"title"
    SortOrder    string   `json:"sort_order"`    // "asc"|"desc"
}

// Update SearchNotes to handle all filters
// Implement full-text search using PostgreSQL tsvector
```

**Frontend changes**:
```typescript
// Create: frontend/src/components/search/AdvancedSearchDialog.tsx
// Create: frontend/src/components/search/SearchFilters.tsx
// Update: frontend/src/stores/notesStore.ts (add advancedSearch method)
```

---

### 5. In-App Notifications (WebSocket)
**Priority**: HIGH
**Complexity**: High
**Impact**: High

**Database**:
```sql
-- File: backend/database/schema.go
CREATE TABLE IF NOT EXISTS notifications (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE NOT NULL,
    type TEXT NOT NULL, -- 'share_invite', 'collaborator_edit', 'mention', 'system'
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    action_url TEXT,
    read BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_notifications_user_id ON notifications(user_id, read, created_at DESC);
```

**Backend changes**:
```go
// File: backend/handlers/notifications.go
type NotificationHandler struct {
    db  database.Database
    hub *websocket.Hub
}

// Endpoints:
// GET /api/v1/notifications (list)
// PUT /api/v1/notifications/:id/read (mark as read)
// PUT /api/v1/notifications/read-all
// DELETE /api/v1/notifications/:id

// Update websocket/hub.go to broadcast notifications
// Emit notification on:
// - Note shared with user
// - Collaborator edits shared note
// - @mention in note
// - Admin announcements
```

**Frontend changes**:
```typescript
// Create: frontend/src/stores/notificationStore.ts
// Create: frontend/src/components/notifications/NotificationBell.tsx
// Create: frontend/src/components/notifications/NotificationPanel.tsx
// Update: WebSocket connection to listen for notifications
```

---

### 6. App Settings UI (Admin)
**Priority**: MEDIUM
**Complexity**: Medium
**Impact**: High (move config from env vars)

**Database**:
```sql
-- Table exists: app_settings
-- Populate with feature flags:
INSERT INTO app_settings (key, value, description) VALUES
('maintenance_mode', 'false', 'Enable maintenance mode'),
('allow_registration', 'true', 'Allow new user registration'),
('default_user_quota_mb', '5', 'Default storage quota per user (MB)'),
('max_file_size_mb', '25', 'Maximum file upload size (MB)'),
('session_duration_hours', '24', 'JWT session duration'),
('require_email_verification', 'false', 'Require email verification for new users'),
('instance_name', 'LeafLock', 'Instance name for branding'),
('primary_color', '#10b981', 'Primary brand color'),
('logo_url', '', 'Custom logo URL');
```

**Backend changes**:
```go
// File: backend/handlers/app_settings.go
// GET /api/v1/admin/settings
// PUT /api/v1/admin/settings/:key
// Validate settings before saving
// Clear cache on update
```

**Frontend changes**:
```typescript
// Create: frontend/src/components/admin/AppSettingsTab.tsx
// Settings categories: General, Security, Storage, Branding
// Real-time preview for branding changes
```

---

### 7. Workspace System
**Priority**: MEDIUM-HIGH
**Complexity**: Very High
**Impact**: Very High (unlocks team features)

**Status**: Database tables exist but completely unused

**Database tables (existing)**:
- `workspaces` - Team workspaces
- `roles` - Role definitions (admin, member, viewer)
- `user_roles` - User-to-role assignments

**Implementation phases**:

**Phase 1: Basic Workspace CRUD**
```go
// File: backend/handlers/workspaces.go
// POST /api/v1/workspaces (create)
// GET /api/v1/workspaces (list user's workspaces)
// GET /api/v1/workspaces/:id
// PUT /api/v1/workspaces/:id (update)
// DELETE /api/v1/workspaces/:id

// Add workspace_id to notes table queries (scope notes to workspace)
```

**Phase 2: Member Management**
```go
// POST /api/v1/workspaces/:id/members (invite)
// GET /api/v1/workspaces/:id/members
// DELETE /api/v1/workspaces/:id/members/:userId
// PATCH /api/v1/workspaces/:id/members/:userId/role
```

**Phase 3: Workspace-Scoped Permissions**
```go
// Implement middleware: CheckWorkspaceAccess
// Update all note/folder/tag handlers to respect workspace_id
// Implement permission checks based on user_roles
```

**Frontend phases**:
```typescript
// Phase 1: Workspace switcher in sidebar
// Phase 2: Workspace settings page
// Phase 3: Member management UI
// Phase 4: Workspace-scoped note views
```

---

### 8. Email Notifications
**Priority**: MEDIUM
**Complexity**: Medium
**Impact**: Medium

**Backend changes**:
```go
// File: backend/services/email.go (extend existing)
// Add email templates:
// - share_invite.html
// - collaborator_activity.html
// - mention_notification.html

// Trigger emails on:
// - Note shared (if user has email_notifications=true)
// - Collaborator edits (digest every 1 hour)
// - @mentions
```

**Database migration**:
```sql
-- Add email digest preferences
ALTER TABLE users ADD COLUMN IF NOT EXISTS email_digest_frequency VARCHAR(20) DEFAULT 'realtime';
-- Values: 'realtime', 'hourly', 'daily', 'never'
```

---

### 9. Granular Collaborator Permissions
**Priority**: MEDIUM
**Complexity**: Medium
**Impact**: Medium

**Database**:
```sql
-- Update collaborations table
ALTER TABLE collaborations ADD COLUMN IF NOT EXISTS can_comment BOOLEAN DEFAULT true;
ALTER TABLE collaborations ADD COLUMN IF NOT EXISTS can_view_versions BOOLEAN DEFAULT true;
ALTER TABLE collaborations ADD COLUMN IF NOT EXISTS can_download BOOLEAN DEFAULT true;
ALTER TABLE collaborations ADD COLUMN IF NOT EXISTS can_share BOOLEAN DEFAULT false;
```

**Backend changes**:
```go
// File: backend/handlers/collaboration.go
// Update ShareNote to accept new permission fields
// Add middleware to check granular permissions before operations
// Implement permission inheritance for folders
```

---

### 10. User Analytics Dashboard
**Priority**: LOW
**Complexity**: Medium
**Impact**: Low-Medium

**Backend**:
```go
// File: backend/handlers/analytics.go
// GET /api/v1/analytics/summary
// - Total notes count
// - Notes created this week/month
// - Most edited notes
// - Storage usage breakdown
// - Collaboration stats

// GET /api/v1/analytics/activity-heatmap
// - Activity by day for last 90 days
```

**Frontend**:
```typescript
// Create: frontend/src/components/analytics/AnalyticsDashboard.tsx
// Use recharts for graphs
// Activity heatmap (GitHub-style)
// Storage usage pie chart
```

---

### 11. Note Enhancements
**Priority**: MEDIUM
**Complexity**: Low-Medium per feature
**Impact**: Medium

**Features to add**:

1. **Note Colors/Icons**
```sql
ALTER TABLE notes ADD COLUMN IF NOT EXISTS color VARCHAR(7); -- Hex color
ALTER TABLE notes ADD COLUMN IF NOT EXISTS icon VARCHAR(50); -- Icon name
```

2. **Table of Contents Generation**
```typescript
// Frontend: Auto-generate from H1-H6 headings in Quill content
// Sticky TOC sidebar for long notes
```

3. **Word Count / Reading Time**
```typescript
// Frontend: Calculate on note content change
// Display in note header
```

4. **Smart Folders (Saved Searches)**
```sql
CREATE TABLE IF NOT EXISTS smart_folders (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    search_query JSONB NOT NULL, -- Saved search criteria
    icon VARCHAR(50),
    created_at TIMESTAMPTZ DEFAULT NOW()
);
```

---

### 12. Public API & Integrations
**Priority**: LOW
**Complexity**: High
**Impact**: High (for advanced users)

**API Keys**:
```sql
CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    key_hash BYTEA NOT NULL UNIQUE, -- SHA-256 hash
    scopes TEXT[] DEFAULT ARRAY['read'], -- ['read', 'write', 'delete']
    last_used_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
```

**Webhooks**:
```sql
CREATE TABLE IF NOT EXISTS webhooks (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    events TEXT[] NOT NULL, -- ['note.created', 'note.updated', 'note.shared']
    secret TEXT NOT NULL, -- HMAC secret for verification
    active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
```

---

### 13. Backup & Disaster Recovery UI
**Priority**: LOW
**Complexity**: Medium
**Impact**: Medium

**Backend**:
```go
// File: backend/handlers/backup.go
// POST /api/v1/admin/backups/create (trigger manual backup)
// GET /api/v1/admin/backups (list available backups)
// POST /api/v1/admin/backups/:id/restore (restore from backup)
// GET /api/v1/admin/backups/:id/download

// Use pg_dump for PostgreSQL
// Store backups in S3-compatible storage or local filesystem
```

**Frontend**:
```typescript
// Create: frontend/src/components/admin/BackupManagement.tsx
// Schedule automatic backups
// Download backup files
// Restore from backup (with confirmation)
```

---

### 14. Key Rotation System
**Priority**: LOW (unless compliance required)
**Complexity**: Very High
**Impact**: High (security feature)

**Implementation**:
```go
// File: backend/handlers/key_rotation.go
// POST /api/v1/account/rotate-key
// 1. Generate new master key
// 2. Decrypt all notes with old key
// 3. Re-encrypt with new key
// 4. Update master_key_encrypted
// 5. Log rotation in key_rotations table

// Background job to process large note collections
// Progress tracking via WebSocket
```

---

## 🎯 RECOMMENDED IMPLEMENTATION ORDER

**Phase 1 - Quick Wins (1-2 weeks)**:
1. ✅ Audit log viewer backend (DONE)
2. Audit log viewer frontend (1-2 days)
3. User profiles & avatars (2-3 days)
4. Advanced search filters (2-3 days)

**Phase 2 - Core Features (2-3 weeks)**:
5. Nested folders (3-4 days)
6. In-app notifications (4-5 days)
7. App settings UI (2-3 days)
8. Note enhancements (colors, TOC, word count) (2-3 days)

**Phase 3 - Advanced (3-4 weeks)**:
9. Workspace system (7-10 days)
10. Granular permissions (2-3 days)
11. Email notifications (3-4 days)
12. User analytics (2-3 days)

**Phase 4 - Enterprise (ongoing)**:
13. Public API & webhooks (5-7 days)
14. Backup/restore UI (3-4 days)
15. Key rotation (5-7 days)

---

## 📊 ESTIMATED EFFORT

**Total estimated development time**: 8-12 weeks for full implementation

**Breakdown**:
- Phase 1 (Quick wins): 1-2 weeks
- Phase 2 (Core features): 2-3 weeks
- Phase 3 (Advanced): 3-4 weeks
- Phase 4 (Enterprise): 2-3 weeks

**Notes**:
- Estimates assume single developer
- Includes testing and documentation
- Frontend work is ~40% of total effort
- Database migrations are straightforward
- Complexity in state management and UI/UX

---

## 🚀 NEXT STEPS

1. **Complete audit log viewer frontend** (highest ROI)
2. **User profiles** (missing basic feature)
3. **Nested folders** (major UX improvement)
4. **Advanced search** (high user value)

After Phase 1 completion, reassess priorities based on user feedback.

---

## 📝 NOTES

- All database migrations use `IF NOT EXISTS` for safety
- Zero-knowledge architecture maintained throughout
- Rate limiting already configured in routes
- WebSocket infrastructure exists, ready for notifications
- Email service exists, needs template expansion
- Admin middleware exists, ready for new admin endpoints

**Generated by**: Claude Code
**Date**: 2025-11-05
**Branch**: claude/notes-app-features-011CUoSATrKv5xkP7tqPs2eU
