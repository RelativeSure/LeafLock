package database

// DatabaseSchema contains the complete PostgreSQL schema for LeafLock
// This includes all tables, indexes, triggers, and functions required for the application
const DatabaseSchema = `
-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- UUIDv7 function for time-ordered UUIDs (PostgreSQL 18+ native or custom implementation)
CREATE OR REPLACE FUNCTION uuid_generate_v7()
RETURNS UUID AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_uuidv7') THEN
        -- Use native pg_uuidv7 if available
        PERFORM uuid_generate_v7();
    ELSE
        -- Custom implementation for older PostgreSQL versions
        DECLARE
            unix_ts_ms BIGINT;
            timestamp_bytes BYTEA;
            random_bytes BYTEA;
            combined BYTEA;
        BEGIN
            unix_ts_ms := EXTRACT(EPOCH FROM NOW()) * 1000;
            timestamp_bytes := substring(int8send(unix_ts_ms::INT8) FROM 2 FOR 6);
            random_bytes := gen_random_bytes(10);

            -- Construct UUIDv7 format: timestamp (48 bits) + version (4 bits) + random (62 bits)
            combined := timestamp_bytes || substring(random_bytes FROM 1);
            return combined::UUID;
        END;
    END IF;
END;
$$ LANGUAGE plpgsql;

-- Users table with zero-knowledge encryption
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email_hash BYTEA UNIQUE NOT NULL, -- SHA-256 hash for unique constraint and GDPR lookups
    email_plaintext TEXT NOT NULL, -- Plaintext email for operational use (password reset, notifications)
    email_search_hash BYTEA UNIQUE, -- Deterministic hash for login lookups
    password_hash TEXT NOT NULL, -- Argon2id hash
    salt BYTEA NOT NULL,
    master_key_encrypted BYTEA NOT NULL, -- User's encrypted master key (encrypted with password-derived key)
    public_key BYTEA, -- For sharing encrypted notes
    private_key_encrypted BYTEA, -- Encrypted with user's derived key
    mfa_secret_encrypted BYTEA, -- Encrypted TOTP secret
    mfa_enabled BOOLEAN DEFAULT false,
    mfa_backup_codes BYTEA[], -- Array of hashed backup codes (Argon2id)
    mfa_backup_codes_used BYTEA[], -- Track used backup codes
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    last_login TIMESTAMPTZ,
    failed_attempts INT DEFAULT 0,
    locked_until TIMESTAMPTZ,
    deleted_at TIMESTAMPTZ
);

-- Ensure admin flag exists
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin BOOLEAN DEFAULT false;

-- Add new encryption columns for enhanced security
ALTER TABLE users ADD COLUMN IF NOT EXISTS email_hash BYTEA UNIQUE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS email_search_hash BYTEA UNIQUE;

-- Add storage tracking columns for file import limits
ALTER TABLE users ADD COLUMN IF NOT EXISTS storage_used BIGINT DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS storage_limit BIGINT DEFAULT 5242880; -- 5MB default limit

-- Add soft delete column for users table (required for idx_users_count_fast index)
ALTER TABLE users ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;

-- Add theme preference column for user customization
ALTER TABLE users ADD COLUMN IF NOT EXISTS theme_preference VARCHAR(20) DEFAULT 'system';

-- Security fix: Add per-user salt for MFA backup codes to prevent rainbow table attacks
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_backup_code_salt BYTEA;

-- Add comprehensive user settings columns
ALTER TABLE users ADD COLUMN IF NOT EXISTS auto_save BOOLEAN DEFAULT true;
ALTER TABLE users ADD COLUMN IF NOT EXISTS auto_save_interval INTEGER DEFAULT 30;
ALTER TABLE users ADD COLUMN IF NOT EXISTS default_view VARCHAR(10) DEFAULT 'list';
ALTER TABLE users ADD COLUMN IF NOT EXISTS notifications_enabled BOOLEAN DEFAULT true;
ALTER TABLE users ADD COLUMN IF NOT EXISTS email_notifications BOOLEAN DEFAULT false;
ALTER TABLE users ADD COLUMN IF NOT EXISTS encryption_enabled BOOLEAN DEFAULT true;
ALTER TABLE users ADD COLUMN IF NOT EXISTS language VARCHAR(10) DEFAULT 'en';
ALTER TABLE users ADD COLUMN IF NOT EXISTS default_note_behavior VARCHAR(20) DEFAULT 'last-seen';
ALTER TABLE users ADD COLUMN IF NOT EXISTS profile_picture_type VARCHAR(20) DEFAULT 'gravatar';
ALTER TABLE users ADD COLUMN IF NOT EXISTS profile_picture_custom_url TEXT;

-- User profile enhancements (Phase 1.2)
ALTER TABLE users ADD COLUMN IF NOT EXISTS display_name TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS bio TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_url TEXT;

-- Password reset tokens table for secure password recovery
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE NOT NULL,
    token_hash BYTEA NOT NULL UNIQUE, -- SHA-256 hash of the reset token
    expires_at TIMESTAMPTZ NOT NULL,
    used BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    ip_address_hash BYTEA, -- SHA-256 hash of IP address where reset was requested
    user_agent_hash BYTEA -- SHA-256 hash of user agent
);

ALTER TABLE password_reset_tokens
    ADD COLUMN IF NOT EXISTS verify_attempts INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS verify_window_start TIMESTAMPTZ;

-- Index for fast token lookups and cleanup
CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_hash ON password_reset_tokens(token_hash) WHERE used = false;
CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_user ON password_reset_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_expires ON password_reset_tokens(expires_at) WHERE used = false;

-- GDPR compliance: Add table to store GDPR deletion keys for email recovery
CREATE TABLE IF NOT EXISTS gdpr_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email_hash BYTEA UNIQUE NOT NULL,
    deletion_key BYTEA NOT NULL, -- Key to decrypt email for GDPR requests
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Remove plaintext email column (after data migration)
-- ALTER TABLE users DROP COLUMN IF EXISTS email;

-- RBAC roles
CREATE TABLE IF NOT EXISTS roles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS user_roles (
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

-- Seed default roles
INSERT INTO roles (name)
SELECT r FROM (VALUES ('admin'), ('user'), ('moderator'), ('auditor')) AS v(r)
ON CONFLICT (name) DO NOTHING;

-- Announcements table for system-wide messages
CREATE TABLE IF NOT EXISTS announcements (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    title TEXT NOT NULL,
    content TEXT NOT NULL, -- Markdown content
    visibility TEXT CHECK (visibility IN ('all', 'logged_in')) DEFAULT 'logged_in',
    style JSONB DEFAULT '{}', -- Style configuration (colors, icons, etc.)
    active BOOLEAN DEFAULT true,
    dismissible BOOLEAN DEFAULT true,
    priority INT DEFAULT 0, -- For ordering (higher = more important)
    start_date TIMESTAMPTZ,
    end_date TIMESTAMPTZ,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Index for active announcements query
CREATE INDEX IF NOT EXISTS idx_announcements_active ON announcements(active, priority DESC, created_at DESC);

-- Workspace table
CREATE TABLE IF NOT EXISTS workspaces (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name_encrypted BYTEA NOT NULL, -- Encrypted workspace name
    owner_id UUID REFERENCES users(id) ON DELETE CASCADE,
    encryption_key_encrypted BYTEA NOT NULL, -- Workspace key encrypted with owner's key
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Notes table with full encryption
CREATE TABLE IF NOT EXISTS notes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
    workspace_id UUID REFERENCES workspaces(id) ON DELETE CASCADE,
    title_encrypted BYTEA NOT NULL, -- Encrypted title
    content_encrypted BYTEA NOT NULL, -- Encrypted content
    content_hash BYTEA NOT NULL, -- For integrity verification
    parent_id UUID REFERENCES notes(id) ON DELETE SET NULL,
    position INT DEFAULT 0,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    deleted_at TIMESTAMPTZ,
    version INT DEFAULT 1,
    is_pinned BOOLEAN DEFAULT FALSE,
    pinned_order INT DEFAULT 0,
    is_locked BOOLEAN DEFAULT FALSE,
    locked_by UUID REFERENCES users(id) ON DELETE SET NULL
);

-- Note versions for history tracking
CREATE TABLE IF NOT EXISTS note_versions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    note_id UUID REFERENCES notes(id) ON DELETE CASCADE,
    version_number INT NOT NULL,
    title_encrypted BYTEA NOT NULL, -- Encrypted title at this version
    content_encrypted BYTEA NOT NULL, -- Encrypted content at this version
    content_hash BYTEA NOT NULL, -- For integrity verification
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(note_id, version_number)
);

-- Encrypted search index (searchable encryption)
CREATE TABLE IF NOT EXISTS search_index (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    note_id UUID REFERENCES notes(id) ON DELETE CASCADE,
    keyword_hash BYTEA NOT NULL, -- HMAC of keyword
    position INT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Collaboration table for shared notes
CREATE TABLE IF NOT EXISTS collaborations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    note_id UUID REFERENCES notes(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    permission TEXT CHECK (permission IN ('read', 'write', 'admin')),
    key_encrypted BYTEA NOT NULL, -- Note key encrypted with user's public key
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(note_id, user_id)
);

-- Audit log for security (zero-knowledge: hashed IP/UA, plaintext metadata)
CREATE TABLE IF NOT EXISTS audit_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id),
    action TEXT NOT NULL,
    resource_type TEXT,
    resource_id UUID,
    ip_address_hash BYTEA, -- SHA-256 hash for privacy
    user_agent_hash BYTEA, -- SHA-256 hash for privacy
    metadata JSONB, -- Non-sensitive metadata in plain JSON
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Zero-knowledge migration: Drop encrypted columns from audit_log
ALTER TABLE audit_log DROP COLUMN IF EXISTS ip_address_encrypted;
ALTER TABLE audit_log DROP COLUMN IF EXISTS user_agent_encrypted;
ALTER TABLE audit_log DROP COLUMN IF EXISTS metadata_encrypted;
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS ip_address_hash BYTEA;
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS user_agent_hash BYTEA;

-- File attachments with encryption
CREATE TABLE IF NOT EXISTS attachments (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    note_id UUID REFERENCES notes(id) ON DELETE CASCADE,
    filename_encrypted BYTEA NOT NULL,
    content_encrypted BYTEA NOT NULL, -- Store encrypted files in DB for simplicity
    mime_type TEXT,
    size_bytes BIGINT,
    checksum BYTEA NOT NULL, -- SHA-256 of encrypted content
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Encryption keys rotation table
CREATE TABLE IF NOT EXISTS key_rotations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    old_key_hash BYTEA NOT NULL,
    new_key_hash BYTEA NOT NULL,
    items_rotated INT DEFAULT 0,
    completed BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

-- Folders table for organizing notes
CREATE TABLE IF NOT EXISTS folders (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    parent_id UUID REFERENCES folders(id) ON DELETE SET NULL, -- NULL for root folders
    name_encrypted BYTEA NOT NULL, -- Encrypted folder name
    color VARCHAR(7) DEFAULT '#3b82f6', -- Hex color code
    position INT DEFAULT 0, -- For custom ordering
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Nested folders enhancements (Phase 2.1)
ALTER TABLE folders ADD COLUMN IF NOT EXISTS depth INTEGER DEFAULT 0;
ALTER TABLE folders ADD COLUMN IF NOT EXISTS path TEXT DEFAULT '/';
CREATE INDEX IF NOT EXISTS idx_folders_parent_id ON folders(parent_id);
CREATE INDEX IF NOT EXISTS idx_folders_path ON folders(path);

-- Add folder_id to notes table for folder organization
ALTER TABLE notes ADD COLUMN IF NOT EXISTS folder_id UUID REFERENCES folders(id) ON DELETE SET NULL;

-- Ensure self-referential relationships do not cascade delete unintended records
ALTER TABLE notes DROP CONSTRAINT IF EXISTS notes_parent_id_fkey;
ALTER TABLE notes ADD CONSTRAINT notes_parent_id_fkey FOREIGN KEY (parent_id) REFERENCES notes(id) ON DELETE SET NULL;

ALTER TABLE folders DROP CONSTRAINT IF EXISTS folders_parent_id_fkey;
ALTER TABLE folders ADD CONSTRAINT folders_parent_id_fkey FOREIGN KEY (parent_id) REFERENCES folders(id) ON DELETE SET NULL;



-- Tags table for organizing notes
CREATE TABLE IF NOT EXISTS tags (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    name_encrypted BYTEA NOT NULL, -- Encrypted tag name
    name_hash BYTEA,
    color VARCHAR(7) DEFAULT '#3b82f6', -- Hex color code
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(user_id, name_encrypted) -- Legacy constraint retained for backward compatibility
);

ALTER TABLE tags ADD COLUMN IF NOT EXISTS name_hash BYTEA;
ALTER TABLE tags DROP CONSTRAINT IF EXISTS tags_user_id_name_encrypted_key;

-- Enforce uniqueness on deterministic tag hashes when available
CREATE UNIQUE INDEX IF NOT EXISTS idx_tags_name_hash_unique
    ON tags(user_id, name_hash)
    WHERE name_hash IS NOT NULL;

-- Junction table for note-tag relationships
CREATE TABLE IF NOT EXISTS note_tags (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    note_id UUID REFERENCES notes(id) ON DELETE CASCADE,
    tag_id UUID REFERENCES tags(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(note_id, tag_id) -- Prevent duplicate assignments
);

-- Templates table for reusable note templates
CREATE TABLE IF NOT EXISTS templates (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    name_encrypted BYTEA NOT NULL, -- Encrypted template name
    description_encrypted BYTEA, -- Encrypted template description
    content_encrypted BYTEA NOT NULL, -- Encrypted template content
    tags TEXT[], -- Array of tag names for categorization
    icon VARCHAR(50) DEFAULT '📝', -- Emoji icon for template
    is_public BOOLEAN DEFAULT false, -- Whether template is shared publicly
    usage_count INT DEFAULT 0, -- Track how often template is used
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Add template_id to notes table for tracking template origin
ALTER TABLE notes ADD COLUMN IF NOT EXISTS template_id UUID REFERENCES templates(id) ON DELETE SET NULL;

-- Functions for automatic updated_at
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Apply updated_at triggers
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'update_users_updated_at') THEN
        CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
            FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'update_workspaces_updated_at') THEN
        CREATE TRIGGER update_workspaces_updated_at BEFORE UPDATE ON workspaces
            FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'update_notes_updated_at') THEN
        CREATE TRIGGER update_notes_updated_at BEFORE UPDATE ON notes
            FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'update_tags_updated_at') THEN
        CREATE TRIGGER update_tags_updated_at BEFORE UPDATE ON tags
            FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'update_folders_updated_at') THEN
        CREATE TRIGGER update_folders_updated_at BEFORE UPDATE ON folders
            FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'update_templates_updated_at') THEN
        CREATE TRIGGER update_templates_updated_at BEFORE UPDATE ON templates
            FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
    END IF;
END $$;


-- Cleanup old deleted notes function (30 days)
CREATE OR REPLACE FUNCTION cleanup_old_deleted_notes()
RETURNS void AS $$
BEGIN
    DELETE FROM notes WHERE deleted_at IS NOT NULL AND deleted_at < NOW() - INTERVAL '30 days';
END;
$$ LANGUAGE plpgsql;

-- Create indexes for better performance (optimized for startup and common queries)
CREATE INDEX IF NOT EXISTS idx_notes_workspace ON notes(workspace_id) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_notes_parent ON notes(parent_id);
CREATE INDEX IF NOT EXISTS idx_notes_created ON notes(created_by, created_at DESC);

-- Critical index for admin validation queries (optimized for fast lookup)
CREATE INDEX IF NOT EXISTS idx_users_email_search_hash ON users(email_search_hash) WHERE email_search_hash IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_users_count_fast ON users(id) WHERE deleted_at IS NULL; -- For fast COUNT(*) queries

-- Partial indexes for performance-critical startup queries
CREATE INDEX IF NOT EXISTS idx_users_admin_flag ON users(is_admin) WHERE is_admin = true;
CREATE INDEX IF NOT EXISTS idx_users_email_hash ON users(email_hash) WHERE email_hash IS NOT NULL;

-- Search index optimization
CREATE INDEX IF NOT EXISTS idx_search_keyword ON search_index(keyword_hash);
CREATE INDEX IF NOT EXISTS idx_note_versions_note ON note_versions(note_id);
CREATE INDEX IF NOT EXISTS idx_attachments_note ON attachments(note_id);
CREATE INDEX IF NOT EXISTS idx_templates_user ON templates(user_id);

-- Migration tracking index for fast version checks
CREATE INDEX IF NOT EXISTS idx_migrations_version ON _migrations(version, applied_at DESC);


-- App settings key-value store
CREATE TABLE IF NOT EXISTS app_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE OR REPLACE FUNCTION update_settings_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END; $$ LANGUAGE plpgsql;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'update_app_settings_updated_at') THEN
        CREATE TRIGGER update_app_settings_updated_at BEFORE UPDATE ON app_settings
        FOR EACH ROW EXECUTE FUNCTION update_settings_updated_at();
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action, created_at DESC);

-- Tags indexes
CREATE INDEX IF NOT EXISTS idx_tags_user ON tags(user_id);
CREATE INDEX IF NOT EXISTS idx_note_tags_note ON note_tags(note_id);
CREATE INDEX IF NOT EXISTS idx_note_tags_tag ON note_tags(tag_id);

-- Folders indexes
CREATE INDEX IF NOT EXISTS idx_folders_user ON folders(user_id);
CREATE INDEX IF NOT EXISTS idx_folders_parent ON folders(parent_id);
CREATE INDEX IF NOT EXISTS idx_folders_position ON folders(user_id, position);
CREATE INDEX IF NOT EXISTS idx_notes_folder ON notes(folder_id);

-- Share links table for shareable note links (RO/RW)
CREATE TABLE IF NOT EXISTS share_links (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    note_id UUID REFERENCES notes(id) ON DELETE CASCADE NOT NULL,
    token TEXT UNIQUE NOT NULL, -- URL-safe random token
    permission TEXT CHECK (permission IN ('read', 'write')) NOT NULL,
    password_hash TEXT, -- Optional password protection (Argon2id)
    expires_at TIMESTAMPTZ, -- NULL for never expires
    max_uses INT, -- NULL for unlimited
    use_count INT DEFAULT 0,
    is_active BOOLEAN DEFAULT true,
    created_by UUID REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    last_accessed_at TIMESTAMPTZ,
    last_accessed_ip BYTEA -- Encrypted IP address
);

-- Share links indexes for fast lookups
CREATE INDEX IF NOT EXISTS idx_share_links_token ON share_links(token) WHERE is_active = true;
CREATE INDEX IF NOT EXISTS idx_share_links_note ON share_links(note_id);
CREATE INDEX IF NOT EXISTS idx_share_links_created_by ON share_links(created_by);
CREATE INDEX IF NOT EXISTS idx_share_links_expires ON share_links(expires_at) WHERE expires_at IS NOT NULL AND is_active = true;

-- Add retention_policy column to notes table for version management (default: 20 versions)
ALTER TABLE notes ADD COLUMN IF NOT EXISTS retention_policy INT DEFAULT 20;

-- Add change_description column to note_versions for better version tracking
ALTER TABLE note_versions ADD COLUMN IF NOT EXISTS change_description TEXT;

-- Add index on note_versions for performance (latest versions first)
CREATE INDEX IF NOT EXISTS idx_note_versions_created_at ON note_versions(note_id, created_at DESC);

-- Add is_pinned column for pinned/favorite notes
DO $$
BEGIN
    -- Drop and recreate to ensure correct type
    ALTER TABLE notes DROP COLUMN IF EXISTS is_pinned CASCADE;
    ALTER TABLE notes ADD COLUMN is_pinned BOOLEAN DEFAULT false;
END $$;

-- Add is_locked column for read-only note protection
DO $$
BEGIN
    ALTER TABLE notes DROP COLUMN IF EXISTS is_locked CASCADE;
    ALTER TABLE notes ADD COLUMN is_locked BOOLEAN DEFAULT false;
    ALTER TABLE notes DROP COLUMN IF EXISTS locked_by CASCADE;
    ALTER TABLE notes ADD COLUMN locked_by UUID REFERENCES users(id) ON DELETE SET NULL;
    ALTER TABLE notes DROP COLUMN IF EXISTS locked_at CASCADE;
    ALTER TABLE notes ADD COLUMN locked_at TIMESTAMPTZ;
END $$;

-- Add pinned_order column for custom ordering of pinned notes
DO $$
BEGIN
    ALTER TABLE notes DROP COLUMN IF EXISTS pinned_order CASCADE;
    ALTER TABLE notes ADD COLUMN pinned_order INT DEFAULT 0;
END $$;

-- Create index for efficient pinned notes queries
CREATE INDEX IF NOT EXISTS idx_notes_pinned ON notes(is_pinned, pinned_order DESC, updated_at DESC) WHERE deleted_at IS NULL;

-- Create index for locked notes queries
CREATE INDEX IF NOT EXISTS idx_notes_locked ON notes(is_locked, locked_by) WHERE is_locked = true;

-- Zero-knowledge migration: Convert email_encrypted to email_plaintext
-- WARNING: This migration assumes SERVER_ENCRYPTION_KEY is no longer used
-- For existing deployments with encrypted emails, manual migration required
ALTER TABLE users ADD COLUMN IF NOT EXISTS email_plaintext TEXT;

-- Drop encrypted email column (data will be lost - migration assumes fresh install or manual data migration)
-- To preserve data, decrypt email_encrypted with old SERVER_ENCRYPTION_KEY before running this
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='users' AND column_name='email_encrypted') THEN
        -- Check if email_plaintext is populated
        IF NOT EXISTS (SELECT 1 FROM users WHERE email_plaintext IS NOT NULL LIMIT 1) THEN
            RAISE WARNING 'email_encrypted exists but email_plaintext is not populated. Manual migration required!';
        END IF;
        -- Drop email_encrypted column
        ALTER TABLE users DROP COLUMN IF EXISTS email_encrypted;
    END IF;
END $$;

-- Make email_plaintext NOT NULL after migration
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='users' AND column_name='email_plaintext' AND is_nullable='YES') THEN
        ALTER TABLE users ALTER COLUMN email_plaintext SET NOT NULL;
    END IF;
END $$;

-- Remove encrypted session metadata from password_reset_tokens
ALTER TABLE password_reset_tokens DROP COLUMN IF EXISTS ip_address_encrypted;
ALTER TABLE password_reset_tokens DROP COLUMN IF EXISTS user_agent_encrypted;
ALTER TABLE password_reset_tokens ADD COLUMN IF NOT EXISTS ip_address_hash BYTEA;
ALTER TABLE password_reset_tokens ADD COLUMN IF NOT EXISTS user_agent_hash BYTEA;

-- Note links table for internal note connections ([[note]] syntax)
CREATE TABLE IF NOT EXISTS note_links (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    source_note_id UUID REFERENCES notes(id) ON DELETE CASCADE NOT NULL,
    target_note_id UUID REFERENCES notes(id) ON DELETE CASCADE NOT NULL,
    link_text TEXT, -- Display text for the link (e.g., "My Note Title")
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(source_note_id, target_note_id) -- Prevent duplicate links
);

-- Note links indexes for fast backlink lookups and graph queries
CREATE INDEX IF NOT EXISTS idx_note_links_source ON note_links(source_note_id);
CREATE INDEX IF NOT EXISTS idx_note_links_target ON note_links(target_note_id);

-- In-app notifications (Phase 2.2)
CREATE TABLE IF NOT EXISTS notifications (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE NOT NULL,
    type TEXT NOT NULL CHECK (type IN ('note_shared', 'note_commented', 'folder_shared', 'mention', 'system', 'collaboration_invite')),
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    action_url TEXT, -- Optional URL for clicking the notification
    metadata JSONB DEFAULT '{}'::jsonb, -- Additional data (note_id, sender_id, etc.)
    is_read BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    read_at TIMESTAMPTZ
);

-- Indexes for fast notification queries
CREATE INDEX IF NOT EXISTS idx_notifications_user_id ON notifications(user_id);
CREATE INDEX IF NOT EXISTS idx_notifications_created_at ON notifications(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_notifications_is_read ON notifications(is_read) WHERE is_read = false;

-- Note enhancements (Phase 2.4)
ALTER TABLE notes ADD COLUMN IF NOT EXISTS color VARCHAR(7) DEFAULT '#3b82f6';
ALTER TABLE notes ADD COLUMN IF NOT EXISTS icon VARCHAR(50) DEFAULT 'file-text';

-- Granular collaboration permissions (Phase 3.2)
ALTER TABLE collaborations ADD COLUMN IF NOT EXISTS can_edit BOOLEAN DEFAULT true;
ALTER TABLE collaborations ADD COLUMN IF NOT EXISTS can_delete BOOLEAN DEFAULT false;
ALTER TABLE collaborations ADD COLUMN IF NOT EXISTS can_share BOOLEAN DEFAULT false;
ALTER TABLE collaborations ADD COLUMN IF NOT EXISTS can_comment BOOLEAN DEFAULT true;
ALTER TABLE collaborations ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;

-- Email notification templates (Phase 3.3)
CREATE TABLE IF NOT EXISTS email_templates (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT UNIQUE NOT NULL,
    subject TEXT NOT NULL,
    body_html TEXT NOT NULL,
    body_text TEXT NOT NULL,
    variables JSONB DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Insert default email templates
INSERT INTO email_templates (name, subject, body_html, body_text, variables) VALUES
('note_shared', 'Note shared with you - LeafLock',
 '<p>Hi {{recipient_name}},</p><p>{{sender_name}} has shared a note with you: <strong>{{note_title}}</strong></p><p>Permission: {{permission}}</p><p><a href="{{note_url}}">View Note</a></p>',
 'Hi {{recipient_name}},\n\n{{sender_name}} has shared a note with you: {{note_title}}\n\nPermission: {{permission}}\n\nView Note: {{note_url}}',
 '["recipient_name", "sender_name", "note_title", "permission", "note_url"]'::jsonb),
('collaboration_invite', 'Collaboration invite - LeafLock',
 '<p>Hi {{recipient_name}},</p><p>{{sender_name}} invited you to collaborate on: <strong>{{note_title}}</strong></p><p><a href="{{note_url}}">Accept Invitation</a></p>',
 'Hi {{recipient_name}},\n\n{{sender_name}} invited you to collaborate on: {{note_title}}\n\nAccept Invitation: {{note_url}}',
 '["recipient_name", "sender_name", "note_title", "note_url"]'::jsonb),
('password_reset', 'Password Reset Request - LeafLock',
 '<p>Hi {{user_name}},</p><p>You requested a password reset. Click the link below to reset your password:</p><p><a href="{{reset_url}}">Reset Password</a></p><p>This link expires in 1 hour.</p>',
 'Hi {{user_name}},\n\nYou requested a password reset. Click the link below:\n\n{{reset_url}}\n\nThis link expires in 1 hour.',
 '["user_name", "reset_url"]'::jsonb)
ON CONFLICT (name) DO NOTHING;

-- Email notification preferences
ALTER TABLE users ADD COLUMN IF NOT EXISTS email_on_note_shared BOOLEAN DEFAULT true;
ALTER TABLE users ADD COLUMN IF NOT EXISTS email_on_collaboration BOOLEAN DEFAULT true;
ALTER TABLE users ADD COLUMN IF NOT EXISTS email_on_mention BOOLEAN DEFAULT true;
ALTER TABLE users ADD COLUMN IF NOT EXISTS email_digest_frequency VARCHAR(20) DEFAULT 'never'; -- 'never', 'daily', 'weekly'

-- Note: Cleanup jobs run automatically via background service every 24 hours
`
