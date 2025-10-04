package database

// DatabaseSchema contains the complete PostgreSQL schema for LeafLock
// This includes all tables, indexes, triggers, and functions required for the application
const DatabaseSchema = `
-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- Users table with encrypted fields
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email_hash BYTEA UNIQUE NOT NULL, -- SHA-256 hash for unique constraint and GDPR lookups
    email_encrypted BYTEA NOT NULL, -- Encrypted email for privacy
    email_search_hash BYTEA UNIQUE, -- Deterministic encryption for login lookups
    password_hash TEXT NOT NULL, -- Argon2id hash
    salt BYTEA NOT NULL,
    master_key_encrypted BYTEA NOT NULL, -- User's encrypted master key
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
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    workspace_id UUID REFERENCES workspaces(id) ON DELETE CASCADE,
    title_encrypted BYTEA NOT NULL, -- Encrypted title
    content_encrypted BYTEA NOT NULL, -- Encrypted content
    content_hash BYTEA NOT NULL, -- For integrity verification
    parent_id UUID REFERENCES notes(id) ON DELETE CASCADE,
    position INT DEFAULT 0,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    deleted_at TIMESTAMPTZ,
    version INT DEFAULT 1
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

-- Audit log for security
CREATE TABLE IF NOT EXISTS audit_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id),
    action TEXT NOT NULL,
    resource_type TEXT,
    resource_id UUID,
    ip_address_encrypted BYTEA,
    user_agent_encrypted BYTEA,
    metadata JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Encrypt audit log metadata field
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS metadata_encrypted BYTEA;

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
    parent_id UUID REFERENCES folders(id) ON DELETE CASCADE, -- NULL for root folders
    name_encrypted BYTEA NOT NULL, -- Encrypted folder name
    color VARCHAR(7) DEFAULT '#3b82f6', -- Hex color code
    position INT DEFAULT 0, -- For custom ordering
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Add folder_id to notes table for folder organization
ALTER TABLE notes ADD COLUMN IF NOT EXISTS folder_id UUID REFERENCES folders(id) ON DELETE SET NULL;



-- Tags table for organizing notes
CREATE TABLE IF NOT EXISTS tags (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    name_encrypted BYTEA NOT NULL, -- Encrypted tag name
    color VARCHAR(7) DEFAULT '#3b82f6', -- Hex color code
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(user_id, name_encrypted) -- Prevent duplicate tag names per user
);

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

-- Note: Cleanup jobs run automatically via background service every 24 hours
`