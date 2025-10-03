-- Reset MFA for a specific user
-- Usage: Replace $1 with the user's email_search_hash or user ID

-- Option 1: Reset MFA by user ID
-- UPDATE users
-- SET mfa_enabled = false,
--     mfa_secret_encrypted = NULL,
--     mfa_backup_codes = NULL,
--     mfa_backup_codes_used = NULL
-- WHERE id = 'USER_UUID_HERE';

-- Option 2: Reset MFA by email (requires email_search_hash)
-- First, you need to generate the email_search_hash using the backend's encryption service
-- Then run:
-- UPDATE users
-- SET mfa_enabled = false,
--     mfa_secret_encrypted = NULL,
--     mfa_backup_codes = NULL,
--     mfa_backup_codes_used = NULL
-- WHERE email_search_hash = E'\\x...'; -- Use hex-encoded bytes

-- Option 3: Emergency reset for all users (USE WITH EXTREME CAUTION)
-- UPDATE users
-- SET mfa_enabled = false,
--     mfa_secret_encrypted = NULL,
--     mfa_backup_codes = NULL,
--     mfa_backup_codes_used = NULL;

-- Verify MFA was reset
-- SELECT id, mfa_enabled,
--        CASE WHEN mfa_secret_encrypted IS NOT NULL THEN 'has_secret' ELSE 'no_secret' END as secret_status,
--        CASE WHEN mfa_backup_codes IS NOT NULL THEN array_length(mfa_backup_codes, 1) ELSE 0 END as backup_codes_count
-- FROM users
-- WHERE id = 'USER_UUID_HERE';

-- Admin note: After resetting MFA, the user will need to:
-- 1. Log in with their email and password (no MFA required)
-- 2. Go to Settings > Security > Multi-Factor Authentication
-- 3. Set up MFA again if desired
