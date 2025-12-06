-- PostgreSQL Security Configuration for LeafLock
-- This script applies security hardening to the PostgreSQL database

-- 1. Enable SSL/TLS encryption
ALTER SYSTEM SET ssl = on;
ALTER SYSTEM SET ssl_cert_file = 'server.crt';
ALTER SYSTEM SET ssl_key_file = 'server.key';
ALTER SYSTEM SET ssl_ca_file = 'root.crt';

-- 2. Set strong password encryption
ALTER SYSTEM SET password_encryption = 'scram-sha-256';

-- 3. Configure connection security
ALTER SYSTEM SET ssl_prefer_server_ciphers = on;
ALTER SYSTEM SET ssl_ciphers = 'HIGH:MEDIUM:+3DES:!aNULL';

-- 4. Enable comprehensive audit logging
ALTER SYSTEM SET log_statement = 'all';
ALTER SYSTEM SET log_connections = on;
ALTER SYSTEM SET log_disconnections = on;
ALTER SYSTEM SET log_duration = on;
ALTER SYSTEM SET log_hostname = on;
ALTER SYSTEM SET log_line_prefix = '%t [%p]: [%l-1] user=%u,db=%d,app=%a,client=%h ';

-- 5. Set connection timeouts and limits
ALTER SYSTEM SET statement_timeout = '30000'; -- 30 seconds
ALTER SYSTEM SET lock_timeout = '10000'; -- 10 seconds
ALTER SYSTEM SET idle_in_transaction_session_timeout = '300000'; -- 5 minutes
ALTER SYSTEM SET connection_timeout = '30';

-- 6. Security-related settings
ALTER SYSTEM SET password_encryption = 'scram-sha-256';
ALTER SYSTEM SET ssl = on;
ALTER SYSTEM SET ssl_prefer_server_ciphers = on;

-- 7. Enable row-level security on sensitive tables
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;

-- 8. Create security policies
CREATE POLICY users_isolation ON users FOR ALL TO app_user 
USING (id = current_user_id());

CREATE POLICY notes_isolation ON notes FOR ALL TO app_user 
USING (user_id = current_user_id() OR EXISTS (
  SELECT 1 FROM note_shares WHERE note_id = notes.id AND shared_with_user_id = current_user_id()
));

CREATE POLICY audit_log_access ON audit_log FOR ALL TO app_user 
USING (user_id = current_user_id() OR current_user_is_admin());

-- 9. Create security functions
CREATE OR REPLACE FUNCTION current_user_id() RETURNS uuid AS $$
BEGIN
  RETURN current_setting('app.current_user_id', true)::uuid;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE FUNCTION current_user_is_admin() RETURNS boolean AS $$
BEGIN
  RETURN current_setting('app.is_admin', true)::boolean;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 10. Create audit logging function
CREATE OR REPLACE FUNCTION audit_log_event(
  event_type text,
  user_id uuid,
  details jsonb DEFAULT '{}'::jsonb
) RETURNS void AS $$
BEGIN
  INSERT INTO audit_log (event_type, user_id, details, created_at)
  VALUES (event_type, user_id, details, now());
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 11. Create indexes for security queries
CREATE INDEX idx_audit_log_user_id ON audit_log(user_id);
CREATE INDEX idx_audit_log_event_type ON audit_log(event_type);
CREATE INDEX idx_audit_log_created_at ON audit_log(created_at);

CREATE INDEX idx_users_email_hash ON users(email_hash);
CREATE INDEX idx_users_created_at ON users(created_at);

-- 12. Create security monitoring function
CREATE OR REPLACE FUNCTION check_security_compliance() RETURNS TABLE (
  issue_type text,
  description text,
  severity text,
  recommendation text
) AS $$
BEGIN
  -- Check for weak passwords
  RETURN QUERY
  SELECT 
    'weak_password'::text,
    'Users with weak password hashes'::text,
    'high'::text,
    'Require users to update their passwords'::text
  FROM users 
  WHERE password_hash IS NOT NULL AND length(password_hash) < 60;

  -- Check for default users
  RETURN QUERY
  SELECT 
    'default_user'::text,
    'Default admin users detected'::text,
    'medium'::text,
    'Change default admin email addresses'::text
  FROM users 
  WHERE email IN ('admin@example.com', 'test@example.com', 'user@example.com');

  -- Check for unencrypted connections
  RETURN QUERY
  SELECT 
    'unencrypted_connection'::text,
    'Unencrypted database connections'::text,
    'high'::text,
    'Ensure all connections use SSL/TLS'::text
  FROM pg_stat_activity 
  WHERE ssl = false AND state != 'idle';

  -- Check for old password reset tokens
  RETURN QUERY
  SELECT 
    'old_token'::text,
    'Password reset tokens older than 7 days'::text,
    'low'::text,
    'Clean up expired password reset tokens'::text
  FROM password_reset_tokens 
	WHERE created_at < now() - interval '7 days' AND used = false;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 13. Create rate limiting functions
CREATE OR REPLACE FUNCTION check_rate_limit(
  identifier text,
  max_requests int,
  window_duration interval
) RETURNS boolean AS $$
DECLARE
  request_count int;
BEGIN
  SELECT COUNT(*) INTO request_count
  FROM rate_limit_log 
  WHERE identifier = check_rate_limit.identifier 
    AND created_at > now() - window_duration;

  RETURN request_count < max_requests;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 14. Create rate limit logging table
CREATE TABLE IF NOT EXISTS rate_limit_log (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  identifier TEXT NOT NULL,
  endpoint TEXT NOT NULL,
  user_id UUID,
  ip_address INET,
  created_at TIMESTAMP NOT NULL DEFAULT now()
);

CREATE INDEX idx_rate_limit_log_identifier ON rate_limit_log(identifier);
CREATE INDEX idx_rate_limit_log_created_at ON rate_limit_log(created_at);

-- 15. Create security audit trigger
CREATE OR REPLACE FUNCTION security_audit_trigger() RETURNS trigger AS $$
BEGIN
  -- Log security-relevant changes
  IF TG_OP = 'UPDATE' THEN
    IF OLD.password_hash IS DISTINCT FROM NEW.password_hash THEN
      PERFORM audit_log_event('password_changed', NEW.id, jsonb_build_object(
			'old_hash_length', length(OLD.password_hash),
			'new_hash_length', length(NEW.password_hash)
		));
    END IF;
	
	IF OLD.email IS DISTINCT FROM NEW.email THEN
      PERFORM audit_log_event('email_changed', NEW.id, jsonb_build_object(
			'old_email', OLD.email,
			'new_email', NEW.email
		));
    END IF;
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Apply the trigger to users table
CREATE TRIGGER users_security_audit
AFTER UPDATE ON users
FOR EACH ROW
EXECUTE FUNCTION security_audit_trigger();

-- 16. Set up automatic security monitoring
CREATE OR REPLACE FUNCTION monitor_security_events() RETURNS void AS $$
DECLARE
  security_issues RECORD;
BEGIN
  FOR security_issues IN SELECT * FROM check_security_compliance() LOOP
    PERFORM audit_log_event(
		'security_issue_detected',
		null,
		jsonb_build_object(
			'issue_type', security_issues.issue_type,
			'description', security_issues.description,
			'severity', security_issues.severity,
			'recommendation', security_issues.recommendation
		)
	);
  END LOOP;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create a scheduled job to run security monitoring (would be set up in your job scheduler)
-- SELECT monitor_security_events();

-- 17. Create backup and recovery procedures
CREATE OR REPLACE FUNCTION create_security_backup() RETURNS void AS $$
BEGIN
  -- Create backup of security-critical tables
  CREATE TABLE audit_log_backup AS SELECT * FROM audit_log WHERE created_at > now() - interval '7 days';
  CREATE TABLE users_backup AS SELECT id, email_hash, is_admin, created_at, updated_at FROM users;
  CREATE TABLE password_reset_tokens_backup AS SELECT * FROM password_reset_tokens WHERE created_at > now() - interval '7 days';
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 18. Set up connection encryption
-- This would be configured in your connection pool or database driver
-- Example: postgresql://user:password@host:port/database?sslmode=require&sslcert=client.crt&sslkey=client.key&sslrootcert=root.crt

-- 19. Final security validation
SELECT check_security_compliance();

-- Grant appropriate permissions
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_user;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO app_user;
GRANT SELECT ON audit_log TO app_user;
GRANT INSERT ON audit_log TO app_user;

-- Revoke dangerous permissions
REVOKE ALL ON pg_user FROM app_user;
REVOKE ALL ON pg_stat_activity FROM app_user;
REVOKE ALL ON pg_database FROM app_user;