# Secure Notes - Troubleshooting Guide

## Table of Contents

1. [Quick Diagnostics](#quick-diagnostics)
2. [Common Issues](#common-issues)
3. [Installation Problems](#installation-problems)
4. [Runtime Issues](#runtime-issues)
5. [Database Problems](#database-problems)
6. [Authentication Issues](#authentication-issues)
7. [Network & Connectivity](#network--connectivity)
8. [Performance Problems](#performance-problems)
9. [Security Concerns](#security-concerns)
10. [Development Issues](#development-issues)
11. [Deployment Problems](#deployment-problems)
12. [Monitoring & Debugging](#monitoring--debugging)

## Quick Diagnostics

### Health Check Commands

**Basic Service Health:**
```bash
# Check if services are running
curl http://localhost:8080/api/v1/health
curl http://localhost:8080/api/v1/ready
curl http://localhost:3000

# Container status
docker ps
# OR
podman ps
# OR
kubectl get pods -n secure-notes

# Service logs
docker compose logs -f
# OR
kubectl logs -f deployment/backend -n secure-notes
```

**System Resources:**
```bash
# Memory usage
free -h
docker stats

# Disk space
df -h

# Network connectivity
ping google.com
nslookup localhost
```

### Component Status Matrix

| Component | Health Check | Expected Response | Troubleshooting |
|-----------|--------------|-------------------|-----------------|
| **Frontend** | `curl http://localhost:3000` | HTML page | [Frontend Issues](#frontend-issues) |
| **Backend** | `curl http://localhost:8080/api/v1/health` | `{"status":"healthy"}` | [Backend Issues](#backend-issues) |
| **PostgreSQL** | `pg_isready -h localhost -p 5432` | "accepting connections" | [Database Problems](#database-problems) |
| **Redis** | `redis-cli ping` | "PONG" | [Redis Issues](#redis-issues) |
| **Nginx** | `curl -I http://localhost` | HTTP 200/301 | [Network Issues](#network--connectivity) |

## Common Issues

### Issue: "Connection Refused" Errors

**Symptoms:**
- `curl: (7) Failed to connect to localhost port 8080: Connection refused`
- `Error: connect ECONNREFUSED 127.0.0.1:8080`
- Frontend shows "Network Error"

**Diagnosis:**
```bash
# Check if backend is running
docker ps | grep backend
netstat -tulpn | grep :8080

# Check backend logs
docker compose logs backend
```

**Solutions:**
```bash
# 1. Start services if not running
docker compose up -d

# 2. Check port conflicts
sudo lsof -i :8080
sudo lsof -i :3000

# 3. Restart specific service
docker compose restart backend

# 4. Check firewall rules (Linux)
sudo ufw status
sudo iptables -L

# 5. For MacOS, check if Docker Desktop is running
open -a Docker
```

### Issue: Database Connection Failures

**Symptoms:**
- `pq: password authentication failed for user "postgres"`
- `dial tcp 127.0.0.1:5432: connect: connection refused`
- Backend logs: "Database setup failed"

**Diagnosis:**
```bash
# Check PostgreSQL status
docker compose logs postgres
docker compose exec postgres pg_isready -U postgres

# Test connection manually
docker compose exec postgres psql -U postgres -d notes
```

**Solutions:**
```bash
# 1. Check password in .env file
cat .env | grep POSTGRES_PASSWORD

# 2. Reset database with correct password
docker compose down
docker volume rm $(docker volume ls -q | grep postgres)
docker compose up -d postgres

# 3. Verify database URL format
echo $DATABASE_URL
# Should be: postgres://postgres:password@postgres:5432/notes?sslmode=disable

# 4. Check PostgreSQL logs for errors
docker compose logs postgres | tail -50
```

### Issue: Redis Authentication Errors

**Symptoms:**
- `WRONGPASS invalid username-password pair`
- `ERR AUTH <password> called without any password configured for the default user`
- Backend cannot connect to Redis

**Diagnosis:**
```bash
# Test Redis connection
docker compose exec redis redis-cli ping
docker compose exec redis redis-cli -a $REDIS_PASSWORD ping
```

**Solutions:**
```bash
# 1. Check Redis password configuration
cat .env | grep REDIS_PASSWORD

# 2. Test authentication manually
docker compose exec redis redis-cli
# Inside redis-cli:
AUTH your-redis-password
ping

# 3. Reset Redis with correct password
docker compose down
docker volume rm $(docker volume ls -q | grep redis)
docker compose up -d redis

# 4. Check Redis configuration
docker compose exec redis cat /usr/local/etc/redis/redis.conf
```

### Issue: Frontend Build Failures

**Symptoms:**
- `Module not found: Error: Can't resolve 'libsodium-wrappers'`
- `npm ERR! code ENOENT`
- `Error: Cannot find module 'react-scripts'`

**Diagnosis:**
```bash
# Check Node.js and npm versions
node --version  # Should be 18+
npm --version   # Should be 9+

# Check package.json and node_modules
cd frontend
ls -la node_modules/
npm list --depth=0
```

**Solutions:**
```bash
cd frontend

# 1. Clean install
rm -rf node_modules package-lock.json
npm install

# 2. Clear npm cache
npm cache clean --force

# 3. Use specific Node.js version (via nvm)
nvm install 20
nvm use 20
npm install

# 4. Check for permission issues
sudo chown -R $(whoami) node_modules/
sudo chown $(whoami) package-lock.json

# 5. Alternative: Use yarn instead of npm
npm install -g yarn
yarn install
```

## Installation Problems

### Docker/Podman Issues

**Issue: Permission Denied**
```
Got permission denied while trying to connect to the Docker daemon socket
```

**Solution:**
```bash
# Add user to docker group (Linux)
sudo usermod -aG docker $USER
newgrp docker

# For Podman
sudo setsebool -P container_manage_cgroup true

# Restart Docker service
sudo systemctl restart docker
```

**Issue: "Image Not Found"**
```
Error response from daemon: pull access denied for secure-notes/backend
```

**Solution:**
```bash
# Build images locally first
docker compose build
# OR
make build

# Check available images
docker images | grep secure-notes
```

**Issue: Out of Disk Space**
```
no space left on device
```

**Solution:**
```bash
# Clean Docker system
docker system prune -a
docker volume prune

# Check disk usage
df -h
docker system df

# Remove unused images
docker image prune -a
```

### Environment Configuration Issues

**Issue: Missing Environment Variables**
```
Error: JWT_SECRET not provided
```

**Solution:**
```bash
# Copy and edit environment file
cp .env.example .env
nano .env

# Generate secure values
openssl rand -base64 64  # For JWT_SECRET
openssl rand -base64 32  # For SERVER_ENCRYPTION_KEY

# Verify environment loading
docker compose config | grep -i secret
```

**Issue: Invalid Environment Values**
```
Error: invalid JWT secret length
```

**Solution:**
```bash
# Check secret lengths
echo $JWT_SECRET | wc -c        # Should be 64+ chars
echo $SERVER_ENCRYPTION_KEY | wc -c  # Should be 32+ chars

# Generate proper length secrets
JWT_SECRET=$(openssl rand -base64 64 | tr -d '\n')
SERVER_ENCRYPTION_KEY=$(openssl rand -base64 32 | tr -d '\n')
```

## Runtime Issues

### Backend Issues

**Issue: High Memory Usage**
```
backend | fatal error: out of memory
```

**Diagnosis:**
```bash
# Check memory usage
docker stats backend
htop
```

**Solutions:**
```bash
# 1. Increase container memory limits
# In docker-compose.yml:
services:
  backend:
    deploy:
      resources:
        limits:
          memory: 1G

# 2. Optimize Go garbage collection
export GOGC=100
export GOMEMLIMIT=512MB

# 3. Check for memory leaks
docker compose exec backend pprof -top -cum http://localhost:8080/debug/pprof/heap
```

**Issue: Slow Response Times**
```
Request timeout after 30 seconds
```

**Diagnosis:**
```bash
# Test API response times
time curl http://localhost:8080/api/v1/health
ab -n 100 -c 10 http://localhost:8080/api/v1/health

# Check database performance
docker compose exec postgres psql -U postgres -d notes \
  -c "SELECT * FROM pg_stat_activity;"
```

**Solutions:**
```bash
# 1. Check database connections
# Increase connection pool size in backend
export DATABASE_MAX_CONNECTIONS=50

# 2. Optimize database queries
# Add indexes for frequently queried fields
psql -c "CREATE INDEX CONCURRENTLY idx_notes_user_updated ON notes(created_by, updated_at DESC);"

# 3. Enable query caching
# Configure Redis for query caching
```

### Frontend Issues

**Issue: Blank Page or White Screen**

**Diagnosis:**
```bash
# Check browser console for JavaScript errors
# Open Developer Tools (F12) → Console

# Check if files are served correctly
curl -I http://localhost:3000
curl -I http://localhost:3000/static/js/main.js
```

**Solutions:**
```bash
# 1. Rebuild frontend with error details
cd frontend
npm run build 2>&1 | tee build.log

# 2. Check for missing environment variables
echo $VITE_API_URL

# 3. Clear browser cache
# Hard refresh: Ctrl+F5 (Windows/Linux) or Cmd+Shift+R (Mac)

# 4. Test production build locally
npm run build
npx serve build/
```

**Issue: Encryption/Decryption Failures**
```
Error: Failed to decrypt note
```

**Diagnosis:**
```javascript
// Check browser console for crypto errors
// Verify libsodium is loaded correctly
console.log(typeof sodium);  // Should be 'object'
console.log(sodium.ready);   // Should be true
```

**Solutions:**
```bash
# 1. Ensure libsodium is properly loaded
cd frontend
npm install libsodium-wrappers
npm install @types/libsodium-wrappers

# 2. Check for browser compatibility
# Modern browsers (Chrome 65+, Firefox 60+, Safari 12+)

# 3. Verify crypto implementation
# Test encryption/decryption in browser console:
await sodium.ready;
const key = sodium.crypto_secretbox_keygen();
const message = 'test message';
const encrypted = sodium.crypto_secretbox_easy(message, sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES), key);
const decrypted = sodium.crypto_secretbox_open_easy(encrypted.slice(24), encrypted.slice(0, 24), key);
console.log(sodium.to_string(decrypted));
```

## Database Problems

### PostgreSQL Issues

**Issue: Database Won't Start**
```
postgres | FATAL: password authentication failed
postgres | database system is shut down
```

**Diagnosis:**
```bash
# Check PostgreSQL logs
docker compose logs postgres | tail -50

# Verify data directory permissions
docker compose exec postgres ls -la /var/lib/postgresql/data/
```

**Solutions:**
```bash
# 1. Reset PostgreSQL data
docker compose down
docker volume rm $(docker volume ls -q | grep postgres)

# 2. Fix ownership issues
docker compose exec postgres chown -R postgres:postgres /var/lib/postgresql/data

# 3. Initialize with correct credentials
docker compose up postgres
docker compose exec postgres createdb -U postgres notes
```

**Issue: Migration Failures**
```
ERROR: relation "users" already exists
```

**Solutions:**
```bash
# 1. Check current database schema
docker compose exec postgres psql -U postgres -d notes -c "\dt"

# 2. Drop and recreate database (DATA LOSS!)
docker compose exec postgres dropdb -U postgres notes
docker compose exec postgres createdb -U postgres notes

# 3. Manual migration execution
docker compose exec postgres psql -U postgres -d notes < migrations.sql
```

**Issue: Database Performance Problems**
```
slow query: duration: 5.234s
```

**Diagnosis:**
```sql
-- Check slow queries
SELECT query, mean_exec_time, calls 
FROM pg_stat_statements 
ORDER BY mean_exec_time DESC 
LIMIT 10;

-- Check table sizes
SELECT schemaname, tablename, 
       pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as size
FROM pg_tables 
WHERE schemaname = 'public'
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;
```

**Solutions:**
```sql
-- Add missing indexes
CREATE INDEX CONCURRENTLY idx_notes_workspace_updated 
ON notes(workspace_id, updated_at DESC) 
WHERE deleted_at IS NULL;

-- Update table statistics
ANALYZE;

-- Vacuum tables
VACUUM ANALYZE notes;

-- Configure PostgreSQL for better performance
ALTER SYSTEM SET shared_buffers = '256MB';
ALTER SYSTEM SET effective_cache_size = '1GB';
SELECT pg_reload_conf();
```

### Redis Issues

**Issue: Redis Memory Problems**
```
OOM command not allowed when used memory > 'maxmemory'
```

**Diagnosis:**
```bash
# Check Redis memory usage
docker compose exec redis redis-cli info memory

# Check memory policy
docker compose exec redis redis-cli config get maxmemory-policy
```

**Solutions:**
```bash
# 1. Increase Redis memory limit
docker compose exec redis redis-cli config set maxmemory 512mb

# 2. Configure eviction policy
docker compose exec redis redis-cli config set maxmemory-policy allkeys-lru

# 3. Clear Redis if safe to do so
docker compose exec redis redis-cli flushall
```

## Authentication Issues

### JWT Token Problems

**Issue: "Invalid Token" Errors**
```
HTTP 401: {"error":"Invalid token"}
```

**Diagnosis:**
```bash
# Check JWT secret configuration
echo $JWT_SECRET | wc -c  # Should be 64+ characters

# Verify token format (3 parts separated by dots)
echo "your-jwt-token" | tr '.' '\n' | wc -l  # Should be 3

# Debug token contents (be careful not to log in production)
# Use https://jwt.io to decode token
```

**Solutions:**
```bash
# 1. Regenerate JWT secret
JWT_SECRET=$(openssl rand -base64 64)
docker compose restart backend

# 2. Clear old tokens
# Users need to log in again

# 3. Check system clock synchronization
ntpdate -s time.nist.gov  # Linux
sntp -sS time.apple.com   # macOS
```

### Password Authentication Issues

**Issue: "Invalid Credentials" on Correct Password**
```
HTTP 401: {"error":"Invalid credentials"}
```

**Diagnosis:**
```sql
-- Check user records
SELECT id, email, failed_attempts, locked_until 
FROM users 
WHERE email = 'user@example.com';

-- Check password hash format
SELECT password_hash 
FROM users 
WHERE email = 'user@example.com';
-- Should start with $argon2id$
```

**Solutions:**
```bash
# 1. Check account lockout
# Wait for lockout period to expire (15 minutes default)

# 2. Reset user password (admin action)
docker compose exec postgres psql -U postgres -d notes -c "
UPDATE users 
SET failed_attempts = 0, locked_until = NULL 
WHERE email = 'user@example.com';"

# 3. Verify Argon2id implementation
# Check backend logs for password verification errors
docker compose logs backend | grep -i "password\|auth"
```

### Account Lockout Issues

**Issue: Account Locked After Valid Logins**
```
{"error":"Account locked. Try again later."}
```

**Diagnosis:**
```sql
-- Check lockout status
SELECT email, failed_attempts, locked_until, last_login
FROM users 
WHERE email = 'user@example.com';
```

**Solutions:**
```sql
-- Unlock account (admin action)
UPDATE users 
SET failed_attempts = 0, locked_until = NULL 
WHERE email = 'user@example.com';

-- Adjust lockout settings (in backend config)
-- MAX_LOGIN_ATTEMPTS=10
-- LOCKOUT_DURATION=5m
```

## Network & Connectivity

### CORS Issues

**Issue: "CORS Policy" Errors in Browser**
```
Access to fetch at 'http://localhost:8080/api/v1/notes' from origin 'http://localhost:3000' 
has been blocked by CORS policy
```

**Solutions:**
```bash
# 1. Check CORS_ORIGINS environment variable
echo $CORS_ORIGINS

# 2. Update CORS configuration
export CORS_ORIGINS="http://localhost:3000,http://localhost,https://localhost"
docker compose restart backend

# 3. For development, allow all origins (INSECURE)
export CORS_ORIGINS="*"
docker compose restart backend

# 4. Check preflight requests
curl -X OPTIONS -H "Origin: http://localhost:3000" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: Content-Type,Authorization" \
  http://localhost:8080/api/v1/notes
```

### SSL/TLS Certificate Issues

**Issue: "Certificate Not Trusted" Errors**
```
SSL certificate error: self signed certificate
```

**Solutions:**
```bash
# 1. Generate new self-signed certificates
./init-ssl.sh

# 2. Trust certificate in browser
# Chrome: Go to https://localhost, click "Advanced" → "Proceed to localhost"

# 3. Add certificate to system trust store (Linux)
sudo cp ssl/cert.pem /usr/local/share/ca-certificates/secure-notes.crt
sudo update-ca-certificates

# 4. For production, use Let's Encrypt
# Configure cert-manager in Kubernetes
# Or use certbot for standalone servers
```

### Port Conflicts

**Issue: "Port Already in Use"**
```
Error starting userland proxy: listen tcp 0.0.0.0:8080: bind: address already in use
```

**Diagnosis:**
```bash
# Find process using port
sudo lsof -i :8080
sudo netstat -tulpn | grep :8080

# For Windows
netstat -ano | findstr :8080
```

**Solutions:**
```bash
# 1. Kill process using port
sudo kill -9 <PID>

# 2. Use different ports
# In docker-compose.yml:
ports:
  - "8081:8080"  # Backend
  - "3001:80"    # Frontend

# 3. Stop conflicting services
sudo systemctl stop apache2  # If using port 80
sudo systemctl stop nginx    # If using port 80
```

## Performance Problems

### High Resource Usage

**Issue: High CPU Usage**

**Diagnosis:**
```bash
# Monitor CPU usage
htop
docker stats

# Check for infinite loops or high-frequency operations
# Backend profiling
go tool pprof http://localhost:8080/debug/pprof/profile?seconds=30

# Database query analysis
docker compose exec postgres psql -U postgres -d notes -c "
SELECT query, calls, mean_exec_time, total_exec_time
FROM pg_stat_statements 
ORDER BY total_exec_time DESC 
LIMIT 10;"
```

**Solutions:**
```bash
# 1. Optimize database queries
# Add appropriate indexes
# Use EXPLAIN ANALYZE to understand query plans

# 2. Implement caching
# Use Redis for frequently accessed data
# Enable HTTP caching headers

# 3. Configure resource limits
# In docker-compose.yml or Kubernetes
resources:
  limits:
    cpu: 500m
    memory: 512Mi
```

### Slow Database Queries

**Issue: Database Queries Taking Too Long**

**Diagnosis:**
```sql
-- Enable query logging
ALTER SYSTEM SET log_statement = 'all';
ALTER SYSTEM SET log_duration = on;
SELECT pg_reload_conf();

-- Identify slow queries
SELECT query, mean_exec_time, stddev_exec_time, calls
FROM pg_stat_statements
WHERE mean_exec_time > 100  -- queries taking >100ms
ORDER BY mean_exec_time DESC;
```

**Solutions:**
```sql
-- Add indexes for common query patterns
CREATE INDEX CONCURRENTLY idx_notes_user_created 
ON notes(created_by, created_at DESC);

CREATE INDEX CONCURRENTLY idx_notes_workspace_title 
ON notes(workspace_id) 
WHERE deleted_at IS NULL;

-- Update PostgreSQL configuration
ALTER SYSTEM SET work_mem = '16MB';
ALTER SYSTEM SET maintenance_work_mem = '256MB';
ALTER SYSTEM SET effective_cache_size = '2GB';
SELECT pg_reload_conf();

-- Vacuum and analyze tables
VACUUM ANALYZE notes;
VACUUM ANALYZE users;
```

## Security Concerns

### Potential Security Issues

**Issue: Suspected Brute Force Attack**
```
Multiple failed login attempts from same IP
```

**Detection:**
```sql
-- Check recent failed logins
SELECT ip_address_encrypted, COUNT(*) as attempts,
       MAX(created_at) as latest_attempt
FROM audit_log 
WHERE action = 'login.failed' 
  AND created_at > NOW() - INTERVAL '1 hour'
GROUP BY ip_address_encrypted
HAVING COUNT(*) > 10
ORDER BY attempts DESC;
```

**Response:**
```bash
# 1. Check rate limiting
curl -v http://localhost:8080/api/v1/auth/login
# Look for X-RateLimit headers

# 2. Temporarily block IP (using firewall)
sudo iptables -A INPUT -s 192.168.1.100 -j DROP

# 3. Review authentication logs
docker compose logs backend | grep -i "login\|auth" | tail -100

# 4. Enable additional monitoring
# Set up alerts for repeated failures
```

**Issue: Unusual Data Access Patterns**
```
User accessing large amounts of data unexpectedly
```

**Detection:**
```sql
-- Check for unusual access patterns
SELECT user_id, COUNT(*) as api_calls,
       MAX(created_at) as latest_call
FROM audit_log 
WHERE action LIKE 'notes.%'
  AND created_at > NOW() - INTERVAL '1 hour'
GROUP BY user_id
HAVING COUNT(*) > 100  -- Adjust threshold
ORDER BY api_calls DESC;
```

**Response:**
```sql
-- Temporarily suspend account if necessary
UPDATE users 
SET locked_until = NOW() + INTERVAL '1 hour'
WHERE id = 'suspicious-user-id';

-- Review audit trail
SELECT action, resource_id, created_at 
FROM audit_log 
WHERE user_id = 'suspicious-user-id'
ORDER BY created_at DESC 
LIMIT 50;
```

## Development Issues

### Build Problems

**Issue: Go Build Failures**
```
go: module not found
cannot find package
```

**Solutions:**
```bash
cd backend

# 1. Download dependencies
go mod download
go mod tidy

# 2. Verify Go version (1.21+ required)
go version

# 3. Clear module cache
go clean -modcache
go mod download

# 4. Check GOPATH and GOROOT
go env GOPATH
go env GOROOT

# 5. Build with verbose output
go build -v .
```

**Issue: Frontend TypeScript Errors**
```
Property 'X' does not exist on type 'Y'
Cannot find module 'X'
```

**Solutions:**
```bash
cd frontend

# 1. Install type definitions
npm install --save-dev @types/react @types/node
npm install --save-dev typescript

# 2. Check TypeScript configuration
npx tsc --noEmit

# 3. Clear TypeScript cache
rm -rf node_modules/.cache
npm run build

# 4. Update dependencies
npm update
```

### Hot Reload Issues

**Issue: Changes Not Reflecting in Development**

**Solutions:**
```bash
# Frontend hot reload issues
cd frontend
rm -rf node_modules/.cache
npm start

# Backend auto-reload (using air)
cd backend
go install github.com/cosmtrek/air@latest
air

# Docker volume issues on Windows/macOS
# Use bind mounts instead of volumes
# In docker-compose.yml:
volumes:
  - ./frontend/src:/app/src
  - ./backend:/app
```

## Deployment Problems

### Kubernetes Issues

**Issue: Pod CrashLoopBackOff**
```
kubectl get pods -n secure-notes
NAME           READY   STATUS             RESTARTS   AGE
backend-xxx    0/1     CrashLoopBackOff   5          5m
```

**Diagnosis:**
```bash
# Check pod logs
kubectl logs backend-xxx -n secure-notes
kubectl describe pod backend-xxx -n secure-notes

# Check previous container logs
kubectl logs backend-xxx -n secure-notes --previous

# Check events
kubectl get events -n secure-notes --sort-by='.lastTimestamp'
```

**Solutions:**
```bash
# 1. Fix configuration issues
kubectl edit deployment backend -n secure-notes

# 2. Check resource limits
kubectl describe deployment backend -n secure-notes

# 3. Verify secrets and configmaps
kubectl get secrets -n secure-notes
kubectl describe secret secure-notes-secrets -n secure-notes

# 4. Check probes configuration
# Adjust liveness/readiness probe timing
livenessProbe:
  initialDelaySeconds: 30
  periodSeconds: 10
  timeoutSeconds: 5
```

**Issue: Ingress Not Working**
```
502 Bad Gateway
SSL certificate error
```

**Diagnosis:**
```bash
# Check ingress status
kubectl get ingress -n secure-notes
kubectl describe ingress secure-notes-ingress -n secure-notes

# Check ingress controller
kubectl get pods -n ingress-nginx
kubectl logs -f deployment/ingress-nginx-controller -n ingress-nginx
```

**Solutions:**
```bash
# 1. Verify ingress controller is running
kubectl get pods -n ingress-nginx

# 2. Check certificate status (if using cert-manager)
kubectl get certificates -n secure-notes
kubectl describe certificate secure-notes-tls -n secure-notes

# 3. Test service connectivity
kubectl port-forward svc/backend 8080:8080 -n secure-notes
curl http://localhost:8080/api/v1/health

# 4. Check ingress annotations
kubectl annotate ingress secure-notes-ingress -n secure-notes \
  nginx.ingress.kubernetes.io/ssl-redirect="true"
```

### Docker Issues

**Issue: Container Won't Start**
```
docker: Error response from daemon: driver failed programming external connectivity
```

**Solutions:**
```bash
# 1. Restart Docker daemon
sudo systemctl restart docker

# 2. Check Docker network conflicts
docker network ls
docker network prune

# 3. Check firewall rules
sudo ufw status
sudo iptables -L

# 4. Use host networking (temporary workaround)
docker run --network host your-image

# 5. Reset Docker to factory defaults
# Docker Desktop: Settings → Troubleshoot → Reset to factory defaults
```

## Monitoring & Debugging

### Log Analysis

**Backend Application Logs:**
```bash
# View real-time logs
docker compose logs -f backend

# Search for specific errors
docker compose logs backend | grep -i "error\|panic\|fatal"

# View structured logs with timestamps
docker compose logs backend --timestamps | tail -100

# Export logs for analysis
docker compose logs backend > backend-$(date +%Y%m%d).log
```

**Database Query Logs:**
```sql
-- Enable query logging
ALTER SYSTEM SET log_statement = 'all';
ALTER SYSTEM SET log_duration = on;
ALTER SYSTEM SET log_min_duration_statement = 1000;  -- Log queries >1s
SELECT pg_reload_conf();

-- View slow queries
SELECT query, calls, total_exec_time, mean_exec_time
FROM pg_stat_statements
ORDER BY total_exec_time DESC
LIMIT 10;
```

### Performance Monitoring

**System Resource Monitoring:**
```bash
# Real-time container stats
docker stats --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}"

# Historical resource usage
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  sebp/elk docker stats --no-stream

# Database performance monitoring
docker compose exec postgres psql -U postgres -d notes -c "
SELECT 
  schemaname,
  tablename,
  attname,
  n_distinct,
  correlation
FROM pg_stats 
WHERE schemaname = 'public'
ORDER BY n_distinct DESC;"
```

### Health Monitoring Script

```bash
#!/bin/bash
# health-check.sh

echo "=== Secure Notes Health Check ==="
echo "Timestamp: $(date)"
echo

# Check service availability
services=("frontend:3000" "backend:8080" "postgres:5432" "redis:6379")
for service in "${services[@]}"; do
    name=$(echo $service | cut -d: -f1)
    port=$(echo $service | cut -d: -f2)
    
    if nc -z localhost $port 2>/dev/null; then
        echo "✓ $name is running on port $port"
    else
        echo "✗ $name is NOT responding on port $port"
    fi
done

echo

# Check API health
if curl -s http://localhost:8080/api/v1/health | grep -q "healthy"; then
    echo "✓ Backend API is healthy"
else
    echo "✗ Backend API health check failed"
fi

# Check database connection
if docker compose exec -T postgres pg_isready -U postgres >/dev/null 2>&1; then
    echo "✓ PostgreSQL is ready"
else
    echo "✗ PostgreSQL connection failed"
fi

# Check Redis
if docker compose exec -T redis redis-cli ping | grep -q "PONG"; then
    echo "✓ Redis is responding"
else
    echo "✗ Redis connection failed"
fi

echo
echo "=== Resource Usage ==="
echo "Memory:"
free -h | grep -E "(Mem|Swap)"
echo "Disk:"
df -h / | tail -1

echo
echo "=== Recent Errors ==="
docker compose logs --tail=10 backend | grep -i "error\|warn\|panic" || echo "No recent errors found"
```

### Debugging Checklist

**When something is not working:**

1. **Basic Connectivity**
   - [ ] Services are running (`docker ps` or `kubectl get pods`)
   - [ ] Ports are accessible (`netstat -tulpn`)
   - [ ] No firewall blocking connections
   - [ ] DNS resolution working

2. **Configuration**  
   - [ ] Environment variables set correctly
   - [ ] Database connection string valid
   - [ ] CORS origins configured properly
   - [ ] SSL certificates valid and not expired

3. **Resources**
   - [ ] Sufficient disk space available
   - [ ] Adequate memory allocated
   - [ ] CPU not maxed out
   - [ ] Database connections available

4. **Security**
   - [ ] Authentication tokens valid
   - [ ] No rate limiting blocking requests
   - [ ] Account not locked out
   - [ ] Permissions set correctly

5. **Data Integrity**
   - [ ] Database migrations completed
   - [ ] No corrupted data
   - [ ] Encryption/decryption working
   - [ ] Backup/restore functioning

This troubleshooting guide should help you diagnose and resolve most issues with the Secure Notes application. For complex problems, collect the relevant logs and system information before reaching out for additional support.