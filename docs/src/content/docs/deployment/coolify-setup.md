# Coolify Deployment Guide for LeafLock

This guide provides step-by-step instructions for deploying LeafLock on Coolify.

## Prerequisites

- Coolify instance with Docker support
- Domain name configured in Coolify (e.g., leaflock.app)
- SSL certificate configured in Coolify

## Required Environment Variables

Set these environment variables in your Coolify project configuration:

### Backend Environment Variables (Required)

```bash
# Database Configuration
POSTGRES_PASSWORD=<strong-password-64-chars>

# Redis Configuration  
REDIS_PASSWORD=<strong-password-32-chars>

# Security Keys (Critical)
JWT_SECRET=<64-character-random-string>
SERVER_ENCRYPTION_KEY=<32-character-random-string>

# CORS Configuration
CORS_ORIGINS=https://leaflock.app,https://www.leaflock.app
```

### Frontend Environment Variables (Required)

```bash
# Runtime Configuration
BACKEND_INTERNAL_URL=http://backend:8080
PORT=80

# Build-time Configuration
VITE_API_URL=https://leaflock.app/api/v1
VITE_ENABLE_ADMIN_PANEL=false
```

### Optional Environment Variables

```bash
# Application Settings
APP_ENV=production
ENABLE_REGISTRATION=true
ADMIN_USER_IDS=<comma-separated-user-ids>
```

## Generating Secure Keys

Use OpenSSL to generate secure passwords and keys:

```bash
# Generate POSTGRES_PASSWORD (64 chars)
openssl rand -hex 32

# Generate REDIS_PASSWORD (32 chars) 
openssl rand -hex 16

# Generate JWT_SECRET (64 chars)
openssl rand -hex 32

# Generate SERVER_ENCRYPTION_KEY (32 chars)
openssl rand -hex 16
```

## Coolify Project Setup

1. **Create New Project**
   - Go to Coolify dashboard
   - Click "New Project"
   - Select "Docker Compose" deployment type

2. **Repository Configuration**
   - Connect your Git repository
   - Select branch: `master` (or your main branch)
   - Set build path: `/`

3. **Environment Variables**
   - Go to "Environment" tab
   - Add all required environment variables listed above
   - Ensure no trailing spaces or quotes around values

4. **Domain Configuration**
   - Go to "Domains" tab
   - Add your domain (e.g., leaflock.app)
   - Enable SSL/TLS certificate
   - Configure redirect from www to non-www if desired

5. **Deploy Configuration**
   - Docker Compose file: `docker-compose.coolify.yml`
   - Build command: (leave empty - handled by Dockerfile)
   - Start command: (leave empty - handled by Docker Compose)

## Deployment Process

1. **Initial Deployment**
   ```bash
   # Coolify will automatically:
   # 1. Pull latest code from repository
   # 2. Build frontend and backend containers
   # 3. Start services in correct order (postgres → redis → backend → frontend)
   # 4. Run health checks on all services
   ```

2. **Monitor Deployment**
   - Check "Logs" tab for build progress
   - Verify all services are healthy in "Services" tab
   - Test endpoints after deployment

## Health Check Endpoints

- **Frontend**: `https://leaflock.app/` (should return React app)
- **Backend**: `https://leaflock.app/api/v1/health` (should return JSON health status)

## Troubleshooting

### Frontend Shows "No Available Server"

**Cause**: Port configuration mismatch or missing environment variables

**Solution**:
1. Verify `PORT=80` is set in frontend environment variables
2. Verify `BACKEND_INTERNAL_URL=http://backend:8080` is set
3. Check frontend container logs for startup errors

### Backend Connection Errors

**Cause**: Database or Redis connection issues

**Solution**:
1. Verify `POSTGRES_PASSWORD` and `REDIS_PASSWORD` are set correctly
2. Check backend container logs for connection errors
3. Ensure database and Redis containers are healthy

### Build Failures

**Cause**: Missing build arguments or dependency issues

**Solution**:
1. Verify `VITE_API_URL` is set correctly for frontend builds
2. Check build logs for specific error messages
3. Ensure repository has latest code

### SSL/Certificate Issues

**Cause**: Domain not properly configured or certificate not generated

**Solution**:
1. Verify domain DNS points to Coolify server
2. Check SSL certificate status in Coolify domains tab
3. Ensure CORS_ORIGINS includes your actual domain

## Monitoring and Maintenance

### Regular Checks
- Monitor container resource usage
- Check application logs for errors
- Verify database and Redis storage usage
- Test backup and restore procedures

### Updates
- Pull latest code from repository
- Redeploy through Coolify interface
- Monitor deployment for any issues
- Test functionality after updates

### Scaling
- Monitor response times and resource usage
- Consider adding more backend instances if needed
- Set up database read replicas for high traffic

## Security Considerations

- **Never commit secrets to repository**
- **Rotate JWT_SECRET and SERVER_ENCRYPTION_KEY periodically**
- **Use strong, unique passwords for database and Redis**
- **Enable automatic security updates in Coolify**
- **Monitor access logs for suspicious activity**
- **Backup encryption keys securely**

## Support

For deployment issues:
- Check Coolify documentation
- Review container logs in Coolify dashboard
- Verify all environment variables are set correctly
- Test health endpoints manually

For application issues:
- Check backend logs for API errors
- Verify database connections
- Test frontend-backend connectivity
- Review browser console for client-side errors