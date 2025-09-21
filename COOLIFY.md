# LeafLock Coolify Deployment Guide

This guide provides step-by-step instructions for deploying LeafLock on Coolify v4+.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Environment Configuration](#environment-configuration)
- [Deployment Process](#deployment-process)
- [Troubleshooting](#troubleshooting)
- [Post-Deployment](#post-deployment)
- [Monitoring and Maintenance](#monitoring-and-maintenance)

## Prerequisites

1. **Coolify Instance**: Running Coolify v4.0+ with Docker support
2. **Domain**: A domain name pointed to your Coolify server
3. **SSL Certificate**: Coolify can auto-generate SSL certificates via Let's Encrypt
4. **Git Repository**: Access to this LeafLock repository

## Quick Start

### 1. Import Project

1. Navigate to your Coolify dashboard
2. Click **"New Resource"** → **"Docker Compose"**
3. Choose **"From Git Repository"**
4. Enter the repository URL: `https://github.com/[your-repo]/LeafLock`
5. Select the appropriate branch (usually `main` or `master`)
6. Set **Docker Compose Location** to: `docker-compose.coolify.yml`

### 2. Basic Configuration

1. **Service Name**: `leaflock`
2. **Domain**: Set your domain (e.g., `leaflock.yourdomain.com`)
3. **SSL**: Enable automatic SSL certificate generation
4. **Build Pack**: Docker Compose
5. **Compose File**: `docker-compose.coolify.yml`

## Environment Configuration

### Required Environment Variables

Configure these in Coolify's **Environment Variables** section:

#### Database Configuration
```bash
# PostgreSQL password (32+ characters recommended)
POSTGRES_PASSWORD=your_secure_postgres_password_here

# Database URL (auto-generated, but can be customized)
DATABASE_URL=postgres://postgres:${POSTGRES_PASSWORD}@postgres:5432/notes?sslmode=prefer
```

#### Redis Configuration
```bash
# Redis password (32+ characters recommended)
REDIS_PASSWORD=your_secure_redis_password_here

# Redis connection URL
REDIS_URL=redis:6379
```

#### Security Keys (CRITICAL)
```bash
# JWT Secret Key (64+ characters)
# Generate with: openssl rand -base64 64
JWT_SECRET=your_64_character_jwt_secret_key_here

# Server Encryption Key (32 characters exactly)
# Generate with: openssl rand -base64 32
SERVER_ENCRYPTION_KEY=your_32_character_encryption_key_here
```

#### CORS and Frontend Configuration
```bash
# Replace with your actual domain
CORS_ORIGINS=https://leaflock.yourdomain.com

# Frontend API URL (replace with your domain)
VITE_API_URL=https://leaflock.yourdomain.com/api/v1

# Enable admin panel in frontend
VITE_ENABLE_ADMIN_PANEL=false
```

#### Application Settings
```bash
# Application environment
APP_ENV=production

# Server port (don't change for Coolify)
PORT=8080

# Enable user registration
ENABLE_REGISTRATION=true

# Metrics endpoint
ENABLE_METRICS=true
```

#### Default Admin User Configuration
```bash
# Enable automatic admin user creation
ENABLE_DEFAULT_ADMIN=true

# Admin credentials
DEFAULT_ADMIN_EMAIL=admin@leaflock.app
DEFAULT_ADMIN_PASSWORD=your_secure_admin_password_here
```

### Generating Secure Values

Use these commands to generate secure random values:

```bash
# PostgreSQL password
openssl rand -base64 32

# Redis password
openssl rand -base64 32

# JWT secret (64 characters)
openssl rand -base64 64

# Server encryption key (32 characters)
openssl rand -base64 32

# Admin password
openssl rand -base64 32
```

## Deployment Process

### Step 1: Repository Setup

1. In Coolify, create a new **Docker Compose** resource
2. Connect your Git repository
3. Select branch and set compose file path: `docker-compose.coolify.yml`

### Step 2: Environment Variables

1. Go to **Environment Variables** tab
2. Add all required variables from the configuration section above
3. **Important**: Ensure no quotes around values with special characters
4. **Double-check**: JWT_SECRET and SERVER_ENCRYPTION_KEY are properly set

### Step 3: Domain and SSL

1. Go to **Domains** tab
2. Add your domain (e.g., `leaflock.yourdomain.com`)
3. Enable **Force HTTPS**
4. Enable **Automatic SSL** (Let's Encrypt)

### Step 4: Deploy

1. Click **Deploy** button
2. Monitor deployment logs in real-time
3. Wait for all services to be healthy (typically 2-3 minutes)

### Step 5: Verify Deployment

Check these endpoints to verify successful deployment:

- **Frontend**: `https://leaflock.yourdomain.com`
- **API Health**: `https://leaflock.yourdomain.com/api/v1/health`
- **API Ready**: `https://leaflock.yourdomain.com/api/v1/ready`

## Troubleshooting

### Common Issues

#### 1. Build Failures

**Symptom**: Docker build fails during deployment

**Solutions**:
- Check Coolify build logs for specific error messages
- Ensure repository branch is correct
- Verify `docker-compose.coolify.yml` exists in repository root

#### 2. Database Connection Issues

**Symptom**: Backend shows database connection errors

**Solutions**:
- Verify `POSTGRES_PASSWORD` is set correctly
- Check if PostgreSQL container is healthy in Coolify dashboard
- Ensure `DATABASE_URL` matches your configuration

#### 3. Redis Connection Issues

**Symptom**: Backend logs show Redis connection failures

**Solutions**:
- Verify `REDIS_PASSWORD` is set correctly
- Check Redis container health
- Ensure `REDIS_URL` is set to `redis:6379`

#### 4. Container Runtime Issues

**Symptom**: Error "sysctl is not in a separate kernel namespace" during Redis startup

**Root Cause**: Coolify's container runtime doesn't allow setting kernel sysctls within containers

**Solutions**:
- The `docker-compose.coolify.yml` has been optimized to work without sysctls
- Performance optimizations (`vm.overcommit_memory`, `net.core.somaxconn`) must be set on the host
- Ask your Coolify administrator to configure these on the host system:
  ```bash
  sudo sysctl -w vm.overcommit_memory=1
  sudo sysctl -w net.core.somaxconn=1024
  ```
- The application will work without these optimizations, just with slightly reduced Redis performance

#### 5. SSL/HTTPS Issues

**Symptom**: SSL certificate not generated or HTTPS redirects fail

**Solutions**:
- Ensure domain points to your Coolify server
- Check DNS propagation (use `dig yourdomain.com`)
- Wait 5-10 minutes for Let's Encrypt certificate generation
- Check Coolify logs for SSL certificate errors

#### 6. Admin Login Issues

**Symptom**: Cannot login with default admin credentials

**Solutions**:
- Verify `DEFAULT_ADMIN_EMAIL` and `DEFAULT_ADMIN_PASSWORD` are set
- Check that `ENABLE_DEFAULT_ADMIN=true`
- Review backend logs for admin user creation messages
- Try clearing browser cache and cookies

### Debugging Commands

Access container logs via Coolify dashboard or SSH:

```bash
# View backend logs
docker logs leaflock-backend

# View database logs
docker logs leaflock-postgres

# View Redis logs
docker logs leaflock-redis

# Check container health
docker ps

# Access backend container
docker exec -it leaflock-backend sh
```

### Environment Variable Issues

**Special Characters in Passwords**:
- Do NOT wrap environment variables in quotes
- Special characters like `#`, `&`, `$`, `!`, `@` are supported directly
- Example: `DEFAULT_ADMIN_PASSWORD=#wmR8xWxZ&#JHZPd8HTYmafctWSe0N*jgPG%bYS@`

## Post-Deployment

### 1. Initial Admin Access

1. Navigate to `https://leaflock.yourdomain.com`
2. Login with your `DEFAULT_ADMIN_EMAIL` and `DEFAULT_ADMIN_PASSWORD`
3. **Immediately change the default admin password**
4. Configure additional admin users if needed

### 2. Security Checklist

- [ ] Change default admin password
- [ ] Verify SSL certificate is active
- [ ] Test all major functionality (create note, encrypt/decrypt)
- [ ] Review and adjust `CORS_ORIGINS` for your domain
- [ ] Set `ENABLE_REGISTRATION=false` if you want invite-only access

### 3. Performance Optimization

- [ ] Monitor resource usage in Coolify dashboard
- [ ] Scale containers if needed (increase CPU/memory limits)
- [ ] Set up regular database backups
- [ ] Configure monitoring alerts

## Monitoring and Maintenance

### Health Monitoring

LeafLock provides several monitoring endpoints:

- **Health Check**: `/api/v1/health` - Comprehensive system status
- **Ready Check**: `/api/v1/ready` - Quick readiness probe
- **Metrics**: `/metrics` - Prometheus metrics (if enabled)

### Regular Maintenance

1. **Database Backups**: Configure regular PostgreSQL backups
2. **Security Updates**: Keep base images updated
3. **Certificate Renewal**: Coolify handles SSL renewal automatically
4. **Log Rotation**: Monitor and manage container logs
5. **Performance Monitoring**: Watch CPU, memory, and disk usage

### Scaling

For high-traffic deployments:

1. **Database**: Consider external PostgreSQL service
2. **Redis**: Use Redis cluster or external Redis service
3. **Load Balancing**: Deploy multiple backend instances
4. **CDN**: Use CDN for static frontend assets

## Support

### Debug Endpoints (Admin Only)

LeafLock includes admin-only debug endpoints for troubleshooting:

- `GET /api/v1/admin/debug/check-admin` - Check admin user status
- `GET /api/v1/admin/debug/users` - List all users with status
- `GET /api/v1/admin/debug/system-health` - Detailed system health
- `POST /api/v1/admin/debug/test-login` - Test login credentials

Access these endpoints with admin authentication for detailed diagnostics.

### Additional Resources

- **LeafLock Documentation**: `README.md` in repository
- **Coolify Documentation**: [https://coolify.io/docs](https://coolify.io/docs)
- **Docker Compose Reference**: `docker-compose.yml` for local development

---

**Security Note**: Always use strong, randomly generated passwords and keys for production deployments. Never commit sensitive environment variables to version control.