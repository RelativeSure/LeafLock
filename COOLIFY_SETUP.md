# 🚀 LeafLock Coolify Deployment Guide

This guide walks you through deploying LeafLock (end-to-end encrypted notes app) on Coolify step-by-step using the Coolify web interface.

## Prerequisites

- ✅ Coolify instance running and accessible
- ✅ Server connected to Coolify (VPS with Docker installed)
- ✅ Domain name (recommended) for SSL certificates
- ✅ GitHub repository access (if using GitHub integration)

## 🔧 Step-by-Step Coolify UI Setup

### Step 1: Create New Resource in Coolify

1. **Login to your Coolify dashboard**
2. **Click "New Resource"** in the top navigation
3. **Select "Docker Compose"** from the options
4. **Choose your server** from the dropdown (where you want to deploy)

### Step 2: Repository Configuration

#### Option A: Public Repository (Recommended)
1. **Select "Public Repository"**
2. **Repository URL**: `https://github.com/RelativeSure/notes`
3. **Branch**: `master` (or your preferred branch)
4. **Docker Compose Location**: `/docker-compose.coolify.yml`
5. **Base Directory**: `/` (root of repository)

#### Option B: GitHub Integration
1. **Select "GitHub App"** (if you have it configured)
2. **Choose the LeafLock repository**
3. **Set branch to** `master`
4. **Docker Compose Location**: `/docker-compose.coolify.yml`

### Step 3: Configure Environment Variables

**Click on "Environment Variables" tab** and add these **required** variables:

#### 🔐 Security Variables (CRITICAL)
```bash
# Generate these with the commands provided:

# PostgreSQL Password (openssl rand -base64 32)
POSTGRES_PASSWORD=YourSecureRandomPassword32Chars

# Redis Password (openssl rand -base64 32)  
REDIS_PASSWORD=YourSecureRedisPassword32Chars

# JWT Secret - 64+ characters (openssl rand -base64 64)
JWT_SECRET=YourVeryLongSecure64CharacterJWTSecretKeyForSigningTokensSecurely

# Encryption Key - exactly 32 chars (openssl rand -base64 32 | head -c 32)
SERVER_ENCRYPTION_KEY=Your32CharacterEncryptionKeyHere
```

#### 🌐 Domain Configuration
```bash
# Your frontend domain (where users will access LeafLock)
CORS_ORIGINS=https://leaflock.yourdomain.com

# Your backend API domain (can be same as frontend)
VITE_API_URL=https://leaflock.yourdomain.com
```

#### ⚙️ Optional Settings
```bash
# Application environment
APP_ENV=production

# Enable user registration (true/false)
ENABLE_REGISTRATION=true

# Enable admin panel (true/false)  
VITE_ENABLE_ADMIN_PANEL=false
```

### Step 4: Service Configuration & Domains

#### Configure Frontend Service
1. **Navigate to Services tab**
2. **Click on "frontend" service**
3. **Add Domain**: 
   - Domain: `leaflock.yourdomain.com`
   - Enable "Force HTTPS"
   - Enable "Generate SSL Certificate"
4. **Port Settings**: Should be `3000:80`

#### Configure Backend Service (Optional Public Access)
1. **Click on "backend" service**  
2. **Add Domain** (if you want API publicly accessible):
   - Domain: `api.leaflock.yourdomain.com`
   - Enable "Force HTTPS"
   - Enable "Generate SSL Certificate"
3. **Port Settings**: Should be `8080:8080`

**Note**: Backend can remain internal-only if frontend is on same domain.

### Step 5: Deploy the Application

1. **Click "Deploy"** button (usually blue, top-right)
2. **Monitor the deployment logs**:
   - Click "Logs" tab
   - Watch for each service starting up
   - Look for successful health checks

#### Expected Log Flow:
```
✅ postgres: Database system is ready to accept connections
✅ redis: Ready to accept connections  
✅ backend: Server started on port 8080
✅ frontend: nginx started successfully
```

### Step 6: Verify Deployment

#### Check Service Health
1. **Visit your frontend URL**: `https://leaflock.yourdomain.com`
2. **Test backend health**: `https://leaflock.yourdomain.com/api/v1/health`
   - Should return: `{"status":"ok","timestamp":"..."}`

#### Test Application Flow
1. **Register a new account**
2. **Create a test note**
3. **Verify encryption** (note content should be encrypted in database)
4. **Test login/logout functionality**

## 🎯 Quick Setup Commands

### Generate All Required Secrets at Once:
```bash
echo "POSTGRES_PASSWORD=$(openssl rand -base64 32)"
echo "REDIS_PASSWORD=$(openssl rand -base64 32)"
echo "JWT_SECRET=$(openssl rand -base64 64)"
echo "SERVER_ENCRYPTION_KEY=$(openssl rand -base64 32 | head -c 32)"
```

### Test Local Environment Setup:
```bash
# Copy the Coolify environment template
cp .env.coolify .env.local

# Edit with your values
nano .env.local

# Test locally first (optional)
docker compose -f docker-compose.coolify.yml --env-file .env.local up -d
```

## 🔍 Troubleshooting

### Common Issues & Solutions

#### ❌ "Required environment variable not set"
- **Solution**: Check all variables in `.env.coolify` are set in Coolify UI
- **Verify**: Environment Variables tab shows all required fields filled

#### ❌ Database connection failed
- **Check**: PostgreSQL container is running and healthy
- **Logs**: Look at `postgres` service logs
- **Fix**: Verify `POSTGRES_PASSWORD` is correctly set

#### ❌ Frontend shows "Network Error"
- **Check**: Backend service is running and accessible
- **Verify**: `VITE_API_URL` matches your backend domain
- **Test**: Visit `/api/v1/health` endpoint directly

#### ❌ CORS errors in browser
- **Fix**: Add your frontend domain to `CORS_ORIGINS`
- **Format**: `https://leaflock.yourdomain.com` (no trailing slash)
- **Multiple domains**: Comma-separated: `https://domain1.com,https://domain2.com`

#### ❌ SSL certificate generation failed  
- **Check**: Domain DNS points to your server IP
- **Wait**: Certificate generation can take a few minutes
- **Retry**: Click "Generate SSL Certificate" again

### Debug Commands in Coolify

1. **View Service Logs**:
   - Click service → "Logs" tab
   - Use "Follow" to see real-time logs

2. **Execute Commands in Containers**:
   - Click service → "Terminal" tab
   - Run diagnostic commands

3. **Check Container Status**:
   - Services tab shows running/stopped status
   - Health check status visible per service

## 🔒 Security Best Practices

### After Deployment:

1. **Change Default Credentials**: Never use example passwords
2. **Backup Database**: Set up regular PostgreSQL backups
3. **Monitor Logs**: Check for suspicious activity
4. **Update Regularly**: Keep Coolify and containers updated
5. **Restrict Access**: Use strong passwords and consider VPN access

### Environment Security:
- ✅ Use strong, unique passwords for all services
- ✅ Keep JWT_SECRET and SERVER_ENCRYPTION_KEY secure
- ✅ Never commit `.env` files to version control  
- ✅ Use HTTPS everywhere (force SSL in Coolify)
- ✅ Regularly rotate passwords and keys

## 📊 Monitoring & Maintenance  

### Health Check Endpoints:
- **Backend Health**: `GET /api/v1/health`
- **Database Ready**: Check backend logs for DB connections
- **Redis Status**: Check backend logs for Redis connections

### Backup Strategy:
```bash
# PostgreSQL backup (run via Coolify terminal on postgres service)
pg_dump -U postgres -h localhost leaflock > backup_$(date +%Y%m%d).sql

# Redis backup (automatic with appendonly=yes in compose file)
# Files stored in redis_data volume
```

### Updates:
1. **Update Code**: Push to GitHub (auto-deploys if configured)
2. **Update Images**: Coolify can auto-update container images  
3. **Manual Deploy**: Click "Deploy" to redeploy with latest code

---

## 🎉 Congratulations!

Your LeafLock encrypted notes application is now running on Coolify with:
- ✅ End-to-end encryption  
- ✅ SSL/HTTPS certificates
- ✅ PostgreSQL database with persistent storage
- ✅ Redis session management
- ✅ Automatic health checks and restarts
- ✅ Professional production setup

**Next Steps:**
- Create your first encrypted note
- Invite users to register accounts  
- Set up monitoring and backups
- Configure admin panel (if needed)

For issues or questions, check the [GitHub repository](https://github.com/RelativeSure/notes) or create an issue.