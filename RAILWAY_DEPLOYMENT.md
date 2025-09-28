# Railway Deployment Guide

This guide walks you through deploying LeafLock to Railway, which eliminates the DNS resolution issues experienced with Coolify.

## Why Railway?

Railway uses **managed PostgreSQL and Redis services** instead of containerized databases, completely eliminating the container-to-container DNS resolution problems that plague Coolify deployments.

## Prerequisites

1. [Railway account](https://railway.app) (free tier available)
2. GitHub repository connected to Railway
3. This repository with Railway configuration files

## Deployment Steps

### 1. Create Railway Project

```bash
# Install Railway CLI (optional)
npm install -g @railway/cli

# Login to Railway
railway login

# Create new project
railway create leaflock
```

Or use the Railway dashboard:
1. Go to [railway.app](https://railway.app)
2. Click "Start a New Project"
3. Connect your GitHub repository

### 2. Add Managed Services

In your Railway project dashboard, add these services:

#### PostgreSQL Service
1. Click "Add Service" → "Database" → "PostgreSQL"
2. Railway will automatically provide `DATABASE_URL` environment variable
3. No additional configuration needed

#### Redis Service
1. Click "Add Service" → "Database" → "Redis"
2. Railway will automatically provide `REDIS_URL` environment variable
3. No additional configuration needed

### 3. Configure Environment Variables

In Railway dashboard, set these environment variables for your backend service:

```bash
# Required Security Variables
JWT_SECRET=your_64_character_jwt_secret_key_here
SERVER_ENCRYPTION_KEY=your_32_character_encryption_key_here

# Admin Configuration
DEFAULT_ADMIN_EMAIL=admin@yourdomain.com
DEFAULT_ADMIN_PASSWORD=YourSecureAdminPassword123!
ENABLE_DEFAULT_ADMIN=true

# Application Settings
APP_ENV=production
ENABLE_REGISTRATION=true
ENABLE_METRICS=true

# CORS Configuration (update with your domain)
CORS_ORIGINS=https://your-frontend-domain.railway.app

# Frontend API URL (update with your backend domain)
VITE_API_URL=https://your-backend-domain.railway.app
```

### 4. Generate Secure Keys

```bash
# Generate JWT Secret (64+ characters)
openssl rand -base64 64

# Generate Server Encryption Key (exactly 32 characters)
openssl rand -base64 32

# Generate Admin Password
openssl rand -base64 24
```

### 5. Deploy Application

Railway will automatically detect the `docker-compose.railway.yml` file and deploy your application.

If using Railway CLI:
```bash
# Deploy from current directory
railway up

# Or deploy specific service
railway up --service backend
railway up --service frontend
```

### 6. Configure Custom Domain (Optional)

1. In Railway dashboard, go to your frontend service
2. Click "Settings" → "Domains"
3. Add your custom domain
4. Update `CORS_ORIGINS` and `VITE_API_URL` environment variables

## Environment Variable Reference

### Backend Service Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `DATABASE_URL` | Automatically provided by Railway PostgreSQL | `postgresql://...` |
| `REDIS_URL` | Automatically provided by Railway Redis | `redis://...` |
| `JWT_SECRET` | 64+ character secret for JWT tokens | `openssl rand -base64 64` |
| `SERVER_ENCRYPTION_KEY` | Exactly 32 character encryption key | `openssl rand -base64 32` |
| `DEFAULT_ADMIN_EMAIL` | Admin user email | `admin@yourdomain.com` |
| `DEFAULT_ADMIN_PASSWORD` | Admin user password | Strong password |
| `CORS_ORIGINS` | Allowed frontend origins | `https://yourapp.railway.app` |

### Frontend Service Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `VITE_API_URL` | Backend API URL | `https://backend.railway.app` |

## Advantages Over Coolify

1. **No DNS Resolution Issues**: Managed services eliminate container networking problems
2. **Automatic SSL**: Railway provides SSL certificates automatically
3. **Preview Deployments**: Automatic preview deployments for pull requests
4. **Managed Databases**: PostgreSQL and Redis are fully managed
5. **Simple Scaling**: Easy horizontal and vertical scaling
6. **Built-in CI/CD**: Automatic deployments from GitHub
7. **Environment Management**: Easy environment variable management

## Monitoring and Logs

Railway provides:
- Real-time application logs
- Resource usage metrics
- Deployment history
- Service health monitoring

Access logs via:
- Railway dashboard
- Railway CLI: `railway logs`

## Troubleshooting

### Common Issues

1. **Environment Variables Not Set**
   - Check Railway dashboard environment variables
   - Ensure all required variables are set

2. **Database Connection Issues**
   - Verify PostgreSQL service is running
   - Check `DATABASE_URL` is automatically provided

3. **CORS Errors**
   - Update `CORS_ORIGINS` with correct frontend domain
   - Ensure both HTTP and HTTPS origins if needed

### Support Resources

- [Railway Documentation](https://docs.railway.app)
- [Railway Discord](https://discord.gg/railway)
- [Railway GitHub](https://github.com/railwayapp)

## Cost Estimation

Railway pricing (as of 2024):
- **Hobby Plan**: $5/month per user
- **Pro Plan**: $20/month per user
- **Usage-based**: $0.20 per GB RAM-hour, $0.10 per GB storage

For LeafLock (estimated monthly cost):
- PostgreSQL: ~$5-10
- Redis: ~$5
- Backend: ~$5-10
- Frontend: ~$5
- **Total**: ~$20-30/month

## Migration from Coolify

If migrating from Coolify:
1. Export your environment variables from Coolify
2. Set them in Railway dashboard
3. Deploy to Railway
4. Update DNS records to point to Railway
5. Test thoroughly before decommissioning Coolify

Railway's managed services approach eliminates the DNS resolution issues that make Coolify deployments unreliable for containerized applications.