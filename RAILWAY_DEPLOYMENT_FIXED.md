# Railway Deployment Guide - Fixed 502 Bad Gateway Issue

## What Was Fixed

### 1. **502 Bad Gateway Issue (Critical Fix)**
- **Problem**: NGINX cached DNS lookups at startup. Railway's IPv6 private network assigns dynamic IPs on each deployment, causing stale DNS → 502 errors
- **Solution**: Replaced NGINX with **Caddy reverse proxy** (Railway-recommended)
  - Caddy handles dynamic DNS resolution natively
  - No DNS caching issues
  - Better IPv6 support
  - Automatic HTTP/2 and dynamic upstream handling

### 2. **ENABLE_REGISTRATION Default Changed**
- **Old**: Defaulted to `true` (security risk)
- **New**: Defaults to `false` (secure by default)
- **Location**: `backend/main.go:6679`

### 3. **Backend Proxy Configuration for Railway**
- **Added**: Fiber `EnableTrustedProxyCheck`, `ProxyHeader`, and `TrustedProxies`
- **Supports**: Railway's IPv6 private network (`fd00::/8`)
- **Benefits**: Correct client IP detection, proper request forwarding

### 4. **Improved Logging**
- Fixed misleading log message showing IPv4 when actually binding to IPv6
- Now correctly shows: `🌐 HTTP server listening on [::]:8080 (Railway IPv6 compatible)`

## Railway Environment Variables

### Backend Service
```bash
APP_ENV=production
CORS_ORIGINS=https://leaflock-frontend-production.up.railway.app,https://app.leaflock.app
DATABASE_URL=${{Postgres.DATABASE_URL}}
DEFAULT_ADMIN_EMAIL=mail@rasmusj.dk
DEFAULT_ADMIN_PASSWORD=<your-secure-password>
ENABLE_DEFAULT_ADMIN=true
ENABLE_METRICS=false
ENABLE_REGISTRATION=false  # ✅ Now defaults to false
JWT_SECRET=<your-64-char-secret>
PORT=8080
REDIS_PASSWORD=${{Redis.REDIS_PASSWORD}}
REDIS_URL=${{Redis.REDIS_URL}}
SERVER_ENCRYPTION_KEY=<your-32-char-key>
TRUST_PROXY_HEADERS=true  # ✅ Required for Railway
VITE_API_URL=https://app.leaflock.app/api/v1
```

### Frontend Service
```bash
APP_ENV=production
BACKEND_INTERNAL_URL=http://motivated-energy.railway.internal:8080  # ✅ Use Railway internal domain
PORT=80
VITE_API_URL=https://leaflock-frontend-production.up.railway.app/api/v1
```

### Shared Variables
```bash
APP_ENV=production
CORS_ORIGINS=https://leaflock-frontend-production.up.railway.app,https://app.leaflock.app
DEFAULT_ADMIN_EMAIL=mail@rasmusj.dk
DEFAULT_ADMIN_PASSWORD=<your-password>
ENABLE_DEFAULT_ADMIN=true
ENABLE_METRICS=false
ENABLE_REGISTRATION=false  # ✅ Secure by default
JWT_SECRET=<your-jwt-secret>
SERVER_ENCRYPTION_KEY=<your-encryption-key>
TRUST_PROXY_HEADERS=true  # ✅ Critical for Railway
VITE_API_URL=https://app.leaflock.app/api/v1
```

## Key Changes in Files

### Frontend Changes
1. **`frontend/Caddyfile`** (NEW)
   - Caddy configuration with dynamic DNS resolution
   - IPv6-compatible reverse proxy
   - Health check endpoint at `/health`
   - Security headers configured

2. **`frontend/Dockerfile`**
   - Changed base image from `nginx:1.27-alpine` to `caddy:2.8-alpine`
   - Updated user from `nginx-user` to `caddy-user`
   - Simplified configuration (Caddy needs less setup)

3. **`frontend/docker-entrypoint.sh`**
   - Updated to launch Caddy instead of NGINX
   - Retained Railway service discovery logic
   - Better logging for debugging

### Backend Changes
1. **`backend/main.go:6679`**
   - Changed `ENABLE_REGISTRATION` default from `"true"` to `"false"`

2. **`backend/main.go:1036-1046`**
   - Added `EnableTrustedProxyCheck: trustProxyHeaders.Load()`
   - Added `ProxyHeader: fiber.HeaderXForwardedFor`
   - Added `TrustedProxies` array with Railway's IPv6 ranges:
     ```go
     TrustedProxies: []string{
         "10.0.0.0/8",      // Private IPv4
         "172.16.0.0/12",   // Private IPv4
         "192.168.0.0/16",  // Private IPv4
         "fd00::/8",        // Private IPv6 (Railway uses this)
         "::1",             // IPv6 localhost
         "127.0.0.1",       // IPv4 localhost
     }
     ```

3. **`backend/main.go:1186`**
   - Improved log message to show Railway IPv6 compatibility

## Testing the Deployment

### 1. Build and Test Locally
```bash
# Test frontend build
cd frontend
docker build -t leaflock-frontend-test .

# Test backend build
cd ../backend
docker build -t leaflock-backend-test .
```

### 2. Deploy to Railway
```bash
# Push to your repository
git add .
git commit -m "Fix: Railway deployment - Replace NGINX with Caddy, fix 502 errors"
git push

# Railway will auto-deploy from your connected repository
```

### 3. Verify Health Checks
```bash
# Backend health check (fast, for Railway)
curl https://your-backend-domain.railway.app/api/v1/health/live

# Backend ready check (full initialization)
curl https://your-backend-domain.railway.app/api/v1/health/ready

# Frontend health check
curl https://your-frontend-domain.railway.app/health
```

### 4. Test Login
```bash
# API login
curl -X POST https://your-backend-domain.railway.app/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"mail@rasmusj.dk","password":"YourPassword"}'

# Browser
# Navigate to https://your-frontend-domain.railway.app and login
```

## Why Caddy Instead of NGINX?

Railway explicitly recommends Caddy for their platform because:

1. **Dynamic DNS Resolution**: Caddy re-resolves backend hostnames on every request (NGINX caches at startup)
2. **IPv6 Native Support**: Better handling of Railway's IPv6-only private network
3. **Simpler Configuration**: No need for resolver directives or variable workarounds
4. **Automatic HTTP/2**: Built-in modern protocols
5. **Environment Variable Substitution**: Native support (NGINX needs `envsubst`)

## Alternative Hosting Providers

If you still experience issues with Railway:

### Fly.io
- **Pros**: Excellent IPv6 support, global anycast, better documentation
- **Pricing**: Similar to Railway, free tier available
- **Migration**: Straightforward with existing Docker setup

### Render
- **Pros**: Simpler than Railway, good free tier, automatic SSL
- **Pricing**: Free tier for static sites, $7/month for web services
- **Migration**: Very easy, similar environment variable setup

### Coolify (Self-Hosted)
- **Pros**: You already have configuration for this, full control
- **Pricing**: Only server costs
- **Migration**: Use existing `docker-compose.coolify.yml`

## Troubleshooting

### 502 Bad Gateway After Deployment
1. Check Railway logs for DNS resolution errors
2. Verify `BACKEND_INTERNAL_URL` is set correctly (use `.railway.internal` domain)
3. Ensure `TRUST_PROXY_HEADERS=true` is set
4. Check that backend is listening on `[::]:{PORT}` (IPv6)

### Registration Not Working
- Check `ENABLE_REGISTRATION` environment variable
- Default is now `false` - set to `true` if you want open registration
- Or use admin panel to manage users

### CORS Errors
- Verify `CORS_ORIGINS` includes both public domains
- Example: `https://app.leaflock.app,https://leaflock-frontend-production.up.railway.app`

## Performance Notes

- **Frontend**: Caddy is slightly faster than NGINX for reverse proxy workloads
- **Backend**: No changes to performance, just better proxy header handling
- **Startup Time**: Same 15-30 second startup time maintained
- **Health Checks**: Use `/api/v1/health/live` for Railway health checks (3-5s response)

## Security Improvements

1. **ENABLE_REGISTRATION** now defaults to `false` (invite-only by default)
2. **Proper proxy header validation** prevents IP spoofing
3. **Railway's IPv6 private network** is now in trusted proxy list
4. **Caddy security headers** automatically applied

## Next Steps

1. Deploy the updated code to Railway
2. Monitor logs for successful startup and health checks
3. Test login functionality
4. Set `ENABLE_REGISTRATION=true` only if you want public registration
5. Consider setting up Railway custom domains for cleaner URLs

## Support

If issues persist:
1. Check Railway logs: `railway logs --service backend` / `railway logs --service frontend`
2. Verify environment variables are set correctly
3. Test health endpoints individually
4. Review CORS settings

Railway should now work correctly with these fixes! The 502 Bad Gateway issue was caused by NGINX's DNS caching, which Caddy solves natively.