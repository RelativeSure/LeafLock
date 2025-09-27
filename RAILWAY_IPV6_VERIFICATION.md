# Railway IPv6 Private Network Verification Guide

## Current Railway Services
- **Backend Public**: leaflock-backend-production.up.railway.app
- **Backend Private**: motivated-energy.railway.internal
- **Frontend Public**: leaflock-frontend-production.up.railway.app
- **Frontend Private**: leaflock-frontend.railway.internal

## ✅ IPv6 Compatibility Status

### Backend (Go/Fiber)
✅ **IPv6 Ready**: Backend already implements `listenWithIPv6Fallback()` function that:
- Tries to bind to `[::]:{port}` first (IPv6)
- Falls back to IPv4 only if IPv6 fails
- Perfect for Railway's IPv6-only private network

### Frontend (Nginx)
✅ **IPv6 Ready**: Frontend docker-entrypoint.sh updated to:
- Auto-detect Railway service discovery variables
- Handle IPv6 address normalization with brackets
- Support Railway's internal hostname pattern

## Required Railway Environment Variables

### Backend Service
```bash
CORS_ORIGINS=https://leaflock-frontend-production.up.railway.app,https://leaflock-frontend.railway.internal,http://leaflock-frontend.railway.internal
```

### Frontend Service
```bash
BACKEND_INTERNAL_URL=http://motivated-energy.railway.internal:8080
VITE_API_URL=https://leaflock-backend-production.up.railway.app
```

## Verification Steps

### 1. Deploy with Updated Environment Variables
Set the environment variables above in Railway dashboard for each service.

### 2. Monitor Backend Logs
Look for successful IPv6 binding:
```
🌐 HTTP server starting on [::]:8080 (startup time: ...)
```
If you see fallback to IPv4, check Railway network configuration.

### 3. Monitor Frontend Logs
Check that service discovery works:
```
=== Frontend Container Startup ===
PORT: 80
BACKEND_INTERNAL_URL: http://motivated-energy.railway.internal:8080
===================================
Detected BACKEND_INTERNAL_URL: http://motivated-energy.railway.internal:8080
```

### 4. Test Private Network Communication
From frontend container, test backend connectivity:
```bash
curl -v http://motivated-energy.railway.internal:8080/api/v1/health
```

### 5. Test Public API Access
From browser, verify frontend can access backend via private network:
```javascript
// This should work from the frontend app
fetch('/api/v1/health').then(r => r.json()).then(console.log)
```

## Expected Behavior

### ✅ Successful IPv6 Private Network Communication
- Backend binds to `[::]:{port}` (IPv6 all interfaces)
- Frontend nginx proxies API calls to `http://motivated-energy.railway.internal:8080`
- Railway's IPv6 mesh network handles service-to-service communication
- Public traffic still flows through public URLs
- Private traffic (API calls) flows through Railway's internal network

### ❌ Potential Issues and Solutions

**Backend falls back to IPv4:**
- Check Railway service configuration
- Verify IPv6 is enabled for the project
- Check for conflicting network configurations

**Frontend cannot reach backend:**
- Verify `BACKEND_INTERNAL_URL` is set correctly
- Check nginx configuration template
- Ensure CORS origins include internal hostnames

**API calls fail with network errors:**
- Check Railway service names match exactly
- Verify port 8080 is correct for backend
- Check service health and startup order

## Testing Script

Run the included test script on Railway:
```bash
./test-railway-ipv6.sh
```

This script will:
- Test backend health via private network
- Check IPv6 connectivity
- Verify DNS resolution of Railway internal hostnames
- Validate environment variables
- Check network interfaces for IPv6

## Railway IPv6 Network Architecture

Railway's private network uses:
- **IPv6-only mesh network** via WireGuard
- **Automatic DNS resolution** for `.railway.internal` domains
- **Zero-configuration networking** between services in same project
- **Isolation** - services cannot communicate across projects/environments

Your LeafLock application is fully compatible with this architecture and should work seamlessly with Railway's IPv6 private networking.