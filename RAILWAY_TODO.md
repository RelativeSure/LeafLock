# Railway IPv6 Setup - TODO for Tomorrow

## What We Found
✅ Your app is already IPv6-ready! Backend has `listenWithIPv6Fallback()` that binds to `[::]:{port}` first.

## What You Need to Do Tomorrow

### 1. Set Railway Environment Variables

**Backend Service (motivated-energy.railway.internal):**
```
CORS_ORIGINS=https://leaflock-frontend-production.up.railway.app,https://leaflock-frontend.railway.internal,http://leaflock-frontend.railway.internal
```

**Frontend Service (leaflock-frontend.railway.internal):**
```
BACKEND_INTERNAL_URL=http://motivated-energy.railway.internal:8080
VITE_API_URL=https://leaflock-backend-production.up.railway.app
```

### 2. Deploy and Check Logs

**Backend logs should show:**
```
🌐 HTTP server starting on [::]:8080
```

**Frontend logs should show:**
```
BACKEND_INTERNAL_URL: http://motivated-energy.railway.internal:8080
```

### 3. Test
Run: `./test-railway-ipv6.sh`

## Files Changed
- `frontend/docker-entrypoint.sh` - Updated Railway service discovery
- `test-railway-ipv6.sh` - Test script
- `RAILWAY_IPV6_VERIFICATION.md` - Full guide

## Your Service Names
- Backend Public: leaflock-backend-production.up.railway.app
- Backend Private: motivated-energy.railway.internal
- Frontend Public: leaflock-frontend-production.up.railway.app
- Frontend Private: leaflock-frontend.railway.internal

That's it! Your code is already IPv6-ready, just need to set the env vars.