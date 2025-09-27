#!/bin/bash
# Test script to verify Railway IPv6 private network communication

echo "=== Railway IPv6 Private Network Communication Test ==="
echo ""

# Test 1: Check if backend is accessible via private network
echo "1. Testing backend health check via private network:"
echo "   URL: http://motivated-energy.railway.internal:8080/api/v1/health"
if command -v curl >/dev/null 2>&1; then
    curl -v -m 10 "http://motivated-energy.railway.internal:8080/api/v1/health" || echo "❌ Private network health check failed"
else
    echo "   (curl not available - manual test required)"
fi
echo ""

# Test 2: Check IPv6 connectivity
echo "2. Testing IPv6 connectivity:"
if command -v ping6 >/dev/null 2>&1; then
    ping6 -c 3 motivated-energy.railway.internal || echo "❌ IPv6 ping failed"
else
    echo "   (ping6 not available - manual test required)"
fi
echo ""

# Test 3: DNS resolution
echo "3. Testing DNS resolution of Railway internal hostnames:"
if command -v nslookup >/dev/null 2>&1; then
    echo "   Backend (motivated-energy.railway.internal):"
    nslookup motivated-energy.railway.internal || echo "❌ Backend DNS resolution failed"
    echo "   Frontend (leaflock-frontend.railway.internal):"
    nslookup leaflock-frontend.railway.internal || echo "❌ Frontend DNS resolution failed"
else
    echo "   (nslookup not available - manual test required)"
fi
echo ""

# Test 4: Environment variables check
echo "4. Checking Railway environment variables:"
echo "   RAILWAY_SERVICE_NAME: ${RAILWAY_SERVICE_NAME:-NOT_SET}"
echo "   RAILWAY_ENVIRONMENT_NAME: ${RAILWAY_ENVIRONMENT_NAME:-NOT_SET}"
echo "   RAILWAY_PROJECT_NAME: ${RAILWAY_PROJECT_NAME:-NOT_SET}"
echo "   Backend Internal URL: ${BACKEND_INTERNAL_URL:-NOT_SET}"
echo ""

# Test 5: Network interface check
echo "5. Checking network interfaces for IPv6:"
if command -v ip >/dev/null 2>&1; then
    echo "   IPv6 interfaces:"
    ip -6 addr show | grep -E "(inet6|scope)" || echo "❌ No IPv6 interfaces found"
elif command -v ifconfig >/dev/null 2>&1; then
    echo "   IPv6 interfaces:"
    ifconfig | grep -E "(inet6|scope)" || echo "❌ No IPv6 interfaces found"
else
    echo "   (ip/ifconfig not available - manual test required)"
fi
echo ""

echo "=== Test Complete ==="
echo ""
echo "Next steps:"
echo "1. Set Railway environment variables:"
echo "   Backend CORS_ORIGINS=https://leaflock-frontend-production.up.railway.app,https://leaflock-frontend.railway.internal"
echo "   Frontend BACKEND_INTERNAL_URL=http://motivated-energy.railway.internal:8080"
echo ""
echo "2. Deploy and check logs for IPv6 binding success:"
echo "   Backend should show: 'HTTP server starting on [::]:8080'"
echo ""
echo "3. Test API calls from frontend to backend via private network"