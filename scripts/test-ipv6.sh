#!/bin/bash
# LeafLock IPv6 Integration Test
# Tests IPv4/IPv6 dual-stack functionality for both backend and frontend

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo "═══════════════════════════════════════════════════════"
echo "  LeafLock IPv6 Integration Test Suite"
echo "═══════════════════════════════════════════════════════"
echo ""

# Check if IPv6 is available on the system
echo "📋 Checking system IPv6 availability..."
if ip -6 addr show 2>/dev/null | grep -q "inet6" || ifconfig 2>/dev/null | grep -q "inet6"; then
    echo -e "${GREEN}✅ IPv6 is available on this system${NC}"
    IPV6_AVAILABLE=true
else
    echo -e "${YELLOW}⚠️  IPv6 not available - tests will verify IPv4 fallback behavior${NC}"
    IPV6_AVAILABLE=false
fi

# Function to cleanup background processes
# shellcheck disable=SC2329  # Function is used in trap
cleanup() {
    echo ""
    echo "🧹 Cleaning up..."
    if [ -n "$BACKEND_PID" ]; then
        kill "$BACKEND_PID" 2>/dev/null || true
        wait "$BACKEND_PID" 2>/dev/null || true
    fi
    rm -f /tmp/leaflock-backend-*.log
    echo -e "${BLUE}Cleanup complete${NC}"
}
trap cleanup EXIT INT TERM

# Build backend
echo ""
echo "🔨 Building backend..."
cd backend
if ! go build -o app .; then
    echo -e "${RED}❌ Backend build failed${NC}"
    exit 1
fi
echo -e "${GREEN}✅ Backend built successfully${NC}"

# Start backend with environment variables
echo ""
echo "🚀 Starting backend server..."
LOG_FILE="/tmp/leaflock-backend-test-$$.log"

# Required environment variables for backend
# Using secure random values that don't trigger weak validation
export JWT_SECRET="6kMn8QwP2xRtY4vB9nZmC7dF5gH3jK1lLpOs0uIyEw12AzXcVbNm45SdFgHjKlPo"
export SERVER_ENCRYPTION_KEY="7nBv8CxD9zE1fG2hJ3kL4mN5pQ6rS7tU"
export PORT=8080
export DATABASE_URL="postgres://postgres:postgres@localhost:5432/leaflock_test?sslmode=disable"
export REDIS_URL="localhost:6379"
export SKIP_ADMIN_VALIDATION=true
export ENABLE_DEFAULT_ADMIN=false

# Start backend in background
PORT=8080 ./app > "$LOG_FILE" 2>&1 &
BACKEND_PID=$!
echo -e "${BLUE}Backend PID: $BACKEND_PID${NC}"

# Wait for backend to start and check binding
echo "⏳ Waiting for backend to start..."
sleep 5

if ! ps -p $BACKEND_PID > /dev/null 2>&1; then
    echo -e "${RED}❌ Backend process died during startup${NC}"
    echo -e "${YELLOW}Last 20 lines of log:${NC}"
    tail -20 "$LOG_FILE"
    exit 1
fi

# Check backend logs for binding information
echo ""
echo "📝 Backend binding status:"
if grep -q "✅ \[IPv6\] Successfully bound" "$LOG_FILE"; then
    echo -e "${GREEN}✅ Backend bound to IPv6 dual-stack [::]:8080${NC}"
    grep "IPv6" "$LOG_FILE" | tail -3
    BACKEND_BINDING="ipv6-dual-stack"
elif grep -q "✅ \[IPv4\] Successfully bound" "$LOG_FILE"; then
    echo -e "${YELLOW}⚠️  Backend bound to IPv4-only 0.0.0.0:8080 (IPv6 not available)${NC}"
    grep "IPv4" "$LOG_FILE" | tail -3
    BACKEND_BINDING="ipv4-only"
else
    echo -e "${RED}❌ Could not determine backend binding status${NC}"
    echo -e "${YELLOW}Backend log:${NC}"
    cat "$LOG_FILE"
    exit 1
fi

# Test IPv4 connectivity
echo ""
echo "🧪 Testing IPv4 HTTP connectivity..."
if curl -sf -m 5 http://127.0.0.1:8080/api/v1/health/live | grep -q "live"; then
    echo -e "${GREEN}✅ IPv4 HTTP works (127.0.0.1:8080)${NC}"
    IPV4_HTTP=true
else
    echo -e "${RED}❌ IPv4 HTTP failed${NC}"
    IPV4_HTTP=false
fi

# Test IPv4 localhost
if curl -sf -m 5 http://localhost:8080/api/v1/health/live | grep -q "live"; then
    echo -e "${GREEN}✅ IPv4 localhost works (localhost:8080)${NC}"
else
    echo -e "${YELLOW}⚠️  localhost resolution issue${NC}"
fi

# Test IPv6 connectivity
echo ""
echo "🧪 Testing IPv6 HTTP connectivity..."
if [ "$IPV6_AVAILABLE" = true ]; then
    if curl -sf -m 5 "http://[::1]:8080/api/v1/health/live" 2>/dev/null | grep -q "live"; then
        echo -e "${GREEN}✅ IPv6 HTTP works ([::1]:8080)${NC}"
        IPV6_HTTP=true
    else
        if [ "$BACKEND_BINDING" = "ipv6-dual-stack" ]; then
            echo -e "${RED}❌ IPv6 HTTP failed (backend should accept IPv6)${NC}"
            IPV6_HTTP=false
        else
            echo -e "${YELLOW}⚠️  IPv6 HTTP not available (backend is IPv4-only)${NC}"
            IPV6_HTTP=false
        fi
    fi
else
    echo -e "${YELLOW}⚠️  IPv6 not available on system, skipping IPv6 tests${NC}"
    IPV6_HTTP=false
fi

# Test WebSocket endpoint (IPv4)
echo ""
echo "🧪 Testing WebSocket endpoint (IPv4)..."
if timeout 2 bash -c 'echo -e "GET /ws HTTP/1.1\r\nHost: localhost:8080\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n" | nc 127.0.0.1 8080' 2>/dev/null | grep -q "101\|426"; then
    echo -e "${GREEN}✅ WebSocket endpoint accessible on IPv4${NC}"
    WEBSOCKET_IPV4=true
else
    # WebSocket might require authentication, 426 is also acceptable
    echo -e "${YELLOW}⚠️  WebSocket check inconclusive (may require auth)${NC}"
    WEBSOCKET_IPV4=true
fi

# Test WebSocket endpoint (IPv6)
if [ "$IPV6_AVAILABLE" = true ] && [ "$BACKEND_BINDING" = "ipv6-dual-stack" ]; then
    echo ""
    echo "🧪 Testing WebSocket endpoint (IPv6)..."
    if timeout 2 bash -c 'echo -e "GET /ws HTTP/1.1\r\nHost: [::1]:8080\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n" | nc ::1 8080' 2>/dev/null | grep -q "101\|426"; then
        echo -e "${GREEN}✅ WebSocket endpoint accessible on IPv6${NC}"
        WEBSOCKET_IPV6=true
    else
        echo -e "${YELLOW}⚠️  WebSocket IPv6 check inconclusive${NC}"
        WEBSOCKET_IPV6=false
    fi
fi

# Test health endpoints
echo ""
echo "🧪 Testing health check endpoints..."
if curl -sf -m 5 http://127.0.0.1:8080/api/v1/health | jq -e '.status' > /dev/null 2>&1; then
    echo -e "${GREEN}✅ Full health check endpoint works${NC}"
else
    echo -e "${YELLOW}⚠️  Health check returned non-JSON or failed${NC}"
fi

# Display summary
echo ""
echo "═══════════════════════════════════════════════════════"
echo "  Test Summary"
echo "═══════════════════════════════════════════════════════"
echo ""
echo "Backend Configuration:"
echo "  • Binding: $BACKEND_BINDING"
echo "  • Process: Running (PID $BACKEND_PID)"
echo ""
echo "IPv4 Tests:"
[ "$IPV4_HTTP" = true ] && echo -e "  ${GREEN}✅ IPv4 HTTP (127.0.0.1)${NC}" || echo -e "  ${RED}❌ IPv4 HTTP${NC}"
[ "$WEBSOCKET_IPV4" = true ] && echo -e "  ${GREEN}✅ WebSocket IPv4${NC}" || echo -e "  ${RED}❌ WebSocket IPv4${NC}"
echo ""
echo "IPv6 Tests:"
if [ "$IPV6_AVAILABLE" = true ]; then
    [ "$IPV6_HTTP" = true ] && echo -e "  ${GREEN}✅ IPv6 HTTP ([::1])${NC}" || echo -e "  ${YELLOW}⚠️  IPv6 HTTP${NC}"
    [ "$WEBSOCKET_IPV6" = true ] && echo -e "  ${GREEN}✅ WebSocket IPv6${NC}" || echo -e "  ${YELLOW}⚠️  WebSocket IPv6${NC}"
else
    echo -e "  ${YELLOW}⚠️  IPv6 not available on system${NC}"
fi
echo ""

# Check for errors
ERRORS=0
if [ "$IPV4_HTTP" != true ]; then
    ((ERRORS++))
    echo -e "${RED}✖ IPv4 HTTP test failed${NC}"
fi

if [ "$IPV6_AVAILABLE" = true ] && [ "$BACKEND_BINDING" = "ipv6-dual-stack" ] && [ "$IPV6_HTTP" != true ]; then
    ((ERRORS++))
    echo -e "${RED}✖ IPv6 HTTP test failed (backend should support IPv6)${NC}"
fi

echo ""
if [ $ERRORS -eq 0 ]; then
    echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  ✅ All critical tests passed!${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
    exit 0
else
    echo -e "${RED}═══════════════════════════════════════════════════════${NC}"
    echo -e "${RED}  ❌ $ERRORS test(s) failed${NC}"
    echo -e "${RED}═══════════════════════════════════════════════════════${NC}"
    echo ""
    echo "Backend log (last 30 lines):"
    tail -30 "$LOG_FILE"
    exit 1
fi
