#!/bin/bash
# Quick network verification for LeafLock developers
# Shows current network configuration and port usage

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo "═══════════════════════════════════════════════════════"
echo "  LeafLock Network Configuration"
echo "═══════════════════════════════════════════════════════"
echo ""

# Check IPv6 availability
echo -e "${BLUE}📡 System IPv6 Status:${NC}"
if ip -6 addr show 2>/dev/null | grep -q "inet6" || ifconfig 2>/dev/null | grep -q "inet6"; then
    echo -e "  ${GREEN}✅ IPv6 enabled${NC}"
    echo ""
    echo "  IPv6 Addresses:"
    if command -v ip &> /dev/null; then
        ip -6 addr show | grep "inet6" | grep -v "fe80" | awk '{print "    • " $2}' | head -5
    else
        ifconfig | grep "inet6" | grep -v "fe80" | awk '{print "    • " $2}' | head -5
    fi
else
    echo -e "  ${YELLOW}⚠️  IPv6 not available${NC}"
fi

echo ""
echo -e "${BLUE}🔌 Port Usage (LeafLock services):${NC}"
if command -v netstat &> /dev/null; then
    netstat -tuln 2>/dev/null | grep -E ":8080|:3000|:5432|:6379" | while read line; do
        echo "  $line"
    done
elif command -v ss &> /dev/null; then
    ss -tuln 2>/dev/null | grep -E ":8080|:3000|:5432|:6379" | while read line; do
        echo "  $line"
    done
else
    echo "  ⚠️  netstat/ss not available"
fi

# Check if ports are listening
echo ""
echo -e "${BLUE}📊 Service Status:${NC}"

check_port() {
    local port=$1
    local name=$2
    if nc -z 127.0.0.1 "$port" 2>/dev/null || timeout 1 bash -c "echo > /dev/tcp/127.0.0.1/$port" 2>/dev/null; then
        echo -e "  ${GREEN}✅ $name (port $port) - Listening${NC}"
        return 0
    else
        echo -e "  ${YELLOW}⚠️  $name (port $port) - Not listening${NC}"
        return 1
    fi
}

check_port 8080 "Backend"
check_port 3000 "Frontend"
check_port 5432 "PostgreSQL"
check_port 6379 "Redis"

# Docker network info
echo ""
echo -e "${BLUE}🐳 Docker Network (if running):${NC}"
if command -v docker &> /dev/null && docker ps > /dev/null 2>&1; then
    if docker network inspect leaflock_default > /dev/null 2>&1; then
        echo "  Network exists: leaflock_default"
        if command -v jq &> /dev/null; then
            docker network inspect leaflock_default | jq -r '.[0].IPAM.Config[] | "  Subnet: \(.Subnet // "N/A")"'
        else
            docker network inspect leaflock_default | grep -A 5 "Config" | grep "Subnet" | awk '{print "  Subnet: " $2}'
        fi
    else
        echo "  ⚠️  leaflock_default network doesn't exist"
    fi

    # Show running containers
    echo ""
    echo "  Running containers:"
    docker ps --filter "name=leaflock" --format "    • {{.Names}} ({{.Status}})" 2>/dev/null || echo "    None"
else
    echo "  ⚠️  Docker not running or not available"
fi

# Environment variables check
echo ""
echo -e "${BLUE}🔧 Environment Configuration:${NC}"
if [ -f ".env" ]; then
    echo "  ✅ .env file exists"

    if grep -q "VITE_API_URL" .env 2>/dev/null; then
        echo "  Frontend API URL: $(grep VITE_API_URL .env | head -1 | cut -d'=' -f2)"
    fi

    if grep -q "VITE_WS_URL" .env 2>/dev/null; then
        echo "  Frontend WS URL: $(grep VITE_WS_URL .env | head -1 | cut -d'=' -f2)"
    fi

    if grep -q "CORS_ORIGINS" .env 2>/dev/null; then
        echo "  CORS Origins: $(grep CORS_ORIGINS .env | head -1 | cut -d'=' -f2)"
    fi
else
    echo "  ⚠️  .env file not found (using defaults)"
fi

# Backend connectivity test
echo ""
echo -e "${BLUE}🧪 Quick Connectivity Test:${NC}"
if curl -sf -m 2 http://127.0.0.1:8080/api/v1/health/live > /dev/null 2>&1; then
    echo -e "  ${GREEN}✅ Backend reachable on IPv4 (127.0.0.1:8080)${NC}"
else
    echo -e "  ${YELLOW}⚠️  Backend not reachable on IPv4${NC}"
fi

if curl -sf -m 2 "http://[::1]:8080/api/v1/health/live" > /dev/null 2>&1; then
    echo -e "  ${GREEN}✅ Backend reachable on IPv6 ([::1]:8080)${NC}"
else
    echo -e "  ${YELLOW}⚠️  Backend not reachable on IPv6 (may not be available)${NC}"
fi

echo ""
echo "═══════════════════════════════════════════════════════"
echo ""
echo "💡 Tips:"
echo "  • Run './scripts/test-ipv6.sh' for comprehensive IPv6 testing"
echo "  • Check CLAUDE.md for IPv6 configuration examples"
echo "  • Use 'docker compose logs backend' to see backend logs"
echo ""
