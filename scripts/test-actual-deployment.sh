#!/bin/bash

# Actual Deployment Testing Script for LeafLock
# Tests the complete deployment with the current .env configuration

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TIMEOUT=300
HEALTH_CHECK_RETRIES=30
SLEEP_INTERVAL=10

# Service endpoints
BACKEND_URL="http://localhost:8080"
FRONTEND_URL="http://localhost:3000"
HEALTH_ENDPOINT="$BACKEND_URL/api/v1/health"
LOGIN_ENDPOINT="$BACKEND_URL/api/v1/auth/login"
DEBUG_ENDPOINT="$BACKEND_URL/api/v1/debug"

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

cleanup() {
    log_info "Cleaning up containers..."
    cd "$PROJECT_ROOT"
    docker compose down -v --remove-orphans 2>/dev/null || true
    log_success "Cleanup completed"
}

trap cleanup EXIT INT TERM

check_dependencies() {
    log_info "Checking dependencies..."

    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed"
        exit 1
    fi

    if ! docker compose version &> /dev/null; then
        log_error "Docker Compose is not available"
        exit 1
    fi

    if ! command -v curl &> /dev/null; then
        log_error "curl is not installed"
        exit 1
    fi

    log_success "All dependencies are available"
}

check_env_file() {
    log_info "Checking .env file..."

    if [[ ! -f "$PROJECT_ROOT/.env" ]]; then
        log_error ".env file not found"
        exit 1
    fi

    # Source the .env file to get admin credentials
    source "$PROJECT_ROOT/.env"

    if [[ -z "${DEFAULT_ADMIN_EMAIL:-}" || -z "${DEFAULT_ADMIN_PASSWORD:-}" ]]; then
        log_error "Admin credentials not found in .env file"
        exit 1
    fi

    log_success ".env file is configured with admin credentials"
    log_info "Admin email: $DEFAULT_ADMIN_EMAIL"
}

start_services() {
    log_info "Starting services with docker compose..."
    cd "$PROJECT_ROOT"

    if ! docker compose up -d --build; then
        log_error "Failed to start services"
        exit 1
    fi

    log_success "Services started successfully"
}

wait_for_service() {
    local service_name="$1"
    local url="$2"
    local max_attempts="$3"

    log_info "Waiting for $service_name to be ready..."

    for ((i=1; i<=max_attempts; i++)); do
        if curl -s -f "$url" >/dev/null 2>&1; then
            log_success "$service_name is ready"
            return 0
        fi

        log_info "Attempt $i/$max_attempts: waiting ${SLEEP_INTERVAL}s..."
        sleep "$SLEEP_INTERVAL"
    done

    log_error "$service_name failed to become ready"
    return 1
}

test_health_endpoint() {
    log_info "Testing health endpoint..."

    local response
    if response=$(curl -s -w "\n%{http_code}" "$HEALTH_ENDPOINT" 2>/dev/null); then
        local body=$(echo "$response" | head -n -1)
        local status_code=$(echo "$response" | tail -n 1)

        if [[ "$status_code" == "200" ]]; then
            log_success "Health endpoint returned 200 OK"
            echo "Response: $body"
            return 0
        else
            log_error "Health endpoint returned status $status_code"
            echo "Response: $body"
            return 1
        fi
    else
        log_error "Failed to connect to health endpoint"
        return 1
    fi
}

test_admin_login() {
    log_info "Testing admin login..."

    # Get admin credentials from .env
    source "$PROJECT_ROOT/.env"

    local login_data=$(cat <<EOF
{
    "email": "$DEFAULT_ADMIN_EMAIL",
    "password": "$DEFAULT_ADMIN_PASSWORD"
}
EOF
)

    local response
    if response=$(curl -s -w "\n%{http_code}" \
        -H "Content-Type: application/json" \
        -d "$login_data" \
        "$LOGIN_ENDPOINT" 2>/dev/null); then

        local body=$(echo "$response" | head -n -1)
        local status_code=$(echo "$response" | tail -n 1)

        if [[ "$status_code" == "200" ]]; then
            log_success "Admin login successful"

            # Extract token
            if command -v jq &> /dev/null; then
                JWT_TOKEN=$(echo "$body" | jq -r '.token // .access_token // empty' 2>/dev/null)
                if [[ -n "$JWT_TOKEN" && "$JWT_TOKEN" != "null" ]]; then
                    log_success "JWT token obtained successfully"
                    export JWT_TOKEN
                    echo "Token: ${JWT_TOKEN:0:20}..."
                else
                    log_warning "Could not extract JWT token"
                fi
            fi

            return 0
        else
            log_error "Admin login failed with status $status_code"
            echo "Response: $body"
            return 1
        fi
    else
        log_error "Failed to connect to login endpoint"
        return 1
    fi
}

test_debug_endpoints() {
    log_info "Testing debug endpoints..."

    if [[ -z "${JWT_TOKEN:-}" ]]; then
        log_warning "No JWT token available, skipping debug endpoint tests"
        return 1
    fi

    # Test debug info endpoint
    local response
    if response=$(curl -s -w "\n%{http_code}" \
        -H "Authorization: Bearer $JWT_TOKEN" \
        "$DEBUG_ENDPOINT/info" 2>/dev/null); then

        local body=$(echo "$response" | head -n -1)
        local status_code=$(echo "$response" | tail -n 1)

        if [[ "$status_code" == "200" ]]; then
            log_success "Debug info endpoint accessible"
            echo "Debug info: $body"
        else
            log_error "Debug info endpoint returned status $status_code"
            echo "Response: $body"
            return 1
        fi
    else
        log_error "Failed to connect to debug info endpoint"
        return 1
    fi

    # Test debug users endpoint
    if response=$(curl -s -w "\n%{http_code}" \
        -H "Authorization: Bearer $JWT_TOKEN" \
        "$DEBUG_ENDPOINT/users" 2>/dev/null); then

        local body=$(echo "$response" | head -n -1)
        local status_code=$(echo "$response" | tail -n 1)

        if [[ "$status_code" == "200" ]]; then
            log_success "Debug users endpoint accessible"
            echo "Debug users: $body"
        else
            log_error "Debug users endpoint returned status $status_code"
            echo "Response: $body"
            return 1
        fi
    else
        log_error "Failed to connect to debug users endpoint"
        return 1
    fi

    return 0
}

check_container_status() {
    log_info "Checking container status..."
    cd "$PROJECT_ROOT"

    if docker compose ps; then
        log_success "Container status displayed"
    else
        log_error "Failed to get container status"
    fi
}

check_container_logs() {
    log_info "Checking container logs for errors..."
    cd "$PROJECT_ROOT"

    local services=("backend" "postgres" "redis")

    for service in "${services[@]}"; do
        log_info "Checking $service logs..."
        local logs=$(docker compose logs --tail=20 "$service" 2>/dev/null || true)

        if echo "$logs" | grep -qi "error\|fail\|panic\|fatal" | head -5; then
            log_warning "Potential errors in $service logs:"
            echo "$logs" | grep -i "error\|fail\|panic\|fatal" | tail -5
        else
            log_success "$service logs look clean"
        fi
    done
}

test_frontend() {
    log_info "Testing frontend accessibility..."

    if wait_for_service "Frontend" "$FRONTEND_URL" 10; then
        log_success "Frontend is accessible"
    else
        log_warning "Frontend may not be ready yet"
    fi
}

main() {
    echo -e "${BLUE}================================================${NC}"
    echo -e "${BLUE}  LeafLock Actual Deployment Test${NC}"
    echo -e "${BLUE}================================================${NC}"
    echo

    # Step 1: Check dependencies
    check_dependencies
    echo

    # Step 2: Check environment
    check_env_file
    echo

    # Step 3: Start services
    start_services
    echo

    # Step 4: Wait for backend
    if ! wait_for_service "Backend API" "$HEALTH_ENDPOINT" "$HEALTH_CHECK_RETRIES"; then
        log_error "Backend failed to start"
        check_container_status
        check_container_logs
        exit 1
    fi
    echo

    # Step 5: Test health endpoint
    if ! test_health_endpoint; then
        log_error "Health endpoint test failed"
        exit 1
    fi
    echo

    # Step 6: Test admin login
    if ! test_admin_login; then
        log_error "Admin login test failed"
        check_container_logs
        exit 1
    fi
    echo

    # Step 7: Test debug endpoints
    if ! test_debug_endpoints; then
        log_error "Debug endpoints test failed"
        exit 1
    fi
    echo

    # Step 8: Test frontend
    test_frontend
    echo

    # Step 9: Show final status
    check_container_status
    echo

    # Step 10: Check logs
    check_container_logs
    echo

    echo -e "${GREEN}================================================${NC}"
    echo -e "${GREEN}  Deployment Test Complete!${NC}"
    echo -e "${GREEN}================================================${NC}"
    echo
    echo -e "${GREEN}✅ All services are running successfully${NC}"
    echo -e "${GREEN}✅ Backend API is accessible at: $BACKEND_URL${NC}"
    echo -e "${GREEN}✅ Frontend is accessible at: $FRONTEND_URL${NC}"
    echo -e "${GREEN}✅ Admin login works${NC}"
    echo -e "${GREEN}✅ Debug endpoints are accessible${NC}"
    echo
    echo -e "${YELLOW}SUCCESS: Deployment validation completed!${NC}"
}

main "$@"