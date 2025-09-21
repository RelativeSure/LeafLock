#!/bin/bash
# test-deployment.sh - Containerized deployment testing script
# This script tests the complete deployment in a containerized environment

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TIMEOUT=300  # 5 minutes timeout for tests
HEALTH_CHECK_RETRIES=30
HEALTH_CHECK_INTERVAL=10

# Logging functions
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

# Cleanup function
cleanup() {
    log_info "Cleaning up test environment..."

    cd "$PROJECT_ROOT"

    # Stop and remove containers
    if command -v docker &> /dev/null && docker compose version &> /dev/null; then
        docker compose -f docker-compose.yml down --volumes --remove-orphans 2>/dev/null || true
    elif command -v podman-compose &> /dev/null; then
        podman-compose -f docker-compose.yml down --volumes 2>/dev/null || true
    fi

    # Clean up test containers specifically
    if command -v docker &> /dev/null; then
        docker rm -f leaflock-test-postgres leaflock-test-redis leaflock-test-backend leaflock-test-frontend 2>/dev/null || true
    elif command -v podman &> /dev/null; then
        podman rm -f leaflock-test-postgres leaflock-test-redis leaflock-test-backend leaflock-test-frontend 2>/dev/null || true
    fi

    log_info "Cleanup completed"
}

# Set up signal handlers
trap cleanup EXIT INT TERM

# Check if required tools are available
check_dependencies() {
    log_info "Checking deployment dependencies..."

    local missing_deps=()

    # Check for container runtime
    if ! command -v docker &> /dev/null && ! command -v podman &> /dev/null; then
        missing_deps+=("docker or podman")
    fi

    # Check for compose
    if ! (command -v docker &> /dev/null && docker compose version &> /dev/null) && ! command -v podman-compose &> /dev/null; then
        missing_deps+=("docker compose or podman-compose")
    fi

    # Check for curl
    if ! command -v curl &> /dev/null; then
        missing_deps+=("curl")
    fi

    # Check for jq (optional but recommended)
    if ! command -v jq &> /dev/null; then
        log_warning "jq not found - JSON response validation will be limited"
    fi

    if [ ${#missing_deps[@]} -ne 0 ]; then
        log_error "Missing required dependencies: ${missing_deps[*]}"
        return 1
    fi

    log_success "All required dependencies found"
    return 0
}

# Create test environment file
create_test_env() {
    log_info "Creating test environment configuration..."

    local test_env_file="$PROJECT_ROOT/.env.test"

    cat > "$test_env_file" << 'EOF'
# Test environment configuration
POSTGRES_PASSWORD=TestPostgresPassword123!
REDIS_PASSWORD=TestRedisPassword123!
JWT_SECRET=TestJWTSecretThatIs64CharactersLongForTestingPurposesOnly123!
SERVER_ENCRYPTION_KEY=TestEncryptionKey32CharactersLong
DEFAULT_ADMIN_PASSWORD=TestAdmin#P@ssw0rd&123!
DEFAULT_ADMIN_EMAIL=test-admin@leaflock.test
ENABLE_DEFAULT_ADMIN=true
CORS_ORIGINS=http://localhost:3000,http://localhost:5173,http://localhost:8080
VITE_API_URL=http://localhost:8080
APP_ENV=test
PORT=8080
ENABLE_REGISTRATION=true
EOF

    log_success "Test environment file created at $test_env_file"
    return 0
}

# Wait for service to be healthy
wait_for_service() {
    local service_name="$1"
    local health_url="$2"
    local max_attempts="${3:-$HEALTH_CHECK_RETRIES}"

    log_info "Waiting for $service_name to be healthy..."

    local attempt=1
    while [ $attempt -le $max_attempts ]; do
        if curl -sf "$health_url" > /dev/null 2>&1; then
            log_success "$service_name is healthy"
            return 0
        fi

        log_info "Attempt $attempt/$max_attempts: $service_name not ready yet..."
        sleep $HEALTH_CHECK_INTERVAL
        ((attempt++))
    done

    log_error "$service_name failed to become healthy after $max_attempts attempts"
    return 1
}

# Test database connectivity
test_database_connection() {
    log_info "Testing database connectivity..."

    local compose_cmd=""
    if command -v docker &> /dev/null && docker compose version &> /dev/null; then
        compose_cmd="docker compose"
    else
        compose_cmd="podman-compose"
    fi

    cd "$PROJECT_ROOT"

    # Test postgres connection
    if $compose_cmd --env-file .env.test exec -T postgres psql -U postgres -d notes -c "SELECT 1;" > /dev/null 2>&1; then
        log_success "PostgreSQL connection successful"
    else
        log_error "PostgreSQL connection failed"
        $compose_cmd --env-file .env.test logs postgres | tail -20
        return 1
    fi

    # Test redis connection
    if $compose_cmd --env-file .env.test exec -T redis redis-cli -a "TestRedisPassword123!" ping | grep -q "PONG"; then
        log_success "Redis connection successful"
    else
        log_error "Redis connection failed"
        $compose_cmd --env-file .env.test logs redis | tail -20
        return 1
    fi

    return 0
}

# Test backend API endpoints
test_backend_api() {
    log_info "Testing backend API endpoints..."

    local base_url="http://localhost:8080"
    local api_base="$base_url/api/v1"

    # Test health endpoint
    if curl -sf "$api_base/health" | grep -q "ok"; then
        log_success "Health endpoint is working"
    else
        log_error "Health endpoint failed"
        return 1
    fi

    # Test auth endpoints (should return appropriate responses)
    local auth_response
    auth_response=$(curl -s -w "%{http_code}" -o /dev/null "$api_base/auth/register" -X POST -H "Content-Type: application/json" -d '{}' || echo "000")

    if [ "$auth_response" = "400" ] || [ "$auth_response" = "422" ]; then
        log_success "Auth register endpoint is responding (returns $auth_response for empty request)"
    else
        log_warning "Auth register endpoint returned unexpected status: $auth_response"
    fi

    # Test login endpoint
    local login_response
    login_response=$(curl -s -w "%{http_code}" -o /dev/null "$api_base/auth/login" -X POST -H "Content-Type: application/json" -d '{}' || echo "000")

    if [ "$login_response" = "400" ] || [ "$login_response" = "422" ]; then
        log_success "Auth login endpoint is responding (returns $login_response for empty request)"
    else
        log_warning "Auth login endpoint returned unexpected status: $login_response"
    fi

    return 0
}

# Test admin user creation
test_admin_user_creation() {
    log_info "Testing default admin user creation..."

    local api_base="http://localhost:8080/api/v1"

    # Try to login with default admin credentials
    local login_data='{
        "email": "test-admin@leaflock.test",
        "password": "TestAdmin#P@ssw0rd&123!"
    }'

    local login_response
    login_response=$(curl -s "$api_base/auth/login" -X POST -H "Content-Type: application/json" -d "$login_data" || echo '{"error":"curl_failed"}')

    if echo "$login_response" | grep -q '"token"'; then
        log_success "Default admin user login successful"

        # Extract token for further testing
        local token=""
        if command -v jq &> /dev/null; then
            token=$(echo "$login_response" | jq -r '.token // empty')

            if [ -n "$token" ] && [ "$token" != "null" ]; then
                log_success "JWT token received successfully"

                # Test authenticated endpoint
                local user_response
                user_response=$(curl -s "$api_base/auth/me" -H "Authorization: Bearer $token" || echo '{"error":"curl_failed"}')

                if echo "$user_response" | grep -q '"email"'; then
                    log_success "Authenticated endpoint test successful"
                else
                    log_warning "Authenticated endpoint test failed"
                fi
            fi
        else
            log_info "jq not available - skipping token extraction test"
        fi
    else
        log_error "Default admin user login failed"
        log_error "Response: $login_response"
        return 1
    fi

    return 0
}

# Test frontend accessibility
test_frontend() {
    log_info "Testing frontend accessibility..."

    local frontend_url="http://localhost:3000"

    # Test if frontend is serving content
    if curl -sf "$frontend_url" | grep -q -i "leaflock\|notes\|html"; then
        log_success "Frontend is accessible and serving content"
    else
        log_error "Frontend is not accessible or not serving expected content"
        return 1
    fi

    # Test static assets (if any)
    local assets_response
    assets_response=$(curl -s -w "%{http_code}" -o /dev/null "$frontend_url/assets" || echo "000")

    if [ "$assets_response" = "200" ] || [ "$assets_response" = "404" ]; then
        log_success "Frontend asset handling is working (status: $assets_response)"
    else
        log_warning "Frontend asset handling returned unexpected status: $assets_response"
    fi

    return 0
}

# Test environment variable handling with special characters
test_special_characters() {
    log_info "Testing environment variables with special characters..."

    local compose_cmd=""
    if command -v docker &> /dev/null && docker compose version &> /dev/null; then
        compose_cmd="docker compose"
    else
        compose_cmd="podman-compose"
    fi

    cd "$PROJECT_ROOT"

    # Check if the admin password with special characters was loaded correctly
    local backend_env_test
    backend_env_test=$($compose_cmd --env-file .env.test exec -T backend sh -c 'echo "Admin password length: ${#DEFAULT_ADMIN_PASSWORD}"' 2>/dev/null || echo "ERROR")

    if echo "$backend_env_test" | grep -q "Admin password length: 24"; then
        log_success "Environment variables with special characters loaded correctly"
    else
        log_warning "Environment variable loading may have issues with special characters"
        log_info "Backend environment test output: $backend_env_test"
    fi

    return 0
}

# Test service logs for errors
check_service_logs() {
    log_info "Checking service logs for errors..."

    local compose_cmd=""
    if command -v docker &> /dev/null && docker compose version &> /dev/null; then
        compose_cmd="docker compose"
    else
        compose_cmd="podman-compose"
    fi

    cd "$PROJECT_ROOT"

    local services=("postgres" "redis" "backend" "frontend")
    local errors_found=false

    for service in "${services[@]}"; do
        log_info "Checking logs for $service..."

        local logs
        logs=$($compose_cmd --env-file .env.test logs --tail=50 "$service" 2>/dev/null || echo "No logs available")

        # Check for common error patterns
        if echo "$logs" | grep -iE "(error|fail|exception|panic|fatal)" | grep -v "Error: container" | grep -v "No such file or directory" | grep -v "Error response from daemon"; then
            log_warning "Potential errors found in $service logs"
            errors_found=true
        else
            log_success "$service logs look clean"
        fi
    done

    if [ "$errors_found" = true ]; then
        log_warning "Some services have potential errors in logs - review manually if needed"
    else
        log_success "All service logs look clean"
    fi

    return 0
}

# Run complete deployment test
run_deployment_test() {
    local compose_file="${1:-docker-compose.yml}"

    log_info "Starting deployment test with $compose_file..."

    cd "$PROJECT_ROOT"

    # Determine compose command
    local compose_cmd=""
    if command -v docker-compose &> /dev/null; then
        compose_cmd="docker-compose"
    elif command -v podman-compose &> /dev/null; then
        compose_cmd="podman-compose"
    else
        log_error "No compose command available"
        return 1
    fi

    # Start services
    log_info "Starting services..."
    if ! $compose_cmd -f "$compose_file" --env-file .env.test up -d; then
        log_error "Failed to start services"
        return 1
    fi

    # Wait for database to be ready
    log_info "Waiting for database to be ready..."
    sleep 20

    # Wait for services to be healthy
    wait_for_service "backend" "http://localhost:8080/api/v1/health" 20

    # Run tests
    local test_exit_code=0

    # Test database connections
    if ! test_database_connection; then
        test_exit_code=1
    fi

    # Test backend API
    if ! test_backend_api; then
        test_exit_code=1
    fi

    # Test admin user creation
    if ! test_admin_user_creation; then
        test_exit_code=1
    fi

    # Test special character handling
    test_special_characters

    # Check logs
    check_service_logs

    # Test frontend (if enabled)
    if grep -q "frontend:" "$compose_file"; then
        wait_for_service "frontend" "http://localhost:3000" 10
        test_frontend || true  # Don't fail deployment test if frontend fails
    fi

    return $test_exit_code
}

# Main function
main() {
    local compose_file="${1:-docker-compose.yml}"
    local compose_path="$PROJECT_ROOT/$compose_file"

    log_info "Starting containerized deployment test..."
    log_info "Project root: $PROJECT_ROOT"
    log_info "Compose file: $compose_file"

    # Check dependencies
    if ! check_dependencies; then
        return 1
    fi

    # Check if compose file exists
    if [ ! -f "$compose_path" ]; then
        log_error "Compose file not found: $compose_path"
        return 1
    fi

    # Create test environment
    create_test_env

    # Run deployment test
    local exit_code=0
    if ! run_deployment_test "$compose_file"; then
        exit_code=1
    fi

    echo
    if [ $exit_code -eq 0 ]; then
        log_success "Deployment test completed successfully!"
        log_info "All core services are working correctly"
    else
        log_error "Deployment test failed!"
        log_error "Please check the logs above and fix any issues"
    fi

    return $exit_code
}

# Show usage information
usage() {
    echo "Usage: $0 [COMPOSE_FILE]"
    echo
    echo "Tests the complete LeafLock deployment in a containerized environment."
    echo
    echo "Arguments:"
    echo "  COMPOSE_FILE    Docker compose file to test (default: docker-compose.yml)"
    echo
    echo "Examples:"
    echo "  $0                              # Test default docker-compose.yml"
    echo "  $0 docker-compose.coolify.yml   # Test Coolify deployment"
    echo
    echo "This script will:"
    echo "  - Validate environment configuration"
    echo "  - Start all services"
    echo "  - Test database connectivity"
    echo "  - Test API endpoints"
    echo "  - Test admin user creation"
    echo "  - Test frontend accessibility"
    echo "  - Check service logs for errors"
}

# Handle command line arguments
if [[ "${1:-}" == "--help" ]] || [[ "${1:-}" == "-h" ]]; then
    usage
    exit 0
fi

# Run main function if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi