#!/bin/bash
# validate-docker-compose.sh - Docker Compose configuration validation script
# This script validates docker-compose files and environment configurations

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
COMPOSE_FILES=("docker-compose.yml" "docker-compose.coolify.yml")
ENV_FILES=(".env" ".env.example")

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

# Check if required tools are available
check_dependencies() {
    log_info "Checking required dependencies..."

    local missing_deps=()

    # Check for docker or podman
    if ! command -v docker &> /dev/null && ! command -v podman &> /dev/null; then
        missing_deps+=("docker or podman")
    fi

    # Check for docker compose or podman-compose
    if ! (command -v docker &> /dev/null && docker compose version &> /dev/null) && ! command -v podman-compose &> /dev/null; then
        missing_deps+=("docker compose or podman-compose")
    fi

    # Check for yq (YAML processor)
    if ! command -v yq &> /dev/null; then
        log_warning "yq not found - advanced YAML validation will be skipped"
    fi

    if [ ${#missing_deps[@]} -ne 0 ]; then
        log_error "Missing required dependencies: ${missing_deps[*]}"
        return 1
    fi

    log_success "All required dependencies found"
    return 0
}

# Validate docker-compose file syntax
validate_compose_syntax() {
    local compose_file="$1"
    local compose_path="$PROJECT_ROOT/$compose_file"

    log_info "Validating syntax of $compose_file..."

    if [ ! -f "$compose_path" ]; then
        log_error "$compose_file not found at $compose_path"
        return 1
    fi

    # Use docker compose or podman-compose to validate
    local compose_cmd=""
    if command -v docker &> /dev/null && docker compose version &> /dev/null; then
        compose_cmd="docker compose"
    elif command -v podman-compose &> /dev/null; then
        compose_cmd="podman-compose"
    else
        log_error "No compose command available"
        return 1
    fi

    # Test syntax by running config validation
    if cd "$PROJECT_ROOT" && $compose_cmd -f "$compose_file" config --quiet 2>/dev/null; then
        log_success "$compose_file syntax is valid"
        return 0
    else
        log_error "$compose_file has syntax errors"
        # Show detailed error
        cd "$PROJECT_ROOT" && $compose_cmd -f "$compose_file" config 2>&1 | head -20
        return 1
    fi
}

# Validate required environment variables in compose file
validate_env_vars() {
    local compose_file="$1"
    local compose_path="$PROJECT_ROOT/$compose_file"

    log_info "Validating environment variables in $compose_file..."

    # Extract environment variables from compose file
    local env_vars
    env_vars=$(grep -oP '\$\{[^}]+\}' "$compose_path" | sort | uniq | sed 's/[${:}]//g' | sed 's/:-.*$//')

    if [ -z "$env_vars" ]; then
        log_warning "No environment variables found in $compose_file"
        return 0
    fi

    log_info "Found environment variables:"
    echo "$env_vars" | while read -r var; do
        echo "  - $var"
    done

    # Check critical variables
    local critical_vars=("POSTGRES_PASSWORD" "REDIS_PASSWORD" "JWT_SECRET" "SERVER_ENCRYPTION_KEY" "DEFAULT_ADMIN_PASSWORD")
    local missing_critical=()

    for var in "${critical_vars[@]}"; do
        if ! echo "$env_vars" | grep -q "^$var$"; then
            missing_critical+=("$var")
        fi
    done

    if [ ${#missing_critical[@]} -ne 0 ]; then
        log_warning "Critical environment variables not referenced in $compose_file: ${missing_critical[*]}"
    else
        log_success "All critical environment variables are referenced"
    fi

    return 0
}

# Validate service dependencies
validate_service_dependencies() {
    local compose_file="$1"
    local compose_path="$PROJECT_ROOT/$compose_file"

    log_info "Validating service dependencies in $compose_file..."

    if command -v yq &> /dev/null; then
        # Use yq for advanced YAML processing
        local services
        services=$(yq eval '.services | keys | .[]' "$compose_path" 2>/dev/null)

        log_info "Services found: $(echo "$services" | tr '\n' ' ')"

        # Check if backend depends on postgres and redis
        local backend_depends
        backend_depends=$(yq eval '.services.backend.depends_on | keys | .[]' "$compose_path" 2>/dev/null || echo "")

        if echo "$backend_depends" | grep -q "postgres" && echo "$backend_depends" | grep -q "redis"; then
            log_success "Backend service has correct dependencies"
        else
            log_warning "Backend service may be missing dependencies on postgres/redis"
        fi

        # Check health checks
        local services_with_health
        services_with_health=$(yq eval '.services | to_entries | map(select(.value.healthcheck)) | .[].key' "$compose_path" 2>/dev/null || echo "")

        if [ -n "$services_with_health" ]; then
            log_success "Services with health checks: $(echo "$services_with_health" | tr '\n' ' ')"
        else
            log_warning "No health checks found in services"
        fi
    else
        log_info "yq not available - skipping advanced dependency validation"
    fi

    return 0
}

# Validate volume and network configurations
validate_infrastructure() {
    local compose_file="$1"
    local compose_path="$PROJECT_ROOT/$compose_file"

    log_info "Validating infrastructure configuration in $compose_file..."

    # Check for volumes section
    if grep -q "^volumes:" "$compose_path"; then
        log_success "Volumes section found"
    else
        log_warning "No volumes section found - data may not persist"
    fi

    # Check for networks section
    if grep -q "^networks:" "$compose_path"; then
        log_success "Networks section found"
    else
        log_warning "No networks section found - using default bridge network"
    fi

    # Check for exposed ports
    local exposed_ports
    exposed_ports=$(grep -oP '^\s*-\s*"\d+:\d+"' "$compose_path" | wc -l)

    if [ "$exposed_ports" -gt 0 ]; then
        log_info "Found $exposed_ports exposed port mappings"
    else
        log_warning "No port mappings found - services may not be accessible"
    fi

    return 0
}

# Test docker-compose with dry-run
test_compose_dry_run() {
    local compose_file="$1"

    log_info "Testing $compose_file with dry-run..."

    local compose_cmd=""
    if command -v docker &> /dev/null && docker compose version &> /dev/null; then
        compose_cmd="docker compose"
    elif command -v podman-compose &> /dev/null; then
        compose_cmd="podman-compose"
    else
        log_error "No compose command available"
        return 1
    fi

    # Test with fake environment to avoid requiring real .env
    cd "$PROJECT_ROOT"

    # Create temporary .env for testing
    local test_env_file=$(mktemp)
    cat > "$test_env_file" << 'EOF'
POSTGRES_PASSWORD=test_password_123
REDIS_PASSWORD=test_redis_password_123
JWT_SECRET=test_jwt_secret_key_that_is_64_characters_long_for_testing_only
SERVER_ENCRYPTION_KEY=test_32_character_encryption_key
DEFAULT_ADMIN_PASSWORD=TestAdmin123!
CORS_ORIGINS=http://localhost:3000
VITE_API_URL=http://localhost:8080
EOF

    # Test config generation
    if $compose_cmd -f "$compose_file" --env-file "$test_env_file" config > /dev/null 2>&1; then
        log_success "$compose_file configuration test passed"
        rm -f "$test_env_file"
        return 0
    else
        log_error "$compose_file configuration test failed"
        $compose_cmd -f "$compose_file" --env-file "$test_env_file" config 2>&1 | head -10
        rm -f "$test_env_file"
        return 1
    fi
}

# Main validation function
main() {
    log_info "Starting Docker Compose validation..."
    log_info "Project root: $PROJECT_ROOT"

    local exit_code=0

    # Check dependencies first
    if ! check_dependencies; then
        exit_code=1
    fi

    # Validate each compose file
    for compose_file in "${COMPOSE_FILES[@]}"; do
        echo
        log_info "=== Validating $compose_file ==="

        if [ -f "$PROJECT_ROOT/$compose_file" ]; then
            # Syntax validation
            if ! validate_compose_syntax "$compose_file"; then
                exit_code=1
                continue
            fi

            # Environment variable validation
            validate_env_vars "$compose_file"

            # Service dependency validation
            validate_service_dependencies "$compose_file"

            # Infrastructure validation
            validate_infrastructure "$compose_file"

            # Dry-run test
            if ! test_compose_dry_run "$compose_file"; then
                exit_code=1
            fi

            log_success "$compose_file validation completed"
        else
            log_warning "$compose_file not found - skipping"
        fi
    done

    echo
    if [ $exit_code -eq 0 ]; then
        log_success "All Docker Compose validations passed!"
    else
        log_error "Some validations failed. Please fix the issues above."
    fi

    return $exit_code
}

# Run main function if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi