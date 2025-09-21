#!/bin/bash
# validate-coolify.sh - Coolify deployment validation script
# This script validates Coolify-specific deployment configurations

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
COOLIFY_COMPOSE="docker-compose.coolify.yml"
COOLIFY_ENV=".env.coolify"

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

# Required Coolify environment variables
COOLIFY_REQUIRED_VARS=(
    "POSTGRES_PASSWORD"
    "REDIS_PASSWORD"
    "JWT_SECRET"
    "SERVER_ENCRYPTION_KEY"
    "DEFAULT_ADMIN_PASSWORD"
    "DEFAULT_ADMIN_EMAIL"
    "VITE_API_URL"
)

# Optional but recommended for production
COOLIFY_RECOMMENDED_VARS=(
    "CORS_ORIGINS"
    "APP_ENV"
    "ENABLE_DEFAULT_ADMIN"
    "ENABLE_REGISTRATION"
)

# Check Coolify-specific requirements
validate_coolify_compose_structure() {
    local compose_path="$PROJECT_ROOT/$COOLIFY_COMPOSE"

    log_info "Validating Coolify compose structure..."

    if [ ! -f "$compose_path" ]; then
        log_error "Coolify compose file not found: $compose_path"
        return 1
    fi

    # Check for Coolify-specific features
    local validations_passed=0
    local total_validations=10

    # 1. Check for required parameter substitution
    if grep -q '\${.*:?.*}' "$compose_path"; then
        log_success "Required parameter substitution found"
        ((validations_passed++))
    else
        log_warning "No required parameter substitution found - variables won't fail if missing"
    fi

    # 2. Check for no external port exposure on backend
    if ! grep -A 10 "backend:" "$compose_path" | grep -q "ports:"; then
        log_success "Backend has no external port exposure (good for Coolify)"
        ((validations_passed++))
    else
        log_warning "Backend exposes ports - Coolify will handle this"
    fi

    # 3. Check for internal service communication
    if grep -q "postgres:5432\|redis:6379\|backend:8080" "$compose_path"; then
        log_success "Internal service communication configured"
        ((validations_passed++))
    else
        log_error "Missing internal service references"
    fi

    # 4. Check for proper health checks
    local services_with_healthcheck
    services_with_healthcheck=$(grep -c "healthcheck:" "$compose_path" || echo "0")
    if [ "$services_with_healthcheck" -ge 2 ]; then
        log_success "Multiple services have health checks ($services_with_healthcheck)"
        ((validations_passed++))
    else
        log_warning "Few services have health checks ($services_with_healthcheck)"
    fi

    # 5. Check for Coolify labels
    if grep -q "coolify\." "$compose_path"; then
        log_success "Coolify labels found"
        ((validations_passed++))
    else
        log_warning "No Coolify labels found - add them for better Coolify integration"
    fi

    # 6. Check for proper volume configuration
    if grep -q "postgres_data:\|redis_data:" "$compose_path"; then
        log_success "Data persistence volumes configured"
        ((validations_passed++))
    else
        log_error "Missing data persistence volumes"
    fi

    # 7. Check for network configuration
    if grep -q "networks:" "$compose_path"; then
        log_success "Custom network configuration found"
        ((validations_passed++))
    else
        log_warning "No custom network - using default"
    fi

    # 8. Check for security configurations
    if grep -q "sslmode=prefer\|sslmode=require" "$compose_path"; then
        log_success "SSL configuration found for database"
        ((validations_passed++))
    else
        log_warning "Database SSL configuration not found"
    fi

    # 9. Check for proper restart policies
    local restart_policies
    restart_policies=$(grep -c "restart:" "$compose_path" || echo "0")
    if [ "$restart_policies" -ge 3 ]; then
        log_success "Restart policies configured for services ($restart_policies)"
        ((validations_passed++))
    else
        log_warning "Missing restart policies for some services"
    fi

    # 10. Check for production-ready configurations
    if grep -q "APP_ENV.*production" "$compose_path"; then
        log_success "Production environment configuration found"
        ((validations_passed++))
    else
        log_info "Environment not set to production (may be intentional)"
        ((validations_passed++))
    fi

    log_info "Coolify structure validation: $validations_passed/$total_validations checks passed"

    if [ $validations_passed -ge 8 ]; then
        log_success "Coolify compose structure is well configured"
        return 0
    else
        log_warning "Coolify compose structure needs improvements"
        return 1
    fi
}

# Validate environment variable requirements for Coolify
validate_coolify_env_requirements() {
    log_info "Validating Coolify environment variable requirements..."

    # Check if .env.coolify exists
    local coolify_env_path="$PROJECT_ROOT/$COOLIFY_ENV"

    if [ -f "$coolify_env_path" ]; then
        log_success "Coolify environment file found: $COOLIFY_ENV"

        # Parse the environment file
        local env_vars=()
        while IFS= read -r line; do
            # Skip comments and empty lines
            [[ "$line" =~ ^[[:space:]]*# ]] && continue
            [[ "$line" =~ ^[[:space:]]*$ ]] && continue

            # Parse variable=value
            if [[ "$line" =~ ^[[:space:]]*([^=]+)=(.*)$ ]]; then
                local var_name="${BASH_REMATCH[1]}"
                env_vars+=("$var_name")
            fi
        done < "$coolify_env_path"

        # Check required variables
        local missing_required=()
        for required_var in "${COOLIFY_REQUIRED_VARS[@]}"; do
            local found=false
            for var in "${env_vars[@]}"; do
                if [ "$var" = "$required_var" ]; then
                    found=true
                    break
                fi
            done
            if [ "$found" = false ]; then
                missing_required+=("$required_var")
            fi
        done

        if [ ${#missing_required[@]} -eq 0 ]; then
            log_success "All required environment variables are present in $COOLIFY_ENV"
        else
            log_error "Missing required variables in $COOLIFY_ENV: ${missing_required[*]}"
            return 1
        fi

        # Check recommended variables
        local missing_recommended=()
        for recommended_var in "${COOLIFY_RECOMMENDED_VARS[@]}"; do
            local found=false
            for var in "${env_vars[@]}"; do
                if [ "$var" = "$recommended_var" ]; then
                    found=true
                    break
                fi
            done
            if [ "$found" = false ]; then
                missing_recommended+=("$recommended_var")
            fi
        done

        if [ ${#missing_recommended[@]} -eq 0 ]; then
            log_success "All recommended environment variables are present"
        else
            log_info "Missing recommended variables: ${missing_recommended[*]}"
        fi

    else
        log_warning "Coolify environment file not found: $coolify_env_path"
        log_info "You will need to set environment variables in Coolify UI"
        return 1
    fi

    return 0
}

# Check Coolify v4+ compatibility
validate_coolify_v4_compatibility() {
    local compose_path="$PROJECT_ROOT/$COOLIFY_COMPOSE"

    log_info "Validating Coolify v4+ compatibility..."

    local compatibility_score=0
    local max_score=8

    # 1. Check compose version
    if grep -q "version: '3\.[0-9]'" "$compose_path"; then
        log_success "Compatible Docker Compose version found"
        ((compatibility_score++))
    else
        log_warning "Docker Compose version not specified or incompatible"
    fi

    # 2. Check for proper service naming (no underscores)
    if ! grep -oP 'services:\s*\n\s*\K[^:]+' "$compose_path" | grep -q '_'; then
        log_success "Service names are Coolify-compatible (no underscores)"
        ((compatibility_score++))
    else
        log_warning "Service names contain underscores - may cause issues in Coolify"
    fi

    # 3. Check for internal network usage
    if grep -q "networks:" "$compose_path" && ! grep -q "external: true" "$compose_path"; then
        log_success "Using internal networks (recommended for Coolify)"
        ((compatibility_score++))
    else
        log_info "Network configuration may need adjustment for Coolify"
    fi

    # 4. Check for proper health check format
    if grep -A 5 "healthcheck:" "$compose_path" | grep -q "test:" && grep -A 5 "healthcheck:" "$compose_path" | grep -q "interval:"; then
        log_success "Health checks are properly configured for Coolify"
        ((compatibility_score++))
    else
        log_warning "Health check format may not be optimal for Coolify"
    fi

    # 5. Check for environment variable security
    if grep -q '\${.*:?.*Please set.*}' "$compose_path"; then
        log_success "Environment variables have security validation"
        ((compatibility_score++))
    else
        log_warning "Environment variables lack error messages for missing values"
    fi

    # 6. Check for volume persistence
    if grep -q "driver: local" "$compose_path"; then
        log_success "Local volume drivers specified (good for Coolify)"
        ((compatibility_score++))
    else
        log_info "Volume drivers not specified (Coolify will use defaults)"
        ((compatibility_score++))
    fi

    # 7. Check for no host network binding
    if ! grep -q "network_mode: host" "$compose_path"; then
        log_success "No host network binding (good for Coolify)"
        ((compatibility_score++))
    else
        log_error "Host network binding found - incompatible with Coolify"
    fi

    # 8. Check for resource limits (optional but recommended)
    if grep -q "deploy:" "$compose_path" || grep -q "mem_limit:\|cpus:" "$compose_path"; then
        log_success "Resource limits configured"
        ((compatibility_score++))
    else
        log_info "No resource limits specified (Coolify will manage resources)"
        ((compatibility_score++))
    fi

    log_info "Coolify v4+ compatibility: $compatibility_score/$max_score"

    if [ $compatibility_score -ge 6 ]; then
        log_success "Configuration is compatible with Coolify v4+"
        return 0
    else
        log_warning "Configuration may have compatibility issues with Coolify v4+"
        return 1
    fi
}

# Test environment variable parsing with Coolify format
test_coolify_env_parsing() {
    log_info "Testing Coolify environment variable parsing..."

    local compose_path="$PROJECT_ROOT/$COOLIFY_COMPOSE"

    # Create test environment variables
    local test_env_file=$(mktemp)
    cat > "$test_env_file" << 'EOF'
POSTGRES_PASSWORD=CoolifyTestPassword123!
REDIS_PASSWORD=CoolifyTestRedis123!
JWT_SECRET=CoolifyTestJWTSecretThatIs64CharactersLongForTestingOnly123!
SERVER_ENCRYPTION_KEY=CoolifyTest32CharEncryptionKey
DEFAULT_ADMIN_PASSWORD=CoolifyAdmin#P@ss&123!
DEFAULT_ADMIN_EMAIL=admin@coolify.test
VITE_API_URL=https://leaflock.example.com/api/v1
CORS_ORIGINS=https://leaflock.example.com
APP_ENV=production
EOF

    # Test compose config generation
    local compose_cmd=""
    if command -v docker &> /dev/null && docker compose version &> /dev/null; then
        compose_cmd="docker compose"
    elif command -v podman-compose &> /dev/null; then
        compose_cmd="podman-compose"
    else
        log_warning "No compose command available - skipping env parsing test"
        rm -f "$test_env_file"
        return 0
    fi

    cd "$PROJECT_ROOT"

    if $compose_cmd -f "$COOLIFY_COMPOSE" --env-file "$test_env_file" config > /dev/null 2>&1; then
        log_success "Environment variable parsing successful"

        # Test specific variable substitution
        local config_output
        config_output=$($compose_cmd -f "$COOLIFY_COMPOSE" --env-file "$test_env_file" config 2>/dev/null)

        # Check if sensitive values are properly substituted
        if echo "$config_output" | grep -q "CoolifyTestPassword123!" && echo "$config_output" | grep -q "admin@coolify.test"; then
            log_success "Environment variables are correctly substituted"
        else
            log_warning "Environment variable substitution may have issues"
        fi

        # Check for required variable validation
        if echo "$config_output" | grep -q "Please set.*in Coolify"; then
            log_warning "Some variables still show error messages (expected if not all vars set)"
        fi

    else
        log_error "Environment variable parsing failed"
        $compose_cmd -f "$COOLIFY_COMPOSE" --env-file "$test_env_file" config 2>&1 | head -10
        rm -f "$test_env_file"
        return 1
    fi

    rm -f "$test_env_file"
    return 0
}

# Generate Coolify deployment checklist
generate_coolify_checklist() {
    log_info "Generating Coolify deployment checklist..."

    cat << 'EOF'

=== COOLIFY DEPLOYMENT CHECKLIST ===

BEFORE DEPLOYMENT:
□ Set all required environment variables in Coolify UI:
  □ POSTGRES_PASSWORD (32+ characters, strong password)
  □ REDIS_PASSWORD (32+ characters, strong password)
  □ JWT_SECRET (64+ characters, random string)
  □ SERVER_ENCRYPTION_KEY (32 characters, random string)
  □ DEFAULT_ADMIN_PASSWORD (strong password with special chars)
  □ DEFAULT_ADMIN_EMAIL (valid email address)
  □ VITE_API_URL (your actual domain: https://yourdomain.com/api/v1)

□ Set optional environment variables:
  □ CORS_ORIGINS (your actual domain: https://yourdomain.com)
  □ APP_ENV=production
  □ ENABLE_DEFAULT_ADMIN=true (for first deployment)
  □ ENABLE_REGISTRATION=true/false (as needed)

□ Configure domain and SSL in Coolify:
  □ Set custom domain for frontend service
  □ Enable SSL certificate generation
  □ Configure proper routing

DEPLOYMENT PROCESS:
□ Import the project to Coolify
□ Select docker-compose.coolify.yml as compose file
□ Set all environment variables in Coolify UI (NOT in .env file)
□ Configure domain settings for frontend service
□ Deploy the application
□ Monitor deployment logs for errors

POST-DEPLOYMENT VERIFICATION:
□ Check all services are running
□ Verify health checks are passing
□ Test frontend accessibility at your domain
□ Test backend API at yourdomain.com/api/v1/health
□ Test admin login with default credentials
□ Change default admin password immediately
□ Verify database persistence across restarts
□ Test user registration (if enabled)
□ Check service logs for any errors

SECURITY CHECKLIST:
□ All passwords are strong and unique
□ JWT_SECRET is properly randomized
□ SERVER_ENCRYPTION_KEY is properly randomized
□ Default admin password is changed after first login
□ CORS_ORIGINS is restricted to your domain only
□ SSL is properly configured and working
□ Database connections use SSL (sslmode=prefer)

COOLIFY-SPECIFIC NOTES:
- Do NOT use .env files with Coolify - set variables in UI
- Coolify will handle port mapping automatically
- Use internal service names for communication (postgres:5432, redis:6379)
- Monitor resource usage in Coolify dashboard
- Use Coolify's backup features for data persistence

EOF
}

# Validate domain configuration for Coolify
validate_domain_config() {
    local compose_path="$PROJECT_ROOT/$COOLIFY_COMPOSE"

    log_info "Validating domain configuration for Coolify..."

    # Check for localhost references that should be changed
    if grep -q "localhost" "$compose_path"; then
        log_warning "localhost references found - these should be updated for production:"
        grep -n "localhost" "$compose_path" || true
    else
        log_success "No localhost references found"
    fi

    # Check for proper API URL configuration
    if grep -q "VITE_API_URL.*https://" "$compose_path"; then
        log_success "HTTPS API URL configured"
    else
        log_warning "VITE_API_URL should use HTTPS for production deployment"
    fi

    # Check for SSL configuration
    if grep -q "sslmode=prefer\|sslmode=require" "$compose_path"; then
        log_success "Database SSL configuration found"
    else
        log_warning "Database SSL should be enabled for production"
    fi

    return 0
}

# Main validation function
main() {
    log_info "Starting Coolify deployment validation..."
    log_info "Project root: $PROJECT_ROOT"

    local exit_code=0

    # Check if Coolify compose file exists
    if [ ! -f "$PROJECT_ROOT/$COOLIFY_COMPOSE" ]; then
        log_error "Coolify compose file not found: $PROJECT_ROOT/$COOLIFY_COMPOSE"
        return 1
    fi

    echo
    log_info "=== Coolify Compose Structure ==="
    if ! validate_coolify_compose_structure; then
        exit_code=1
    fi

    echo
    log_info "=== Coolify Environment Variables ==="
    validate_coolify_env_requirements || true  # Don't fail if .env.coolify doesn't exist

    echo
    log_info "=== Coolify v4+ Compatibility ==="
    if ! validate_coolify_v4_compatibility; then
        exit_code=1
    fi

    echo
    log_info "=== Environment Variable Parsing ==="
    if ! test_coolify_env_parsing; then
        exit_code=1
    fi

    echo
    log_info "=== Domain Configuration ==="
    validate_domain_config

    echo
    log_info "=== Deployment Checklist ==="
    generate_coolify_checklist

    echo
    if [ $exit_code -eq 0 ]; then
        log_success "Coolify validation completed successfully!"
        log_info "Your configuration is ready for Coolify deployment"
    else
        log_error "Coolify validation found issues that need to be addressed"
    fi

    return $exit_code
}

# Show usage information
usage() {
    echo "Usage: $0"
    echo
    echo "Validates LeafLock configuration for Coolify deployment."
    echo
    echo "This script validates:"
    echo "  - Coolify compose file structure"
    echo "  - Environment variable requirements"
    echo "  - Coolify v4+ compatibility"
    echo "  - Domain and SSL configuration"
    echo "  - Deployment best practices"
    echo
    echo "Files validated:"
    echo "  - docker-compose.coolify.yml"
    echo "  - .env.coolify (if present)"
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