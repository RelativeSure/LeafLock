#!/bin/bash
# validate-env.sh - Environment variable validation script
# This script validates .env files and environment variable configurations

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

# Critical environment variables that must be set
CRITICAL_VARS=(
    "POSTGRES_PASSWORD"
    "REDIS_PASSWORD"
    "JWT_SECRET"
    "SERVER_ENCRYPTION_KEY"
    "DEFAULT_ADMIN_PASSWORD"
)

# Optional but recommended variables
RECOMMENDED_VARS=(
    "CORS_ORIGINS"
    "VITE_API_URL"
    "ENABLE_DEFAULT_ADMIN"
    "DEFAULT_ADMIN_EMAIL"
    "PORT"
)

# Validate environment variable format and security
validate_var_security() {
    local var_name="$1"
    local var_value="$2"

    case "$var_name" in
        "POSTGRES_PASSWORD"|"REDIS_PASSWORD"|"DEFAULT_ADMIN_PASSWORD")
            # Password validation
            if [ ${#var_value} -lt 12 ]; then
                log_error "$var_name is too short (minimum 12 characters)"
                return 1
            fi

            if [[ ! "$var_value" =~ [A-Z] ]]; then
                log_warning "$var_name should contain uppercase letters"
            fi

            if [[ ! "$var_value" =~ [a-z] ]]; then
                log_warning "$var_name should contain lowercase letters"
            fi

            if [[ ! "$var_value" =~ [0-9] ]]; then
                log_warning "$var_name should contain numbers"
            fi

            if [[ ! "$var_value" =~ [^A-Za-z0-9] ]]; then
                log_warning "$var_name should contain special characters"
            fi

            # Check for default/weak passwords
            local weak_passwords=("password" "123456" "admin" "changeme" "your_secure_password_here" "your_secure_postgres_password_here" "your_secure_redis_password_here")
            for weak in "${weak_passwords[@]}"; do
                if [[ "$var_value" == *"$weak"* ]]; then
                    log_error "$var_name contains weak/default password patterns"
                    return 1
                fi
            done

            log_success "$var_name meets security requirements"
            ;;

        "JWT_SECRET")
            if [ ${#var_value} -lt 32 ]; then
                log_error "$var_name is too short (minimum 32 characters, recommended 64+)"
                return 1
            elif [ ${#var_value} -lt 64 ]; then
                log_warning "$var_name should be at least 64 characters for production"
            fi

            if [[ "$var_value" == *"your_64_character_jwt_secret_key_here"* ]]; then
                log_error "$var_name contains default placeholder value"
                return 1
            fi

            log_success "$var_name meets security requirements"
            ;;

        "SERVER_ENCRYPTION_KEY")
            # Check for 32 characters (raw) or 42-44 characters (base64 variants)
            if [ ${#var_value} -ne 32 ] && ([ ${#var_value} -lt 42 ] || [ ${#var_value} -gt 44 ]); then
                log_error "$var_name must be exactly 32 characters (raw) or 42-44 characters (base64)"
                return 1
            fi

            if [[ "$var_value" == *"your_32_character_encryption_key_here"* ]]; then
                log_error "$var_name contains default placeholder value"
                return 1
            fi

            log_success "$var_name meets security requirements"
            ;;

        "CORS_ORIGINS")
            # Validate CORS origins format
            if [[ ! "$var_value" =~ ^https?://[^,]+(,https?://[^,]+)*$ ]] && [[ "$var_value" != "*" ]]; then
                log_warning "$var_name format may be incorrect (expected: http://domain.com,https://domain.com)"
            fi

            if [[ "$var_value" == "*" ]]; then
                log_warning "$var_name is set to wildcard (*) - not recommended for production"
            fi

            log_success "$var_name format is valid"
            ;;

        "DEFAULT_ADMIN_EMAIL")
            # Validate email format
            if [[ ! "$var_value" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
                log_error "$var_name is not a valid email address"
                return 1
            fi

            log_success "$var_name is valid"
            ;;

        "VITE_API_URL")
            # Validate URL format
            if [[ ! "$var_value" =~ ^https?://[^/]+(/.*)? ]]; then
                log_error "$var_name is not a valid URL"
                return 1
            fi

            log_success "$var_name is valid"
            ;;
    esac

    return 0
}

# Test environment variable with special characters in container
test_env_with_special_chars() {
    local test_password="Test#P@ssw0rd&123!"

    log_info "Testing environment variables with special characters..."

    # Create a test docker-compose file
    local test_compose=$(mktemp)
    cat > "$test_compose" << 'EOF'
version: '3.8'
services:
  test:
    image: alpine:latest
    environment:
      TEST_PASSWORD: ${TEST_PASSWORD}
    command: sh -c 'echo "Password from env: $TEST_PASSWORD" && [ "$TEST_PASSWORD" = "Test#P@ssw0rd&123!" ] && echo "SUCCESS: Special characters preserved" || echo "ERROR: Special characters corrupted"'
EOF

    # Create test env file
    local test_env_file=$(mktemp)
    echo "TEST_PASSWORD=$test_password" > "$test_env_file"

    # Test with docker or podman
    local compose_cmd=""
    if command -v docker &> /dev/null && docker compose version &> /dev/null; then
        compose_cmd="docker compose"
    elif command -v podman-compose &> /dev/null; then
        compose_cmd="podman-compose"
    else
        log_warning "No compose command available - skipping special character test"
        rm -f "$test_compose" "$test_env_file"
        return 0
    fi

    # Run the test
    if $compose_cmd -f "$test_compose" --env-file "$test_env_file" run --rm test 2>/dev/null | grep -q "SUCCESS: Special characters preserved"; then
        log_success "Special characters in environment variables work correctly"
    else
        log_error "Special characters in environment variables are corrupted"
        $compose_cmd -f "$test_compose" --env-file "$test_env_file" run --rm test 2>&1 || true
    fi

    rm -f "$test_compose" "$test_env_file"
}

# Check for quotes around values (common mistake)
check_quotes_in_env() {
    local env_file="$1"

    log_info "Checking for incorrect quotes in $env_file..."

    local quoted_vars=()
    while IFS= read -r line; do
        # Skip comments and empty lines
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ "$line" =~ ^[[:space:]]*$ ]] && continue

        # Check for quoted values
        if [[ "$line" =~ ^[^=]+=[\"\'](.*)[\"\']*$ ]]; then
            local var_name=$(echo "$line" | cut -d'=' -f1)
            quoted_vars+=("$var_name")
        fi
    done < "$env_file"

    if [ ${#quoted_vars[@]} -gt 0 ]; then
        log_warning "Variables with quotes found (may cause issues in docker-compose): ${quoted_vars[*]}"
        log_info "Remove quotes from these variables unless they're part of the actual value"
    else
        log_success "No problematic quotes found"
    fi
}

# Validate a specific .env file
validate_env_file() {
    local env_file="$1"
    local env_path="$PROJECT_ROOT/$env_file"

    log_info "Validating $env_file..."

    if [ ! -f "$env_path" ]; then
        log_error "$env_file not found at $env_path"
        return 1
    fi

    local exit_code=0

    # Check file permissions
    local perms=$(stat -c %a "$env_path")
    if [ "$perms" -gt 600 ]; then
        log_warning "$env_file has overly permissive permissions ($perms). Consider: chmod 600 $env_path"
    else
        log_success "$env_file has appropriate permissions ($perms)"
    fi

    # Parse environment variables
    local env_vars=()
    local env_values=()

    while IFS= read -r line; do
        # Skip comments and empty lines
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ "$line" =~ ^[[:space:]]*$ ]] && continue

        # Parse variable=value
        if [[ "$line" =~ ^[[:space:]]*([^=]+)=(.*)$ ]]; then
            local var_name="${BASH_REMATCH[1]}"
            local var_value="${BASH_REMATCH[2]}"
            env_vars+=("$var_name")
            env_values+=("$var_value")
        fi
    done < "$env_path"

    log_info "Found ${#env_vars[@]} environment variables in $env_file"

    # Check for critical variables
    local missing_critical=()
    for critical_var in "${CRITICAL_VARS[@]}"; do
        local found=false
        for var in "${env_vars[@]}"; do
            if [ "$var" = "$critical_var" ]; then
                found=true
                break
            fi
        done
        if [ "$found" = false ]; then
            missing_critical+=("$critical_var")
        fi
    done

    if [ ${#missing_critical[@]} -gt 0 ]; then
        log_error "Missing critical environment variables: ${missing_critical[*]}"
        exit_code=1
    else
        log_success "All critical environment variables are present"
    fi

    # Validate each variable
    for i in "${!env_vars[@]}"; do
        local var_name="${env_vars[$i]}"
        local var_value="${env_values[$i]}"

        # Check if it's a critical variable and validate it
        for critical_var in "${CRITICAL_VARS[@]}"; do
            if [ "$var_name" = "$critical_var" ]; then
                if ! validate_var_security "$var_name" "$var_value"; then
                    exit_code=1
                fi
                break
            fi
        done

        # Check recommended variables too
        for recommended_var in "${RECOMMENDED_VARS[@]}"; do
            if [ "$var_name" = "$recommended_var" ]; then
                validate_var_security "$var_name" "$var_value" || true
                break
            fi
        done
    done

    # Check for quotes
    check_quotes_in_env "$env_path"

    return $exit_code
}

# Test .env file loading in docker-compose
test_env_loading() {
    local env_file="$1"
    local env_path="$PROJECT_ROOT/$env_file"

    log_info "Testing .env file loading with docker-compose..."

    if [ ! -f "$env_path" ]; then
        log_warning "$env_file not found - skipping loading test"
        return 0
    fi

    # Create a simple test compose file
    local test_compose=$(mktemp)
    cat > "$test_compose" << 'EOF'
version: '3.8'
services:
  test:
    image: alpine:latest
    env_file:
      - .env
    environment:
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
      REDIS_PASSWORD: ${REDIS_PASSWORD}
      DEFAULT_ADMIN_PASSWORD: ${DEFAULT_ADMIN_PASSWORD}
    command: sh -c 'echo "Loaded envs - POSTGRES_PASSWORD length: ${#POSTGRES_PASSWORD}, REDIS_PASSWORD length: ${#REDIS_PASSWORD}, DEFAULT_ADMIN_PASSWORD length: ${#DEFAULT_ADMIN_PASSWORD}"'
EOF

    local compose_cmd=""
    if command -v docker &> /dev/null && docker compose version &> /dev/null; then
        compose_cmd="docker compose"
    elif command -v podman-compose &> /dev/null; then
        compose_cmd="podman-compose"
    else
        log_warning "No compose command available - skipping env loading test"
        rm -f "$test_compose"
        return 0
    fi

    # Test env loading
    cd "$PROJECT_ROOT"
    if $compose_cmd -f "$test_compose" run --rm test 2>/dev/null | grep -q "Loaded envs"; then
        log_success "Environment file loads correctly in docker-compose"
    else
        log_error "Environment file failed to load in docker-compose"
        $compose_cmd -f "$test_compose" run --rm test 2>&1 || true
    fi

    rm -f "$test_compose"
}

# Generate secure environment values
generate_secure_values() {
    log_info "Generating secure values for missing environment variables..."

    echo "# Generated secure values - copy to your .env file"
    echo "# Generated on $(date)"
    echo

    # Check if openssl is available
    if command -v openssl &> /dev/null; then
        echo "POSTGRES_PASSWORD=$(openssl rand -base64 32 | tr -d '/+=')"
        echo "REDIS_PASSWORD=$(openssl rand -base64 32 | tr -d '/+=')"
        echo "JWT_SECRET=$(openssl rand -base64 64 | tr -d '/+=')"
        echo "SERVER_ENCRYPTION_KEY=$(openssl rand -base64 32 | tr -d '/+=')"
        echo "DEFAULT_ADMIN_PASSWORD=$(openssl rand -base64 16 | tr -d '/+=' | sed 's/.*/&Admin123!/')"
    else
        echo "# Install openssl to generate secure random values:"
        echo "# POSTGRES_PASSWORD=<generate 32+ character password>"
        echo "# REDIS_PASSWORD=<generate 32+ character password>"
        echo "# JWT_SECRET=<generate 64+ character secret>"
        echo "# SERVER_ENCRYPTION_KEY=<generate 32 character key>"
        echo "# DEFAULT_ADMIN_PASSWORD=<generate strong admin password>"
    fi

    echo
    echo "CORS_ORIGINS=http://localhost:3000,http://localhost:5173"
    echo "VITE_API_URL=http://localhost:8080"
    echo "ENABLE_DEFAULT_ADMIN=true"
    echo "DEFAULT_ADMIN_EMAIL=admin@leaflock.app"
}

# Main validation function
main() {
    local env_file="${1:-.env}"

    log_info "Starting environment validation..."
    log_info "Project root: $PROJECT_ROOT"

    local exit_code=0

    # Test special characters handling
    test_env_with_special_chars

    echo
    # Validate .env file if it exists
    if [ -f "$PROJECT_ROOT/$env_file" ]; then
        if ! validate_env_file "$env_file"; then
            exit_code=1
        fi

        echo
        test_env_loading "$env_file"
    else
        log_warning "$env_file not found"

        # Check if .env.example exists and suggest copying
        if [ -f "$PROJECT_ROOT/.env.example" ]; then
            log_info "Found .env.example - copy it to .env and update the values"
            log_info "Command: cp $PROJECT_ROOT/.env.example $PROJECT_ROOT/.env"
        fi

        echo
        generate_secure_values
        exit_code=1
    fi

    echo
    if [ $exit_code -eq 0 ]; then
        log_success "Environment validation passed!"
    else
        log_error "Environment validation failed. Please fix the issues above."
    fi

    return $exit_code
}

# Show usage information
usage() {
    echo "Usage: $0 [ENV_FILE]"
    echo
    echo "Validates environment variables for LeafLock deployment."
    echo
    echo "Arguments:"
    echo "  ENV_FILE    Environment file to validate (default: .env)"
    echo
    echo "Examples:"
    echo "  $0                    # Validate .env"
    echo "  $0 .env.production    # Validate .env.production"
    echo "  $0 --generate         # Generate secure values"
}

# Handle command line arguments
if [[ "${1:-}" == "--help" ]] || [[ "${1:-}" == "-h" ]]; then
    usage
    exit 0
elif [[ "${1:-}" == "--generate" ]]; then
    generate_secure_values
    exit 0
fi

# Run main function if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi