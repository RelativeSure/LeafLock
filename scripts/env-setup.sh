#!/bin/bash

# LeafLock Environment Configuration Setup
# Validates, generates, and manages environment configurations for all deployment targets

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
ENV_EXAMPLE="${PROJECT_ROOT}/.env.example"
ENV_FILE="${PROJECT_ROOT}/.env"
ENV_PROD_FILE="${PROJECT_ROOT}/.env.production"
ENV_DEV_FILE="${PROJECT_ROOT}/.env.development"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_section() {
    echo -e "${CYAN}[SECTION]${NC} $1"
}

# Function to generate secure random strings
generate_password() {
    local length=${1:-32}
    openssl rand -base64 $((length * 3 / 4)) | tr -d "=+/" | cut -c1-"$length"
}

generate_hex() {
    local length=${1:-32}
    openssl rand -hex $((length / 2))
}

# Function to validate password strength
validate_password_strength() {
    local password="$1"
    local min_length=${2:-16}
    local errors=0
    
    # Check length
    if [[ ${#password} -lt $min_length ]]; then
        log_error "Password must be at least $min_length characters long"
        ((errors++))
    fi
    
    # Check for different character types
    if ! [[ "$password" =~ [A-Z] ]]; then
        log_warn "Password should contain uppercase letters"
    fi
    
    if ! [[ "$password" =~ [a-z] ]]; then
        log_warn "Password should contain lowercase letters"
    fi
    
    if ! [[ "$password" =~ [0-9] ]]; then
        log_warn "Password should contain numbers"
    fi
    
    if ! [[ "$password" =~ [^A-Za-z0-9] ]]; then
        log_warn "Password should contain special characters"
    fi
    
    return $errors
}

# Function to validate environment variables
validate_environment() {
    local env_file="$1"
    local environment="${2:-production}"
    
    log_section "Validating $environment environment ($env_file)"
    
    if [[ ! -f "$env_file" ]]; then
        log_error "Environment file not found: $env_file"
        return 1
    fi
    
    # Source the environment file
    local temp_env
    temp_env=$(mktemp)
    # Remove comments and empty lines, then source
    grep -v '^#\|^$' "$env_file" > "$temp_env"
    source "$temp_env"
    rm "$temp_env"
    
    local errors=0
    local warnings=0
    
    # Required variables for all environments
    local required_vars=(
        "POSTGRES_PASSWORD"
        "REDIS_PASSWORD"
        "JWT_SECRET"
        "SERVER_ENCRYPTION_KEY"
    )
    
    # Additional required variables by environment
    case "$environment" in
        production)
            required_vars+=(
                "CORS_ORIGINS"
            )
            ;;
        development)
            required_vars+=(
                "VITE_API_URL"
            )
            ;;
    esac
    
    # Check required variables
    for var in "${required_vars[@]}"; do
        if [[ -z "${!var:-}" ]]; then
            log_error "Missing required variable: $var"
            ((errors++))
        elif [[ "${!var}" == *"ChangeThis"* ]] || [[ "${!var}" == *"GenerateRandom"* ]] || [[ "${!var}" == *"example"* ]]; then
            log_error "Default placeholder value detected for: $var"
            ((errors++))
        fi
    done
    
    # Validate specific variables
    if [[ -n "${POSTGRES_PASSWORD:-}" ]]; then
        if ! validate_password_strength "$POSTGRES_PASSWORD" 16; then
            log_error "POSTGRES_PASSWORD does not meet strength requirements"
            ((errors++))
        fi
    fi
    
    if [[ -n "${REDIS_PASSWORD:-}" ]]; then
        if ! validate_password_strength "$REDIS_PASSWORD" 16; then
            log_error "REDIS_PASSWORD does not meet strength requirements"
            ((errors++))
        fi
    fi
    
    if [[ -n "${JWT_SECRET:-}" ]]; then
        if [[ ${#JWT_SECRET} -lt 64 ]]; then
            log_error "JWT_SECRET must be at least 64 characters long"
            ((errors++))
        fi
    fi
    
    if [[ -n "${SERVER_ENCRYPTION_KEY:-}" ]]; then
        if [[ ${#SERVER_ENCRYPTION_KEY} -ne 32 ]]; then
            log_error "SERVER_ENCRYPTION_KEY must be exactly 32 characters long"
            ((errors++))
        fi
    fi
    
    # Environment-specific validations
    case "$environment" in
        production)
            # Check CORS origins
            if [[ -n "${CORS_ORIGINS:-}" ]]; then
                if [[ "$CORS_ORIGINS" == *"localhost"* ]]; then
                    log_warn "CORS_ORIGINS contains localhost in production environment"
                    ((warnings++))
                fi
                
                # Validate CORS format
                IFS=',' read -ra ORIGINS <<< "$CORS_ORIGINS"
                for origin in "${ORIGINS[@]}"; do
                    origin=$(echo "$origin" | xargs) # trim whitespace
                    if [[ ! "$origin" =~ ^https?://[a-zA-Z0-9.-]+(\:[0-9]+)?$ ]]; then
                        log_warn "Invalid CORS origin format: $origin"
                        ((warnings++))
                    fi
                done
            fi
            
            # Check for HTTPS in production
            if [[ -n "${VITE_API_URL:-}" ]] && [[ "$VITE_API_URL" == http://* ]]; then
                log_warn "VITE_API_URL should use HTTPS in production"
                ((warnings++))
            fi
            ;;
    esac
    
    # Security checks
    log_info "Running security checks..."
    
    # Check for common weak passwords
    local weak_patterns=("password" "123456" "admin" "secret" "test")
    for var in POSTGRES_PASSWORD REDIS_PASSWORD; do
        if [[ -n "${!var:-}" ]]; then
            local value="${!var,,}" # lowercase
            for pattern in "${weak_patterns[@]}"; do
                if [[ "$value" == *"$pattern"* ]]; then
                    log_error "$var contains weak pattern: $pattern"
                    ((errors++))
                    break
                fi
            done
        fi
    done
    
    # Summary
    log_info "Validation complete:"
    log_info "  Errors: $errors"
    log_info "  Warnings: $warnings"
    
    if [[ $errors -eq 0 ]]; then
        log_success "Environment validation passed"
        return 0
    else
        log_error "Environment validation failed"
        return 1
    fi
}

# Function to generate environment file
generate_environment() {
    local environment="$1"
    local output_file="$2"
    local interactive="${3:-false}"
    
    log_section "Generating $environment environment configuration"
    
    # Backup existing file
    if [[ -f "$output_file" ]]; then
        local backup_file="${output_file}.backup.$(date +%Y%m%d_%H%M%S)"
        cp "$output_file" "$backup_file"
        log_info "Backed up existing file to: $backup_file"
    fi
    
    # Generate secure values
    local postgres_password
    local redis_password
    local jwt_secret
    local server_encryption_key
    local cors_origins
    local vite_api_url
    
    if [[ "$interactive" == "true" ]]; then
        # Interactive mode - prompt for custom values
        read -rp "Enter PostgreSQL password (press Enter for auto-generated): " postgres_password
        [[ -z "$postgres_password" ]] && postgres_password=$(generate_password 24)
        
        read -rp "Enter Redis password (press Enter for auto-generated): " redis_password
        [[ -z "$redis_password" ]] && redis_password=$(generate_password 24)
        
        read -rp "Enter JWT secret (press Enter for auto-generated): " jwt_secret
        [[ -z "$jwt_secret" ]] && jwt_secret=$(generate_password 64)
        
        read -rp "Enter server encryption key (press Enter for auto-generated): " server_encryption_key
        [[ -z "$server_encryption_key" ]] && server_encryption_key=$(generate_password 32)
        
        if [[ "$environment" == "production" ]]; then
            read -rp "Enter CORS origins (comma-separated): " cors_origins
            read -rp "Enter API URL: " vite_api_url
        fi
    else
        # Auto-generate all values
        postgres_password=$(generate_password 24)
        redis_password=$(generate_password 24)
        jwt_secret=$(generate_password 64)
        server_encryption_key=$(generate_password 32)
    fi
    
    # Set environment-specific defaults
    case "$environment" in
        production)
            [[ -z "${cors_origins:-}" ]] && cors_origins="https://your-domain.com"
            [[ -z "${vite_api_url:-}" ]] && vite_api_url="https://your-api-domain.com"
            ;;
        development)
            cors_origins="http://localhost:3000,http://localhost:5173"
            vite_api_url="http://localhost:8080"
            ;;
    esac
    
    # Create environment file
    cat > "$output_file" <<EOF
# LeafLock - $environment Environment Configuration
# Generated: $(date)
# WARNING: Keep this file secure and never commit to version control!

#
# Database Configuration
#
POSTGRES_PASSWORD=$postgres_password
REDIS_PASSWORD=$redis_password

#
# Application Security
#
JWT_SECRET=$jwt_secret
SERVER_ENCRYPTION_KEY=$server_encryption_key

#
# CORS and API Configuration
#
CORS_ORIGINS=$cors_origins
VITE_API_URL=$vite_api_url

#
# Database Connection URLs (derived from above)
#
DATABASE_URL=postgres://postgres:\${POSTGRES_PASSWORD}@localhost:5432/notes?sslmode=disable
REDIS_URL=localhost:6379

#
# Application Settings
#
PORT=8080
EOF
    
    # Add environment-specific configurations
    case "$environment" in
        production)
            cat >> "$output_file" <<EOF

#
# Production-specific settings
#
NODE_ENV=production
LOG_LEVEL=info
RATE_LIMIT_ENABLED=true
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100

#
# SSL/TLS Configuration (uncomment and configure for production)
#
# SSL_CERT_PATH=/path/to/cert.pem
# SSL_KEY_PATH=/path/to/key.pem
# FORCE_HTTPS=true

#
# Monitoring and Logging (optional)
#
# SENTRY_DSN=your-sentry-dsn
# LOG_FILE_PATH=/var/log/secure-notes.log
EOF
            ;;
        development)
            cat >> "$output_file" <<EOF

#
# Development-specific settings
#
NODE_ENV=development
LOG_LEVEL=debug
RATE_LIMIT_ENABLED=false
HOT_RELOAD=true

#
# Development database URLs (using Docker services)
#
DATABASE_URL=postgres://postgres:\${POSTGRES_PASSWORD}@localhost:5432/notes?sslmode=disable
REDIS_URL=localhost:6379
EOF
            ;;
    esac
    
    # Set appropriate permissions
    chmod 600 "$output_file"
    
    log_success "Generated $environment environment file: $output_file"
    log_warn "File permissions set to 600 (owner read/write only)"
}

# Function to compare environments
compare_environments() {
    local file1="$1"
    local file2="$2"
    
    log_section "Comparing environment files"
    
    if [[ ! -f "$file1" ]]; then
        log_error "File not found: $file1"
        return 1
    fi
    
    if [[ ! -f "$file2" ]]; then
        log_error "File not found: $file2"
        return 1
    fi
    
    log_info "Comparing variables between files..."
    
    # Extract variable names from both files
    local vars1
    local vars2
    vars1=$(grep '^[A-Z_].*=' "$file1" | cut -d'=' -f1 | sort)
    vars2=$(grep '^[A-Z_].*=' "$file2" | cut -d'=' -f1 | sort)
    
    # Find differences
    local only_in_1
    local only_in_2
    only_in_1=$(comm -23 <(echo "$vars1") <(echo "$vars2"))
    only_in_2=$(comm -13 <(echo "$vars1") <(echo "$vars2"))
    
    if [[ -n "$only_in_1" ]]; then
        log_warn "Variables only in $file1:"
        while IFS= read -r line; do echo "  - $line"; done <<< "$only_in_1"
    fi

    if [[ -n "$only_in_2" ]]; then
        log_warn "Variables only in $file2:"
        while IFS= read -r line; do echo "  - $line"; done <<< "$only_in_2"
    fi
    
    if [[ -z "$only_in_1" && -z "$only_in_2" ]]; then
        log_success "Both files have the same variables"
    fi
}

# Function to show environment info
show_environment_info() {
    local env_file="$1"
    
    if [[ ! -f "$env_file" ]]; then
        log_error "Environment file not found: $env_file"
        return 1
    fi
    
    log_section "Environment Information: $env_file"
    
    # Source the environment file safely
    local temp_env
    temp_env=$(mktemp)
    grep -v '^#\|^$' "$env_file" > "$temp_env"
    
    echo "Variables found:"
    while IFS='=' read -r key value; do
        if [[ -n "$key" && "$key" != *" "* ]]; then
            # Mask sensitive values
            case "$key" in
                *PASSWORD*|*SECRET*|*KEY*)
                    echo "  $key=[MASKED]"
                    ;;
                *)
                    echo "  $key=$value"
                    ;;
            esac
        fi
    done < "$temp_env"
    
    rm "$temp_env"
    
    # Show file permissions and security info
    local perms
    perms=$(stat -c "%a" "$env_file")
    echo
    echo "Security Information:"
    echo "  File permissions: $perms"
    
    if [[ "$perms" != "600" ]]; then
        log_warn "File permissions are not 600 (recommended for security)"
    fi
    
    # Check if file is in .gitignore
    if [[ -f "${PROJECT_ROOT}/.gitignore" ]]; then
        if grep -q "$(basename "$env_file")" "${PROJECT_ROOT}/.gitignore"; then
            log_success "File is properly excluded from git"
        else
            log_warn "File may not be excluded from git - check .gitignore"
        fi
    fi
}

# Main function
main() {
    local action="$1"
    shift || true
    
    case "$action" in
        generate|gen)
            local environment="${1:-production}"
            local interactive="${2:-false}"
            
            case "$environment" in
                prod|production)
                    generate_environment "production" "$ENV_PROD_FILE" "$interactive"
                    ;;
                dev|development)
                    generate_environment "development" "$ENV_DEV_FILE" "$interactive"
                    ;;
                *)
                    generate_environment "$environment" "$ENV_FILE" "$interactive"
                    ;;
            esac
            ;;
            
        validate|check)
            local env_file="${1:-$ENV_FILE}"
            local environment="production"
            
            # Detect environment from filename
            if [[ "$env_file" == *"dev"* ]]; then
                environment="development"
            fi
            
            validate_environment "$env_file" "$environment"
            ;;
            
        compare|diff)
            local file1="${1:-$ENV_FILE}"
            local file2="${2:-$ENV_EXAMPLE}"
            compare_environments "$file1" "$file2"
            ;;
            
        info|show)
            local env_file="${1:-$ENV_FILE}"
            show_environment_info "$env_file"
            ;;
            
        setup|init)
            log_info "Setting up all environment configurations..."
            
            # Generate development environment
            generate_environment "development" "$ENV_DEV_FILE" false
            
            # Generate production environment template
            generate_environment "production" "$ENV_PROD_FILE" false
            
            # Create main .env as development by default
            if [[ ! -f "$ENV_FILE" ]]; then
                cp "$ENV_DEV_FILE" "$ENV_FILE"
                log_info "Created .env as development environment"
            fi
            
            log_success "Environment setup complete"
            ;;
            
        --help|-h)
            cat <<EOF
Usage: $0 COMMAND [OPTIONS]

Commands:
  generate [ENV] [INTERACTIVE]  Generate environment configuration
                                ENV: prod/dev/production/development
                                INTERACTIVE: true/false
  
  validate [FILE]               Validate environment file
                                Default: .env
  
  compare [FILE1] [FILE2]       Compare two environment files
                                Default: .env vs .env.example
  
  info [FILE]                   Show environment information
                                Default: .env
  
  setup                         Setup all environment configurations
  
  --help                        Show this help message

Examples:
  $0 generate prod              # Generate production config
  $0 generate dev true          # Generate dev config interactively
  $0 validate .env.production   # Validate specific file
  $0 compare .env .env.production
  $0 info .env.development
  $0 setup                      # Setup all environments

Generated files:
  .env.development - Development configuration
  .env.production  - Production configuration template
  .env             - Active configuration (defaults to development)

Security Notes:
- All generated files have 600 permissions (owner read/write only)
- Never commit .env files to version control
- Regularly rotate passwords and secrets
- Use strong, unique passwords for each environment
EOF
            ;;
            
        *)
            log_error "Unknown command: $action"
            echo "Use '$0 --help' for usage information"
            exit 1
            ;;
    esac
}

# Check dependencies
if ! command -v openssl &> /dev/null; then
    log_error "Required command 'openssl' is not installed"
    exit 1
fi

# Ensure we have at least one argument
if [[ $# -eq 0 ]]; then
    log_error "No command specified"
    echo "Use '$0 --help' for usage information"
    exit 1
fi

# Run main function
main "$@"
