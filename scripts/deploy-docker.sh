#!/bin/bash

# Secure Notes Docker Compose Deployment Script
# One-command deployment with environment validation and health checks

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
ENV_FILE="${PROJECT_ROOT}/.env"
COMPOSE_FILE="${PROJECT_ROOT}/docker-compose.yml"
# Production configuration is now integrated into main docker-compose.yml

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
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

# Function to generate secure random strings
generate_password() {
    local length=${1:-32}
    openssl rand -base64 $length | tr -d "=+/" | cut -c1-$length
}

# Function to validate environment
validate_environment() {
    log_info "Validating environment configuration..."
    
    local errors=0
    
    # Check if .env file exists
    if [[ ! -f "$ENV_FILE" ]]; then
        log_warn "No .env file found, creating from template..."
        if [[ -f "${PROJECT_ROOT}/.env.example" ]]; then
            cp "${PROJECT_ROOT}/.env.example" "$ENV_FILE"
            log_info "Copied .env.example to .env"
        else
            log_error ".env.example not found"
            ((errors++))
        fi
    fi
    
    # Source environment variables
    if [[ -f "$ENV_FILE" ]]; then
        source "$ENV_FILE"
    fi
    
    # Validate required environment variables
    local required_vars=(
        "POSTGRES_PASSWORD"
        "REDIS_PASSWORD"
        "JWT_SECRET"
        "SERVER_ENCRYPTION_KEY"
    )
    
    for var in "${required_vars[@]}"; do
        if [[ -z "${!var:-}" ]]; then
            log_error "Missing required environment variable: $var"
            ((errors++))
        elif [[ "${!var}" == *"ChangeThis"* ]] || [[ "${!var}" == *"GenerateRandom"* ]]; then
            log_error "Please update the default value for: $var"
            ((errors++))
        fi
    done
    
    # Validate JWT_SECRET length (should be at least 32 chars)
    if [[ -n "${JWT_SECRET:-}" ]] && [[ ${#JWT_SECRET} -lt 32 ]]; then
        log_error "JWT_SECRET must be at least 32 characters long"
        ((errors++))
    fi
    
    # Validate SERVER_ENCRYPTION_KEY length (should be 32 chars)
    if [[ -n "${SERVER_ENCRYPTION_KEY:-}" ]] && [[ ${#SERVER_ENCRYPTION_KEY} -ne 32 ]]; then
        log_error "SERVER_ENCRYPTION_KEY must be exactly 32 characters long"
        ((errors++))
    fi
    
    if [[ $errors -gt 0 ]]; then
        log_error "Environment validation failed with $errors errors"
        log_info "Please fix the errors above and run the script again"
        return 1
    fi
    
    log_success "Environment validation passed"
    return 0
}

# Function to auto-generate missing secrets
auto_generate_secrets() {
    log_info "Generating missing secrets..."
    
    local updated=false
    local temp_env=$(mktemp)
    
    # Read existing .env file
    while IFS= read -r line; do
        if [[ $line == POSTGRES_PASSWORD=* ]] && [[ $line == *"ChangeThis"* ]]; then
            echo "POSTGRES_PASSWORD=$(generate_password 24)" >> "$temp_env"
            updated=true
            log_info "Generated new POSTGRES_PASSWORD"
        elif [[ $line == REDIS_PASSWORD=* ]] && [[ $line == *"ChangeThis"* ]]; then
            echo "REDIS_PASSWORD=$(generate_password 24)" >> "$temp_env"
            updated=true
            log_info "Generated new REDIS_PASSWORD"
        elif [[ $line == JWT_SECRET=* ]] && [[ $line == *"ChangeThis"* ]]; then
            echo "JWT_SECRET=$(generate_password 64)" >> "$temp_env"
            updated=true
            log_info "Generated new JWT_SECRET"
        elif [[ $line == SERVER_ENCRYPTION_KEY=* ]] && [[ $line == *"ChangeThis"* ]]; then
            echo "SERVER_ENCRYPTION_KEY=$(generate_password 32)" >> "$temp_env"
            updated=true
            log_info "Generated new SERVER_ENCRYPTION_KEY"
        else
            echo "$line" >> "$temp_env"
        fi
    done < "$ENV_FILE"
    
    if [[ $updated == true ]]; then
        mv "$temp_env" "$ENV_FILE"
        log_success "Updated .env with generated secrets"
    else
        rm "$temp_env"
        log_info "No secrets needed generation"
    fi
}

# Function to check Docker and Docker Compose
check_dependencies() {
    log_info "Checking dependencies..."
    
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed or not in PATH"
        return 1
    fi
    
    if ! docker compose version &> /dev/null; then
        log_error "Docker Compose is not available"
        return 1
    fi
    
    # Check if Docker daemon is running
    if ! docker info &> /dev/null; then
        log_error "Docker daemon is not running"
        return 1
    fi
    
    log_success "All dependencies are available"
    return 0
}

# Function to deploy services
deploy_services() {
    local environment=${1:-"dev"}
    
    log_info "Deploying Secure Notes ($environment environment)..."
    
    # Change to project root
    cd "$PROJECT_ROOT"
    
    # Use main compose file for all environments
    local compose_files=("-f" "$COMPOSE_FILE")
    if [[ "$environment" == "prod" ]]; then
        log_info "Using production environment configuration"
    fi
    
    # Pull latest images for services that don't need building
    log_info "Pulling latest base images..."
    docker compose "${compose_files[@]}" pull postgres redis nginx || true
    
    # Build and start services
    log_info "Building and starting services..."
    docker compose "${compose_files[@]}" up -d --build
    
    log_success "Services started successfully"
}

# Function to wait for services to be healthy
wait_for_services() {
    log_info "Waiting for services to be healthy..."
    
    local max_attempts=60
    local attempt=0
    
    cd "$PROJECT_ROOT"
    
    while [[ $attempt -lt $max_attempts ]]; do
        if docker compose ps --filter health=healthy --quiet | grep -q .; then
            # Check if all expected services are healthy
            local healthy_count
            healthy_count=$(docker compose ps --filter health=healthy --quiet | wc -l)
            local total_count
            total_count=$(docker compose ps --quiet | wc -l)
            
            if [[ $healthy_count -eq $total_count ]]; then
                log_success "All services are healthy"
                return 0
            fi
        fi
        
        ((attempt++))
        log_info "Waiting for services to be healthy... ($attempt/$max_attempts)"
        sleep 5
    done
    
    log_error "Services did not become healthy within expected time"
    log_info "Service status:"
    docker compose ps
    return 1
}

# Function to run health checks
run_health_checks() {
    log_info "Running health checks..."
    
    local base_url="http://localhost:8080"
    local frontend_url="http://localhost:3000"
    
    # Check backend health
    log_info "Checking backend health..."
    if curl -sf "$base_url/api/v1/health" > /dev/null; then
        log_success "Backend is healthy"
    else
        log_error "Backend health check failed"
        return 1
    fi
    
    # Check frontend
    log_info "Checking frontend..."
    if curl -sf "$frontend_url" > /dev/null; then
        log_success "Frontend is accessible"
    else
        log_error "Frontend accessibility check failed"
        return 1
    fi
    
    log_success "All health checks passed"
}

# Function to show deployment summary
show_summary() {
    log_success "🎉 Secure Notes deployed successfully!"
    echo
    echo "Access your application:"
    echo "  Frontend: http://localhost:3000"
    echo "  Backend API: http://localhost:8080"
    echo "  Health Check: http://localhost:8080/api/v1/health"
    echo
    echo "Useful commands:"
    echo "  View logs: docker compose logs -f"
    echo "  Stop services: docker compose down"
    echo "  Restart services: docker compose restart"
    echo "  Update services: $0 --update"
    echo
}

# Function to cleanup on failure
cleanup_on_failure() {
    log_error "Deployment failed. Cleaning up..."
    cd "$PROJECT_ROOT"
    docker compose down --remove-orphans || true
}

# Function to update deployment
update_deployment() {
    log_info "Updating Secure Notes deployment..."
    cd "$PROJECT_ROOT"
    
    # Pull latest images and rebuild
    docker compose pull
    docker compose up -d --build
    
    # Wait for services
    wait_for_services
    run_health_checks
    
    log_success "Update completed successfully"
}

# Main function
main() {
    local environment="dev"
    local auto_generate=false
    local update_only=false
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --prod|--production)
                environment="prod"
                shift
                ;;
            --auto-generate-secrets)
                auto_generate=true
                shift
                ;;
            --update)
                update_only=true
                shift
                ;;
            --help|-h)
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --prod                  Use production configuration"
                echo "  --auto-generate-secrets Automatically generate missing secrets"
                echo "  --update                Update existing deployment"
                echo "  --help                  Show this help message"
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done
    
    # Set up error handling
    trap cleanup_on_failure ERR
    
    log_info "🚀 Starting Secure Notes deployment..."
    
    # Update only mode
    if [[ $update_only == true ]]; then
        update_deployment
        return 0
    fi
    
    # Pre-deployment checks
    check_dependencies
    
    # Handle environment configuration
    if [[ $auto_generate == true ]]; then
        auto_generate_secrets
    fi
    
    validate_environment
    
    # Deploy services
    deploy_services "$environment"
    
    # Wait for services to be ready
    wait_for_services
    
    # Run health checks
    run_health_checks
    
    # Show summary
    show_summary
    
    log_success "Deployment completed successfully!"
}

# Check for required commands
for cmd in docker curl openssl; do
    if ! command -v "$cmd" &> /dev/null; then
        log_error "Required command '$cmd' is not installed"
        exit 1
    fi
done

# Run main function
main "$@"