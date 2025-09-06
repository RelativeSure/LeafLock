#!/bin/bash
# deploy-from-ghcr.sh - Deploy using images from GitHub Container Registry

set -euo pipefail

# Configuration
GITHUB_REPOSITORY="${GITHUB_REPOSITORY:-relativesure/notes}"
VERSION="${VERSION:-latest}"
COMPOSE_FILE="docker-compose.yml"
OVERRIDE_FILE="docker-compose.ghcr.yml"

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

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if required files exist
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed or not in PATH"
        exit 1
    fi
    
    if ! command -v docker-compose &> /dev/null; then
        log_error "Docker Compose is not installed or not in PATH"
        exit 1
    fi
    
    if [[ ! -f "$COMPOSE_FILE" ]]; then
        log_error "Base compose file not found: $COMPOSE_FILE"
        exit 1
    fi
    
    if [[ ! -f "$OVERRIDE_FILE" ]]; then
        log_error "Override compose file not found: $OVERRIDE_FILE"
        exit 1
    fi
    
    if [[ ! -f ".env" ]]; then
        log_warning ".env file not found, using default environment"
        if [[ ! -f ".env.example" ]]; then
            log_error "Neither .env nor .env.example found"
            exit 1
        fi
        cp .env.example .env
        log_info "Copied .env.example to .env - please review and update settings"
    fi
    
    log_success "Prerequisites check passed"
}

# Pull latest images
pull_images() {
    log_info "Pulling latest container images..."
    
    export GITHUB_REPOSITORY VERSION
    
    if docker-compose -f "$COMPOSE_FILE" -f "$OVERRIDE_FILE" pull; then
        log_success "Successfully pulled all images"
    else
        log_error "Failed to pull some images"
        exit 1
    fi
}

# Deploy services
deploy_services() {
    log_info "Deploying services..."
    
    export GITHUB_REPOSITORY VERSION
    
    # Stop existing services
    log_info "Stopping existing services..."
    docker-compose -f "$COMPOSE_FILE" -f "$OVERRIDE_FILE" down
    
    # Start services
    log_info "Starting services..."
    if docker-compose -f "$COMPOSE_FILE" -f "$OVERRIDE_FILE" up -d; then
        log_success "Services started successfully"
    else
        log_error "Failed to start services"
        exit 1
    fi
}

# Health check
health_check() {
    log_info "Performing health checks..."
    
    local max_attempts=30
    local attempt=1
    
    while [[ $attempt -le $max_attempts ]]; do
        log_info "Health check attempt $attempt/$max_attempts..."
        
        # Check backend health
        if curl -sf http://localhost:8080/api/v1/health > /dev/null 2>&1; then
            log_success "Backend is healthy"
            
            # Check frontend accessibility
            if curl -sf http://localhost:3000/ > /dev/null 2>&1; then
                log_success "Frontend is accessible"
                break
            else
                log_warning "Frontend not yet accessible"
            fi
        else
            log_warning "Backend not yet healthy"
        fi
        
        if [[ $attempt -eq $max_attempts ]]; then
            log_error "Health checks failed after $max_attempts attempts"
            log_info "Service status:"
            docker-compose -f "$COMPOSE_FILE" -f "$OVERRIDE_FILE" ps
            exit 1
        fi
        
        sleep 2
        ((attempt++))
    done
    
    log_success "All services are healthy!"
}

# Show deployment status
show_status() {
    log_info "Deployment Status:"
    echo
    docker-compose -f "$COMPOSE_FILE" -f "$OVERRIDE_FILE" ps --format table
    echo
    
    log_info "Service URLs:"
    echo "  🌐 Frontend: http://localhost:3000"
    echo "  🔧 Backend API: http://localhost:8080"
    echo "  📊 Health Check: http://localhost:8080/api/v1/health"
    echo
    
    log_info "Container Images Used:"
    echo "  📦 Backend: ghcr.io/$GITHUB_REPOSITORY/backend:$VERSION"
    echo "  📦 Frontend: ghcr.io/$GITHUB_REPOSITORY/frontend:$VERSION"
}

# Main deployment function
main() {
    echo "🚀 Deploying Secure Notes from GitHub Container Registry"
    echo "================================================="
    echo "Repository: $GITHUB_REPOSITORY"
    echo "Version: $VERSION"
    echo "================================================="
    echo
    
    check_prerequisites
    pull_images
    deploy_services
    health_check
    show_status
    
    log_success "🎉 Deployment completed successfully!"
    echo
    log_info "To view logs: docker-compose -f $COMPOSE_FILE -f $OVERRIDE_FILE logs -f"
    log_info "To stop services: docker-compose -f $COMPOSE_FILE -f $OVERRIDE_FILE down"
}

# Handle script arguments
case "${1:-deploy}" in
    "pull")
        check_prerequisites
        pull_images
        ;;
    "deploy")
        main
        ;;
    "status")
        show_status
        ;;
    "logs")
        docker-compose -f "$COMPOSE_FILE" -f "$OVERRIDE_FILE" logs -f
        ;;
    "stop")
        docker-compose -f "$COMPOSE_FILE" -f "$OVERRIDE_FILE" down
        ;;
    "restart")
        docker-compose -f "$COMPOSE_FILE" -f "$OVERRIDE_FILE" restart
        ;;
    *)
        echo "Usage: $0 [pull|deploy|status|logs|stop|restart]"
        echo
        echo "Commands:"
        echo "  pull    - Pull latest images from registry"
        echo "  deploy  - Full deployment (pull + deploy + health check)"
        echo "  status  - Show current deployment status"
        echo "  logs    - Follow service logs"
        echo "  stop    - Stop all services"
        echo "  restart - Restart all services"
        echo
        echo "Environment Variables:"
        echo "  GITHUB_REPOSITORY - GitHub repository (default: relativesure/notes)"
        echo "  VERSION          - Image version tag (default: latest)"
        exit 1
        ;;
esac