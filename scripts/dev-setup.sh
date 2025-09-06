#!/bin/bash

# Secure Notes Development Environment Setup
# Quick setup for local development with hot reload

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BACKEND_DIR="${PROJECT_ROOT}/backend"
FRONTEND_DIR="${PROJECT_ROOT}/frontend"
ENV_FILE="${PROJECT_ROOT}/.env"

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

# Function to check dependencies
check_dependencies() {
    log_info "Checking development dependencies..."
    
    local required_tools=()
    local optional_tools=()
    
    # Check for backend dependencies
    if [[ ! -f "$BACKEND_DIR/go.mod" ]]; then
        log_error "Backend directory or go.mod not found"
        return 1
    fi
    
    if ! command -v go &> /dev/null; then
        required_tools+=("go (https://golang.org/dl/)")
    fi
    
    # Check for frontend dependencies
    if [[ ! -f "$FRONTEND_DIR/package.json" ]]; then
        log_error "Frontend directory or package.json not found"
        return 1
    fi
    
    if ! command -v node &> /dev/null; then
        required_tools+=("node.js (https://nodejs.org/)")
    fi
    
    if ! command -v npm &> /dev/null; then
        required_tools+=("npm (comes with Node.js)")
    fi
    
    # Check for optional tools
    if ! command -v docker &> /dev/null; then
        optional_tools+=("docker (for database services)")
    fi
    
    if ! command -v air &> /dev/null; then
        optional_tools+=("air (go install github.com/cosmtrek/air@latest)")
    fi
    
    # Report missing tools
    if [[ ${#required_tools[@]} -gt 0 ]]; then
        log_error "Missing required tools:"
        for tool in "${required_tools[@]}"; do
            echo "  - $tool"
        done
        return 1
    fi
    
    if [[ ${#optional_tools[@]} -gt 0 ]]; then
        log_warn "Optional tools not found (recommended):"
        for tool in "${optional_tools[@]}"; do
            echo "  - $tool"
        done
    fi
    
    log_success "Dependencies check passed"
    return 0
}

# Function to setup environment
setup_environment() {
    log_info "Setting up development environment..."
    
    # Create .env if it doesn't exist
    if [[ ! -f "$ENV_FILE" ]]; then
        if [[ -f "${PROJECT_ROOT}/.env.example" ]]; then
            cp "${PROJECT_ROOT}/.env.example" "$ENV_FILE"
            log_info "Created .env from template"
        else
            # Create a minimal .env for development
            cat > "$ENV_FILE" <<EOF
# Development environment configuration
POSTGRES_PASSWORD=devpassword123
REDIS_PASSWORD=devredispass123
JWT_SECRET=devsecret1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKL
SERVER_ENCRYPTION_KEY=dev12345678901234567890123456789
CORS_ORIGINS=http://localhost:3000,http://localhost:5173
VITE_API_URL=http://localhost:8080

# Database (for development with Docker)
DATABASE_URL=postgres://postgres:devpassword123@localhost:5432/notes?sslmode=disable
REDIS_URL=localhost:6379
EOF
            log_info "Created basic .env file for development"
        fi
    fi
    
    log_success "Environment setup completed"
}

# Function to install backend dependencies
setup_backend() {
    log_info "Setting up backend dependencies..."
    
    cd "$BACKEND_DIR"
    
    # Download Go modules
    go mod download
    go mod verify
    
    log_success "Backend dependencies installed"
}

# Function to install frontend dependencies
setup_frontend() {
    log_info "Setting up frontend dependencies..."
    
    cd "$FRONTEND_DIR"
    
    # Install npm dependencies
    if [[ -f "package-lock.json" ]]; then
        npm ci
    else
        npm install
    fi
    
    log_success "Frontend dependencies installed"
}

# Function to start database services
start_databases() {
    log_info "Starting database services with Docker..."
    
    cd "$PROJECT_ROOT"
    
    # Check if Docker is available
    if ! command -v docker &> /dev/null; then
        log_error "Docker is required to start database services"
        return 1
    fi
    
    # Start only database services
    docker compose up -d postgres redis
    
    # Wait for services to be ready
    log_info "Waiting for databases to be ready..."
    local max_attempts=30
    local attempt=0
    
    while [[ $attempt -lt $max_attempts ]]; do
        if docker compose exec postgres pg_isready -U postgres >/dev/null 2>&1 && \
           docker compose exec redis redis-cli ping >/dev/null 2>&1; then
            log_success "Databases are ready"
            return 0
        fi
        
        ((attempt++))
        log_info "Waiting for databases... ($attempt/$max_attempts)"
        sleep 2
    done
    
    log_error "Databases did not become ready in time"
    return 1
}

# Function to start backend in development mode
start_backend_dev() {
    log_info "Starting backend in development mode..."
    
    cd "$BACKEND_DIR"
    
    # Use air for hot reload if available, otherwise use go run
    if command -v air &> /dev/null; then
        log_info "Using air for hot reload"
        air &
    else
        log_info "Using go run (install air for hot reload)"
        go run main.go &
    fi
    
    # Store backend PID
    local backend_pid=$!
    echo $backend_pid > "${PROJECT_ROOT}/.backend.pid"
    
    log_success "Backend started in development mode"
}

# Function to start frontend in development mode
start_frontend_dev() {
    log_info "Starting frontend in development mode..."
    
    cd "$FRONTEND_DIR"
    
    # Start Vite development server
    npm run dev &
    
    # Store frontend PID
    local frontend_pid=$!
    echo $frontend_pid > "${PROJECT_ROOT}/.frontend.pid"
    
    log_success "Frontend started in development mode"
}

# Function to check service health
check_services() {
    log_info "Checking service health..."
    
    local max_attempts=30
    local attempt=0
    
    # Wait for backend
    while [[ $attempt -lt $max_attempts ]]; do
        if curl -sf http://localhost:8080/api/v1/health >/dev/null 2>&1; then
            log_success "Backend is healthy"
            break
        fi
        
        ((attempt++))
        if [[ $attempt -eq $max_attempts ]]; then
            log_warn "Backend health check timeout"
        fi
        sleep 2
    done
    
    # Check frontend (Vite usually starts on 5173)
    local frontend_ports=(5173 3000)
    for port in "${frontend_ports[@]}"; do
        if curl -sf "http://localhost:$port" >/dev/null 2>&1; then
            log_success "Frontend is running on port $port"
            break
        fi
    done
}

# Function to show development info
show_dev_info() {
    log_success "🚀 Development environment is ready!"
    echo
    echo "Services running:"
    echo "  - PostgreSQL: localhost:5432"
    echo "  - Redis: localhost:6379"
    echo "  - Backend API: http://localhost:8080"
    echo "  - Frontend: http://localhost:5173 (or :3000)"
    echo
    echo "API Endpoints:"
    echo "  - Health Check: http://localhost:8080/api/v1/health"
    echo "  - API Docs: http://localhost:8080/api/v1/docs (if implemented)"
    echo
    echo "Development commands:"
    echo "  - Stop services: $0 stop"
    echo "  - Restart: $0 restart"
    echo "  - View logs: docker compose logs -f"
    echo "  - Database shell: docker compose exec postgres psql -U postgres -d notes"
    echo "  - Redis CLI: docker compose exec redis redis-cli"
    echo
    echo "File locations:"
    echo "  - Backend logs: Check terminal or air output"
    echo "  - Frontend: Vite dev server output"
    echo "  - Environment: $ENV_FILE"
    echo
}

# Function to stop services
stop_services() {
    log_info "Stopping development services..."
    
    cd "$PROJECT_ROOT"
    
    # Stop frontend
    if [[ -f ".frontend.pid" ]]; then
        local frontend_pid
        frontend_pid=$(cat .frontend.pid)
        if kill -0 "$frontend_pid" 2>/dev/null; then
            kill "$frontend_pid" || true
        fi
        rm -f .frontend.pid
    fi
    
    # Stop backend
    if [[ -f ".backend.pid" ]]; then
        local backend_pid
        backend_pid=$(cat .backend.pid)
        if kill -0 "$backend_pid" 2>/dev/null; then
            kill "$backend_pid" || true
        fi
        rm -f .backend.pid
    fi
    
    # Stop database services
    docker compose down postgres redis || true
    
    log_success "Services stopped"
}

# Function to cleanup PIDs on exit
cleanup() {
    stop_services
}

# Main function
main() {
    local action=${1:-"start"}
    
    case "$action" in
        start|setup)
            # Set up cleanup trap
            trap cleanup EXIT INT TERM
            
            log_info "🔧 Setting up Secure Notes development environment..."
            
            check_dependencies
            setup_environment
            setup_backend
            setup_frontend
            start_databases
            
            # Wait a bit for databases to be fully ready
            sleep 3
            
            start_backend_dev
            start_frontend_dev
            
            # Wait for services to start
            sleep 5
            check_services
            show_dev_info
            
            # Keep script running
            log_info "Development environment is running. Press Ctrl+C to stop."
            wait
            ;;
            
        stop)
            stop_services
            ;;
            
        restart)
            stop_services
            sleep 2
            main start
            ;;
            
        install|deps)
            check_dependencies
            setup_backend
            setup_frontend
            log_success "Dependencies installed successfully"
            ;;
            
        databases|db)
            start_databases
            log_info "Databases are running. Use '$0 stop' to stop them."
            ;;
            
        --help|-h)
            echo "Usage: $0 [COMMAND]"
            echo ""
            echo "Commands:"
            echo "  start    Start full development environment (default)"
            echo "  stop     Stop all development services"
            echo "  restart  Restart all services"
            echo "  install  Install dependencies only"
            echo "  db       Start databases only"
            echo "  --help   Show this help message"
            echo ""
            echo "The start command will:"
            echo "  1. Check dependencies"
            echo "  2. Set up environment"
            echo "  3. Install backend/frontend dependencies"
            echo "  4. Start database services (Docker)"
            echo "  5. Start backend with hot reload"
            echo "  6. Start frontend with hot reload"
            echo ""
            exit 0
            ;;
            
        *)
            log_error "Unknown command: $action"
            echo "Use '$0 --help' for usage information"
            exit 1
            ;;
    esac
}

# Check for required commands
if ! command -v curl &> /dev/null; then
    log_error "curl is required but not installed"
    exit 1
fi

# Run main function
main "$@"