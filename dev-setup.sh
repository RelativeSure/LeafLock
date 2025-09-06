#!/bin/bash

# Secure Notes Development Environment Setup Script
# This script automates the complete development environment setup

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Configuration
PROJECT_NAME="Secure Notes"
MIN_NODE_VERSION="18"
MIN_GO_VERSION="1.23"
DOCKER_REQUIRED="yes"

# Logging functions
log_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

log_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

log_error() {
    echo -e "${RED}❌ $1${NC}"
}

log_step() {
    echo -e "${PURPLE}🔄 $1${NC}"
}

# Banner
show_banner() {
    echo -e "${BLUE}"
    cat << "EOF"
╔══════════════════════════════════════════════════╗
║                                                  ║
║        🔒 SECURE NOTES DEVELOPMENT SETUP        ║
║                                                  ║
║     Automated environment configuration for      ║
║          rapid development onboarding            ║
║                                                  ║
╚══════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

# Check system requirements
check_requirements() {
    log_step "Checking system requirements..."
    
    local errors=0
    
    # Check Node.js
    if command -v node &> /dev/null; then
        local node_version=$(node -v | sed 's/v//' | cut -d. -f1)
        if [ "$node_version" -ge "$MIN_NODE_VERSION" ]; then
            log_success "Node.js $(node -v) found"
        else
            log_error "Node.js version $MIN_NODE_VERSION+ required, found $(node -v)"
            errors=$((errors + 1))
        fi
    else
        log_error "Node.js not found. Please install Node.js $MIN_NODE_VERSION+"
        errors=$((errors + 1))
    fi
    
    # Check Go
    if command -v go &> /dev/null; then
        local go_version=$(go version | grep -oP 'go\d+\.\d+' | sed 's/go//')
        if [ "$(echo "$go_version >= $MIN_GO_VERSION" | bc -l)" -eq 1 ] 2>/dev/null || [[ "$go_version" == "$MIN_GO_VERSION"* ]]; then
            log_success "Go $(go version | grep -oP 'go\d+\.\d+\.\d+') found"
        else
            log_error "Go version $MIN_GO_VERSION+ required, found $(go version)"
            errors=$((errors + 1))
        fi
    else
        log_error "Go not found. Please install Go $MIN_GO_VERSION+"
        errors=$((errors + 1))
    fi
    
    # Check Docker/Podman
    if command -v podman &> /dev/null; then
        log_success "Podman found"
    elif command -v docker &> /dev/null; then
        log_success "Docker found"
    else
        log_error "Neither Docker nor Podman found. Please install one of them."
        errors=$((errors + 1))
    fi
    
    # Check git
    if command -v git &> /dev/null; then
        log_success "Git found"
    else
        log_error "Git not found. Please install Git."
        errors=$((errors + 1))
    fi
    
    if [ $errors -gt 0 ]; then
        log_error "Please fix the above issues before continuing."
        exit 1
    fi
    
    log_success "All system requirements met!"
}

# Setup environment file
setup_env_file() {
    log_step "Setting up environment configuration..."
    
    if [ ! -f ".env" ]; then
        log_info "Creating .env file from template..."
        cp .env.example .env
        
        # Generate secure random values
        log_info "Generating secure random values..."
        
        # Generate PostgreSQL password
        local postgres_password=$(openssl rand -base64 32 | tr -d '\n')
        sed -i "s/your_secure_postgres_password_here/$postgres_password/g" .env
        
        # Generate Redis password
        local redis_password=$(openssl rand -base64 32 | tr -d '\n')
        sed -i "s/your_secure_redis_password_here/$redis_password/g" .env
        
        # Generate JWT secret
        local jwt_secret=$(openssl rand -base64 64 | tr -d '\n')
        sed -i "s/your_64_character_jwt_secret_key_here_change_for_production/$jwt_secret/g" .env
        
        # Generate encryption key
        local encryption_key=$(openssl rand -base64 32 | tr -d '\n')
        sed -i "s/your_32_character_encryption_key_here/$encryption_key/g" .env
        
        log_success "Environment file created with secure random values"
    else
        log_info "Environment file already exists, skipping creation"
    fi
}

# Install dependencies
install_dependencies() {
    log_step "Installing project dependencies..."
    
    # Backend dependencies
    log_info "Installing Go backend dependencies..."
    cd backend
    go mod download
    go mod tidy
    cd ..
    log_success "Go dependencies installed"
    
    # Frontend dependencies
    log_info "Installing Node.js frontend dependencies..."
    cd frontend
    npm ci --silent
    cd ..
    log_success "Node.js dependencies installed"
}

# Setup development tools
setup_dev_tools() {
    log_step "Setting up development tools..."
    
    # Install Go tools
    log_info "Installing Go development tools..."
    cd backend
    make install-tools 2>/dev/null || log_warning "Some Go tools might not be available"
    cd ..
    
    # Check for additional useful tools
    if ! command -v watchexec &> /dev/null; then
        log_info "Consider installing watchexec for file watching: cargo install watchexec-cli"
    fi
    
    if ! command -v jq &> /dev/null; then
        log_info "Consider installing jq for JSON processing: apt install jq / brew install jq"
    fi
    
    log_success "Development tools setup complete"
}

# Setup Git hooks
setup_git_hooks() {
    log_step "Setting up Git hooks..."
    
    # Create pre-commit hook
    mkdir -p .git/hooks
    cat > .git/hooks/pre-commit << 'EOF'
#!/bin/bash
set -e

echo "Running pre-commit checks..."

# Check for secrets in staged files
if git diff --cached --name-only | grep -E '\.(env|key|pem)$' | head -1; then
    echo "❌ Potential secret files detected. Please review:"
    git diff --cached --name-only | grep -E '\.(env|key|pem)$'
    exit 1
fi

# Run backend checks if Go files changed
if git diff --cached --name-only | grep -q '\.go$'; then
    echo "🔄 Running Go checks..."
    cd backend
    make fmt vet test-unit 2>/dev/null || {
        echo "❌ Backend checks failed"
        exit 1
    }
    cd ..
    echo "✅ Go checks passed"
fi

# Run frontend checks if JS/TS files changed
if git diff --cached --name-only | grep -qE '\.(js|ts|jsx|tsx)$'; then
    echo "🔄 Running frontend checks..."
    cd frontend
    npm run lint 2>/dev/null || {
        echo "❌ Frontend lint failed"
        exit 1
    }
    cd ..
    echo "✅ Frontend checks passed"
fi

echo "✅ All pre-commit checks passed"
EOF
    chmod +x .git/hooks/pre-commit
    log_success "Git hooks configured"
}

# Start development services
start_dev_services() {
    log_step "Starting development services..."
    
    if command -v podman &> /dev/null; then
        log_info "Using Podman..."
        make up 2>/dev/null || log_warning "Failed to start with Podman, try manual startup"
    else
        log_info "Using Docker..."
        docker-compose up -d 2>/dev/null || log_warning "Failed to start with Docker, try manual startup"
    fi
    
    # Wait a moment for services to start
    sleep 3
    
    # Health check
    log_info "Performing health check..."
    local max_attempts=10
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        if curl -s http://localhost:8080/api/v1/health > /dev/null 2>&1; then
            log_success "Backend health check passed"
            break
        fi
        
        if [ $attempt -eq $max_attempts ]; then
            log_warning "Backend health check failed after $max_attempts attempts"
            break
        fi
        
        log_info "Waiting for backend to start... (attempt $attempt/$max_attempts)"
        sleep 2
        attempt=$((attempt + 1))
    done
}

# Show completion message
show_completion() {
    echo
    echo -e "${GREEN}"
    cat << "EOF"
╔══════════════════════════════════════════════════╗
║                                                  ║
║           🎉 SETUP COMPLETED SUCCESSFULLY! 🎉    ║
║                                                  ║
╚══════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
    
    log_info "Your development environment is ready!"
    echo
    log_info "Quick start commands:"
    echo -e "  ${BLUE}Frontend dev server:${NC} cd frontend && npm run dev"
    echo -e "  ${BLUE}Backend dev server:${NC}  cd backend && go run main.go"
    echo -e "  ${BLUE}Run tests:${NC}           make test (from root) or cd backend && make test"
    echo -e "  ${BLUE}View logs:${NC}           make logs"
    echo -e "  ${BLUE}Stop services:${NC}       make down"
    echo
    log_info "Access points:"
    echo -e "  ${BLUE}Frontend:${NC} http://localhost:3000"
    echo -e "  ${BLUE}Backend:${NC}  http://localhost:8080"
    echo -e "  ${BLUE}Health:${NC}   http://localhost:8080/api/v1/health"
    echo
    log_info "Useful files:"
    echo -e "  ${BLUE}.env${NC}               - Environment configuration"
    echo -e "  ${BLUE}CLAUDE.md${NC}          - Development guidance"
    echo -e "  ${BLUE}GETTING_STARTED.md${NC} - Detailed setup instructions"
    echo
}

# Main setup function
main() {
    show_banner
    
    log_info "Starting development environment setup for $PROJECT_NAME..."
    log_info "This will take 2-5 minutes depending on your internet connection."
    echo
    
    check_requirements
    setup_env_file
    install_dependencies
    setup_dev_tools
    setup_git_hooks
    start_dev_services
    
    show_completion
}

# Handle script interruption
cleanup() {
    log_warning "Setup interrupted. You may need to run this script again."
    exit 1
}

trap cleanup INT TERM

# Run main function
main "$@"