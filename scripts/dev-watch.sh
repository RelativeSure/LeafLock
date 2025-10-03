#!/bin/bash
# Note: Prefer leaflock.sh docker:* for local runs. This script runs a custom dev hot-reload loop.

# Development File Watcher and Hot Reload Script
# Provides intelligent file watching with hot reload for both backend and frontend

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
BACKEND_DIR="backend"
FRONTEND_DIR="frontend"
LOG_FILE="/tmp/leaflock-dev.log"

# PIDs for process management
BACKEND_PID=""
FRONTEND_PID=""
BACKEND_WATCH_PID=""
FRONTEND_WATCH_PID=""

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$LOG_FILE"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$LOG_FILE"
}

log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
}

log_backend() {
    echo -e "${PURPLE}[BACKEND]${NC} $1" | tee -a "$LOG_FILE"
}

log_frontend() {
    echo -e "${CYAN}[FRONTEND]${NC} $1" | tee -a "$LOG_FILE"
}

# Banner
show_banner() {
    clear
    echo -e "${BLUE}"
    cat << "EOF"
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║              🔥 LEAFLOCK HOT RELOAD DEVELOPMENT SERVER 🔥             ║
║                                                               ║
║     Intelligent file watching with automatic reload          ║
║        • Go backend with instant rebuild                     ║
║        • React frontend with Vite hot reload                 ║
║        • Real-time test execution                            ║
║        • Smart change detection                              ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check if we're in the right directory
    if [ ! -f "CLAUDE.md" ] || [ ! -d "$BACKEND_DIR" ] || [ ! -d "$FRONTEND_DIR" ]; then
        log_error "Please run this script from the project root directory"
        exit 1
    fi
    
    # Check for required tools
    local missing_tools=()
    
    if ! command -v watchexec &> /dev/null; then
        missing_tools+=("watchexec")
    fi
    
    if ! command -v go &> /dev/null; then
        missing_tools+=("go")
    fi
    
    if ! command -v node &> /dev/null; then
        missing_tools+=("node")
    fi
    
    if [ ${#missing_tools[@]} -gt 0 ]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        log_info "Install watchexec with: cargo install watchexec-cli"
        exit 1
    fi
    
    log_success "All prerequisites met"
}

# Setup development database
setup_dev_database() {
    log_info "Setting up development databases..."
    
    # Check if containers are running
    if command -v podman &> /dev/null; then
        if ! podman pod exists leaflock 2>/dev/null; then
            log_info "Starting development services with Podman..."
            make up &>/dev/null || {
                log_warning "Failed to start services automatically"
                return 1
            }
        fi
    elif command -v docker &> /dev/null; then
        if ! docker-compose ps | grep -q "Up"; then
            log_info "Starting development services with Docker..."
            docker-compose up -d &>/dev/null || {
                log_warning "Failed to start services automatically"
                return 1
            }
        fi
    fi
    
    # Wait for database to be ready
    local max_attempts=10
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        if curl -s http://localhost:8080/api/v1/health > /dev/null 2>&1; then
            log_success "Development services are ready"
            return 0
        fi
        
        if [ $attempt -eq $max_attempts ]; then
            log_warning "Services not ready after $max_attempts attempts"
            return 1
        fi
        
        sleep 2
        attempt=$((attempt + 1))
    done
}

# Kill process tree
kill_process_tree() {
    local pid=$1
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        # Kill all children
        pkill -P "$pid" 2>/dev/null || true
        # Kill the process itself
        kill "$pid" 2>/dev/null || true
        # Force kill if still running
        sleep 1
        kill -9 "$pid" 2>/dev/null || true
    fi
}

# Cleanup function
cleanup() {
    log_info "Shutting down development servers..."
    
    # Kill all watched processes
    kill_process_tree "$BACKEND_WATCH_PID"
    kill_process_tree "$FRONTEND_WATCH_PID"
    kill_process_tree "$BACKEND_PID"
    kill_process_tree "$FRONTEND_PID"
    
    # Clean up any remaining processes
    pkill -f "go run main.go" 2>/dev/null || true
    pkill -f "npm run dev" 2>/dev/null || true
    pkill -f "watchexec" 2>/dev/null || true
    
    log_success "Development servers stopped"
    exit 0
}

# Start backend with hot reload
start_backend_watch() {
    log_backend "Setting up Go backend with hot reload..."
    
    cd "$BACKEND_DIR"
    
    # Create a wrapper script for backend restart
    cat > /tmp/backend-restart.sh << 'EOF'
#!/bin/bash
echo "🔄 Backend file changed, restarting..."

# Kill existing backend
pkill -f "go run main.go" 2>/dev/null || true

# Wait a moment
sleep 0.5

# Build and run
if go build -o /tmp/leaflock-dev .; then
    echo "✅ Backend build successful, starting server..."
    /tmp/leaflock-dev &
    echo $! > /tmp/backend.pid
    echo "🚀 Backend server restarted"
else
    echo "❌ Backend build failed"
fi
EOF
    chmod +x /tmp/backend-restart.sh
    
    # Start initial backend
    log_backend "Starting initial backend server..."
    if go build -o /tmp/leaflock-dev .; then
        /tmp/leaflock-dev &
        BACKEND_PID=$!
        echo $BACKEND_PID > /tmp/backend.pid
        log_success "Backend server started (PID: $BACKEND_PID)"
    else
        log_error "Failed to build backend"
        cd ..
        return 1
    fi
    
    # Start file watcher
    log_backend "Starting file watcher for Go files..."
    watchexec \
        --restart \
        --clear \
        --watch . \
        --exts go \
        --ignore "*.test" \
        --ignore "*.tmp" \
        --ignore "coverage.*" \
        /tmp/backend-restart.sh &
    
    BACKEND_WATCH_PID=$!
    log_success "Backend file watcher started (PID: $BACKEND_WATCH_PID)"
    
    cd ..
}

# Start frontend with hot reload
start_frontend_watch() {
    log_frontend "Setting up React frontend with Vite hot reload..."
    
    cd "$FRONTEND_DIR"
    
    # Start Vite dev server (has built-in hot reload)
    log_frontend "Starting Vite development server..."
    npm run dev &
    FRONTEND_PID=$!
    echo $FRONTEND_PID > /tmp/frontend.pid
    
    log_success "Frontend server started with Vite hot reload (PID: $FRONTEND_PID)"
    
    cd ..
}

# Monitor processes
monitor_processes() {
    log_info "Monitoring development servers..."
    
    while true; do
        # Check if backend is still running
        if [ -f /tmp/backend.pid ]; then
            local backend_pid=$(cat /tmp/backend.pid 2>/dev/null || echo "")
            if [ -n "$backend_pid" ] && ! kill -0 "$backend_pid" 2>/dev/null; then
                log_warning "Backend process died unexpectedly"
            fi
        fi
        
        # Check if frontend is still running
        if [ -n "$FRONTEND_PID" ] && ! kill -0 "$FRONTEND_PID" 2>/dev/null; then
            log_warning "Frontend process died unexpectedly"
            # Try to restart frontend
            cd "$FRONTEND_DIR"
            npm run dev &
            FRONTEND_PID=$!
            cd ..
            log_info "Frontend process restarted"
        fi
        
        sleep 5
    done
}

# Show status
show_status() {
    echo
    log_info "Development Environment Status:"
    echo -e "  ${GREEN}✓${NC} Backend: http://localhost:8080 (Go with hot reload)"
    echo -e "  ${GREEN}✓${NC} Frontend: http://localhost:3000 (React with Vite HMR)"
    echo -e "  ${GREEN}✓${NC} Health Check: http://localhost:8080/api/v1/health"
    echo -e "  ${BLUE}📝${NC} Logs: $LOG_FILE"
    echo
    log_info "File watchers active for:"
    echo -e "  ${PURPLE}🔍${NC} Backend: *.go files in $BACKEND_DIR/"
    echo -e "  ${CYAN}🔍${NC} Frontend: All files (Vite built-in)"
    echo
    log_info "Press Ctrl+C to stop all development servers"
    echo
}

# Run tests on file change
setup_test_watchers() {
    log_info "Setting up test watchers..."
    
    # Backend test watcher
    cd "$BACKEND_DIR"
    watchexec \
        --watch . \
        --exts go \
        --ignore "main.go" \
        --ignore "*.tmp" \
        "echo '🧪 Running backend tests...' && make test-unit --quiet" &
    cd ..
    
    # Frontend test watcher (if tests exist)
    if [ -d "$FRONTEND_DIR/src" ] && find "$FRONTEND_DIR/src" -name "*.test.*" -o -name "*.spec.*" | grep -q .; then
        cd "$FRONTEND_DIR"
        npm run test:watch &>/dev/null &
        cd ..
        log_info "Frontend test watcher started"
    fi
}

# Main execution
main() {
    # Handle interruption
    trap cleanup INT TERM
    
    show_banner
    
    # Clear log file
    true > "$LOG_FILE"
    
    check_prerequisites
    setup_dev_database
    
    log_info "Starting hot reload development environment..."
    
    start_backend_watch
    sleep 2  # Give backend time to start
    
    start_frontend_watch
    sleep 2  # Give frontend time to start
    
    # Optional: setup test watchers
    if [[ "${1:-}" == "--with-tests" ]]; then
        setup_test_watchers
        log_info "Test watchers enabled"
    fi
    
    show_status
    
    # Monitor and keep running
    monitor_processes
}

# Help message
show_help() {
    echo "LeafLock Development Hot Reload Server"
    echo
    echo "Usage: $0 [options]"
    echo
    echo "Options:"
    echo "  --with-tests    Enable automatic test running on file changes"
    echo "  --help          Show this help message"
    echo
    echo "This script provides:"
    echo "  • Hot reload for Go backend (automatic rebuild and restart)"
    echo "  • Hot Module Replacement for React frontend (Vite)"
    echo "  • Intelligent file watching"
    echo "  • Process monitoring and automatic restart"
    echo "  • Centralized logging"
    echo
}

# Parse command line arguments
case "${1:-}" in
    --help|-h)
        show_help
        exit 0
        ;;
    *)
        main "$@"
        ;;
esac
