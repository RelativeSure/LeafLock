#!/bin/bash

# Error Handler and Recovery Script
# Automated error detection and recovery for Secure Notes development

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m'

# Configuration
ERROR_LOG="/tmp/secure-notes-errors.log"
RECOVERY_LOG="/tmp/secure-notes-recovery.log"
MAX_RETRIES=3
RETRY_DELAY=5

# Error tracking
declare -A error_counts
declare -A recovery_attempts

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$RECOVERY_LOG"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$RECOVERY_LOG"
}

log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "$RECOVERY_LOG"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$ERROR_LOG" | tee -a "$RECOVERY_LOG"
}

log_recovery() {
    echo -e "${PURPLE}[RECOVERY]${NC} $1" | tee -a "$RECOVERY_LOG"
}

# Initialize error handling
init_error_handler() {
    # Create log files
    touch "$ERROR_LOG" "$RECOVERY_LOG"
    
    # Set up error handling
    trap 'handle_script_error $? $LINENO $BASH_COMMAND' ERR
    trap 'cleanup_on_exit' EXIT
    
    log_info "Error handler initialized"
}

# Script error handler
handle_script_error() {
    local exit_code=$1
    local line_number=$2
    local command=$3
    
    log_error "Script error at line $line_number: '$command' (exit code: $exit_code)"
    
    # Don't exit immediately, try to continue with recovery
    set +e
}

# Cleanup function
cleanup_on_exit() {
    log_info "Cleaning up error handler..."
}

# Check service health
check_service_health() {
    local service=$1
    local url=$2
    local timeout=${3:-10}
    
    if curl -sf --max-time "$timeout" "$url" >/dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

# Generic retry function
retry_command() {
    local command="$1"
    local description="$2"
    local max_attempts="${3:-$MAX_RETRIES}"
    
    local attempt=1
    while [ $attempt -le $max_attempts ]; do
        log_info "Attempting $description (attempt $attempt/$max_attempts)"
        
        if eval "$command"; then
            log_success "$description succeeded"
            return 0
        else
            log_warning "$description failed (attempt $attempt/$max_attempts)"
            
            if [ $attempt -lt $max_attempts ]; then
                log_info "Waiting $RETRY_DELAY seconds before retry..."
                sleep $RETRY_DELAY
            fi
            
            ((attempt++))
        fi
    done
    
    log_error "$description failed after $max_attempts attempts"
    return 1
}

# Backend error recovery
recover_backend() {
    log_recovery "Attempting backend recovery..."
    
    # Check if backend process is running
    if pgrep -f "secure-notes\|go run main.go" >/dev/null; then
        log_info "Backend process is running"
    else
        log_warning "Backend process not found"
        
        # Try to restart backend
        if [ -f backend/main.go ]; then
            log_recovery "Restarting backend..."
            cd backend
            
            # Kill any existing processes
            pkill -f "go run main.go" || true
            pkill -f "secure-notes" || true
            
            # Rebuild and start
            if retry_command "go build -o app main.go" "Backend build"; then
                nohup ./app > /tmp/backend.log 2>&1 &
                log_success "Backend restarted"
                
                # Wait for startup
                sleep 3
                
                if check_service_health "backend" "http://localhost:8080/api/v1/health"; then
                    log_success "Backend health check passed"
                else
                    log_error "Backend health check failed after restart"
                    return 1
                fi
            else
                log_error "Backend build failed"
                return 1
            fi
            
            cd ..
        else
            log_error "Backend source code not found"
            return 1
        fi
    fi
    
    return 0
}

# Frontend error recovery
recover_frontend() {
    log_recovery "Attempting frontend recovery..."
    
    # Check if frontend process is running
    if pgrep -f "vite\|npm.*dev" >/dev/null; then
        log_info "Frontend process is running"
        
        # Check if accessible
        if check_service_health "frontend" "http://localhost:3000"; then
            log_success "Frontend is accessible"
            return 0
        else
            log_warning "Frontend not accessible, restarting..."
        fi
    else
        log_warning "Frontend process not found"
    fi
    
    # Try to restart frontend
    if [ -f frontend/package.json ]; then
        log_recovery "Restarting frontend..."
        cd frontend
        
        # Kill any existing processes
        pkill -f "vite" || true
        pkill -f "npm.*dev" || true
        
        # Check if node_modules exists
        if [ ! -d node_modules ]; then
            log_recovery "Installing frontend dependencies..."
            if ! retry_command "npm ci" "Frontend dependency installation"; then
                return 1
            fi
        fi
        
        # Start frontend
        nohup npm run dev > /tmp/frontend.log 2>&1 &
        log_success "Frontend restarted"
        
        # Wait for startup
        sleep 5
        
        if check_service_health "frontend" "http://localhost:3000" 15; then
            log_success "Frontend health check passed"
        else
            log_warning "Frontend may still be starting up"
        fi
        
        cd ..
    else
        log_error "Frontend package.json not found"
        return 1
    fi
    
    return 0
}

# Database error recovery
recover_database() {
    log_recovery "Attempting database recovery..."
    
    if command -v podman >/dev/null 2>&1; then
        # Check PostgreSQL
        if podman exec secure-notes-postgres pg_isready -U postgres >/dev/null 2>&1; then
            log_success "PostgreSQL is ready"
        else
            log_warning "PostgreSQL not ready, attempting recovery..."
            
            # Try to restart PostgreSQL container
            if retry_command "podman restart secure-notes-postgres" "PostgreSQL restart"; then
                sleep 5
                if podman exec secure-notes-postgres pg_isready -U postgres >/dev/null 2>&1; then
                    log_success "PostgreSQL recovered"
                else
                    log_error "PostgreSQL recovery failed"
                    return 1
                fi
            else
                return 1
            fi
        fi
        
        # Check Redis
        if podman exec secure-notes-redis redis-cli ping >/dev/null 2>&1; then
            log_success "Redis is ready"
        else
            log_warning "Redis not ready, attempting recovery..."
            
            # Try to restart Redis container
            if retry_command "podman restart secure-notes-redis" "Redis restart"; then
                sleep 5
                if podman exec secure-notes-redis redis-cli ping >/dev/null 2>&1; then
                    log_success "Redis recovered"
                else
                    log_error "Redis recovery failed"
                    return 1
                fi
            else
                return 1
            fi
        fi
    else
        log_warning "Podman not available, cannot check database containers"
    fi
    
    return 0
}

# Container error recovery
recover_containers() {
    log_recovery "Attempting container recovery..."
    
    if command -v podman >/dev/null 2>&1; then
        # Check pod status
        if podman pod exists secure-notes 2>/dev/null; then
            pod_status=$(podman pod inspect secure-notes --format "{{.State}}")
            
            if [ "$pod_status" = "Running" ]; then
                log_success "Pod is running"
            else
                log_warning "Pod is not running, attempting restart..."
                
                if retry_command "podman pod restart secure-notes" "Pod restart"; then
                    log_success "Pod restarted"
                    sleep 10  # Wait for services to start
                else
                    log_error "Pod restart failed"
                    return 1
                fi
            fi
        else
            log_warning "Pod does not exist, attempting to recreate..."
            
            if retry_command "make up" "Container startup"; then
                log_success "Containers started"
                sleep 15  # Wait for full startup
            else
                log_error "Container startup failed"
                return 1
            fi
        fi
    elif command -v docker >/dev/null 2>&1; then
        # Docker compose recovery
        log_recovery "Attempting Docker Compose recovery..."
        
        if retry_command "docker-compose restart" "Docker Compose restart"; then
            log_success "Docker services restarted"
            sleep 10
        else
            log_error "Docker Compose restart failed"
            return 1
        fi
    fi
    
    return 0
}

# Network error recovery
recover_network() {
    log_recovery "Attempting network recovery..."
    
    # Check for port conflicts
    ports=(3000 8080 5432 6379)
    for port in "${ports[@]}"; do
        if netstat -tlnp 2>/dev/null | grep ":$port " >/dev/null; then
            log_info "Port $port is in use"
            
            # Check if it's our service
            process=$(netstat -tlnp 2>/dev/null | grep ":$port " | awk '{print $7}' | head -1)
            if [[ "$process" =~ (node|go|postgres|redis) ]]; then
                log_info "Port $port used by expected service: $process"
            else
                log_warning "Port $port used by unexpected process: $process"
                
                # Ask user if they want to kill the process
                read -p "Kill process using port $port? (y/n): " -n 1 -r
                echo
                if [[ $REPLY =~ ^[Yy]$ ]]; then
                    pid=$(echo "$process" | cut -d'/' -f1)
                    kill "$pid" 2>/dev/null || log_warning "Could not kill process $pid"
                fi
            fi
        else
            log_warning "Port $port is not in use"
        fi
    done
    
    return 0
}

# Permission error recovery
recover_permissions() {
    log_recovery "Checking and fixing permissions..."
    
    # Fix common permission issues
    files_to_fix=(.env backend/app)
    
    for file in "${files_to_fix[@]}"; do
        if [ -f "$file" ]; then
            current_perms=$(stat -c %a "$file")
            
            case "$file" in
                .env)
                    if [ "$current_perms" != "600" ]; then
                        log_recovery "Fixing .env permissions (was $current_perms, setting to 600)"
                        chmod 600 "$file"
                    fi
                    ;;
                backend/app)
                    if [ "$current_perms" != "755" ]; then
                        log_recovery "Fixing backend binary permissions (was $current_perms, setting to 755)"
                        chmod 755 "$file"
                    fi
                    ;;
            esac
        fi
    done
    
    # Fix directory permissions
    directories=(backend frontend)
    for dir in "${directories[@]}"; do
        if [ -d "$dir" ]; then
            # Ensure directory is readable and executable
            find "$dir" -type d -exec chmod 755 {} \; 2>/dev/null || true
        fi
    done
    
    return 0
}

# Comprehensive recovery attempt
full_recovery() {
    log_recovery "Starting full system recovery..."
    
    local recovery_success=0
    
    # Step 1: Fix permissions
    if recover_permissions; then
        log_success "Permissions recovery completed"
    else
        log_error "Permissions recovery failed"
        ((recovery_success++))
    fi
    
    # Step 2: Recover containers/databases
    if recover_containers && recover_database; then
        log_success "Container and database recovery completed"
    else
        log_error "Container/database recovery failed"
        ((recovery_success++))
    fi
    
    # Step 3: Recover application services
    if recover_backend; then
        log_success "Backend recovery completed"
    else
        log_error "Backend recovery failed"
        ((recovery_success++))
    fi
    
    if recover_frontend; then
        log_success "Frontend recovery completed"
    else
        log_error "Frontend recovery failed"
        ((recovery_success++))
    fi
    
    # Step 4: Network recovery
    if recover_network; then
        log_success "Network recovery completed"
    else
        log_error "Network recovery failed"
        ((recovery_success++))
    fi
    
    # Final health check
    log_info "Performing final health check..."
    sleep 5
    
    if check_service_health "backend" "http://localhost:8080/api/v1/health"; then
        log_success "Backend final health check passed"
    else
        log_error "Backend final health check failed"
        ((recovery_success++))
    fi
    
    if check_service_health "frontend" "http://localhost:3000" 10; then
        log_success "Frontend final health check passed"
    else
        log_warning "Frontend final health check failed (may still be starting)"
    fi
    
    if [ $recovery_success -eq 0 ]; then
        log_success "Full recovery completed successfully!"
        return 0
    else
        log_error "Full recovery completed with $recovery_success errors"
        return 1
    fi
}

# Monitor for errors continuously
monitor_errors() {
    log_info "Starting error monitoring..."
    
    while true; do
        # Check backend health
        if ! check_service_health "backend" "http://localhost:8080/api/v1/health" 5; then
            log_error "Backend health check failed - attempting recovery"
            recover_backend
        fi
        
        # Check for high error rates in logs
        if command -v podman >/dev/null 2>&1; then
            error_count=$(podman logs --tail=50 secure-notes-backend 2>/dev/null | grep -i "error\|panic\|fatal" | wc -l)
            if [ "$error_count" -gt 5 ]; then
                log_warning "High error rate detected in backend logs ($error_count errors)"
            fi
        fi
        
        # Sleep before next check
        sleep 30
    done
}

# Main function
main() {
    echo -e "${BLUE}"
    cat << "EOF"
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║           🚨 SECURE NOTES ERROR HANDLER & RECOVERY 🚨          ║
║                                                                ║
║         Automated error detection and system recovery         ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
    
    init_error_handler
    
    case "${1:-help}" in
        backend)
            recover_backend
            ;;
        frontend)
            recover_frontend
            ;;
        database)
            recover_database
            ;;
        containers)
            recover_containers
            ;;
        network)
            recover_network
            ;;
        permissions)
            recover_permissions
            ;;
        full)
            full_recovery
            ;;
        monitor)
            monitor_errors
            ;;
        help|*)
            echo "Usage: $0 [backend|frontend|database|containers|network|permissions|full|monitor]"
            echo
            echo "Recovery options:"
            echo "  backend      - Recover backend service"
            echo "  frontend     - Recover frontend service"
            echo "  database     - Recover database services"
            echo "  containers   - Recover container infrastructure"
            echo "  network      - Recover network connectivity"
            echo "  permissions  - Fix file permissions"
            echo "  full         - Full system recovery (recommended)"
            echo "  monitor      - Continuous error monitoring"
            echo
            echo "Examples:"
            echo "  $0 full              # Comprehensive recovery"
            echo "  $0 backend           # Just fix backend"
            echo "  $0 monitor           # Start monitoring"
            echo
            ;;
    esac
    
    log_info "Recovery logs saved to: $RECOVERY_LOG"
    log_info "Error logs saved to: $ERROR_LOG"
}

# Run main function
main "$@"