#!/bin/bash

# Development Debugging and Error Analysis Tools
# Comprehensive debugging utilities for LeafLock application

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
LOG_DIR="/tmp/leaflock-debug"
DEBUG_PORT=2345
PPROF_PORT=6060

# Logging functions
log_info() {
    echo -e "${BLUE}[DEBUG]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_section() {
    echo -e "${PURPLE}[SECTION]${NC} $1"
}

# Create debug log directory
setup_debug_environment() {
    mkdir -p "$LOG_DIR"
    log_info "Debug environment setup at: $LOG_DIR"
}

# System health check
health_check() {
    log_section "System Health Check"
    
    # Check if services are running
    log_info "Checking service status..."
    
    if curl -sf http://localhost:8080/api/v1/health >/dev/null 2>&1; then
        log_success "Backend service is healthy"
    else
        log_error "Backend service is not responding"
        log_info "Backend troubleshooting:"
        echo "  - Check if containers are running: make status"
        echo "  - View backend logs: make logs"
        echo "  - Restart services: make restart"
    fi
    
    if curl -sf http://localhost:3000 >/dev/null 2>&1; then
        log_success "Frontend service is accessible"
    else
        log_warning "Frontend service may not be running on port 3000"
        log_info "Frontend troubleshooting:"
        echo "  - Start frontend: cd frontend && npm run dev"
        echo "  - Check Vite process: ps aux | grep vite"
    fi
    
    # Check database connectivity
    log_info "Checking database connectivity..."
    if command -v podman >/dev/null 2>&1; then
        if podman exec leaflock-postgres pg_isready -U postgres >/dev/null 2>&1; then
            log_success "PostgreSQL is ready"
        else
            log_error "PostgreSQL connection failed"
        fi
        
        if podman exec leaflock-redis redis-cli ping >/dev/null 2>&1; then
            log_success "Redis is ready"
        else
            log_error "Redis connection failed"
        fi
    fi
}

# Analyze logs for common issues
analyze_logs() {
    log_section "Log Analysis"
    
    # Backend logs analysis
    log_info "Analyzing backend logs for errors..."
    if command -v podman >/dev/null 2>&1; then
        # Get recent backend logs
        podman logs --tail=100 leaflock-backend 2>/dev/null | tee "$LOG_DIR/backend-recent.log" | {
            error_count=$(grep -ci "error\|panic\|fatal")
            warn_count=$(grep -ci "warn")
            
            echo "Error patterns found:"
            echo "  Errors/Panics/Fatals: $error_count"
            echo "  Warnings: $warn_count"
            
            if [ "$error_count" -gt 0 ]; then
                log_warning "Recent errors found:"
                grep -i "error\|panic\|fatal" "$LOG_DIR/backend-recent.log" | tail -5
            fi
        }
    fi
    
    # System logs
    log_info "Checking system logs for issues..."
    if [ -f /var/log/syslog ]; then
        grep -i "leaflock\|docker\|podman" /var/log/syslog | tail -10 > "$LOG_DIR/system.log" || true
    fi
    
    # Development logs
    if [ -f /tmp/leaflock-dev.log ]; then
        log_info "Analyzing development logs..."
        tail -100 /tmp/leaflock-dev.log > "$LOG_DIR/development.log"
        
        error_count=$(grep -ci "error\|failed\|exception" "$LOG_DIR/development.log")
        if [ "$error_count" -gt 0 ]; then
            log_warning "Development errors found:"
            grep -i "error\|failed\|exception" "$LOG_DIR/development.log" | tail -3
        fi
    fi
}

# Network connectivity debug
network_debug() {
    log_section "Network Connectivity Debug"
    
    # Port checks
    log_info "Checking port availability..."
    
    ports=(3000 8080 5432 6379)
    for port in "${ports[@]}"; do
        if netstat -tlnp 2>/dev/null | grep ":$port " >/dev/null; then
            log_success "Port $port is in use"
        else
            log_warning "Port $port is not in use"
        fi
    done
    
    # DNS resolution
    log_info "Checking DNS resolution..."
    if nslookup localhost >/dev/null 2>&1; then
        log_success "localhost resolves correctly"
    else
        log_warning "localhost resolution issues"
    fi
    
    # CORS check
    log_info "Testing CORS configuration..."
    cors_response=$(curl -s -H "Origin: http://localhost:3000" \
                         -H "Access-Control-Request-Method: GET" \
                         -X OPTIONS \
                         http://localhost:8080/api/v1/health 2>/dev/null || echo "failed")
    
    if [[ "$cors_response" != "failed" ]]; then
        log_success "CORS preflight request successful"
    else
        log_warning "CORS preflight request failed"
    fi
}

# Database debug
database_debug() {
    log_section "Database Debug"
    
    if command -v podman >/dev/null 2>&1; then
        # PostgreSQL debug
        log_info "PostgreSQL diagnostics..."
        
        # Connection count
        conn_count=$(podman exec leaflock-postgres psql -U postgres -d notes -t -c "SELECT count(*) FROM pg_stat_activity;" 2>/dev/null || echo "0")
        log_info "Active connections: $conn_count"
        
        # Database size
        db_size=$(podman exec leaflock-postgres psql -U postgres -d notes -t -c "SELECT pg_size_pretty(pg_database_size('notes'));" 2>/dev/null || echo "unknown")
        log_info "Database size: $db_size"
        
        # Recent queries
        log_info "Getting slow query statistics..."
        podman exec leaflock-postgres psql -U postgres -d notes -c "
            SELECT query, mean_time, calls, total_time 
            FROM pg_stat_statements 
            ORDER BY mean_time DESC 
            LIMIT 5;" 2>/dev/null || log_warning "pg_stat_statements not available"
        
        # Redis debug
        log_info "Redis diagnostics..."
        
        # Redis info
        redis_info=$(podman exec leaflock-redis redis-cli info memory 2>/dev/null || echo "failed")
        if [[ "$redis_info" != "failed" ]]; then
            echo "$redis_info" | grep -E "used_memory_human|maxmemory_human" || true
        fi
        
        # Session count
        session_count=$(podman exec leaflock-redis redis-cli eval "return #redis.call('keys', 'session:*')" 0 2>/dev/null || echo "0")
        log_info "Active sessions: $session_count"
    fi
}

# Performance analysis
performance_debug() {
    log_section "Performance Analysis"
    
    # System resources
    log_info "System resource usage:"
    
    # Memory usage
    free -h | grep -E "Mem:|Swap:"
    
    # CPU load
    uptime
    
    # Disk usage
    df -h | grep -E "/$|/var|/tmp"
    
    # Process monitoring
    log_info "Top processes consuming resources:"
    ps aux --sort=-%cpu | head -10
    
    # Container resource usage
    if command -v podman >/dev/null 2>&1; then
        log_info "Container resource usage:"
        podman stats --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}" 2>/dev/null || log_warning "Could not get container stats"
    fi
}

# Application-specific debug
app_debug() {
    log_section "Application Debug"
    
    # Backend debug
    log_info "Backend application diagnostics..."
    
    # Check Go version
    if command -v go >/dev/null 2>&1; then
        log_info "Go version: $(go version)"
    fi
    
    # Check if backend binary exists and is recent
    if [ -f backend/app ]; then
        backend_age=$(stat -c %Y backend/app 2>/dev/null || echo "0")
        current_time=$(date +%s)
        age_minutes=$(( (current_time - backend_age) / 60 ))
        log_info "Backend binary age: ${age_minutes} minutes"
    fi
    
    # Frontend debug
    log_info "Frontend application diagnostics..."
    
    # Check Node.js version
    if command -v node >/dev/null 2>&1; then
        log_info "Node.js version: $(node --version)"
        log_info "npm version: $(npm --version)"
    fi
    
    # Check if frontend build exists
    if [ -d frontend/dist ]; then
        build_age=$(stat -c %Y frontend/dist 2>/dev/null || echo "0")
        current_time=$(date +%s)
        age_minutes=$(( (current_time - build_age) / 60 ))
        log_info "Frontend build age: ${age_minutes} minutes"
    fi
    
    # Check for common configuration issues
    log_info "Configuration validation..."
    
    # Environment file check
    if [ -f .env ]; then
        log_success ".env file exists"
        
        # Check for empty values
        empty_vars=$(grep -cE "^[A-Z_]+=$" .env)
        if [ "$empty_vars" -gt 0 ]; then
            log_warning "$empty_vars environment variables are empty"
            grep -E "^[A-Z_]+=$" .env | head -3
        fi
    else
        log_error ".env file missing - run ./dev-setup.sh to create it"
    fi
}

# Security debug
security_debug() {
    log_section "Security Debug"
    
    # File permissions check
    log_info "Checking critical file permissions..."
    
    files_to_check=(.env backend/app)
    for file in "${files_to_check[@]}"; do
        if [ -f "$file" ]; then
            perms=$(stat -c %A "$file")
            log_info "$file permissions: $perms"
            
            # Check if .env is too permissive
            if [[ "$file" == ".env" && "$perms" == *"r--r--r--"* ]]; then
                log_warning ".env file is world-readable - consider: chmod 600 .env"
            fi
        fi
    done
    
    # Port security check
    log_info "Checking for services listening on all interfaces..."
    netstat -tlnp 2>/dev/null | grep "0.0.0.0:" | head -5 || true
    
    # SSL/TLS check
    if curl -k https://localhost:8080/api/v1/health >/dev/null 2>&1; then
        log_info "HTTPS endpoint is accessible"
    else
        log_info "HTTPS endpoint not available (development mode)"
    fi
}

# Generate debug report
generate_report() {
    log_section "Generating Debug Report"
    
    report_file="$LOG_DIR/debug-report-$(date +%Y%m%d-%H%M%S).txt"
    
    {
        echo "LeafLock Debug Report"
        echo "Generated: $(date)"
        echo "System: $(uname -a)"
        echo "=========================="
        echo
        
        echo "SYSTEM INFORMATION"
        echo "---------------"
        uptime
        free -h
        df -h
        echo
        
        echo "SERVICE STATUS"
        echo "-------------"
        if command -v podman >/dev/null 2>&1; then
            podman ps -a --pod
        elif command -v docker >/dev/null 2>&1; then
            docker ps -a
        fi
        echo
        
        echo "NETWORK INFORMATION"
        echo "------------------"
        netstat -tlnp | grep -E ":(3000|8080|5432|6379)"
        echo
        
        echo "RECENT ERRORS"
        echo "------------"
        if [ -f "$LOG_DIR/backend-recent.log" ]; then
            grep -i "error\|panic\|fatal" "$LOG_DIR/backend-recent.log" | tail -10
        fi
        echo
        
        echo "ENVIRONMENT VARIABLES"
        echo "-------------------"
        env | grep -E "^(NODE_|GO|PATH|PORT|DATABASE_URL|REDIS_URL)" | sort
        echo
        
    } > "$report_file"
    
    log_success "Debug report saved to: $report_file"
}

# Interactive debugging session
interactive_debug() {
    log_section "Interactive Debug Session"
    
    echo "Available debug commands:"
    echo "1. Health check"
    echo "2. Log analysis"
    echo "3. Network debug"
    echo "4. Database debug"
    echo "5. Performance analysis"
    echo "6. Application debug"
    echo "7. Security debug"
    echo "8. Generate full report"
    echo "9. Exit"
    echo
    
    while true; do
        read -p "Select option (1-9): " choice
        
        case $choice in
            1) health_check ;;
            2) analyze_logs ;;
            3) network_debug ;;
            4) database_debug ;;
            5) performance_debug ;;
            6) app_debug ;;
            7) security_debug ;;
            8) generate_report ;;
            9) log_info "Exiting debug session"; break ;;
            *) log_warning "Invalid option. Please select 1-9." ;;
        esac
        
        echo
        read -p "Press Enter to continue..."
        echo
    done
}

# Main function
main() {
    echo -e "${BLUE}"
    cat << "EOF"
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║          🐛 SECURE NOTES DEBUG & ERROR ANALYSIS 🐛             ║
║                                                                ║
║        Comprehensive debugging tools for development          ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
    
    setup_debug_environment
    
    case "${1:-interactive}" in
        health)
            health_check
            ;;
        logs)
            analyze_logs
            ;;
        network)
            network_debug
            ;;
        database)
            database_debug
            ;;
        performance)
            performance_debug
            ;;
        app)
            app_debug
            ;;
        security)
            security_debug
            ;;
        report)
            health_check
            analyze_logs
            network_debug
            database_debug
            performance_debug
            app_debug
            security_debug
            generate_report
            ;;
        interactive)
            interactive_debug
            ;;
        *)
            echo "Usage: $0 [health|logs|network|database|performance|app|security|report|interactive]"
            echo
            echo "Available modes:"
            echo "  health       - Basic health checks"
            echo "  logs         - Log analysis"
            echo "  network      - Network connectivity debug"
            echo "  database     - Database diagnostics"
            echo "  performance  - Performance analysis"
            echo "  app          - Application-specific debug"
            echo "  security     - Security debug"
            echo "  report       - Generate full debug report"
            echo "  interactive  - Interactive debug session (default)"
            exit 1
            ;;
    esac
    
    log_info "Debug logs saved to: $LOG_DIR"
}

# Run main function
main "$@"
