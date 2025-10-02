#!/bin/bash
# Note: Prefer leaflock.sh troubleshoot for quick checks; this script offers an in-depth interactive flow.

# LeafLock Troubleshooting Tool
# Diagnoses and fixes common deployment issues

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Status symbols
CHECKMARK="✓"
CROSS="✗"
WARNING="⚠"
INFO="ℹ"
WRENCH="🔧"
SEARCH="🔍"

# Logging functions
log_info() {
    echo -e "${BLUE}${INFO}${NC} $1"
}

log_success() {
    echo -e "${GREEN}${CHECKMARK}${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}${WARNING}${NC} $1"
}

log_error() {
    echo -e "${RED}${CROSS}${NC} $1"
}

log_section() {
    echo -e "${CYAN}━━━ $1 ━━━${NC}"
}

log_fix() {
    echo -e "${PURPLE}${WRENCH}${NC} $1"
}

log_search() {
    echo -e "${BLUE}${SEARCH}${NC} $1"
}

# Function to collect system information
collect_system_info() {
    log_section "System Information"
    
    echo "Timestamp: $(date)"
    echo "User: $(whoami)"
    echo "Working Directory: $(pwd)"
    
    # Operating System
    if [[ -f /etc/os-release ]]; then
        echo "OS: $(grep PRETTY_NAME /etc/os-release | cut -d'"' -f2)"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo "OS: macOS $(sw_vers -productVersion)"
    else
        echo "OS: Unknown"
    fi
    
    # System resources
    if command -v free &> /dev/null; then
        echo "Memory: $(free -h | grep '^Mem:' | awk '{print $2 " total, " $3 " used, " $7 " available"}')"
    fi
    
    if command -v df &> /dev/null; then
        echo "Disk Space: $(df -h . | tail -1 | awk '{print $4 " available (" $5 " used)"}')"
    fi
    
    # Network connectivity
    log_info "Testing network connectivity..."
    if ping -c 1 8.8.8.8 &> /dev/null; then
        log_success "Internet connectivity: Available"
    else
        log_error "Internet connectivity: Failed"
    fi
}

# Function to diagnose Docker issues
diagnose_docker() {
    log_section "Docker Diagnosis"
    
    # Check Docker installation
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed"
        echo "Fix: Install Docker from https://docs.docker.com/get-docker/"
        return 1
    fi
    
    log_success "Docker CLI is available"
    
    # Check Docker daemon
    if ! docker info &> /dev/null; then
        log_error "Docker daemon is not running"
        log_fix "Try: sudo systemctl start docker (Linux) or start Docker Desktop"
        return 1
    fi
    
    log_success "Docker daemon is running"
    
    # Check Docker Compose
    if ! docker compose version &> /dev/null; then
        log_error "Docker Compose is not available"
        log_fix "Docker Compose v2 is required. Update Docker to latest version."
        return 1
    fi
    
    log_success "Docker Compose is available"
    
    # Check for running containers
    cd "$PROJECT_ROOT"
    local containers
    containers=$(docker compose ps -q 2>/dev/null || echo "")
    
    if [[ -n "$containers" ]]; then
        log_info "Found running containers:"
        docker compose ps
        
        # Check container health
        while read -r container_id; do
            if [[ -n "$container_id" ]]; then
                local container_name
                container_name=$(docker inspect "$container_id" --format '{{.Name}}' | sed 's|^/||')
                local health_status
                health_status=$(docker inspect "$container_id" --format='{{.State.Health.Status}}' 2>/dev/null || echo "none")
                
                case "$health_status" in
                    healthy)
                        log_success "Container $container_name is healthy"
                        ;;
                    unhealthy)
                        log_error "Container $container_name is unhealthy"
                        log_fix "Check logs: docker logs $container_name"
                        ;;
                    starting)
                        log_warn "Container $container_name health check is starting"
                        ;;
                    none)
                        local container_status
                        container_status=$(docker inspect "$container_id" --format='{{.State.Status}}')
                        if [[ "$container_status" == "running" ]]; then
                            log_info "Container $container_name is running (no health check)"
                        else
                            log_error "Container $container_name is not running (status: $container_status)"
                        fi
                        ;;
                esac
            fi
        done <<< "$containers"
    else
        log_warn "No containers are currently running"
        log_fix "Start services with: ./scripts/deploy-docker.sh"
    fi
}

# Function to diagnose Kubernetes issues
diagnose_kubernetes() {
    local namespace="${1:-leaflock}"
    
    log_section "Kubernetes Diagnosis"
    
    # Check kubectl
    if ! command -v kubectl &> /dev/null; then
        log_error "kubectl is not installed"
        log_fix "Install kubectl: https://kubernetes.io/docs/tasks/tools/"
        return 1
    fi
    
    log_success "kubectl is available"
    
    # Check cluster connectivity
    if ! kubectl cluster-info &> /dev/null; then
        log_error "Cannot connect to Kubernetes cluster"
        log_fix "Check kubeconfig: kubectl config current-context"
        return 1
    fi
    
    log_success "Connected to Kubernetes cluster"
    
    # Check namespace
    if ! kubectl get namespace "$namespace" &> /dev/null; then
        log_error "Namespace $namespace does not exist"
        log_fix "Create namespace: kubectl create namespace $namespace"
        return 1
    fi
    
    log_success "Namespace $namespace exists"
    
    # Check deployments
    local deployments
    deployments=$(kubectl get deployments -n "$namespace" --no-headers 2>/dev/null || echo "")
    
    if [[ -n "$deployments" ]]; then
        log_info "Deployments in namespace $namespace:"
        echo "$deployments"
        
        # Analyze each deployment
        while read -r line; do
            if [[ -n "$line" ]]; then
                local name ready uptodate available
                read -r name ready uptodate available _ <<< "$line"
                
                if [[ "$ready" == "$available" ]] && [[ "$available" != "0" ]]; then
                    log_success "Deployment $name is healthy ($ready/$available)"
                else
                    log_error "Deployment $name has issues ($ready/$available)"
                    log_fix "Check deployment: kubectl describe deployment $name -n $namespace"
                fi
            fi
        done <<< "$deployments"
    else
        log_warn "No deployments found in namespace $namespace"
    fi
    
    # Check pods
    local pods
    pods=$(kubectl get pods -n "$namespace" --no-headers 2>/dev/null || echo "")
    
    if [[ -n "$pods" ]]; then
        log_info "Analyzing pod status..."
        
        local running_count=0
        local total_count=0
        
        while read -r line; do
            if [[ -n "$line" ]]; then
                ((total_count++))
                local name ready status restarts
                read -r name ready status restarts _ <<< "$line"
                
                case "$status" in
                    Running)
                        ((running_count++))
                        if [[ "$ready" == "1/1" ]]; then
                            log_success "Pod $name is running and ready"
                        else
                            log_warn "Pod $name is running but not ready ($ready)"
                        fi
                        ;;
                    Pending|ContainerCreating)
                        log_warn "Pod $name is pending/creating"
                        log_fix "Check events: kubectl describe pod $name -n $namespace"
                        ;;
                    ImagePullBackOff|ErrImagePull)
                        log_error "Pod $name has image pull issues"
                        log_fix "Check image availability and pull secrets"
                        ;;
                    CrashLoopBackOff)
                        log_error "Pod $name is crash looping"
                        log_fix "Check logs: kubectl logs $name -n $namespace"
                        ;;
                    Error|Failed)
                        log_error "Pod $name has failed"
                        log_fix "Check logs and events: kubectl describe pod $name -n $namespace"
                        ;;
                    *)
                        log_warn "Pod $name has status: $status"
                        ;;
                esac
                
                # Check restart count
                if [[ "$restarts" -gt 5 ]]; then
                    log_warn "Pod $name has high restart count: $restarts"
                fi
            fi
        done <<< "$pods"
        
        log_info "Pod summary: $running_count/$total_count running"
    else
        log_warn "No pods found in namespace $namespace"
    fi
    
    # Check services
    log_info "Checking services..."
    local services
    services=$(kubectl get services -n "$namespace" --no-headers 2>/dev/null || echo "")
    
    if [[ -n "$services" ]]; then
        while read -r line; do
            if [[ -n "$line" ]]; then
                local name type cluster_ip
                read -r name type cluster_ip _ <<< "$line"
                log_success "Service $name ($type) at $cluster_ip"
            fi
        done <<< "$services"
    fi
    
    # Check helm releases
    if command -v helm &> /dev/null; then
        log_info "Checking Helm releases..."
        local releases
        releases=$(helm list -n "$namespace" --no-headers 2>/dev/null || echo "")
        
        if [[ -n "$releases" ]]; then
            while read -r line; do
                if [[ -n "$line" ]]; then
                    local name namespace revision updated status chart app_version
                    read -r name namespace revision updated status chart app_version <<< "$line"
                    
                    case "$status" in
                        deployed)
                            log_success "Helm release $name is deployed (revision $revision)"
                            ;;
                        failed)
                            log_error "Helm release $name has failed"
                            log_fix "Check release: helm status $name -n $namespace"
                            ;;
                        *)
                            log_warn "Helm release $name status: $status"
                            ;;
                    esac
                fi
            done <<< "$releases"
        else
            log_info "No Helm releases found"
        fi
    fi
}

# Function to diagnose network issues
diagnose_network() {
    log_section "Network Diagnosis"
    
    # Test DNS resolution
    log_search "Testing DNS resolution..."
    if nslookup google.com &> /dev/null; then
        log_success "DNS resolution is working"
    else
        log_error "DNS resolution failed"
        log_fix "Check /etc/resolv.conf or network settings"
    fi
    
    # Test port connectivity
    local ports_to_test=(
        "localhost:8080:Backend API"
        "localhost:3000:Frontend"
        "localhost:5432:PostgreSQL"
        "localhost:6379:Redis"
    )
    
    log_search "Testing port connectivity..."
    for port_info in "${ports_to_test[@]}"; do
        local host port service
        IFS=':' read -r host port service <<< "$port_info"

        if timeout 5 bash -c "cat < /dev/null > /dev/tcp/$host/$port" 2>/dev/null; then
            log_success "$service ($host:$port) is reachable"
        else
            log_warn "$service ($host:$port) is not reachable"
        fi
    done
    
    # Check Docker network (if Docker is available)
    if command -v docker &> /dev/null && docker info &> /dev/null; then
        log_search "Checking Docker networks..."
        local networks
        networks=$(docker network ls --filter name=leaflock --format "{{.Name}}" 2>/dev/null || echo "")
        
        if [[ -n "$networks" ]]; then
            while read -r network; do
                if [[ -n "$network" ]]; then
                    log_success "Docker network $network exists"
                    
                    # Check connected containers
                    local containers
                    containers=$(docker network inspect "$network" --format '{{range .Containers}}{{.Name}} {{end}}' 2>/dev/null || echo "")
                    if [[ -n "$containers" ]]; then
                        log_info "Connected containers: $containers"
                    fi
                fi
            done <<< "$networks"
        else
            log_warn "No leaflock Docker networks found"
        fi
    fi
}

# Function to diagnose environment issues
diagnose_environment() {
    log_section "Environment Diagnosis"
    
    cd "$PROJECT_ROOT"
    
    # Check .env file
    if [[ ! -f ".env" ]]; then
        log_error ".env file not found"
        log_fix "Create .env file: cp .env.example .env"
        return 1
    fi
    
    log_success ".env file exists"
    
    # Validate environment file
    if [[ -x "./scripts/env-setup.sh" ]]; then
        log_search "Validating environment configuration..."
        if ./scripts/env-setup.sh validate; then
            log_success "Environment configuration is valid"
        else
            log_error "Environment configuration has issues"
            log_fix "Fix environment: ./scripts/env-setup.sh setup"
        fi
    fi
    
    # Check file permissions
    local env_perms
    env_perms=$(stat -c "%a" .env 2>/dev/null || stat -f "%A" .env 2>/dev/null || echo "unknown")
    
    if [[ "$env_perms" == "600" ]]; then
        log_success ".env file has secure permissions (600)"
    else
        log_warn ".env file permissions: $env_perms (should be 600)"
        log_fix "Fix permissions: chmod 600 .env"
    fi
    
    # Check for required directories
    local required_dirs=("backend" "frontend" "scripts")
    for dir in "${required_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            log_success "Directory $dir exists"
        else
            log_error "Directory $dir is missing"
        fi
    done
    
    # Check for required files
    local required_files=(
        "docker-compose.yml"
        "backend/Dockerfile"
        "frontend/Dockerfile"
        "backend/go.mod"
        "frontend/package.json"
    )
    
    for file in "${required_files[@]}"; do
        if [[ -f "$file" ]]; then
            log_success "File $file exists"
        else
            log_error "File $file is missing"
        fi
    done
}

# Function to diagnose specific service issues
diagnose_service() {
    local service="$1"
    local deployment_type="${2:-auto}"
    
    log_section "Service Diagnosis: $service"
    
    case "$service" in
        backend|api)
            # Test backend health
            log_search "Testing backend health..."
            if curl -sf http://localhost:8080/api/v1/health >/dev/null 2>&1; then
                log_success "Backend health endpoint is responding"
            else
                log_error "Backend health endpoint is not responding"
                
                if [[ "$deployment_type" == "docker" ]] || docker ps | grep -q leaflock-backend; then
                    log_fix "Check backend logs: docker logs leaflock-backend"
                    log_fix "Restart backend: docker compose restart backend"
                elif [[ "$deployment_type" == "k8s" ]] || kubectl get pods -n leaflock | grep -q backend; then
                    log_fix "Check backend logs: kubectl logs -l app=leaflock-backend -n leaflock"
                    log_fix "Restart backend: kubectl rollout restart deployment/leaflock-backend -n leaflock"
                else
                    log_fix "Check if backend service is running"
                fi
            fi
            ;;
            
        frontend|web)
            # Test frontend
            log_search "Testing frontend..."
            if curl -sf http://localhost:3000 >/dev/null 2>&1; then
                log_success "Frontend is responding"
            else
                log_error "Frontend is not responding"
                
                if [[ "$deployment_type" == "docker" ]] || docker ps | grep -q leaflock-frontend; then
                    log_fix "Check frontend logs: docker logs leaflock-frontend"
                    log_fix "Restart frontend: docker compose restart frontend"
                elif [[ "$deployment_type" == "k8s" ]] || kubectl get pods -n leaflock | grep -q frontend; then
                    log_fix "Check frontend logs: kubectl logs -l app=leaflock-frontend -n leaflock"
                    log_fix "Restart frontend: kubectl rollout restart deployment/leaflock-frontend -n leaflock"
                else
                    log_fix "Check if frontend service is running"
                fi
            fi
            ;;
            
        database|postgres|db)
            # Test database connectivity
            log_search "Testing database connectivity..."
            
            if command -v psql &> /dev/null; then
                local db_url="postgres://postgres:password@localhost:5432/notes"
                if [[ -f ".env" ]]; then
                    # Try to extract password from .env
                    local db_pass
                    db_pass=$(grep "^POSTGRES_PASSWORD=" .env | cut -d'=' -f2 2>/dev/null || echo "")
                    if [[ -n "$db_pass" ]]; then
                        db_url="postgres://postgres:$db_pass@localhost:5432/notes"
                    fi
                fi
                
                if psql "$db_url" -c "SELECT 1;" &>/dev/null; then
                    log_success "Database is accessible"
                else
                    log_error "Cannot connect to database"
                    
                    if docker ps | grep -q leaflock-postgres; then
                        log_fix "Check database logs: docker logs leaflock-postgres"
                        log_fix "Check database status: docker compose exec postgres pg_isready"
                    else
                        log_fix "Database container may not be running"
                    fi
                fi
            else
                log_warn "psql not available for database testing"
            fi
            ;;
            
        redis|cache)
            # Test Redis connectivity
            log_search "Testing Redis connectivity..."
            
            if command -v redis-cli &> /dev/null; then
                if redis-cli -h localhost -p 6379 ping | grep -q "PONG"; then
                    log_success "Redis is accessible"
                else
                    log_error "Cannot connect to Redis"
                    
                    if docker ps | grep -q leaflock-redis; then
                        log_fix "Check Redis logs: docker logs leaflock-redis"
                        log_fix "Check Redis status: docker compose exec redis redis-cli ping"
                    else
                        log_fix "Redis container may not be running"
                    fi
                fi
            else
                log_warn "redis-cli not available for Redis testing"
            fi
            ;;
            
        *)
            log_error "Unknown service: $service"
            echo "Available services: backend, frontend, database, redis"
            return 1
            ;;
    esac
}

# Function to generate diagnostic report
generate_diagnostic_report() {
    local output_file="${1:-diagnostic-report-$(date +%Y%m%d_%H%M%S).txt}"
    
    log_section "Generating Diagnostic Report"
    
    {
        echo "LeafLock Diagnostic Report"
        echo "=============================="
        echo "Generated: $(date)"
        echo "User: $(whoami)"
        echo "Directory: $(pwd)"
        echo
        
        # Collect all diagnostic information
        collect_system_info
        echo
        diagnose_environment
        echo
        diagnose_docker
        echo
        diagnose_network
        echo
        
        # Try Kubernetes if available
        if command -v kubectl &> /dev/null && kubectl cluster-info &> /dev/null; then
            diagnose_kubernetes
            echo
        fi
        
        # Service-specific diagnostics
        for service in backend frontend database redis; do
            diagnose_service "$service"
            echo
        done
        
    } > "$output_file" 2>&1
    
    log_success "Diagnostic report saved to: $output_file"
    
    # Also display summary
    echo
    log_section "Diagnostic Summary"
    grep -E "(✓|✗|⚠)" "$output_file" | tail -20
}

# Function to provide quick fixes
quick_fixes() {
    log_section "Quick Fixes for Common Issues"
    
    echo "1. Services not starting:"
    echo "   • Check Docker daemon: sudo systemctl status docker"
    echo "   • Recreate services: docker compose down && docker compose up -d"
    echo "   • Check port conflicts: sudo netstat -tulpn | grep :8080"
    echo
    
    echo "2. Permission issues:"
    echo "   • Fix .env permissions: chmod 600 .env"
    echo "   • Fix script permissions: chmod +x scripts/*.sh"
    echo "   • Check Docker socket: sudo chmod 666 /var/run/docker.sock"
    echo
    
    echo "3. Environment issues:"
    echo "   • Generate new .env: ./scripts/env-setup.sh setup"
    echo "   • Validate config: ./scripts/env-setup.sh validate"
    echo "   • Reset to defaults: cp .env.example .env"
    echo
    
    echo "4. Network connectivity:"
    echo "   • Reset Docker network: docker network prune"
    echo "   • Check firewall: sudo ufw status"
    echo "   • Test with curl: curl -v http://localhost:8080/api/v1/health"
    echo
    
    echo "5. Database issues:"
    echo "   • Reset database: docker compose down -v && docker compose up -d"
    echo "   • Check logs: docker logs leaflock-postgres"
    echo "   • Connect manually: docker compose exec postgres psql -U postgres"
    echo
    
    echo "6. Image issues (Kubernetes):"
    echo "   • Build images: ./scripts/build.sh build"
    echo "   • Load to kind: kind load docker-image leaflock/backend:latest"
    echo "   • Check image pull policy: kubectl describe pod <pod-name>"
    echo
}

# Main function
main() {
    local action="${1:-full}"
    shift || true
    
    case "$action" in
        full|all)
            log_section "Full Diagnostic Scan"
            collect_system_info
            echo
            diagnose_environment
            echo
            diagnose_docker
            echo
            diagnose_network
            echo
            
            # Auto-detect and diagnose Kubernetes if available
            if command -v kubectl &> /dev/null && kubectl cluster-info &> /dev/null; then
                diagnose_kubernetes "${1:-leaflock}"
                echo
            fi
            ;;
            
        docker)
            diagnose_docker
            ;;
            
        k8s|kubernetes)
            diagnose_kubernetes "${1:-leaflock}"
            ;;
            
        network)
            diagnose_network
            ;;
            
        env|environment)
            diagnose_environment
            ;;
            
        service)
            local service="${1:-backend}"
            local deployment="${2:-auto}"
            diagnose_service "$service" "$deployment"
            ;;
            
        report)
            generate_diagnostic_report "$1"
            ;;
            
        fixes|help)
            quick_fixes
            ;;
            
        --help|-h)
            cat <<EOF
Usage: $0 COMMAND [OPTIONS]

Commands:
  full                          Run full diagnostic scan (default)
  docker                        Diagnose Docker deployment issues
  k8s [NAMESPACE]              Diagnose Kubernetes deployment issues  
  network                       Diagnose network connectivity issues
  environment                   Diagnose environment configuration
  service SERVICE [TYPE]        Diagnose specific service
  report [FILE]                 Generate diagnostic report
  fixes                         Show quick fixes for common issues
  --help                        Show this help

Services:
  backend, frontend, database, redis

Deployment Types:
  docker, k8s, auto (default)

Examples:
  $0                           # Full diagnostic scan
  $0 docker                    # Check Docker deployment
  $0 k8s leaflock          # Check Kubernetes in namespace
  $0 service backend docker    # Check backend service in Docker
  $0 report my-report.txt      # Generate diagnostic report
  $0 fixes                     # Show common fixes

Exit Codes:
  0 - No major issues found
  1 - Issues detected that need attention
EOF
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
    log_error "Required command 'curl' is not installed"
    exit 1
fi

# Run main function
main "$@"
