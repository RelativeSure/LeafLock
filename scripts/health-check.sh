#!/bin/bash

# Secure Notes Health Check and Monitoring Tool
# Comprehensive health monitoring for all deployment targets

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Default endpoints
BACKEND_URL="${BACKEND_URL:-http://localhost:8080}"
FRONTEND_URL="${FRONTEND_URL:-http://localhost:3000}"

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
CLOCK="🕒"

# Logging functions with status symbols
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

log_waiting() {
    echo -e "${PURPLE}${CLOCK}${NC} $1"
}

# Global health tracking
declare -g TOTAL_CHECKS=0
declare -g PASSED_CHECKS=0
declare -g FAILED_CHECKS=0
declare -g WARNING_CHECKS=0

# Function to record check result
record_check() {
    local status="$1"  # pass, fail, warn
    ((TOTAL_CHECKS++))
    
    case "$status" in
        pass) ((PASSED_CHECKS++)) ;;
        fail) ((FAILED_CHECKS++)) ;;
        warn) ((WARNING_CHECKS++)) ;;
    esac
}

# Function to test HTTP endpoint
test_http_endpoint() {
    local url="$1"
    local name="$2"
    local timeout="${3:-10}"
    local expected_code="${4:-200}"
    
    log_info "Testing $name: $url"
    
    local response_code
    local response_time
    local response_body
    
    # Use curl to test endpoint
    if response_code=$(curl -s -o /dev/null -w "%{http_code},%{time_total}" \
                      --connect-timeout "$timeout" \
                      --max-time "$timeout" \
                      --fail-with-body \
                      "$url" 2>/dev/null); then
        
        IFS=',' read -r code time <<< "$response_code"
        response_time=$(printf "%.3f" "$time")
        
        if [[ "$code" == "$expected_code" ]]; then
            log_success "$name is healthy (${code}, ${response_time}s)"
            record_check "pass"
            return 0
        else
            log_error "$name returned unexpected status: $code"
            record_check "fail"
            return 1
        fi
    else
        log_error "$name is unreachable or failed"
        record_check "fail"
        return 1
    fi
}

# Function to test database connectivity
test_database() {
    local db_type="$1"  # postgres or redis
    local connection_string="$2"
    
    log_info "Testing $db_type database connectivity"
    
    case "$db_type" in
        postgres)
            if command -v psql &> /dev/null; then
                if psql "$connection_string" -c "SELECT 1;" &>/dev/null; then
                    log_success "PostgreSQL database is accessible"
                    record_check "pass"
                    return 0
                else
                    log_error "PostgreSQL database connection failed"
                    record_check "fail"
                    return 1
                fi
            else
                log_warn "psql not available, skipping PostgreSQL test"
                record_check "warn"
                return 1
            fi
            ;;
            
        redis)
            if command -v redis-cli &> /dev/null; then
                local host port password
                # Parse Redis URL (simplified)
                if [[ "$connection_string" =~ redis://?([^:]+)?:?([^@]+)?@?([^:]+):([0-9]+) ]]; then
                    host="${BASH_REMATCH[3]:-localhost}"
                    port="${BASH_REMATCH[4]:-6379}"
                else
                    host="localhost"
                    port="6379"
                fi
                
                if redis-cli -h "$host" -p "$port" ping | grep -q "PONG"; then
                    log_success "Redis database is accessible"
                    record_check "pass"
                    return 0
                else
                    log_error "Redis database connection failed"
                    record_check "fail"
                    return 1
                fi
            else
                log_warn "redis-cli not available, skipping Redis test"
                record_check "warn"
                return 1
            fi
            ;;
    esac
}

# Function to test API endpoints
test_api_endpoints() {
    local base_url="$1"
    
    log_section "API Endpoint Health Checks"
    
    # Test health endpoint
    test_http_endpoint "$base_url/api/v1/health" "Health Check" 5 200
    
    # Test if API is responsive (may return different codes for auth)
    local endpoints=(
        "/api/v1/auth/status:401"  # Should return 401 without auth
        "/api/v1/notes:401"        # Should return 401 without auth
    )
    
    for endpoint in "${endpoints[@]}"; do
        IFS':' read -r path expected <<< "$endpoint"
        test_http_endpoint "$base_url$path" "API Endpoint $path" 5 "$expected"
    done
}

# Function to test frontend
test_frontend() {
    local frontend_url="$1"
    
    log_section "Frontend Health Checks"
    
    # Test main page
    test_http_endpoint "$frontend_url/" "Frontend Root" 10 200
    
    # Test health endpoint if available
    test_http_endpoint "$frontend_url/health" "Frontend Health" 5 200 || true
    
    # Test static assets (if we can detect them)
    log_info "Testing frontend static assets"
    
    local response_body
    response_body=$(curl -s "$frontend_url/" 2>/dev/null || echo "")
    
    if [[ -n "$response_body" ]]; then
        # Check for common frontend indicators
        if echo "$response_body" | grep -q -i "<!DOCTYPE html>"; then
            log_success "Frontend serves HTML content"
            record_check "pass"
        else
            log_warn "Frontend response doesn't appear to be HTML"
            record_check "warn"
        fi
        
        # Check for React indicators
        if echo "$response_body" | grep -q -i "react\|vite"; then
            log_success "Frontend appears to be React/Vite application"
            record_check "pass"
        fi
        
        # Check for error indicators
        if echo "$response_body" | grep -q -i "error\|404\|500"; then
            log_error "Frontend response contains error indicators"
            record_check "fail"
        fi
    fi
}

# Function to test Docker deployment
test_docker_deployment() {
    log_section "Docker Deployment Health Checks"
    
    cd "$PROJECT_ROOT"
    
    # Check if Docker is available
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not available"
        record_check "fail"
        return 1
    fi
    
    # Check Docker daemon
    if ! docker info &> /dev/null; then
        log_error "Docker daemon is not running"
        record_check "fail"
        return 1
    fi
    
    log_success "Docker is available and running"
    record_check "pass"
    
    # Check if containers are running
    local containers=(
        "secure-notes-backend"
        "secure-notes-frontend"
        "secure-notes-postgres"
        "secure-notes-redis"
    )
    
    for container in "${containers[@]}"; do
        if docker ps --filter "name=$container" --filter "status=running" | grep -q "$container"; then
            log_success "Container $container is running"
            record_check "pass"
            
            # Check container health if healthcheck is defined
            local health_status
            health_status=$(docker inspect "$container" --format='{{.State.Health.Status}}' 2>/dev/null || echo "none")
            
            case "$health_status" in
                healthy)
                    log_success "Container $container is healthy"
                    record_check "pass"
                    ;;
                unhealthy)
                    log_error "Container $container is unhealthy"
                    record_check "fail"
                    ;;
                starting)
                    log_waiting "Container $container health check is starting"
                    record_check "warn"
                    ;;
                none)
                    log_info "Container $container has no health check defined"
                    ;;
            esac
        else
            log_error "Container $container is not running"
            record_check "fail"
        fi
    done
}

# Function to test Kubernetes deployment
test_kubernetes_deployment() {
    local namespace="${1:-secure-notes}"
    
    log_section "Kubernetes Deployment Health Checks"
    
    # Check if kubectl is available
    if ! command -v kubectl &> /dev/null; then
        log_error "kubectl is not available"
        record_check "fail"
        return 1
    fi
    
    # Check cluster connectivity
    if ! kubectl cluster-info &> /dev/null; then
        log_error "Cannot connect to Kubernetes cluster"
        record_check "fail"
        return 1
    fi
    
    log_success "Connected to Kubernetes cluster"
    record_check "pass"
    
    # Check namespace
    if kubectl get namespace "$namespace" &> /dev/null; then
        log_success "Namespace $namespace exists"
        record_check "pass"
    else
        log_error "Namespace $namespace does not exist"
        record_check "fail"
        return 1
    fi
    
    # Check deployments
    local deployments=(
        "secure-notes-backend"
        "secure-notes-frontend"
    )
    
    for deployment in "${deployments[@]}"; do
        log_info "Checking deployment: $deployment"
        
        if kubectl get deployment "$deployment" -n "$namespace" &> /dev/null; then
            local ready_replicas
            local desired_replicas
            
            ready_replicas=$(kubectl get deployment "$deployment" -n "$namespace" -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo "0")
            desired_replicas=$(kubectl get deployment "$deployment" -n "$namespace" -o jsonpath='{.spec.replicas}' 2>/dev/null || echo "1")
            
            if [[ "$ready_replicas" == "$desired_replicas" ]] && [[ "$ready_replicas" -gt 0 ]]; then
                log_success "Deployment $deployment is ready ($ready_replicas/$desired_replicas)"
                record_check "pass"
            else
                log_error "Deployment $deployment is not ready ($ready_replicas/$desired_replicas)"
                record_check "fail"
            fi
        else
            log_error "Deployment $deployment not found"
            record_check "fail"
        fi
    done
    
    # Check pods
    log_info "Checking pod status"
    local pod_status
    pod_status=$(kubectl get pods -n "$namespace" --no-headers 2>/dev/null || echo "")
    
    if [[ -n "$pod_status" ]]; then
        local running_pods
        local total_pods
        running_pods=$(echo "$pod_status" | grep -c "Running" || echo "0")
        total_pods=$(echo "$pod_status" | wc -l)
        
        log_info "Pod status: $running_pods/$total_pods running"
        
        if [[ "$running_pods" -eq "$total_pods" ]] && [[ "$total_pods" -gt 0 ]]; then
            log_success "All pods are running"
            record_check "pass"
        else
            log_warn "Not all pods are running"
            record_check "warn"
            
            # Show problematic pods
            echo "$pod_status" | grep -v "Running" | while read -r line; do
                log_error "Problematic pod: $line"
            done
        fi
    else
        log_error "No pods found in namespace $namespace"
        record_check "fail"
    fi
    
    # Check services
    log_info "Checking services"
    local services=(
        "secure-notes-backend"
        "secure-notes-frontend"
    )
    
    for service in "${services[@]}"; do
        if kubectl get service "$service" -n "$namespace" &> /dev/null; then
            log_success "Service $service exists"
            record_check "pass"
        else
            log_error "Service $service not found"
            record_check "fail"
        fi
    done
}

# Function to run performance tests
test_performance() {
    local backend_url="$1"
    local frontend_url="$2"
    
    log_section "Performance Tests"
    
    # Test backend response time
    log_info "Testing backend response time"
    local response_times=()
    
    for i in {1..5}; do
        local time
        time=$(curl -s -o /dev/null -w "%{time_total}" \
              --connect-timeout 5 \
              --max-time 10 \
              "$backend_url/api/v1/health" 2>/dev/null || echo "999")
        response_times+=("$time")
    done
    
    # Calculate average response time
    local total=0
    local count=0
    for time in "${response_times[@]}"; do
        if [[ $(echo "$time < 10" | bc -l 2>/dev/null || echo "1") -eq 1 ]]; then
            total=$(echo "$total + $time" | bc -l 2>/dev/null || echo "$total")
            ((count++))
        fi
    done
    
    if [[ $count -gt 0 ]]; then
        local avg
        avg=$(echo "scale=3; $total / $count" | bc -l 2>/dev/null || echo "unknown")
        
        if [[ $(echo "$avg < 1.0" | bc -l 2>/dev/null || echo "0") -eq 1 ]]; then
            log_success "Backend average response time: ${avg}s (excellent)"
            record_check "pass"
        elif [[ $(echo "$avg < 2.0" | bc -l 2>/dev/null || echo "0") -eq 1 ]]; then
            log_success "Backend average response time: ${avg}s (good)"
            record_check "pass"
        else
            log_warn "Backend average response time: ${avg}s (slow)"
            record_check "warn"
        fi
    else
        log_error "Backend performance test failed"
        record_check "fail"
    fi
    
    # Test frontend response time
    log_info "Testing frontend response time"
    local frontend_time
    frontend_time=$(curl -s -o /dev/null -w "%{time_total}" \
                   --connect-timeout 5 \
                   --max-time 10 \
                   "$frontend_url/" 2>/dev/null || echo "999")
    
    if [[ $(echo "$frontend_time < 10" | bc -l 2>/dev/null || echo "1") -eq 1 ]]; then
        if [[ $(echo "$frontend_time < 2.0" | bc -l 2>/dev/null || echo "0") -eq 1 ]]; then
            log_success "Frontend response time: ${frontend_time}s"
            record_check "pass"
        else
            log_warn "Frontend response time: ${frontend_time}s (consider optimization)"
            record_check "warn"
        fi
    else
        log_error "Frontend performance test failed"
        record_check "fail"
    fi
}

# Function to generate health report
generate_health_report() {
    log_section "Health Check Summary"
    
    local health_percentage
    if [[ $TOTAL_CHECKS -gt 0 ]]; then
        health_percentage=$(( (PASSED_CHECKS * 100) / TOTAL_CHECKS ))
    else
        health_percentage=0
    fi
    
    echo
    echo "📊 Health Check Results:"
    echo "  Total Checks: $TOTAL_CHECKS"
    echo "  ✓ Passed: $PASSED_CHECKS"
    echo "  ✗ Failed: $FAILED_CHECKS"
    echo "  ⚠ Warnings: $WARNING_CHECKS"
    echo "  Health Score: ${health_percentage}%"
    echo
    
    # Overall status
    if [[ $FAILED_CHECKS -eq 0 ]]; then
        if [[ $WARNING_CHECKS -eq 0 ]]; then
            log_success "🎉 All systems are healthy!"
            echo "Your Secure Notes application is running perfectly."
        else
            log_warn "⚠️ Systems are operational with warnings"
            echo "Your application is running but some optimizations are recommended."
        fi
    else
        log_error "🚨 System health issues detected"
        echo "Your application has some problems that need attention."
        echo
        echo "Recommended actions:"
        echo "1. Check failed services and restart if necessary"
        echo "2. Verify network connectivity and firewall settings"
        echo "3. Check logs for detailed error information"
        echo "4. Ensure all dependencies are properly configured"
    fi
    
    # Return appropriate exit code
    if [[ $FAILED_CHECKS -eq 0 ]]; then
        return 0
    else
        return 1
    fi
}

# Function to monitor continuously
monitor_continuously() {
    local interval="${1:-30}"
    local deployment_type="${2:-docker}"
    local namespace="${3:-secure-notes}"
    
    log_section "Continuous Monitoring (${interval}s intervals)"
    log_info "Press Ctrl+C to stop monitoring"
    
    local iteration=0
    
    while true; do
        ((iteration++))
        echo
        log_section "Health Check Iteration #$iteration"
        echo "Time: $(date)"
        
        # Reset counters
        TOTAL_CHECKS=0
        PASSED_CHECKS=0
        FAILED_CHECKS=0
        WARNING_CHECKS=0
        
        # Run appropriate health checks
        case "$deployment_type" in
            docker)
                test_docker_deployment
                ;;
            k8s|kubernetes)
                test_kubernetes_deployment "$namespace"
                ;;
        esac
        
        # Always test endpoints if they're reachable
        test_http_endpoint "$BACKEND_URL/api/v1/health" "Backend Health" 5 200 &>/dev/null && {
            test_api_endpoints "$BACKEND_URL"
            test_frontend "$FRONTEND_URL"
        }
        
        # Show brief summary
        local health_percentage
        if [[ $TOTAL_CHECKS -gt 0 ]]; then
            health_percentage=$(( (PASSED_CHECKS * 100) / TOTAL_CHECKS ))
        else
            health_percentage=0
        fi
        
        echo "Health Score: ${health_percentage}% (${PASSED_CHECKS}/${TOTAL_CHECKS} checks passed)"
        
        sleep "$interval"
    done
}

# Main function
main() {
    local action="${1:-full}"
    shift || true
    
    case "$action" in
        full|all)
            log_section "Comprehensive Health Check for Secure Notes"
            
            # Detect deployment type
            local deployment_type="unknown"
            
            if docker ps &>/dev/null && docker ps | grep -q "secure-notes"; then
                deployment_type="docker"
            elif command -v kubectl &>/dev/null && kubectl get ns secure-notes &>/dev/null; then
                deployment_type="kubernetes"
            fi
            
            log_info "Detected deployment type: $deployment_type"
            
            # Run appropriate health checks
            case "$deployment_type" in
                docker)
                    test_docker_deployment
                    ;;
                kubernetes)
                    test_kubernetes_deployment "${1:-secure-notes}"
                    ;;
                *)
                    log_warn "No deployment detected, testing endpoints only"
                    ;;
            esac
            
            # Test API endpoints
            test_api_endpoints "$BACKEND_URL"
            
            # Test frontend
            test_frontend "$FRONTEND_URL"
            
            # Run performance tests
            test_performance "$BACKEND_URL" "$FRONTEND_URL"
            
            # Generate report
            generate_health_report
            ;;
            
        api)
            test_api_endpoints "$BACKEND_URL"
            generate_health_report
            ;;
            
        frontend)
            test_frontend "$FRONTEND_URL"
            generate_health_report
            ;;
            
        docker)
            test_docker_deployment
            generate_health_report
            ;;
            
        k8s|kubernetes)
            test_kubernetes_deployment "${1:-secure-notes}"
            generate_health_report
            ;;
            
        performance|perf)
            test_performance "$BACKEND_URL" "$FRONTEND_URL"
            generate_health_report
            ;;
            
        monitor)
            local interval="${1:-30}"
            local deployment_type="${2:-docker}"
            local namespace="${3:-secure-notes}"
            monitor_continuously "$interval" "$deployment_type" "$namespace"
            ;;
            
        --help|-h)
            cat <<EOF
Usage: $0 COMMAND [OPTIONS]

Commands:
  full                          Run comprehensive health checks (default)
  api                          Test API endpoints only
  frontend                     Test frontend only
  docker                       Test Docker deployment
  k8s [NAMESPACE]              Test Kubernetes deployment
  performance                  Run performance tests
  monitor [INTERVAL] [TYPE]    Monitor continuously
  --help                       Show this help

Environment Variables:
  BACKEND_URL                  Backend URL (default: http://localhost:8080)
  FRONTEND_URL                 Frontend URL (default: http://localhost:3000)

Examples:
  $0                          # Full health check
  $0 api                      # Test API only
  $0 k8s secure-notes         # Test Kubernetes deployment
  $0 monitor 60 docker        # Monitor Docker deployment every 60s
  
  BACKEND_URL=https://api.example.com $0 api    # Test remote API

Exit Codes:
  0 - All checks passed
  1 - Some checks failed
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
    log_error "curl is required but not installed"
    exit 1
fi

# Handle interrupt signal for continuous monitoring
trap 'log_info "Monitoring stopped"; exit 0' INT TERM

# Run main function
main "$@"