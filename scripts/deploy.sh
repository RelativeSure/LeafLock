#!/bin/bash

# Secure Notes Master Deployment Script
# One-command deployment for all environments and platforms

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPTS_DIR="$SCRIPT_DIR/scripts"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Status symbols
ROCKET="🚀"
CHECKMARK="✓"
CROSS="✗"
WARNING="⚠"
GEAR="⚙"

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
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

log_deploy() {
    echo -e "${PURPLE}${ROCKET}${NC} $1"
}

# Function to check dependencies
check_dependencies() {
    local platform="$1"
    local missing_deps=()
    
    case "$platform" in
        docker)
            command -v docker >/dev/null || missing_deps+=("docker")
            ;;
        k8s|kubernetes)
            command -v kubectl >/dev/null || missing_deps+=("kubectl")
            command -v helm >/dev/null || missing_deps+=("helm")
            command -v docker >/dev/null || missing_deps+=("docker")
            ;;
        dev|development)
            command -v go >/dev/null || missing_deps+=("go")
            command -v node >/dev/null || missing_deps+=("node")
            command -v npm >/dev/null || missing_deps+=("npm")
            ;;
    esac
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log_error "Missing dependencies for $platform deployment:"
        for dep in "${missing_deps[@]}"; do
            echo "  - $dep"
        done
        return 1
    fi
    
    return 0
}

# Function to show deployment options
show_deployment_menu() {
    echo -e "${CYAN}🎯 Secure Notes Deployment Options${NC}"
    echo
    echo "Choose your deployment target:"
    echo
    echo "  1) 🔧 Development Environment"
    echo "     • Local development with hot reload"
    echo "     • Databases in Docker, apps on host"
    echo "     • Fast iteration and debugging"
    echo
    echo "  2) 🐳 Docker Compose (Local)"
    echo "     • Complete stack in containers"
    echo "     • Production-like environment"
    echo "     • Easy to start and stop"
    echo
    echo "  3) 🐳 Docker Compose (Production)"
    echo "     • Hardened production configuration"
    echo "     • SSL/TLS enabled"
    echo "     • Resource limits and monitoring"
    echo
    echo "  4) ☸️  Kubernetes (Local)"
    echo "     • Deploy to local Kubernetes cluster"
    echo "     • kind, minikube, or Docker Desktop"
    echo "     • Good for testing K8s deployment"
    echo
    echo "  5) ☸️  Kubernetes (Production)"
    echo "     • Deploy to production Kubernetes"
    echo "     • Includes ingress and SSL"
    echo "     • High availability configuration"
    echo
    echo "  6) 🔍 Health Check"
    echo "     • Check deployment status"
    echo "     • Comprehensive health monitoring"
    echo "     • Performance testing"
    echo
    echo "  7) 🛠️  Troubleshoot Issues"
    echo "     • Diagnose deployment problems"
    echo "     • Show quick fixes"
    echo "     • Generate diagnostic report"
    echo
    echo "  8) ⚙️  Environment Setup"
    echo "     • Configure environment variables"
    echo "     • Generate secure secrets"
    echo "     • Validate configuration"
    echo
}

# Function to get user choice
get_user_choice() {
    local choice
    while true; do
        echo -n "Enter your choice (1-8): "
        read -r choice
        
        case "$choice" in
            1|2|3|4|5|6|7|8)
                echo "$choice"
                return 0
                ;;
            *)
                log_error "Invalid choice. Please enter a number between 1-8."
                ;;
        esac
    done
}

# Function to deploy development environment
deploy_development() {
    log_deploy "Starting development environment deployment..."
    
    if ! check_dependencies "development"; then
        return 1
    fi
    
    if [[ -x "$SCRIPTS_DIR/dev-setup.sh" ]]; then
        "$SCRIPTS_DIR/dev-setup.sh" start
    else
        log_error "Development setup script not found or not executable"
        return 1
    fi
}

# Function to deploy Docker Compose
deploy_docker() {
    local environment="${1:-dev}"
    
    log_deploy "Starting Docker Compose deployment ($environment)..."
    
    if ! check_dependencies "docker"; then
        return 1
    fi
    
    local args=()
    
    case "$environment" in
        prod|production)
            args+=("--prod")
            log_warn "Production deployment requires proper SSL certificates and environment configuration"
            ;;
    esac
    
    if [[ -x "$SCRIPTS_DIR/deploy-docker.sh" ]]; then
        "$SCRIPTS_DIR/deploy-docker.sh" "${args[@]}"
    else
        log_error "Docker deployment script not found or not executable"
        return 1
    fi
}

# Function to deploy Kubernetes
deploy_kubernetes() {
    local environment="${1:-dev}"
    local domain="${2:-secure-notes.local}"
    
    log_deploy "Starting Kubernetes deployment ($environment)..."
    
    if ! check_dependencies "kubernetes"; then
        return 1
    fi
    
    local args=()
    
    case "$environment" in
        prod|production)
            args+=("--prod")
            echo -n "Enter your domain name [$domain]: "
            read -r user_domain
            [[ -n "$user_domain" ]] && domain="$user_domain"
            args+=("--domain" "$domain")
            ;;
    esac
    
    if [[ -x "$SCRIPTS_DIR/deploy-k8s.sh" ]]; then
        "$SCRIPTS_DIR/deploy-k8s.sh" "${args[@]}"
    else
        log_error "Kubernetes deployment script not found or not executable"
        return 1
    fi
}

# Function to run health check
run_health_check() {
    log_deploy "Running health check..."
    
    if [[ -x "$SCRIPTS_DIR/health-check.sh" ]]; then
        "$SCRIPTS_DIR/health-check.sh" full
    else
        log_error "Health check script not found or not executable"
        return 1
    fi
}

# Function to run troubleshooting
run_troubleshoot() {
    log_deploy "Running troubleshooting diagnostics..."
    
    if [[ -x "$SCRIPTS_DIR/troubleshoot.sh" ]]; then
        "$SCRIPTS_DIR/troubleshoot.sh" full
    else
        log_error "Troubleshoot script not found or not executable"
        return 1
    fi
}

# Function to setup environment
setup_environment() {
    log_deploy "Setting up environment configuration..."
    
    if [[ -x "$SCRIPTS_DIR/env-setup.sh" ]]; then
        echo "Environment setup options:"
        echo "  1) Setup all environments (recommended)"
        echo "  2) Generate production config"
        echo "  3) Generate development config"
        echo "  4) Validate existing config"
        echo
        echo -n "Choose option (1-4): "
        read -r env_choice
        
        case "$env_choice" in
            1)
                "$SCRIPTS_DIR/env-setup.sh" setup
                ;;
            2)
                "$SCRIPTS_DIR/env-setup.sh" generate prod
                ;;
            3)
                "$SCRIPTS_DIR/env-setup.sh" generate dev
                ;;
            4)
                "$SCRIPTS_DIR/env-setup.sh" validate
                ;;
            *)
                log_error "Invalid choice"
                return 1
                ;;
        esac
    else
        log_error "Environment setup script not found or not executable"
        return 1
    fi
}

# Function to handle command line arguments
handle_cli_args() {
    local action="$1"
    shift || true
    
    case "$action" in
        dev|development)
            deploy_development
            ;;
        docker)
            deploy_docker "dev"
            ;;
        docker-prod)
            deploy_docker "prod"
            ;;
        k8s|kubernetes)
            deploy_kubernetes "dev"
            ;;
        k8s-prod)
            deploy_kubernetes "prod" "${1:-}"
            ;;
        health)
            run_health_check
            ;;
        troubleshoot|fix)
            run_troubleshoot
            ;;
        env|environment)
            setup_environment
            ;;
        --help|-h)
            show_help
            ;;
        *)
            log_error "Unknown command: $action"
            show_help
            exit 1
            ;;
    esac
}

# Function to show help
show_help() {
    cat <<EOF
Usage: $0 [COMMAND] [OPTIONS]

Commands:
  dev                           Deploy development environment
  docker                        Deploy with Docker Compose (development)
  docker-prod                   Deploy with Docker Compose (production)
  k8s                          Deploy to Kubernetes (development)
  k8s-prod [DOMAIN]            Deploy to Kubernetes (production)
  health                       Run health check
  troubleshoot                 Run troubleshooting diagnostics
  env                          Setup environment configuration
  --help                       Show this help

Interactive Mode:
  Run without arguments to see the interactive menu.

Examples:
  $0                          # Interactive menu
  $0 dev                      # Start development environment
  $0 docker                   # Deploy with Docker Compose
  $0 k8s-prod myapp.com      # Deploy to production Kubernetes
  $0 health                   # Check deployment health

Environment Variables:
  SKIP_DEPS_CHECK             Skip dependency checking
  FORCE_OVERWRITE             Overwrite existing configurations

For detailed documentation, see: ./docs/DEPLOYMENT.md
EOF
}

# Function to show banner
show_banner() {
    echo -e "${PURPLE}"
    cat << 'EOF'
   ____                             _   _       _            
  / ___|  ___  ___ _   _ _ __ ___   | \ | | ___ | |_ ___  ___ 
  \___ \ / _ \/ __| | | | '__/ _ \  |  \| |/ _ \| __/ _ \/ __|
   ___) |  __/ (__| |_| | | |  __/  | |\  | (_) | ||  __/\__ \
  |____/ \___|\___|\__,_|_|  \___|  |_| \_|\___/ \__\___||___/

EOF
    echo -e "${NC}"
    echo -e "${BLUE}          Secure End-to-End Encrypted Notes Application${NC}"
    echo -e "${BLUE}                    Production-Ready Deployment${NC}"
    echo
}

# Main function
main() {
    show_banner
    
    # Handle command line arguments
    if [[ $# -gt 0 ]]; then
        handle_cli_args "$@"
        return $?
    fi
    
    # Interactive mode
    show_deployment_menu
    
    local choice
    choice=$(get_user_choice)
    
    echo
    log_section "Starting Deployment Process"
    
    case "$choice" in
        1)
            deploy_development
            ;;
        2)
            deploy_docker "dev"
            ;;
        3)
            deploy_docker "prod"
            ;;
        4)
            deploy_kubernetes "dev"
            ;;
        5)
            deploy_kubernetes "prod"
            ;;
        6)
            run_health_check
            ;;
        7)
            run_troubleshoot
            ;;
        8)
            setup_environment
            ;;
    esac
    
    local exit_code=$?
    
    echo
    if [[ $exit_code -eq 0 ]]; then
        log_success "Deployment completed successfully!"
        echo
        echo "Next steps:"
        echo "  • Check service health: $0 health"
        echo "  • View logs and monitor services"
        echo "  • Review security settings for production"
        echo
        echo "Need help? Run: $0 troubleshoot"
    else
        log_error "Deployment failed!"
        echo
        echo "Troubleshooting:"
        echo "  • Check the error messages above"
        echo "  • Run diagnostics: $0 troubleshoot"
        echo "  • Check the documentation"
    fi
    
    return $exit_code
}

# Ensure we're in the project root
cd "$SCRIPT_DIR"

# Check for required scripts
if [[ ! -d "$SCRIPTS_DIR" ]]; then
    log_error "Scripts directory not found: $SCRIPTS_DIR"
    exit 1
fi

# Make sure scripts are executable
find "$SCRIPTS_DIR" -name "*.sh" -exec chmod +x {} \; 2>/dev/null || true

# Run main function
main "$@"