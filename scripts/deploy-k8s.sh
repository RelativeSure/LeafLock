#!/bin/bash
# Note: For common local tasks, prefer leaflock.sh. This script remains for advanced/CI Kubernetes deploy flows.

# LeafLock Kubernetes Deployment Script
# One-command deployment with image building, secret generation, and health monitoring

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
HELM_CHART_DIR="${PROJECT_ROOT}/helm/leaflock"
NAMESPACE="leaflock"
RELEASE_NAME="leaflock"

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
    openssl rand -base64 "$length" | tr -d "=+/" | cut -c1-"$length"
}

generate_base64() {
    local length=${1:-32}
    openssl rand -base64 "$length"
}

# Function to check dependencies
check_dependencies() {
    log_info "Checking dependencies..."
    
    local required_commands=("kubectl" "helm" "docker")
    
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            log_error "Required command '$cmd' is not installed"
            return 1
        fi
    done
    
    # Check kubectl connectivity
    if ! kubectl cluster-info &> /dev/null; then
        log_error "Cannot connect to Kubernetes cluster"
        return 1
    fi
    
    log_success "All dependencies are available"
    return 0
}

# Function to create namespace
create_namespace() {
    log_info "Creating namespace: $NAMESPACE"
    
    if kubectl get namespace "$NAMESPACE" &> /dev/null; then
        log_info "Namespace $NAMESPACE already exists"
    else
        kubectl create namespace "$NAMESPACE"
        log_success "Created namespace: $NAMESPACE"
    fi
}

# Function to build and load images
build_and_load_images() {
    local registry=${1:-""}
    local version=${2:-"$(git rev-parse --short HEAD)"}
    
    log_info "Building container images..."
    
    # Build images using the build script
    cd "$PROJECT_ROOT"
    VERSION="$version" REGISTRY="$registry" ./scripts/build.sh build
    
    # Check if we need to load images into cluster (for local development)
    if [[ -z "$registry" ]] || [[ "$registry" == "localhost"* ]]; then
        log_info "Loading images into local cluster..."
        
        # For kind cluster
        if command -v kind &> /dev/null && kind get clusters 2>/dev/null | grep -q .; then
            local cluster_name
            cluster_name=$(kind get clusters | head -n1)
            kind load docker-image "leaflock/backend:$version" --name "$cluster_name"
            kind load docker-image "leaflock/frontend:$version" --name "$cluster_name"
            log_success "Images loaded into kind cluster"
        
        # For minikube
        elif command -v minikube &> /dev/null && minikube status &> /dev/null; then
            eval "$(minikube docker-env)"
            VERSION="$version" ./scripts/build.sh build
            log_success "Images built in minikube environment"
        
        # For k3s/other local clusters
        else
            log_warn "Local cluster type not detected, assuming images are available"
        fi
    fi
}

# Function to create secrets
create_secrets() {
    log_info "Creating Kubernetes secrets..."
    
    # Generate secrets if they don't exist
    local postgres_password
    local redis_password
    local jwt_secret
    local server_encryption_key
    
    # Check if secrets already exist
    if kubectl get secret leaflock-secrets -n "$NAMESPACE" &> /dev/null; then
        log_info "Secrets already exist, updating if needed..."
        
        # Get existing secrets
        postgres_password=$(kubectl get secret leaflock-secrets -n "$NAMESPACE" -o jsonpath='{.data.postgres-password}' | base64 -d 2>/dev/null || echo "")
        redis_password=$(kubectl get secret leaflock-secrets -n "$NAMESPACE" -o jsonpath='{.data.redis-password}' | base64 -d 2>/dev/null || echo "")
        jwt_secret=$(kubectl get secret leaflock-secrets -n "$NAMESPACE" -o jsonpath='{.data.jwt-secret}' | base64 -d 2>/dev/null || echo "")
        server_encryption_key=$(kubectl get secret leaflock-secrets -n "$NAMESPACE" -o jsonpath='{.data.server-encryption-key}' | base64 -d 2>/dev/null || echo "")
    fi
    
    # Generate missing secrets
    [[ -z "$postgres_password" ]] && postgres_password=$(generate_password 24)
    [[ -z "$redis_password" ]] && redis_password=$(generate_password 24)
    [[ -z "$jwt_secret" ]] && jwt_secret=$(generate_password 64)
    [[ -z "$server_encryption_key" ]] && server_encryption_key=$(generate_password 32)
    
    # Create main secrets
    kubectl create secret generic leaflock-secrets \
        --from-literal=postgres-password="$postgres_password" \
        --from-literal=redis-password="$redis_password" \
        --from-literal=jwt-secret="$jwt_secret" \
        --from-literal=server-encryption-key="$server_encryption_key" \
        --namespace="$NAMESPACE" \
        --dry-run=client -o yaml | kubectl apply -f -
    
    # Create PostgreSQL secrets (for Bitnami chart compatibility)
    kubectl create secret generic leaflock-postgresql \
        --from-literal=postgres-password="$postgres_password" \
        --from-literal=password="$postgres_password" \
        --namespace="$NAMESPACE" \
        --dry-run=client -o yaml | kubectl apply -f -
    
    # Create Redis secrets (for Bitnami chart compatibility)
    kubectl create secret generic leaflock-redis \
        --from-literal=redis-password="$redis_password" \
        --namespace="$NAMESPACE" \
        --dry-run=client -o yaml | kubectl apply -f -
    
    log_success "Secrets created/updated successfully"
}

# Function to deploy with Helm
deploy_with_helm() {
    local environment=${1:-"dev"}
    local registry=${2:-""}
    local version=${3:-"$(git rev-parse --short HEAD)"}
    local domain=${4:-"leaflock.app"}
    
    log_info "Deploying with Helm (environment: $environment)..."
    
    # Prepare Helm values
    local values_file="$HELM_CHART_DIR/values.yaml"
    if [[ "$environment" == "prod" ]] && [[ -f "$HELM_CHART_DIR/values-prod.yaml" ]]; then
        values_file="$HELM_CHART_DIR/values-prod.yaml"
    elif [[ "$environment" == "dev" ]] && [[ -f "$HELM_CHART_DIR/values-dev.yaml" ]]; then
        values_file="$HELM_CHART_DIR/values-dev.yaml"
    fi
    
    # Create temporary values override
    local temp_values
    temp_values=$(mktemp)
    
    cat > "$temp_values" <<EOF
global:
  imageRegistry: "$registry"

backend:
  image:
    registry: "$registry"
    repository: leaflock/backend
    tag: "$version"

frontend:
  image:
    registry: "$registry"
    repository: leaflock/frontend
    tag: "$version"

ingress:
  enabled: true
  hosts:
    - host: $domain
      paths:
        - path: /
          pathType: Prefix
          service:
            name: frontend
            port: 80
        - path: /api
          pathType: Prefix
          service:
            name: backend
            port: 8080
  tls:
    - secretName: leaflock-tls
      hosts:
        - $domain

secrets:
  jwtSecret: ""
  serverEncryptionKey: ""

postgresql:
  auth:
    existingSecret: "leaflock-postgresql"
    secretKeys:
      adminPasswordKey: "postgres-password"
      userPasswordKey: "password"

redis:
  auth:
    existingSecret: "leaflock-redis"
    existingSecretPasswordKey: "redis-password"
EOF
    
    # Add Bitnami repo if not exists
    if ! helm repo list | grep -q "bitnami"; then
        helm repo add bitnami https://charts.bitnami.com/bitnami
    fi
    
    # Update Helm dependencies
    cd "$HELM_CHART_DIR"
    helm dependency update
    
    # Deploy with Helm
    helm upgrade --install "$RELEASE_NAME" . \
        --namespace "$NAMESPACE" \
        --create-namespace \
        --values "$values_file" \
        --values "$temp_values" \
        --wait \
        --timeout 600s
    
    # Cleanup
    rm "$temp_values"
    
    log_success "Helm deployment completed"
}

# Function to wait for deployment
wait_for_deployment() {
    log_info "Waiting for deployment to be ready..."
    
    # Wait for deployments
    local deployments=("backend" "frontend")
    
    for deployment in "${deployments[@]}"; do
        log_info "Waiting for $deployment deployment..."
        kubectl rollout status deployment/leaflock-"$deployment" -n "$NAMESPACE" --timeout=300s
    done
    
    # Wait for StatefulSets (PostgreSQL, Redis)
    log_info "Waiting for database services..."
    kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=postgresql -n "$NAMESPACE" --timeout=300s || true
    kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=redis -n "$NAMESPACE" --timeout=300s || true
    
    log_success "All deployments are ready"
}

# Function to run health checks
run_health_checks() {
    log_info "Running health checks..."
    
    # Get service endpoints
    local backend_service
    local frontend_service
    
    backend_service=$(kubectl get svc leaflock-backend -n "$NAMESPACE" -o jsonpath='{.spec.clusterIP}')
    frontend_service=$(kubectl get svc leaflock-frontend -n "$NAMESPACE" -o jsonpath='{.spec.clusterIP}')
    
    # Create a temporary pod for testing
    kubectl run test-pod --rm -i --restart=Never --image=curlimages/curl:8.5.0 -n "$NAMESPACE" -- /bin/sh -c "
        echo 'Testing backend health...'
        curl -f http://$backend_service:8080/api/v1/health || exit 1
        echo 'Backend health check passed'
        
        echo 'Testing frontend...'
        curl -f http://$frontend_service:80/ || exit 1
        echo 'Frontend check passed'
    " || {
        log_error "Health checks failed"
        return 1
    }
    
    log_success "Health checks passed"
}

# Function to show deployment status
show_deployment_status() {
    local domain=${1:-"leaflock.app"}
    
    log_info "Deployment Status:"
    echo
    
    # Show pods
    kubectl get pods -n "$NAMESPACE" -o wide
    echo
    
    # Show services
    kubectl get svc -n "$NAMESPACE"
    echo
    
    # Show ingress
    kubectl get ingress -n "$NAMESPACE"
    echo
    
    # Show access information
    log_success "🎉 LeafLock deployed to Kubernetes!"
    echo
    echo "Access Information:"
    
    # Check if ingress is available
    if kubectl get ingress -n "$NAMESPACE" &> /dev/null; then
        echo "  Application: https://$domain"
        echo "  API: https://$domain/api"
    else
        echo "  Use port-forwarding to access the application:"
        echo "    Frontend: kubectl port-forward svc/leaflock-frontend -n $NAMESPACE 3000:80"
        echo "    Backend: kubectl port-forward svc/leaflock-backend -n $NAMESPACE 8080:8080"
    fi
    
    echo
    echo "Useful commands:"
    echo "  View logs: kubectl logs -f deployment/leaflock-backend -n $NAMESPACE"
    echo "  View pods: kubectl get pods -n $NAMESPACE"
    echo "  Shell access: kubectl exec -it deployment/leaflock-backend -n $NAMESPACE -- /bin/sh"
    echo "  Delete deployment: helm uninstall $RELEASE_NAME -n $NAMESPACE"
    echo
}

# Function to cleanup on failure
cleanup_on_failure() {
    log_error "Deployment failed. Checking resources..."
    
    # Show pod status for debugging
    kubectl get pods -n "$NAMESPACE" || true
    kubectl describe pods -n "$NAMESPACE" | grep -A 10 "Events:" || true
}

# Main function
main() {
    local environment="dev"
    local registry=""
    local version
    local domain="leaflock.app"
    local build_images=true
    local create_namespace_flag=true
    
    version="$(git rev-parse --short HEAD 2>/dev/null || echo "latest")"
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --prod|--production)
                environment="prod"
                shift
                ;;
            --registry)
                registry="$2"
                shift 2
                ;;
            --version)
                version="$2"
                shift 2
                ;;
            --domain)
                domain="$2"
                shift 2
                ;;
            --no-build)
                build_images=false
                shift
                ;;
            --no-namespace)
                create_namespace_flag=false
                shift
                ;;
            --help|-h)
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --prod                 Use production configuration"
                echo "  --registry REGISTRY    Container registry URL"
                echo "  --version VERSION      Image version tag"
                echo "  --domain DOMAIN        Application domain name"
                echo "  --no-build             Skip building container images"
                echo "  --no-namespace         Skip namespace creation"
                echo "  --help                 Show this help message"
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
    
    log_info "🚀 Starting Kubernetes deployment..."
    log_info "Environment: $environment"
    log_info "Version: $version"
    log_info "Registry: ${registry:-"local"}"
    log_info "Domain: $domain"
    
    # Pre-deployment checks
    check_dependencies
    
    # Create namespace
    if [[ $create_namespace_flag == true ]]; then
        create_namespace
    fi
    
    # Build and load images
    if [[ $build_images == true ]]; then
        build_and_load_images "$registry" "$version"
    fi
    
    # Create secrets
    create_secrets
    
    # Deploy with Helm
    deploy_with_helm "$environment" "$registry" "$version" "$domain"
    
    # Wait for deployment
    wait_for_deployment
    
    # Run health checks
    run_health_checks
    
    # Show status
    show_deployment_status "$domain"
    
    log_success "Kubernetes deployment completed successfully!"
}

# Check for required commands
for cmd in kubectl helm docker git; do
    if ! command -v "$cmd" &> /dev/null; then
        log_error "Required command '$cmd' is not installed"
        exit 1
    fi
done

# Run main function
main "$@"
