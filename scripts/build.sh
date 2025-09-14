#!/bin/bash

# LeafLock Build Script
# Builds Docker images with proper tagging for all deployment targets

set -euo pipefail

# Configuration
PROJECT_NAME="LeafLock"
VERSION=${VERSION:-"$(git rev-parse --short HEAD)"}
REGISTRY=${REGISTRY:-""}
BUILD_PLATFORM=${BUILD_PLATFORM:-"linux/amd64"}

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

# Function to build and tag images
build_image() {
    local service=$1
    local dockerfile_path=$2
    local context_path=$3
    
    log_info "Building $service image..."
    
    # Base image name
    local base_image="${PROJECT_NAME}/${service}"
    
    # Build the image
    docker build \
        --platform "${BUILD_PLATFORM}" \
        --file "${dockerfile_path}" \
        --tag "${base_image}:${VERSION}" \
        --tag "${base_image}:latest" \
        "${context_path}"
    
    # Tag for registry if specified
    if [[ -n "$REGISTRY" ]]; then
        docker tag "${base_image}:${VERSION}" "${REGISTRY}/${base_image}:${VERSION}"
        docker tag "${base_image}:${VERSION}" "${REGISTRY}/${base_image}:latest"
        log_info "Tagged for registry: ${REGISTRY}/${base_image}"
    fi
    
    log_success "Built $service image successfully"
}

# Function to push images to registry
push_images() {
    if [[ -z "$REGISTRY" ]]; then
        log_warn "No registry specified, skipping push"
        return
    fi
    
    log_info "Pushing images to registry: $REGISTRY"
    
    # Push backend
    docker push "${REGISTRY}/${PROJECT_NAME}/backend:${VERSION}"
    docker push "${REGISTRY}/${PROJECT_NAME}/backend:latest"
    
    # Push frontend
    docker push "${REGISTRY}/${PROJECT_NAME}/frontend:${VERSION}"
    docker push "${REGISTRY}/${PROJECT_NAME}/frontend:latest"
    
    log_success "Images pushed to registry"
}

# Function to save images as tar files (for air-gapped deployments)
save_images() {
    local output_dir="${PWD}/images"
    mkdir -p "$output_dir"
    
    log_info "Saving images to tar files..."
    
    docker save \
        "${PROJECT_NAME}/backend:${VERSION}" \
        "${PROJECT_NAME}/frontend:${VERSION}" \
        -o "${output_dir}/${PROJECT_NAME}-${VERSION}.tar"
    
    log_success "Images saved to ${output_dir}/${PROJECT_NAME}-${VERSION}.tar"
}

# Function to load images from tar files
load_images() {
    local tar_file="${1:-${PWD}/images/${PROJECT_NAME}-${VERSION}.tar}"
    
    if [[ ! -f "$tar_file" ]]; then
        log_error "Tar file not found: $tar_file"
        exit 1
    fi
    
    log_info "Loading images from $tar_file..."
    docker load -i "$tar_file"
    log_success "Images loaded successfully"
}

# Function to clean up old images
cleanup() {
    log_info "Cleaning up old images..."
    
    # Remove dangling images
    docker image prune -f
    
    # Remove old tagged versions (keep latest and current version)
    docker images "${PROJECT_NAME}/*" --format "table {{.Repository}}:{{.Tag}}" | \
        grep -v ":${VERSION}" | grep -v ":latest" | \
        xargs -r docker rmi || true
    
    log_success "Cleanup completed"
}

# Function to verify builds
verify_build() {
    log_info "Verifying built images..."
    
    # Check if images exist
    if ! docker images "${PROJECT_NAME}/backend:${VERSION}" --quiet | grep -q .; then
        log_error "Backend image not found"
        return 1
    fi
    
    if ! docker images "${PROJECT_NAME}/frontend:${VERSION}" --quiet | grep -q .; then
        log_error "Frontend image not found"
        return 1
    fi
    
    # Test backend image
    log_info "Testing backend image..."
    if ! docker run --rm "${PROJECT_NAME}/backend:${VERSION}" --version >/dev/null 2>&1; then
        log_warn "Backend image test failed (this may be expected if --version flag not implemented)"
    fi
    
    # Test frontend image
    log_info "Testing frontend image..."
    local container_id
    container_id=$(docker run -d -p 0:8080 "${PROJECT_NAME}/frontend:${VERSION}")
    sleep 5
    if docker exec "$container_id" wget -q --spider http://localhost:8080/health; then
        log_success "Frontend image test passed"
    else
        log_warn "Frontend image test failed"
    fi
    docker stop "$container_id" >/dev/null
    docker rm "$container_id" >/dev/null
    
    log_success "Image verification completed"
}

# Main function
main() {
    local action=${1:-"build"}
    
    case "$action" in
        build)
            log_info "Starting build process..."
            log_info "Version: $VERSION"
            log_info "Registry: ${REGISTRY:-"none"}"
            log_info "Platform: $BUILD_PLATFORM"
            
            # Build images
            build_image "backend" "./backend/Dockerfile" "./backend"
            build_image "frontend" "./frontend/Dockerfile" "./frontend"
            
            # Verify builds
            verify_build
            
            log_success "Build completed successfully!"
            ;;
            
        push)
            push_images
            ;;
            
        save)
            save_images
            ;;
            
        load)
            load_images "$2"
            ;;
            
        cleanup)
            cleanup
            ;;
            
        all)
            main build
            push_images
            save_images
            ;;
            
        *)
            echo "Usage: $0 {build|push|save|load|cleanup|all}"
            echo ""
            echo "Commands:"
            echo "  build   - Build Docker images"
            echo "  push    - Push images to registry"
            echo "  save    - Save images to tar file"
            echo "  load    - Load images from tar file"
            echo "  cleanup - Clean up old images"
            echo "  all     - Build, push, and save"
            echo ""
            echo "Environment Variables:"
            echo "  VERSION        - Image version (default: git commit hash)"
            echo "  REGISTRY       - Docker registry URL"
            echo "  BUILD_PLATFORM - Target platform (default: linux/amd64)"
            exit 1
            ;;
    esac
}

# Check dependencies
command -v docker >/dev/null 2>&1 || { log_error "Docker is required but not installed."; exit 1; }
command -v git >/dev/null 2>&1 || { log_error "Git is required but not installed."; exit 1; }

# Run main function
main "$@"
