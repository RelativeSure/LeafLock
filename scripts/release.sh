#!/bin/bash
# release.sh - Local release management script
# Usage: ./scripts/release.sh [patch|minor|major|prerelease] [--dry-run] [--notes "Custom notes"]

set -euo pipefail

# Configuration
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GITHUB_REPO="${GITHUB_REPOSITORY:-$(git config --get remote.origin.url | sed 's/.*github\.com[:/]\([^/]*\/[^/]*\)\.git/\1/')}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Default values
VERSION_TYPE="patch"
DRY_RUN=false
CUSTOM_NOTES=""
SKIP_TESTS=false

# Logging functions
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step() { echo -e "${PURPLE}[STEP]${NC} $1"; }

# Show usage information
show_usage() {
    cat << EOF
🚀 Release Management Script

Usage: $0 [VERSION_TYPE] [OPTIONS]

Version Types:
  patch      Increment patch version (1.0.0 → 1.0.1) - Default
  minor      Increment minor version (1.0.0 → 1.1.0)
  major      Increment major version (1.0.0 → 2.0.0)  
  prerelease Create prerelease (1.0.0 → 1.0.1-rc.TIMESTAMP)
  custom     Use custom version (requires --version)

Options:
  --version VERSION    Custom version number (e.g., 2.1.0)
  --notes "TEXT"       Custom release notes
  --dry-run           Show what would be done without executing
  --skip-tests        Skip pre-release tests (use with caution)
  --help              Show this help message

Examples:
  $0 patch                           # Create patch release (1.0.0 → 1.0.1)
  $0 minor --notes "New features"    # Create minor release with custom notes
  $0 major --dry-run                 # Preview major release changes
  $0 custom --version "2.0.0-beta"  # Create custom version release
  $0 prerelease                      # Create prerelease version

Prerequisites:
  - GitHub CLI (gh) installed and authenticated
  - Clean working directory (no uncommitted changes)
  - Push access to the repository

EOF
}

# Parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            patch|minor|major|prerelease|custom)
                VERSION_TYPE="$1"
                shift
                ;;
            --version)
                CUSTOM_VERSION="$2"
                VERSION_TYPE="custom"
                shift 2
                ;;
            --notes)
                CUSTOM_NOTES="$2"
                shift 2
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --skip-tests)
                SKIP_TESTS=true
                shift
                ;;
            --help)
                show_usage
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done

    if [[ "$VERSION_TYPE" == "custom" && -z "${CUSTOM_VERSION:-}" ]]; then
        log_error "Custom version type requires --version option"
        exit 1
    fi
}

# Check prerequisites
check_prerequisites() {
    log_step "Checking prerequisites..."
    
    # Check if we're in a git repository
    if ! git rev-parse --git-dir > /dev/null 2>&1; then
        log_error "Not in a git repository"
        exit 1
    fi
    
    # Check if GitHub CLI is installed
    if ! command -v gh &> /dev/null; then
        log_error "GitHub CLI (gh) is not installed. Install from: https://cli.github.com/"
        exit 1
    fi
    
    # Check if authenticated with GitHub
    if ! gh auth status &> /dev/null; then
        log_error "Not authenticated with GitHub CLI. Run: gh auth login"
        exit 1
    fi
    
    # Check for uncommitted changes
    if [[ -n "$(git status --porcelain)" ]]; then
        log_error "Working directory has uncommitted changes. Please commit or stash them first."
        git status --short
        exit 1
    fi
    
    # Check if on main/master branch
    CURRENT_BRANCH=$(git branch --show-current)
    if [[ "$CURRENT_BRANCH" != "main" && "$CURRENT_BRANCH" != "master" ]]; then
        log_warning "You're not on main/master branch (current: $CURRENT_BRANCH)"
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 0
        fi
    fi
    
    # Pull latest changes
    log_info "Pulling latest changes..."
    git pull origin "$CURRENT_BRANCH"
    
    log_success "Prerequisites check passed"
}

# Get current version
get_current_version() {
    CURRENT_VERSION=$(git describe --tags --abbrev=0 2>/dev/null || echo "v0.0.0")
    log_info "Current version: $CURRENT_VERSION"
    echo "$CURRENT_VERSION"
}

# Calculate next version
calculate_next_version() {
    local current_version="$1"
    local version_type="$2"
    
    if [[ "$version_type" == "custom" ]]; then
        if [[ ! $CUSTOM_VERSION =~ ^v ]]; then
            echo "v$CUSTOM_VERSION"
        else
            echo "$CUSTOM_VERSION"
        fi
        return
    fi
    
    # Remove 'v' prefix for calculation
    local current_clean="${current_version#v}"
    
    # Split version into components
    IFS='.' read -r major minor patch <<< "$current_clean"
    
    # Default values if empty
    major=${major:-0}
    minor=${minor:-0}
    patch=${patch:-0}
    
    case "$version_type" in
        "major")
            major=$((major + 1))
            minor=0
            patch=0
            ;;
        "minor")
            minor=$((minor + 1))
            patch=0
            ;;
        "patch")
            patch=$((patch + 1))
            ;;
        "prerelease")
            patch=$((patch + 1))
            local timestamp=$(date +%Y%m%d%H%M%S)
            echo "v${major}.${minor}.${patch}-rc.${timestamp}"
            return
            ;;
    esac
    
    echo "v${major}.${minor}.${patch}"
}

# Generate changelog
generate_changelog() {
    local current_version="$1"
    local next_version="$2"
    
    log_step "Generating changelog..."
    
    if [[ "$current_version" == "v0.0.0" ]]; then
        # First release - get all commits
        git log --pretty=format:"* %s (%h)" --no-merges
    else
        # Get commits since last tag
        git log "${current_version}..HEAD" --pretty=format:"* %s (%h)" --no-merges
    fi
}

# Show release preview
show_release_preview() {
    local current_version="$1"
    local next_version="$2"
    local changelog="$3"
    
    echo
    log_step "📋 Release Preview"
    echo "=================================================="
    echo -e "${BLUE}Repository:${NC} $GITHUB_REPO"
    echo -e "${BLUE}Current Version:${NC} $current_version"
    echo -e "${BLUE}Next Version:${NC} $next_version"
    echo -e "${BLUE}Version Type:${NC} $VERSION_TYPE"
    echo -e "${BLUE}Skip Tests:${NC} $SKIP_TESTS"
    echo
    echo -e "${BLUE}Changelog:${NC}"
    if [[ -n "$changelog" ]]; then
        echo "$changelog"
    else
        echo "* Maintenance release"
    fi
    echo
    if [[ -n "$CUSTOM_NOTES" ]]; then
        echo -e "${BLUE}Custom Notes:${NC}"
        echo "$CUSTOM_NOTES"
        echo
    fi
    echo -e "${BLUE}Container Images:${NC}"
    echo "📦 ghcr.io/$GITHUB_REPO/backend:$next_version"
    echo "📦 ghcr.io/$GITHUB_REPO/frontend:$next_version"
    echo "=================================================="
    echo
}

# Trigger release workflow
trigger_release() {
    local version_type="$1"
    local custom_version="${2:-}"
    local custom_notes="${3:-}"
    local skip_tests="$4"
    
    log_step "Triggering GitHub Actions release workflow..."
    
    local gh_args=(
        "workflow" "run" "release-streamlined.yml"
        "--field" "version_type=$version_type"
        "--field" "skip_tests=$skip_tests"
    )
    
    if [[ -n "$custom_version" ]]; then
        gh_args+=("--field" "custom_version=$custom_version")
    fi
    
    if [[ -n "$custom_notes" ]]; then
        gh_args+=("--field" "release_notes=$custom_notes")
    fi
    
    if gh "${gh_args[@]}"; then
        log_success "Release workflow triggered successfully!"
        
        # Get the workflow URL
        local workflow_url="https://github.com/$GITHUB_REPO/actions/workflows/release-streamlined.yml"
        echo
        log_info "🔗 Monitor progress: $workflow_url"
        log_info "📦 Packages will be available: https://github.com/$GITHUB_REPO/pkgs/container"
        
        # Wait a bit then check status
        log_info "Waiting for workflow to start..."
        sleep 5
        
        if command -v gh &> /dev/null; then
            log_info "Recent workflow runs:"
            gh run list --workflow="release-streamlined.yml" --limit=3
        fi
    else
        log_error "Failed to trigger release workflow"
        exit 1
    fi
}

# Main execution
main() {
    echo "🚀 Release Management Script"
    echo "============================"
    echo
    
    # Parse arguments
    parse_arguments "$@"
    
    # Check prerequisites
    check_prerequisites
    
    # Get version information
    local current_version
    current_version=$(get_current_version)
    
    local next_version
    if [[ "$VERSION_TYPE" == "custom" ]]; then
        next_version=$(calculate_next_version "$current_version" "custom")
    else
        next_version=$(calculate_next_version "$current_version" "$VERSION_TYPE")
    fi
    
    # Generate changelog
    local changelog
    changelog=$(generate_changelog "$current_version" "$next_version")
    
    # Show preview
    show_release_preview "$current_version" "$next_version" "$changelog"
    
    # Confirm or execute
    if [[ "$DRY_RUN" == "true" ]]; then
        log_warning "🔍 DRY RUN - No changes will be made"
        exit 0
    fi
    
    echo -e "${YELLOW}Do you want to create this release? (y/N):${NC} "
    read -n 1 -r
    echo
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        # Trigger the release
        local custom_version_arg=""
        if [[ "$VERSION_TYPE" == "custom" ]]; then
            custom_version_arg="${next_version#v}"
        fi
        
        trigger_release "$VERSION_TYPE" "$custom_version_arg" "$CUSTOM_NOTES" "$SKIP_TESTS"
        
        log_success "🎉 Release process initiated!"
        log_info "The release will be created by GitHub Actions. Check the workflow for progress."
    else
        log_info "Release cancelled"
        exit 0
    fi
}

# Handle script interruption
trap 'log_error "Script interrupted"; exit 1' INT TERM

# Run main function
main "$@"