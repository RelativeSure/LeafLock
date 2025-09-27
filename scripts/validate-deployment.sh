#!/bin/bash
# validate-deployment.sh - Comprehensive deployment validation suite
# This script orchestrates all deployment validation tests

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Test configuration
RUN_FULL_DEPLOYMENT_TEST=false
RUN_COOLIFY_TESTS=false
CLEANUP_ON_EXIT=true
VERBOSE_OUTPUT=false

# Logging functions with enhanced formatting
log_header() {
    echo
    echo -e "${CYAN}${BOLD}============================================================${NC}"
    echo -e "${CYAN}${BOLD} $1${NC}"
    echo -e "${CYAN}${BOLD}============================================================${NC}"
    echo
}

log_section() {
    echo
    echo -e "${BLUE}${BOLD}=== $1 ===${NC}"
    echo
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_verbose() {
    if [ "$VERBOSE_OUTPUT" = true ]; then
        echo -e "${CYAN}[VERBOSE]${NC} $1"
    fi
}

# Results tracking
declare -A test_results
declare -a test_order

record_test_result() {
    local test_name="$1"
    local result="$2"  # "PASS", "FAIL", "WARN", "SKIP"

    test_results["$test_name"]="$result"
    test_order+=("$test_name")
}

# Show usage information
usage() {
    cat << 'EOF'
Usage: validate-deployment.sh [OPTIONS]

Comprehensive deployment validation suite for LeafLock.

OPTIONS:
    --full                Run full deployment tests (starts containers)
    --coolify            Include Coolify-specific validations
    --no-cleanup         Don't cleanup containers after tests
    --verbose            Show verbose output
    --help, -h           Show this help message

VALIDATION TESTS:
    1. Docker Compose Syntax         - Validates compose file syntax
    2. Environment Variables         - Validates .env file and security
    3. Coolify Configuration        - Validates Coolify deployment setup
    4. Container Build Test         - Tests container image building
    5. Full Deployment Test         - Starts and tests complete deployment

EXAMPLES:
    ./validate-deployment.sh                    # Basic validation
    ./validate-deployment.sh --full             # Full deployment test
    ./validate-deployment.sh --coolify          # Include Coolify tests
    ./validate-deployment.sh --full --coolify   # Complete validation suite

FILES VALIDATED:
    - docker-compose.yml
    - docker-compose.coolify.yml
    - .env
    - .env.example
    - Dockerfile (backend/frontend)

The script will provide a comprehensive report at the end with:
    - Overall validation status
    - Individual test results
    - Recommendations for improvements
    - Next steps for deployment

EOF
}

# Check script dependencies
check_script_dependencies() {
    log_section "Checking Script Dependencies"

    local scripts=(
        "validate-docker-compose.sh"
        "validate-env.sh"
        "validate-coolify.sh"
        "test-deployment.sh"
    )

    local missing_scripts=()

    for script in "${scripts[@]}"; do
        if [ -f "$SCRIPT_DIR/$script" ] && [ -x "$SCRIPT_DIR/$script" ]; then
            log_success "$script is available and executable"
        else
            log_error "$script is missing or not executable"
            missing_scripts+=("$script")
        fi
    done

    if [ ${#missing_scripts[@]} -gt 0 ]; then
        log_error "Missing required validation scripts: ${missing_scripts[*]}"
        return 1
    fi

    log_success "All validation scripts are available"
    return 0
}

# Validate Docker Compose files
run_compose_validation() {
    log_section "Docker Compose Validation"

    log_info "Running docker-compose syntax validation..."

    if "$SCRIPT_DIR/validate-docker-compose.sh"; then
        log_success "Docker Compose validation passed"
        record_test_result "Docker Compose Syntax" "PASS"
        return 0
    else
        log_error "Docker Compose validation failed"
        record_test_result "Docker Compose Syntax" "FAIL"
        return 1
    fi
}

# Validate environment variables
run_env_validation() {
    log_section "Environment Variable Validation"

    log_info "Running environment variable validation..."

    if "$SCRIPT_DIR/validate-env.sh"; then
        log_success "Environment variable validation passed"
        record_test_result "Environment Variables" "PASS"
        return 0
    else
        log_error "Environment variable validation failed"
        record_test_result "Environment Variables" "FAIL"
        return 1
    fi
}

# Validate Coolify configuration
run_coolify_validation() {
    log_section "Coolify Configuration Validation"

    if [ "$RUN_COOLIFY_TESTS" = false ]; then
        log_info "Coolify validation skipped (use --coolify to enable)"
        record_test_result "Coolify Configuration" "SKIP"
        return 0
    fi

    log_info "Running Coolify deployment validation..."

    if "$SCRIPT_DIR/validate-coolify.sh"; then
        log_success "Coolify validation passed"
        record_test_result "Coolify Configuration" "PASS"
        return 0
    else
        log_error "Coolify validation failed"
        record_test_result "Coolify Configuration" "FAIL"
        return 1
    fi
}

# Test container builds
run_build_test() {
    log_section "Container Build Test"

    log_info "Testing container image builds..."

    local build_exit_code=0

    # Test backend build
    log_info "Building backend container..."
    cd "$PROJECT_ROOT"

    if docker build -t leaflock-backend-test ./backend > /dev/null 2>&1 || podman build -t leaflock-backend-test ./backend > /dev/null 2>&1; then
        log_success "Backend container build successful"
    else
        log_error "Backend container build failed"
        build_exit_code=1
    fi

    # Test frontend build
    log_info "Building frontend container..."

    if docker build -t leaflock-frontend-test ./frontend > /dev/null 2>&1 || podman build -t leaflock-frontend-test ./frontend > /dev/null 2>&1; then
        log_success "Frontend container build successful"
    else
        log_error "Frontend container build failed"
        build_exit_code=1
    fi

    # Cleanup test images
    if [ "$CLEANUP_ON_EXIT" = true ]; then
        log_verbose "Cleaning up test images..."
        docker rmi leaflock-backend-test leaflock-frontend-test 2>/dev/null || true
        podman rmi leaflock-backend-test leaflock-frontend-test 2>/dev/null || true
    fi

    if [ $build_exit_code -eq 0 ]; then
        log_success "Container build test passed"
        record_test_result "Container Build" "PASS"
        return 0
    else
        log_error "Container build test failed"
        record_test_result "Container Build" "FAIL"
        return 1
    fi
}

# Run full deployment test
run_deployment_test() {
    log_section "Full Deployment Test"

    if [ "$RUN_FULL_DEPLOYMENT_TEST" = false ]; then
        log_info "Full deployment test skipped (use --full to enable)"
        record_test_result "Full Deployment" "SKIP"
        return 0
    fi

    log_info "Running complete deployment test..."
    log_warning "This will start containers and may take several minutes..."

    # Test standard docker-compose
    log_info "Testing docker-compose.yml deployment..."
    if "$SCRIPT_DIR/test-deployment.sh" docker-compose.yml; then
        log_success "Standard deployment test passed"

        # Test Coolify deployment if enabled
        if [ "$RUN_COOLIFY_TESTS" = true ]; then
            log_info "Testing docker-compose.coolify.yml deployment..."
            if "$SCRIPT_DIR/test-deployment.sh" docker-compose.coolify.yml; then
                log_success "Coolify deployment test passed"
                record_test_result "Full Deployment" "PASS"
                return 0
            else
                log_error "Coolify deployment test failed"
                record_test_result "Full Deployment" "FAIL"
                return 1
            fi
        else
            record_test_result "Full Deployment" "PASS"
            return 0
        fi
    else
        log_error "Standard deployment test failed"
        record_test_result "Full Deployment" "FAIL"
        return 1
    fi
}

# Generate security recommendations
generate_security_recommendations() {
    log_section "Security Recommendations"

    local env_file="$PROJECT_ROOT/.env"
    local recommendations=()

    # Check if .env exists and analyze it
    if [ -f "$env_file" ]; then
        # Check for default/weak passwords
        if grep -q "your_secure.*password" "$env_file" 2>/dev/null; then
            recommendations+=("Update default password placeholders in .env file")
        fi

        # Check for short passwords
        if grep -E "PASSWORD=.{1,11}$" "$env_file" 2>/dev/null; then
            recommendations+=("Use longer passwords (12+ characters minimum)")
        fi

        # Check for missing special characters in passwords
        if grep -E "PASSWORD=[A-Za-z0-9]+$" "$env_file" 2>/dev/null; then
            recommendations+=("Add special characters to passwords for better security")
        fi

        # Check CORS origins
        if grep -q "^CORS_ORIGINS=" "$env_file" 2>/dev/null; then
            cors_value=$(grep "^CORS_ORIGINS=" "$env_file" 2>/dev/null | tail -n1 | cut -d'=' -f2-)
            if [[ "$cors_value" == *"*"* ]]; then
                allow_wildcards=true
                IFS=',' read -ra origins <<< "$cors_value"
                for origin in "${origins[@]}"; do
                    trimmed_origin="${origin#${origin%%[![:space:]]*}}"
                    trimmed_origin="${trimmed_origin%${trimmed_origin##*[![:space:]]]}}"
                    if [[ "$trimmed_origin" == http*://* ]]; then
                        if [[ "$trimmed_origin" == *"://*."* ]]; then
                            # Allowed wildcard subdomain pattern (e.g., https://*.example.com)
                            continue
                        fi
                    fi
                    allow_wildcards=false
                    break
                done
                if [ "$allow_wildcards" = false ]; then
                    recommendations+=("Restrict CORS_ORIGINS to specific domains (avoid wildcard *)")
                fi
            fi
        fi

        # Check for HTTP in production URLs
        if grep -q "VITE_API_URL=http://" "$env_file" 2>/dev/null; then
            recommendations+=("Use HTTPS for VITE_API_URL in production")
        fi
    else
        recommendations+=("Create .env file from .env.example template")
    fi

    # Check SSL mode in compose files
    if ! grep -q "sslmode=require" "$PROJECT_ROOT"/docker-compose*.yml 2>/dev/null; then
        recommendations+=("Consider using sslmode=require for database connections in production")
    fi

    if [ ${#recommendations[@]} -gt 0 ]; then
        log_warning "Security improvements recommended:"
        for rec in "${recommendations[@]}"; do
            echo "  • $rec"
        done
    else
        log_success "No immediate security concerns found"
    fi
}

# Generate final report
generate_final_report() {
    log_header "VALIDATION SUMMARY REPORT"

    local total_tests=0
    local passed_tests=0
    local failed_tests=0
    local warning_tests=0
    local skipped_tests=0

    echo -e "${BOLD}Test Results:${NC}"
    echo "=============="

    for test_name in "${test_order[@]}"; do
        local result="${test_results[$test_name]}"
        ((total_tests++))

        case "$result" in
            "PASS")
                echo -e "  ${GREEN}✓${NC} $test_name"
                ((passed_tests++))
                ;;
            "FAIL")
                echo -e "  ${RED}✗${NC} $test_name"
                ((failed_tests++))
                ;;
            "WARN")
                echo -e "  ${YELLOW}⚠${NC} $test_name"
                ((warning_tests++))
                ;;
            "SKIP")
                echo -e "  ${CYAN}-${NC} $test_name (skipped)"
                ((skipped_tests++))
                ;;
        esac
    done

    echo
    echo -e "${BOLD}Summary:${NC}"
    echo "========="
    echo "  Total tests:   $total_tests"
    echo "  Passed:        $passed_tests"
    echo "  Failed:        $failed_tests"
    echo "  Warnings:      $warning_tests"
    echo "  Skipped:       $skipped_tests"

    echo
    if [ $failed_tests -eq 0 ]; then
        if [ $warning_tests -eq 0 ]; then
            log_success "All tests passed! Your deployment is ready."
        else
            log_warning "Tests passed with warnings. Review recommendations above."
        fi

        echo -e "${BOLD}Next Steps:${NC}"
        echo "==========="
        if [ "$RUN_COOLIFY_TESTS" = true ]; then
            echo "  1. Set environment variables in Coolify UI"
            echo "  2. Configure domain and SSL in Coolify"
            echo "  3. Deploy using docker-compose.coolify.yml"
            echo "  4. Monitor deployment logs"
            echo "  5. Test the deployed application"
            echo "  6. Change default admin password"
        else
            echo "  1. Review and update .env file with secure values"
            echo "  2. Run deployment: docker-compose up -d"
            echo "  3. Test the application endpoints"
            echo "  4. Change default admin password"
            echo "  5. Consider running with --coolify for production deployment"
        fi

        return 0
    else
        log_error "Some tests failed. Please fix the issues before deployment."

        echo -e "${BOLD}Failed Tests:${NC}"
        echo "============="
        for test_name in "${test_order[@]}"; do
            if [ "${test_results[$test_name]}" = "FAIL" ]; then
                echo "  • $test_name"
            fi
        done

        echo
        echo -e "${BOLD}Recommended Actions:${NC}"
        echo "===================="
        echo "  1. Fix the failed tests listed above"
        echo "  2. Run individual validation scripts for detailed error information"
        echo "  3. Re-run this validation suite after fixes"
        echo "  4. Consider running with --verbose for more detailed output"

        return 1
    fi
}

# Main validation orchestration
main() {
    log_header "LEAFLOCK DEPLOYMENT VALIDATION SUITE"

    log_info "Starting comprehensive deployment validation..."
    log_info "Project root: $PROJECT_ROOT"
    log_info "Options: full=$RUN_FULL_DEPLOYMENT_TEST, coolify=$RUN_COOLIFY_TESTS, cleanup=$CLEANUP_ON_EXIT"

    local overall_exit_code=0

    # Check script dependencies first
    if ! check_script_dependencies; then
        log_error "Cannot proceed without required validation scripts"
        return 1
    fi

    # Run validation tests in order
    run_compose_validation || overall_exit_code=1
    run_env_validation || overall_exit_code=1
    run_coolify_validation || overall_exit_code=1
    run_build_test || overall_exit_code=1
    run_deployment_test || overall_exit_code=1

    # Generate security recommendations
    generate_security_recommendations

    # Generate final report
    generate_final_report

    return $overall_exit_code
}

# Parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --full)
                RUN_FULL_DEPLOYMENT_TEST=true
                shift
                ;;
            --coolify)
                RUN_COOLIFY_TESTS=true
                shift
                ;;
            --no-cleanup)
                CLEANUP_ON_EXIT=false
                shift
                ;;
            --verbose)
                VERBOSE_OUTPUT=true
                shift
                ;;
            --help|-h)
                usage
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done
}

# Cleanup function for signal handling
cleanup() {
    if [ "$CLEANUP_ON_EXIT" = true ]; then
        log_verbose "Performing cleanup..."

        # Stop any running containers from tests
        cd "$PROJECT_ROOT"
        docker compose -f docker-compose.yml down --volumes --remove-orphans 2>/dev/null || true
        podman-compose -f docker-compose.yml down --volumes 2>/dev/null || true

        # Remove test images
        docker rmi leaflock-backend-test leaflock-frontend-test 2>/dev/null || true
        podman rmi leaflock-backend-test leaflock-frontend-test 2>/dev/null || true
    fi
}

# Set up signal handlers
trap cleanup EXIT INT TERM

# Run main function if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    parse_arguments "$@"
    main
fi
