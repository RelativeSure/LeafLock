#!/bin/bash
# Note: Prefer leaflock.sh test to run this end-to-end test automation.

# Automated Testing and Validation Workflow
# Comprehensive test automation for LeafLock development

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
TEST_RESULTS_DIR="/tmp/leaflock-test-results"
COVERAGE_THRESHOLD=80
PERFORMANCE_THRESHOLD=1000  # ms
PARALLEL_JOBS=4

# Test tracking
declare -A test_results
declare -A test_timings

# Logging functions
log_info() {
    echo -e "${BLUE}[TEST]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[FAIL]${NC} $1"
}

log_section() {
    echo -e "${PURPLE}[SECTION]${NC} $1"
}

# Initialize test environment
setup_test_environment() {
    log_info "Setting up test environment..."
    
    # Create results directory
    mkdir -p "$TEST_RESULTS_DIR"
    
    # Clear previous results
    rm -f "$TEST_RESULTS_DIR"/*.log "$TEST_RESULTS_DIR"/*.xml "$TEST_RESULTS_DIR"/*.json
    
    log_success "Test environment initialized"
}

# Run backend unit tests
run_backend_unit_tests() {
    log_section "Backend Unit Tests"
    
    local start_time=$(date +%s)
    local test_file="$TEST_RESULTS_DIR/backend-unit.log"
    
    cd backend
    
    log_info "Running Go unit tests..."
    
    if go test -short -v -timeout=5m ./... > "$test_file" 2>&1; then
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        
        test_results[backend_unit]="PASS"
        test_timings[backend_unit]=$duration
        
        # Extract test statistics
        local tests_run=$(grep -c "=== RUN" "$test_file" || echo "0")
        local tests_passed=$(grep -c "--- PASS:" "$test_file" || echo "0")
        
        log_success "Backend unit tests passed ($tests_passed/$tests_run tests, ${duration}s)"
    else
        test_results[backend_unit]="FAIL"
        log_error "Backend unit tests failed"
        
        # Show recent failures
        log_info "Recent test failures:"
        grep -A 5 -B 5 "--- FAIL:" "$test_file" | tail -20 || true
    fi
    
    cd ..
}

# Run backend integration tests
run_backend_integration_tests() {
    log_section "Backend Integration Tests"
    
    local start_time=$(date +%s)
    local test_file="$TEST_RESULTS_DIR/backend-integration.log"
    
    cd backend
    
    # Check if test databases are available
    log_info "Checking test database availability..."
    
    if ! make test-db-up >/dev/null 2>&1; then
        log_warning "Test databases not available, starting..."
        make test-db-up || {
            log_error "Failed to start test databases"
            test_results[backend_integration]="SKIP"
            cd ..
            return 1
        }
    fi
    
    log_info "Running Go integration tests..."
    
    if DATABASE_URL="postgres://test:test@localhost:5433/test_notes?sslmode=disable" \
       REDIS_URL="localhost:6380" \
       go test -v -timeout=10m -run="Integration" ./... > "$test_file" 2>&1; then
        
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        
        test_results[backend_integration]="PASS"
        test_timings[backend_integration]=$duration
        
        log_success "Backend integration tests passed (${duration}s)"
    else
        test_results[backend_integration]="FAIL"
        log_error "Backend integration tests failed"
        
        # Show recent failures
        log_info "Recent integration test failures:"
        grep -A 10 -B 5 "--- FAIL:" "$test_file" | tail -30 || true
    fi
    
    # Cleanup test databases
    make test-db-down >/dev/null 2>&1 || true
    
    cd ..
}

# Run backend security tests
run_backend_security_tests() {
    log_section "Backend Security Tests"
    
    local start_time=$(date +%s)
    local test_file="$TEST_RESULTS_DIR/backend-security.log"
    
    cd backend
    
    log_info "Running security tests..."
    
    if go test -v -timeout=10m -run="Security|Vulnerability|Penetration" ./... > "$test_file" 2>&1; then
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        
        test_results[backend_security]="PASS"
        test_timings[backend_security]=$duration
        
        log_success "Backend security tests passed (${duration}s)"
    else
        test_results[backend_security]="FAIL"
        log_error "Backend security tests failed"
        
        grep -A 5 -B 5 "--- FAIL:" "$test_file" | tail -20 || true
    fi
    
    # Run additional security scans
    log_info "Running vulnerability scan..."
    
    if command -v govulncheck >/dev/null 2>&1; then
        if govulncheck ./... > "$TEST_RESULTS_DIR/vulnerability-scan.log" 2>&1; then
            log_success "Vulnerability scan passed"
        else
            log_warning "Vulnerability scan found issues"
            tail -10 "$TEST_RESULTS_DIR/vulnerability-scan.log"
        fi
    else
        log_warning "govulncheck not available - install with: go install golang.org/x/vuln/cmd/govulncheck@latest"
    fi
    
    cd ..
}

# Run backend coverage analysis
run_backend_coverage() {
    log_section "Backend Coverage Analysis"
    
    local start_time=$(date +%s)
    local coverage_file="$TEST_RESULTS_DIR/backend-coverage.out"
    local coverage_html="$TEST_RESULTS_DIR/backend-coverage.html"
    
    cd backend
    
    log_info "Running coverage analysis..."
    
    if go test -coverprofile="$coverage_file" -covermode=atomic -v ./... >/dev/null 2>&1; then
        # Generate HTML report
        go tool cover -html="$coverage_file" -o "$coverage_html"
        
        # Get coverage percentage
        local coverage=$(go tool cover -func="$coverage_file" | grep total | awk '{print $3}' | sed 's/%//')
        
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        
        test_timings[backend_coverage]=$duration
        
        if [ "$(echo "$coverage >= $COVERAGE_THRESHOLD" | bc -l)" -eq 1 ] 2>/dev/null || [ "${coverage%.*}" -ge "$COVERAGE_THRESHOLD" ]; then
            test_results[backend_coverage]="PASS"
            log_success "Backend coverage: ${coverage}% (threshold: ${COVERAGE_THRESHOLD}%, ${duration}s)"
        else
            test_results[backend_coverage]="FAIL"
            log_error "Backend coverage: ${coverage}% below threshold ${COVERAGE_THRESHOLD}%"
        fi
        
        log_info "Coverage report saved to: $coverage_html"
    else
        test_results[backend_coverage]="FAIL"
        log_error "Coverage analysis failed"
    fi
    
    cd ..
}

# Run frontend unit tests
run_frontend_unit_tests() {
    log_section "Frontend Unit Tests"
    
    local start_time=$(date +%s)
    local test_file="$TEST_RESULTS_DIR/frontend-unit.log"
    
    cd frontend
    
    log_info "Running frontend unit tests..."
    
    if npm test -- --run --reporter=verbose > "$test_file" 2>&1; then
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        
        test_results[frontend_unit]="PASS"
        test_timings[frontend_unit]=$duration
        
        # Extract test statistics
        local tests_summary=$(grep -E "Tests|Suites" "$test_file" | tail -1 || echo "Tests completed")
        
        log_success "Frontend unit tests passed ($tests_summary, ${duration}s)"
    else
        test_results[frontend_unit]="FAIL"
        log_error "Frontend unit tests failed"
        
        # Show recent failures
        log_info "Recent test failures:"
        grep -A 10 "FAIL" "$test_file" | tail -20 || true
    fi
    
    cd ..
}

# Run frontend coverage analysis
run_frontend_coverage() {
    log_section "Frontend Coverage Analysis"
    
    local start_time=$(date +%s)
    local test_file="$TEST_RESULTS_DIR/frontend-coverage.log"
    
    cd frontend
    
    log_info "Running frontend coverage analysis..."
    
    if npm run test:coverage -- --run > "$test_file" 2>&1; then
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        
        test_timings[frontend_coverage]=$duration
        
        # Extract coverage percentage (look for coverage summary)
        local coverage=$(grep -o '[0-9.]*%' "$test_file" | head -1 | sed 's/%//' || echo "0")
        
        if [ "$(echo "$coverage >= $COVERAGE_THRESHOLD" | bc -l)" -eq 1 ] 2>/dev/null || [ "${coverage%.*}" -ge "$COVERAGE_THRESHOLD" ]; then
            test_results[frontend_coverage]="PASS"
            log_success "Frontend coverage: ${coverage}% (threshold: ${COVERAGE_THRESHOLD}%, ${duration}s)"
        else
            test_results[frontend_coverage]="FAIL"
            log_error "Frontend coverage: ${coverage}% below threshold ${COVERAGE_THRESHOLD}%"
        fi
        
        log_info "Coverage report saved to: frontend/coverage/index.html"
    else
        test_results[frontend_coverage]="FAIL"
        log_error "Frontend coverage analysis failed"
    fi
    
    cd ..
}

# Run linting and code quality checks
run_linting_checks() {
    log_section "Linting and Code Quality"
    
    local start_time=$(date +%s)
    
    # Backend linting
    log_info "Running backend linting..."
    
    cd backend
    if make fmt vet lint > "$TEST_RESULTS_DIR/backend-lint.log" 2>&1; then
        test_results[backend_lint]="PASS"
        log_success "Backend linting passed"
    else
        test_results[backend_lint]="FAIL"
        log_error "Backend linting failed"
        tail -20 "$TEST_RESULTS_DIR/backend-lint.log"
    fi
    cd ..
    
    # Frontend linting
    log_info "Running frontend linting..."
    
    cd frontend
    if npm run lint > "$TEST_RESULTS_DIR/frontend-lint.log" 2>&1; then
        test_results[frontend_lint]="PASS"
        log_success "Frontend linting passed"
    else
        test_results[frontend_lint]="FAIL"
        log_error "Frontend linting failed"
        tail -20 "$TEST_RESULTS_DIR/frontend-lint.log"
    fi
    
    # Type checking
    log_info "Running TypeScript type checking..."
    if npm run type-check > "$TEST_RESULTS_DIR/frontend-types.log" 2>&1; then
        test_results[frontend_types]="PASS"
        log_success "TypeScript type checking passed"
    else
        test_results[frontend_types]="FAIL"
        log_error "TypeScript type checking failed"
        tail -20 "$TEST_RESULTS_DIR/frontend-types.log"
    fi
    
    cd ..
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    test_timings[linting]=$duration
}

# Run performance tests
run_performance_tests() {
    log_section "Performance Tests"
    
    local start_time=$(date +%s)
    
    # Backend performance
    cd backend
    log_info "Running backend benchmarks..."
    
    if go test -bench=. -benchtime=5s ./... > "$TEST_RESULTS_DIR/backend-benchmarks.log" 2>&1; then
        test_results[backend_performance]="PASS"
        log_success "Backend benchmarks completed"
        
        # Extract benchmark results
        log_info "Benchmark highlights:"
        grep -E "Benchmark.*ns/op" "$TEST_RESULTS_DIR/backend-benchmarks.log" | head -5 || true
    else
        test_results[backend_performance]="FAIL"
        log_error "Backend benchmarks failed"
    fi
    cd ..
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    test_timings[performance]=$duration
}

# Run build tests
run_build_tests() {
    log_section "Build Tests"
    
    local start_time=$(date +%s)
    
    # Backend build
    log_info "Testing backend build..."
    cd backend
    if go build -o /tmp/leaflock-test . > "$TEST_RESULTS_DIR/backend-build.log" 2>&1; then
        test_results[backend_build]="PASS"
        log_success "Backend build passed"
        rm -f /tmp/leaflock-test
    else
        test_results[backend_build]="FAIL"
        log_error "Backend build failed"
        tail -20 "$TEST_RESULTS_DIR/backend-build.log"
    fi
    cd ..
    
    # Frontend build
    log_info "Testing frontend build..."
    cd frontend
    if npm run build > "$TEST_RESULTS_DIR/frontend-build.log" 2>&1; then
        test_results[frontend_build]="PASS"
        log_success "Frontend build passed"
        
        # Check build size
        if [ -d dist ]; then
            local build_size=$(du -sh dist | cut -f1)
            log_info "Frontend build size: $build_size"
        fi
    else
        test_results[frontend_build]="FAIL"
        log_error "Frontend build failed"
        tail -20 "$TEST_RESULTS_DIR/frontend-build.log"
    fi
    cd ..
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    test_timings[build]=$duration
}

# Run container build tests
run_container_tests() {
    log_section "Container Build Tests"
    
    local start_time=$(date +%s)
    
    if command -v podman >/dev/null 2>&1; then
        CONTAINER_CMD="podman"
    elif command -v docker >/dev/null 2>&1; then
        CONTAINER_CMD="docker"
    else
        log_warning "No container runtime available, skipping container tests"
        test_results[container_build]="SKIP"
        return 0
    fi
    
    # Test backend container build
    log_info "Testing backend container build..."
    cd backend
    if $CONTAINER_CMD build -t leaflock-backend-test -f Dockerfile . > "$TEST_RESULTS_DIR/backend-container.log" 2>&1; then
        log_success "Backend container build passed"
        $CONTAINER_CMD rmi leaflock-backend-test >/dev/null 2>&1 || true
    else
        test_results[container_build]="FAIL"
        log_error "Backend container build failed"
        tail -20 "$TEST_RESULTS_DIR/backend-container.log"
        cd ..
        return 1
    fi
    cd ..
    
    # Test frontend container build
    log_info "Testing frontend container build..."
    cd frontend
    if $CONTAINER_CMD build -t leaflock-frontend-test -f Dockerfile . > "$TEST_RESULTS_DIR/frontend-container.log" 2>&1; then
        log_success "Frontend container build passed"
        $CONTAINER_CMD rmi leaflock-frontend-test >/dev/null 2>&1 || true
        test_results[container_build]="PASS"
    else
        test_results[container_build]="FAIL"
        log_error "Frontend container build failed"
        tail -20 "$TEST_RESULTS_DIR/frontend-container.log"
    fi
    cd ..
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    test_timings[container_build]=$duration
}

# Generate test report
generate_test_report() {
    log_section "Generating Test Report"
    
    local report_file="$TEST_RESULTS_DIR/test-report-$(date +%Y%m%d-%H%M%S).html"
    local json_file="$TEST_RESULTS_DIR/test-results.json"
    
    # Generate JSON report
    {
        echo "{"
        echo "  \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\","
        echo "  \"results\": {"
        
        local first=true
        for test in "${!test_results[@]}"; do
            if [ "$first" = true ]; then
                first=false
            else
                echo ","
            fi
            echo -n "    \"$test\": {"
            echo -n "\"status\": \"${test_results[$test]}\""
            if [[ -n "${test_timings[$test]:-}" ]]; then
                echo -n ", \"duration\": ${test_timings[$test]}"
            fi
            echo -n "}"
        done
        echo
        echo "  }"
        echo "}"
    } > "$json_file"
    
    # Generate HTML report
    {
        cat << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>LeafLock Test Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { background: #f5f5f5; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        .section { margin-bottom: 30px; }
        .test-result { padding: 10px; margin: 5px 0; border-radius: 3px; }
        .pass { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .fail { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        .skip { background: #fff3cd; color: #856404; border: 1px solid #ffeaa7; }
        .summary { display: flex; gap: 20px; margin-bottom: 20px; }
        .metric { padding: 15px; background: #f8f9fa; border-radius: 5px; text-align: center; }
        .metric-value { font-size: 24px; font-weight: bold; color: #007bff; }
    </style>
</head>
<body>
EOF
        echo "<div class='header'>"
        echo "<h1>🧪 LeafLock Test Report</h1>"
        echo "<p>Generated: $(date)</p>"
        echo "<p>System: $(uname -a)</p>"
        echo "</div>"
        
        # Summary metrics
        local total_tests=${#test_results[@]}
        local passed_tests=$(printf '%s\n' "${test_results[@]}" | grep -c "PASS" || echo "0")
        local failed_tests=$(printf '%s\n' "${test_results[@]}" | grep -c "FAIL" || echo "0")
        local skipped_tests=$(printf '%s\n' "${test_results[@]}" | grep -c "SKIP" || echo "0")
        local success_rate=0
        
        if [ "$total_tests" -gt 0 ]; then
            success_rate=$((passed_tests * 100 / total_tests))
        fi
        
        echo "<div class='summary'>"
        echo "<div class='metric'><div class='metric-value'>$total_tests</div><div>Total Tests</div></div>"
        echo "<div class='metric'><div class='metric-value'>$passed_tests</div><div>Passed</div></div>"
        echo "<div class='metric'><div class='metric-value'>$failed_tests</div><div>Failed</div></div>"
        echo "<div class='metric'><div class='metric-value'>${success_rate}%</div><div>Success Rate</div></div>"
        echo "</div>"
        
        # Detailed results
        echo "<div class='section'>"
        echo "<h2>📋 Test Results</h2>"
        
        for test in "${!test_results[@]}"; do
            local status="${test_results[$test]}"
            local css_class=""
            local icon=""
            
            case "$status" in
                PASS) css_class="pass"; icon="✅" ;;
                FAIL) css_class="fail"; icon="❌" ;;
                SKIP) css_class="skip"; icon="⏭️" ;;
            esac
            
            echo "<div class='test-result $css_class'>"
            echo "$icon <strong>$(echo "$test" | tr '_' ' ' | sed 's/\b\w/\u&/g')</strong>: $status"
            if [[ -n "${test_timings[$test]:-}" ]]; then
                echo " (${test_timings[$test]}s)"
            fi
            echo "</div>"
        done
        
        echo "</div>"
        echo "</body></html>"
    } > "$report_file"
    
    log_success "Test report generated:"
    log_info "  HTML: $report_file"
    log_info "  JSON: $json_file"
    
    # Print summary to console
    echo
    log_section "Test Summary"
    echo "  Total Tests: $total_tests"
    echo "  Passed: $passed_tests"
    echo "  Failed: $failed_tests"
    echo "  Skipped: $skipped_tests"
    echo "  Success Rate: ${success_rate}%"
    
    if [ "$failed_tests" -eq 0 ]; then
        log_success "All tests passed! 🎉"
        return 0
    else
        log_error "$failed_tests test(s) failed"
        return 1
    fi
}

# Main test orchestration
run_all_tests() {
    local start_time=$(date +%s)
    
    log_info "Starting comprehensive test suite..."
    
    # Run tests in parallel where possible
    {
        run_backend_unit_tests &
        run_frontend_unit_tests &
        run_linting_checks &
        wait
    }
    
    # Run integration tests (require setup)
    run_backend_integration_tests
    run_backend_security_tests
    
    # Run coverage analysis
    {
        run_backend_coverage &
        run_frontend_coverage &
        wait
    }
    
    # Run performance and build tests
    {
        run_performance_tests &
        run_build_tests &
        wait
    }
    
    # Run container tests
    run_container_tests
    
    local end_time=$(date +%s)
    local total_duration=$((end_time - start_time))
    
    log_info "Test suite completed in ${total_duration}s"
    
    generate_test_report
}

# Quick development test cycle
run_quick_tests() {
    log_info "Running quick development tests..."
    
    {
        run_backend_unit_tests &
        run_frontend_unit_tests &
        run_linting_checks &
        wait
    }
    
    generate_test_report
}

# CI/CD test pipeline
run_ci_tests() {
    log_info "Running CI/CD test pipeline..."
    
    # All tests except performance (which can be flaky in CI)
    run_backend_unit_tests
    run_frontend_unit_tests
    run_linting_checks
    run_backend_integration_tests
    run_backend_security_tests
    run_backend_coverage
    run_frontend_coverage
    run_build_tests
    run_container_tests
    
    generate_test_report
}

# Main function
main() {
    echo -e "${BLUE}"
    cat << "EOF"
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║             🧪 LEAFLOCK AUTOMATED TESTING FRAMEWORK 🧪              ║
║                                                                ║
║     Comprehensive test automation and validation suite        ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
    
    setup_test_environment
    
    case "${1:-all}" in
        quick)
            run_quick_tests
            ;;
        ci)
            run_ci_tests
            ;;
        backend)
            run_backend_unit_tests
            run_backend_integration_tests
            run_backend_security_tests
            run_backend_coverage
            generate_test_report
            ;;
        frontend)
            run_frontend_unit_tests
            run_frontend_coverage
            generate_test_report
            ;;
        lint)
            run_linting_checks
            generate_test_report
            ;;
        build)
            run_build_tests
            run_container_tests
            generate_test_report
            ;;
        all)
            run_all_tests
            ;;
        *)
            echo "Usage: $0 [quick|ci|backend|frontend|lint|build|all]"
            echo
            echo "Test suites:"
            echo "  quick     - Quick development tests (unit + lint)"
            echo "  ci        - CI/CD pipeline tests"
            echo "  backend   - Backend tests (unit, integration, security, coverage)"
            echo "  frontend  - Frontend tests (unit, coverage)"
            echo "  lint      - Code quality and linting"
            echo "  build     - Build and container tests"
            echo "  all       - Complete test suite (default)"
            echo
            exit 1
            ;;
    esac
    
    log_info "Test results saved to: $TEST_RESULTS_DIR"
}

# Run main function
main "$@"
