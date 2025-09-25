#!/bin/bash

# Comprehensive Testing Suite for LeafLock Application
# This script runs all tests (frontend, backend, integration, security) in parallel

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
TEST_RESULTS_DIR="./test-results"
COVERAGE_DIR="./coverage"
BACKEND_DIR="./backend"
FRONTEND_DIR="./frontend"

# Test databases
TEST_POSTGRES_URL="postgres://test:test@localhost:5433/test_notes?sslmode=disable"
TEST_REDIS_URL="localhost:6380"

# Progress tracking
TESTS_TOTAL=0
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0

# Create directories
mkdir -p "$TEST_RESULTS_DIR"
mkdir -p "$COVERAGE_DIR"

# Function to print colored output
print_status() {
    local status=$1
    local message=$2
    local color=$NC
    
    case $status in
        "INFO") color=$BLUE ;;
        "SUCCESS") color=$GREEN ;;
        "WARNING") color=$YELLOW ;;
        "ERROR") color=$RED ;;
        "RUNNING") color=$PURPLE ;;
    esac
    
    echo -e "${color}[$(date '+%H:%M:%S')] [$status]${NC} $message"
}

# Function to run command with timeout and logging
run_test() {
    local test_name=$1
    local command=$2
    local timeout=${3:-300}  # 5 minute default timeout
    local log_file="$TEST_RESULTS_DIR/${test_name}.log"
    
    print_status "RUNNING" "Starting $test_name"
    
    if timeout ${timeout}s bash -c "$command" > "$log_file" 2>&1; then
        print_status "SUCCESS" "$test_name completed successfully"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        print_status "ERROR" "$test_name failed (see $log_file for details)"
        echo "Last 10 lines of $log_file:"
        tail -n 10 "$log_file" | sed 's/^/  /'
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

# Function to check prerequisites
check_prerequisites() {
    print_status "INFO" "Checking prerequisites..."
    
    local missing_deps=()
    
    # Check Go
    if ! command -v go &> /dev/null; then
        missing_deps+=("go")
    fi
    
    # Check Node.js and pnpm
    if ! command -v node &> /dev/null; then
        missing_deps+=("node")
    fi
    
    if ! command -v pnpm &> /dev/null; then
        missing_deps+=("pnpm")
    fi
    
    # Check if test directories exist
    if [ ! -d "$BACKEND_DIR" ]; then
        print_status "ERROR" "Backend directory not found: $BACKEND_DIR"
        exit 1
    fi
    
    if [ ! -d "$FRONTEND_DIR" ]; then
        print_status "ERROR" "Frontend directory not found: $FRONTEND_DIR"
        exit 1
    fi
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        print_status "ERROR" "Missing dependencies: ${missing_deps[*]}"
        exit 1
    fi
    
    print_status "SUCCESS" "All prerequisites satisfied"
}

# Function to setup test environment
setup_test_environment() {
    print_status "INFO" "Setting up test environment..."
    
    # Install backend dependencies
    print_status "INFO" "Installing backend dependencies..."
    cd "$BACKEND_DIR"
    go mod download || {
        print_status "ERROR" "Failed to download backend dependencies"
        exit 1
    }
    cd ..
    
    # Install frontend dependencies
    print_status "INFO" "Installing frontend dependencies..."
    cd "$FRONTEND_DIR"
    pnpm install || {
        print_status "ERROR" "Failed to install frontend dependencies"
        exit 1
    }
    cd ..
    
    print_status "SUCCESS" "Test environment setup complete"
}

# Backend Tests
run_backend_tests() {
    print_status "INFO" "Running backend test suite..."
    cd "$BACKEND_DIR"
    
    # Unit Tests
    TESTS_TOTAL=$((TESTS_TOTAL + 1))
    run_test "backend-unit" "go test -short -v -timeout=5m ./..."
    
    # Race Condition Tests
    TESTS_TOTAL=$((TESTS_TOTAL + 1))
    run_test "backend-race" "go test -race -short -timeout=10m ./..."
    
    # Security Tests  
    TESTS_TOTAL=$((TESTS_TOTAL + 1))
    run_test "backend-security" "go test -v -run='TestPassword|TestCrypto|TestAuth|TestSecurity' -timeout=5m ./..."
    
    # Coverage Test
    TESTS_TOTAL=$((TESTS_TOTAL + 1))
    run_test "backend-coverage" "go test -coverprofile=../coverage/backend-coverage.out -covermode=atomic ./... && go tool cover -html=../coverage/backend-coverage.out -o ../coverage/backend-coverage.html"
    
    # Benchmarks
    TESTS_TOTAL=$((TESTS_TOTAL + 1))
    run_test "backend-benchmarks" "go test -bench=. -benchtime=3s -timeout=10m ./..."
    
    cd ..
}

# Frontend Tests
run_frontend_tests() {
    print_status "INFO" "Running frontend test suite..."
    cd "$FRONTEND_DIR"
    
    # Unit Tests
    TESTS_TOTAL=$((TESTS_TOTAL + 1))
    run_test "frontend-unit" "pnpm test -- --run --reporter=verbose"
    
    # Coverage Tests
    TESTS_TOTAL=$((TESTS_TOTAL + 1))
    run_test "frontend-coverage" "pnpm run test:coverage -- --run"
    
    # Type Check
    TESTS_TOTAL=$((TESTS_TOTAL + 1))
    run_test "frontend-typecheck" "pnpm run typecheck"
    
    # Linting
    TESTS_TOTAL=$((TESTS_TOTAL + 1))
    run_test "frontend-lint" "pnpm run lint"
    
    cd ..
}

# Integration Tests (requires test databases)
run_integration_tests() {
    print_status "INFO" "Running integration tests..."
    
    # Check if test databases are available
    if ! pg_isready -h localhost -p 5433 -U test &> /dev/null; then
        print_status "WARNING" "Test PostgreSQL not available, skipping integration tests"
        TESTS_SKIPPED=$((TESTS_SKIPPED + 1))
        return 0
    fi
    
    if ! redis-cli -p 6380 ping &> /dev/null; then
        print_status "WARNING" "Test Redis not available, skipping integration tests"
        TESTS_SKIPPED=$((TESTS_SKIPPED + 1))
        return 0
    fi
    
    cd "$BACKEND_DIR"
    
    # Integration Tests with real databases
    TESTS_TOTAL=$((TESTS_TOTAL + 1))
    DATABASE_URL="$TEST_POSTGRES_URL" REDIS_URL="$TEST_REDIS_URL" \
        run_test "backend-integration" "go test -v -timeout=15m -tags=integration ./..."
    
    cd ..
}

# Build Tests
run_build_tests() {
    print_status "INFO" "Running build tests..."
    
    # Backend Build Test
    TESTS_TOTAL=$((TESTS_TOTAL + 1))
    run_test "backend-build" "cd $BACKEND_DIR && go build -v -o app ."
    
    # Frontend Build Test
    TESTS_TOTAL=$((TESTS_TOTAL + 1))
    run_test "frontend-build" "cd $FRONTEND_DIR && pnpm run build"
    
    # Docker Build Test (if Docker is available)
    if command -v docker &> /dev/null; then
        TESTS_TOTAL=$((TESTS_TOTAL + 1))
        run_test "docker-build" "docker build -t leaflock-test ."
    else
        print_status "WARNING" "Docker not available, skipping Docker build test"
        TESTS_SKIPPED=$((TESTS_SKIPPED + 1))
    fi
}

# Security Tests
run_security_tests() {
    print_status "INFO" "Running security tests..."
    
    cd "$BACKEND_DIR"
    
    # Crypto Tests
    TESTS_TOTAL=$((TESTS_TOTAL + 1))
    run_test "security-crypto" "go test -v -run='TestCrypto' -timeout=5m ./..."
    
    # Password Security Tests
    TESTS_TOTAL=$((TESTS_TOTAL + 1))
    run_test "security-password" "go test -v -run='TestPassword' -timeout=5m ./..."
    
    # JWT Security Tests
    TESTS_TOTAL=$((TESTS_TOTAL + 1))
    run_test "security-jwt" "go test -v -run='TestJWT' -timeout=5m ./..."
    
    cd ..
    
    cd "$FRONTEND_DIR"
    
    # Frontend Security Tests
    TESTS_TOTAL=$((TESTS_TOTAL + 1))
    run_test "security-frontend" "pnpm run test:security -- --run" 180
    
    cd ..
}

# Performance Tests
run_performance_tests() {
    print_status "INFO" "Running performance tests..."
    
    cd "$BACKEND_DIR"
    
    # Benchmark Tests
    TESTS_TOTAL=$((TESTS_TOTAL + 1))
    run_test "performance-backend" "go test -bench=. -benchmem -benchtime=5s -timeout=15m ./..."
    
    cd ..
}

# Generate Test Report
generate_report() {
    local report_file="$TEST_RESULTS_DIR/test-report.html"
    local total_tests=$((TESTS_PASSED + TESTS_FAILED + TESTS_SKIPPED))
    
    print_status "INFO" "Generating test report..."
    
    cat > "$report_file" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>LeafLock - Test Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { background: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .success { color: #28a745; }
        .error { color: #dc3545; }
        .warning { color: #ffc107; }
        .stats { display: flex; gap: 20px; margin: 20px 0; }
        .stat { background: #f8f9fa; padding: 15px; border-radius: 5px; text-align: center; }
        .log-section { margin: 20px 0; }
        .log-content { background: #f8f9fa; padding: 15px; border-radius: 5px; font-family: monospace; white-space: pre-wrap; }
    </style>
</head>
<body>
    <div class="header">
        <h1>LeafLock - Test Suite Report</h1>
        <p>Generated: $(date)</p>
        <p>Duration: $SECONDS seconds</p>
    </div>
    
    <div class="stats">
        <div class="stat">
            <h3>Total Tests</h3>
            <div style="font-size: 24px; font-weight: bold;">$total_tests</div>
        </div>
        <div class="stat">
            <h3 class="success">Passed</h3>
            <div style="font-size: 24px; font-weight: bold; color: #28a745;">$TESTS_PASSED</div>
        </div>
        <div class="stat">
            <h3 class="error">Failed</h3>
            <div style="font-size: 24px; font-weight: bold; color: #dc3545;">$TESTS_FAILED</div>
        </div>
        <div class="stat">
            <h3 class="warning">Skipped</h3>
            <div style="font-size: 24px; font-weight: bold; color: #ffc107;">$TESTS_SKIPPED</div>
        </div>
    </div>
EOF

    # Add individual test results
    if [ -d "$TEST_RESULTS_DIR" ]; then
        echo "<h2>Test Results</h2>" >> "$report_file"
        for log_file in "$TEST_RESULTS_DIR"/*.log; do
            if [ -f "$log_file" ]; then
                local test_name=$(basename "$log_file" .log)
                echo "<div class='log-section'>" >> "$report_file"
                echo "<h3>$test_name</h3>" >> "$report_file"
                echo "<div class='log-content'>" >> "$report_file"
                cat "$log_file" >> "$report_file"
                echo "</div></div>" >> "$report_file"
            fi
        done
    fi

    echo "</body></html>" >> "$report_file"
    
    print_status "SUCCESS" "Test report generated: $report_file"
}

# Main execution
main() {
    local start_time=$(date +%s)
    
    print_status "INFO" "Starting Comprehensive Test Suite for LeafLock"
    print_status "INFO" "=============================================="
    
    # Parse command line arguments
    local run_integration=true
    local run_security=true
    local run_performance=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --skip-integration)
                run_integration=false
                shift
                ;;
            --skip-security)
                run_security=false
                shift
                ;;
            --include-performance)
                run_performance=true
                shift
                ;;
            --help)
                echo "Usage: $0 [options]"
                echo "Options:"
                echo "  --skip-integration    Skip integration tests"
                echo "  --skip-security      Skip security tests"
                echo "  --include-performance Include performance tests"
                echo "  --help               Show this help message"
                exit 0
                ;;
            *)
                print_status "ERROR" "Unknown option: $1"
                exit 1
                ;;
        esac
    done
    
    # Run test phases
    check_prerequisites
    setup_test_environment
    
    # Core tests (always run)
    run_backend_tests &
    BACKEND_PID=$!
    
    run_frontend_tests &
    FRONTEND_PID=$!
    
    run_build_tests &
    BUILD_PID=$!
    
    # Wait for core tests
    wait $BACKEND_PID
    wait $FRONTEND_PID
    wait $BUILD_PID
    
    # Optional tests
    if [ "$run_integration" = true ]; then
        run_integration_tests
    fi
    
    if [ "$run_security" = true ]; then
        run_security_tests
    fi
    
    if [ "$run_performance" = true ]; then
        run_performance_tests
    fi
    
    # Generate report
    generate_report
    
    # Final summary
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    local total_tests=$((TESTS_PASSED + TESTS_FAILED + TESTS_SKIPPED))
    
    echo ""
    print_status "INFO" "=============================================="
    print_status "INFO" "Test Suite Complete"
    print_status "INFO" "Duration: ${duration}s"
    print_status "INFO" "Total Tests: $total_tests"
    print_status "SUCCESS" "Passed: $TESTS_PASSED"
    print_status "ERROR" "Failed: $TESTS_FAILED"
    print_status "WARNING" "Skipped: $TESTS_SKIPPED"
    
    if [ $TESTS_FAILED -eq 0 ]; then
        print_status "SUCCESS" "🎉 All tests passed!"
        exit 0
    else
        print_status "ERROR" "❌ Some tests failed. Check the logs for details."
        exit 1
    fi
}

# Run main function with all arguments
main "$@"
