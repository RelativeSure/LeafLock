# Makefile for LeafLock backend testing and development

.PHONY: test test-unit test-integration test-security test-coverage test-benchmark test-race clean deps build run help

# Colors for output
GREEN := \033[0;32m
YELLOW := \033[0;33m
RED := \033[0;31m
NC := \033[0m # No Color

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
GOFMT=gofmt
GOLINT=golangci-lint
GORACE=-race
GOBENCH=-bench=.
GOCOVER=-coverprofile=coverage.out -covermode=atomic
GOTESTSUM=gotestsum

# Binary names
BINARY_NAME=leaflock
BINARY_UNIX=$(BINARY_NAME)_unix

# Test parameters
TEST_TIMEOUT=10m
INTEGRATION_TEST_TAG=integration
SECURITY_TEST_TAG=security
COVERAGE_THRESHOLD=72

# Database test parameters
TEST_DB_URL=postgres://test:test@localhost:5433/test_notes?sslmode=disable
TEST_REDIS_URL=localhost:6380

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  $(YELLOW)%-20s$(NC) %s\n", $$1, $$2}' $(MAKEFILE_LIST)

deps: ## Install dependencies
	@echo "$(GREEN)Installing Go dependencies...$(NC)"
	$(GOMOD) download
	$(GOMOD) tidy
	@echo "$(GREEN)Dependencies installed successfully$(NC)"

build: deps ## Build the application
	@echo "$(GREEN)Building application...$(NC)"
	$(GOBUILD) -o $(BINARY_NAME) -v ./...
	@echo "$(GREEN)Build completed: $(BINARY_NAME)$(NC)"

build-linux: deps ## Build for Linux
	@echo "$(GREEN)Building for Linux...$(NC)"
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOBUILD) -o $(BINARY_UNIX) -v ./...
	@echo "$(GREEN)Linux build completed: $(BINARY_UNIX)$(NC)"

run: ## Run the application
	@echo "$(GREEN)Starting application...$(NC)"
	$(GOCMD) run main.go

clean: ## Clean build files and test cache
	@echo "$(YELLOW)Cleaning build files...$(NC)"
	$(GOCLEAN)
	rm -f $(BINARY_NAME)
	rm -f $(BINARY_UNIX)
	rm -f coverage.out
	rm -f coverage.html
	$(GOTEST) -cache=off -clean
	@echo "$(GREEN)Clean completed$(NC)"

fmt: ## Format Go code
	@echo "$(GREEN)Formatting code...$(NC)"
	@find . -name "*.go" \
	  -not -path "./vendor/*" \
	  -not -path "./.gomod/*" \
	  -not -path "./.gopath/*" \
	  -print0 | xargs -0 $(GOFMT) -s -w
	@echo "$(GREEN)Code formatted$(NC)"

lint: ## Run linters
	@echo "$(GREEN)Running linters...$(NC)"
	@if command -v $(GOLINT) >/dev/null 2>&1; then \
		$(GOLINT) run ./...; \
	else \
		echo "$(YELLOW)golangci-lint not found, skipping...$(NC)"; \
	fi

vet: ## Run go vet
	@echo "$(GREEN)Running go vet...$(NC)"
	$(GOCMD) vet ./...

test: deps fmt vet ## Run all tests
	@echo "$(GREEN)Running all tests...$(NC)"
	$(GOTEST) -v -timeout=$(TEST_TIMEOUT) ./...
	@echo "$(GREEN)All tests completed$(NC)"

test-unit: deps ## Run unit tests only
	@echo "$(GREEN)Running unit tests...$(NC)"
	$(GOTEST) -v -short -timeout=5m ./...
	@echo "$(GREEN)Unit tests completed$(NC)"

test-integration: deps ## Run integration tests (requires test database)
	@echo "$(GREEN)Running integration tests...$(NC)"
	@echo "$(YELLOW)Make sure test database is running:$(NC)"
	@echo "  Docker: docker run -d --name test-postgres -p 5433:5432 -e POSTGRES_USER=test -e POSTGRES_PASSWORD=test -e POSTGRES_DB=test_notes postgres:15"
	@echo "  Docker: docker run -d --name test-redis -p 6380:6379 redis:7"
	DATABASE_URL=$(TEST_DB_URL) REDIS_URL=$(TEST_REDIS_URL) $(GOTEST) -v -timeout=$(TEST_TIMEOUT) -run="Integration" ./...
	@echo "$(GREEN)Integration tests completed$(NC)"

test-security: deps ## Run security tests
	@echo "$(GREEN)Running security tests...$(NC)"
	$(GOTEST) -v -timeout=$(TEST_TIMEOUT) -run="Security|Vulnerability|Penetration" ./...
	@echo "$(GREEN)Security tests completed$(NC)"

test-race: deps ## Run tests with race detection
	@echo "$(GREEN)Running tests with race detection...$(NC)"
	$(GOTEST) $(GORACE) -v -short ./...
	@echo "$(GREEN)Race detection tests completed$(NC)"

test-benchmark: deps ## Run benchmark tests
	@echo "$(GREEN)Running benchmark tests...$(NC)"
	$(GOTEST) $(GOBENCH) -v -timeout=$(TEST_TIMEOUT) ./...
	@echo "$(GREEN)Benchmark tests completed$(NC)"

test-coverage: deps ## Run tests with coverage analysis
	@echo "$(GREEN)Running tests with coverage...$(NC)"
	$(GOTEST) $(GOCOVER) -v -timeout=$(TEST_TIMEOUT) ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	$(GOCMD) tool cover -func=coverage.out | grep total | awk '{print "Coverage: " $$3}'
	@echo "$(GREEN)Coverage analysis completed$(NC)"
	@echo "$(YELLOW)Open coverage.html to view detailed coverage report$(NC)"

test-coverage-check: test-coverage ## Check coverage meets threshold
	@echo "$(GREEN)Checking coverage threshold ($(COVERAGE_THRESHOLD)%)...$(NC)"
	@COVERAGE=$$($(GOCMD) tool cover -func=coverage.out | grep total | awk '{print $$3}' | sed 's/%//'); \
	if [ "$$(echo "$$COVERAGE >= $(COVERAGE_THRESHOLD)" | bc)" -eq 1 ]; then \
		echo "$(GREEN)✓ Coverage ($$COVERAGE%) meets threshold ($(COVERAGE_THRESHOLD)%)$(NC)"; \
	else \
		echo "$(RED)✗ Coverage ($$COVERAGE%) below threshold ($(COVERAGE_THRESHOLD)%)$(NC)"; \
		exit 1; \
	fi

test-all: test-unit test-integration test-security test-race test-coverage-check ## Run all test suites
	@echo "$(GREEN)All test suites completed successfully!$(NC)"

test-ci: deps fmt vet test-unit test-coverage-check ## Run CI test suite
	@echo "$(GREEN)CI test suite completed$(NC)"

test-local: deps fmt vet test-unit test-integration test-security test-coverage ## Run local development test suite
	@echo "$(GREEN)Local test suite completed$(NC)"

# Test database management
test-db-up: ## Start test databases with Docker
	@echo "$(GREEN)Starting test databases...$(NC)"
	docker run -d --name test-postgres -p 5433:5432 -e POSTGRES_USER=test -e POSTGRES_PASSWORD=test -e POSTGRES_DB=test_notes postgres:15 || echo "test-postgres already exists"
	docker run -d --name test-redis -p 6380:6379 redis:7 || echo "test-redis already exists"
	@echo "$(GREEN)Test databases started$(NC)"
	@echo "$(YELLOW)Waiting for databases to be ready...$(NC)"
	sleep 5

test-db-down: ## Stop and remove test databases
	@echo "$(YELLOW)Stopping test databases...$(NC)"
	docker stop test-postgres test-redis || true
	docker rm test-postgres test-redis || true
	@echo "$(GREEN)Test databases stopped and removed$(NC)"

test-db-logs: ## Show test database logs
	@echo "$(GREEN)Test database logs:$(NC)"
	@echo "$(YELLOW)PostgreSQL logs:$(NC)"
	docker logs test-postgres || echo "No PostgreSQL container"
	@echo "$(YELLOW)Redis logs:$(NC)"
	docker logs test-redis || echo "No Redis container"

# Performance and profiling
profile-cpu: ## Run CPU profiling
	@echo "$(GREEN)Running CPU profiling...$(NC)"
	$(GOTEST) -cpuprofile=cpu.prof -bench=. ./...
	$(GOCMD) tool pprof cpu.prof

profile-mem: ## Run memory profiling
	@echo "$(GREEN)Running memory profiling...$(NC)"
	$(GOTEST) -memprofile=mem.prof -bench=. ./...
	$(GOCMD) tool pprof mem.prof

profile-block: ## Run blocking profiling
	@echo "$(GREEN)Running blocking profiling...$(NC)"
	$(GOTEST) -blockprofile=block.prof -bench=. ./...
	$(GOCMD) tool pprof block.prof

# Security scanning
security-scan: ## Run security vulnerability scanning
	@echo "$(GREEN)Running security vulnerability scan...$(NC)"
	@if command -v govulncheck >/dev/null 2>&1; then \
		govulncheck ./...; \
	else \
		echo "$(YELLOW)govulncheck not found. Install with: go install golang.org/x/vuln/cmd/govulncheck@latest$(NC)"; \
	fi

security-audit: ## Run dependency audit
	@echo "$(GREEN)Running dependency audit...$(NC)"
	@if command -v nancy >/dev/null 2>&1; then \
		$(GOMOD) list -json -m all | nancy sleuth; \
	else \
		echo "$(YELLOW)nancy not found. Install with: go install github.com/sonatypeoss/nancy@latest$(NC)"; \
	fi

# Documentation
docs: ## Generate documentation
	@echo "$(GREEN)Generating documentation...$(NC)"
	$(GOCMD) doc -all ./...

# Development helpers
watch: ## Watch for changes and run tests
	@echo "$(GREEN)Watching for changes...$(NC)"
	@if command -v watchexec >/dev/null 2>&1; then \
		watchexec -e go -r "make test-unit"; \
	else \
		echo "$(YELLOW)watchexec not found. Install with: cargo install watchexec-cli$(NC)"; \
	fi

install-tools: ## Install development tools
	@echo "$(GREEN)Installing development tools...$(NC)"
	$(GOCMD) install golang.org/x/vuln/cmd/govulncheck@latest
	$(GOCMD) install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	$(GOCMD) install gotest.tools/gotestsum@latest
	@echo "$(GREEN)Development tools installed$(NC)"

# Statistics and reporting
stats: ## Show code statistics
	@echo "$(GREEN)Code Statistics:$(NC)"
	@echo "$(YELLOW)Lines of code:$(NC)"
	find . -name "*.go" -not -path "./vendor/*" | xargs wc -l | tail -1
	@echo "$(YELLOW)Number of Go files:$(NC)"
	find . -name "*.go" -not -path "./vendor/*" | wc -l
	@echo "$(YELLOW)Number of test files:$(NC)"
	find . -name "*_test.go" -not -path "./vendor/*" | wc -l

# Default target
all: deps fmt vet test-coverage build ## Run full development cycle

# Development workflow targets
dev-setup: install-tools test-db-up ## Setup development environment
	@echo "$(GREEN)Development environment setup completed$(NC)"

dev-teardown: test-db-down clean ## Teardown development environment
	@echo "$(GREEN)Development environment teardown completed$(NC)"

# Quick development cycle
quick-test: fmt vet test-unit ## Quick test cycle for development

# Pre-commit hook
pre-commit: fmt vet test-unit lint ## Pre-commit validation
	@echo "$(GREEN)Pre-commit validation passed$(NC)"
