# Testing Commands

Comprehensive testing workflows for Secure Notes application.

## Quick Test Commands

```bash
# Run all tests
make test-all

# Quick development tests
make quick-test

# CI/CD pipeline tests
make test-ci
```

## Backend Testing (Go)

### Unit Tests
```bash
cd backend
make test-unit
```

### Integration Tests
```bash
# Start test databases first
cd backend
make test-db-up

# Run integration tests
make test-integration

# Clean up test databases
make test-db-down
```

### Security Tests
```bash
cd backend
make test-security
```

### Performance Tests
```bash
cd backend
make test-benchmark
```

### Coverage Analysis
```bash
cd backend
make test-coverage

# View coverage report
open coverage.html
```

### Race Condition Detection
```bash
cd backend
make test-race
```

## Frontend Testing (React)

### Unit Tests
```bash
cd frontend
npm test
```

### Watch Mode
```bash
cd frontend
npm run test:watch
```

### Coverage Report
```bash
cd frontend
npm run test:coverage
```

### UI Tests
```bash
cd frontend
npm run test:ui
```

### E2E Tests
```bash
cd frontend
npm run test:e2e
```

## Comprehensive Test Suites

### Full Local Testing
```bash
# Setup test environment
cd backend && make test-db-up

# Run all test suites
make test-local

# Cleanup
cd backend && make test-db-down
```

### Pre-commit Testing
```bash
# Quick validation before commit
make pre-commit

# Or from backend
cd backend && make pre-commit
```

## Security Testing

### Vulnerability Scanning
```bash
# Backend security scan
cd backend && make security-scan

# Frontend security audit
cd frontend && npm audit

# Container security scan
make security-scan
```

### Dependency Auditing
```bash
# Backend dependencies
cd backend && make security-audit

# Frontend dependencies
cd frontend && npm audit --audit-level=high
```

## Performance Testing

### Backend Benchmarks
```bash
cd backend
make test-benchmark
```

### Load Testing
```bash
# Install dependencies first
# npm install -g artillery

# Run load tests (if configured)
artillery run load-test.yml
```

### Memory Profiling
```bash
cd backend
make profile-mem
```

### CPU Profiling
```bash
cd backend
make profile-cpu
```

## Database Testing

### Test Database Management
```bash
# Start test databases
cd backend && make test-db-up

# Check status
cd backend && make test-db-logs

# Stop and clean
cd backend && make test-db-down
```

### Database Migration Testing
```bash
# Test with fresh database
cd backend
make test-db-down
make test-db-up
make test-integration
```

## Continuous Integration

### GitHub Actions Simulation
```bash
# Run exactly what CI runs
cd backend
make test-ci
```

### Pre-push Validation
```bash
# Full validation before pushing
make test-all
make build
```

## Test Results and Reports

### Coverage Reports
- Backend: `backend/coverage.html`
- Frontend: `frontend/coverage/index.html`

### Benchmark Results
- Backend: `backend/*.prof` files (use `go tool pprof`)

### Test Logs
- Development: `/tmp/secure-notes-dev.log`
- Backend tests: Console output + coverage files
- Frontend tests: Console output + coverage reports

## Test Data and Fixtures

### Database Fixtures
```bash
# Located in backend/testdata/ (if exists)
# Automatically loaded during integration tests
```

### Mock Data
```bash
# Backend mocks: Use testify/mock
# Frontend mocks: Use Vitest vi.mock()
```

## Troubleshooting Tests

### Backend Test Issues
```bash
# Clean test cache
cd backend && go clean -testcache

# Verbose test output
cd backend && go test -v ./...

# Run single test
cd backend && go test -run TestSpecificFunction
```

### Frontend Test Issues
```bash
# Clear Node cache
cd frontend && npm cache clean --force

# Reinstall dependencies
cd frontend && rm -rf node_modules package-lock.json && npm install

# Run specific test
cd frontend && npm test -- --run src/specific.test.js
```

### Database Test Issues
```bash
# Reset test databases
cd backend
make test-db-down
make test-db-up

# Check database connectivity
curl http://localhost:5433  # PostgreSQL test port
curl http://localhost:6380  # Redis test port
```

## Performance Benchmarks

### Expected Performance
- Unit tests: < 10 seconds
- Integration tests: < 30 seconds  
- Security tests: < 60 seconds
- E2E tests: < 2 minutes
- Full test suite: < 5 minutes

### Optimization Tips
- Use `-short` flag for quick tests
- Run tests in parallel where possible
- Use test database containers for isolation
- Cache dependencies between test runs