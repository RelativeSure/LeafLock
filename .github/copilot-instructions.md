# LeafLock GitHub Copilot Instructions

**ALWAYS follow these instructions first and only fallback to additional search and context gathering if the information here is incomplete or found to be in error.**

LeafLock is a privacy-first notes application with end-to-end encryption, featuring a Go backend with Fiber framework and a React TypeScript frontend with Vite. All components use container-first development with Podman/Docker support.

## Quick Start - Essential Commands

### Prerequisites Check
```bash
# Verify required tools are available
go version  # Requires Go 1.24+
node --version  # Requires Node.js 20+
pnpm --version  # Requires pnpm 10+
docker --version  # For containerized development
```

### Environment Setup
```bash
# Copy and configure environment
cp .env.example .env
# Edit .env with proper values for DATABASE_URL, REDIS_URL, JWT_SECRET, etc.
```

## Backend Development (Go)

### Core Backend Commands
```bash
cd backend

# Install dependencies (9 seconds)
go mod download

# Build backend (36 seconds)
# NEVER CANCEL: Set timeout to 60+ seconds
go build -o app .

# Format code (0.4 seconds)
make fmt

# Vet code (4.5 seconds)
make vet

# Quick validation cycle (5 seconds total)
make deps && make fmt && make vet
```

### Backend Testing
```bash
cd backend

# Unit tests (10 seconds) - EXPECT SOME FAILURES
# NEVER CANCEL: Set timeout to 30+ minutes for full test suite
make test-unit
# NOTE: Tests may fail due to database connectivity - this is expected in fresh clone

# Coverage check (requires PostgreSQL/Redis services)
make test-coverage-check
# Coverage gate: 72% required

# Integration tests (requires test database)
# Start test databases first:
docker run -d --name test-postgres -p 5433:5432 -e POSTGRES_USER=test -e POSTGRES_PASSWORD=test -e POSTGRES_DB=test_notes postgres:15
docker run -d --name test-redis -p 6380:6379 redis:7
make test-integration
```

### Backend Validation Scenarios
After making backend changes, ALWAYS test:
1. **Build validation**: `go build -o app .` completes successfully
2. **Format check**: `make fmt` runs without changes
3. **Lint check**: `make vet` passes without errors
4. **Health check**: If database is available, backend should start and respond to `/api/v1/health`

## Frontend Development (React + TypeScript)

### Core Frontend Commands
```bash
cd frontend

# Install dependencies (27 seconds)
# NEVER CANCEL: Set timeout to 60+ seconds
pnpm install

# Start dev server (instant startup)
pnpm run dev
# Frontend available at: http://localhost:3000

# Build for production (12 seconds)
# NEVER CANCEL: Set timeout to 30+ seconds
pnpm run build

# Run tests (3 seconds, 199 tests)
pnpm run test

# Type checking (5 seconds) - EXPECT ERRORS
pnpm run typecheck
# NOTE: May have TypeScript errors - build still succeeds

# Linting (3 seconds) - EXPECT ERRORS  
pnpm run lint
# NOTE: May have linting errors - build still succeeds
```

### Frontend Validation Scenarios
After making frontend changes, ALWAYS test:
1. **Build validation**: `pnpm run build` completes successfully
2. **Test validation**: `pnpm run test` passes (199 tests expected)
3. **Dev server**: `pnpm run dev` starts and serves app at localhost:3000
4. **Manual check**: Open browser to verify UI loads correctly

## Full Stack Development

### Working Local Development Setup
```bash
# Option 1: Separate processes (RECOMMENDED for development)
# Terminal 1: Start backend (after setting up PostgreSQL/Redis)
cd backend && ./app

# Terminal 2: Start frontend
cd frontend && pnpm run dev

# Access: Frontend at http://localhost:3000, Backend at http://localhost:8080
```

### Container Development (KNOWN LIMITATIONS)
```bash
# CAUTION: Docker builds may fail due to Alpine package repository issues
# If docker compose fails, use local development instead

# Copy environment
cp .env.example .env
# Edit .env with secure values

# Try container stack (MAY FAIL)
make up
# OR
docker compose up -d --build

# If successful, access:
# - Frontend: http://localhost:3000  
# - Backend API: http://localhost:8080
# - Health check: http://localhost:8080/api/v1/health
```

## Build Timing and Timeout Guidelines

### Critical Timeout Settings
- **Backend build**: 60+ seconds timeout (typically 36 seconds)
- **Frontend dependencies**: 60+ seconds timeout (typically 27 seconds)  
- **Frontend build**: 30+ seconds timeout (typically 12 seconds)
- **Backend tests**: 30+ minutes timeout (unit tests ~10 seconds, full suite longer)
- **Docker builds**: 15+ minutes timeout (often fails due to network issues)

### NEVER CANCEL Commands
These commands MUST be allowed to complete:
- `go build` operations (can take 30-60 seconds)
- `pnpm install` (can take 30+ seconds)
- `pnpm run build` (can take 10-15 seconds)
- `make test` operations (can take several minutes)
- Docker builds (can take 10+ minutes when working)

## Default Admin Account

### First-Time Login Credentials
**ALWAYS change these immediately after first login:**
- Email: `admin@leaflock.app`
- Password: `AdminPass123!`

These are configurable via environment variables:
- `DEFAULT_ADMIN_EMAIL`
- `DEFAULT_ADMIN_PASSWORD`
- `ENABLE_DEFAULT_ADMIN=true`

## Key Validation Workflows

### After Making Code Changes
1. **Backend changes**:
   ```bash
   cd backend
   make fmt && make vet
   go build -o app .
   # If database available: ./app (test startup)
   ```

2. **Frontend changes**:
   ```bash
   cd frontend  
   pnpm run test
   pnpm run build
   # Manual test: pnpm run dev (verify in browser)
   ```

3. **Full stack changes**:
   - Test both backend and frontend individually
   - Test integration if possible (requires database)
   - Run `make up` if Docker environment is working

### Pre-commit Validation
```bash
# Always run before committing
cd backend && make fmt && make vet
cd ../frontend && pnpm run test && pnpm run build
```

## Known Issues and Workarounds

### Docker Build Failures
- **Issue**: Alpine package repositories often fail with permission denied
- **Workaround**: Use local development setup instead
- **Commands that may fail**: `make up`, `docker compose up --build`

### Test Failures
- **Backend tests**: May fail without database connectivity
- **Frontend linting**: Currently has 4 linting errors (unused variables)
- **TypeScript**: Currently has 24 TypeScript errors
- **All builds succeed** despite linting/typing errors

### Expected Build Behavior
- Backend builds and runs (fails gracefully without database)
- Frontend builds successfully despite TypeScript/linting errors
- Tests pass when run individually
- Dev servers start successfully

## Repository Structure Reference

```plaintext
backend/          - Go service with Fiber framework
├── main.go       - Entry point
├── Makefile      - Build and test automation  
├── go.mod        - Go dependencies
└── *_test.go     - Test files

frontend/         - React 18 + TypeScript + Vite
├── src/          - Source code
├── package.json  - Dependencies and scripts
└── vite.config.ts - Build configuration

.env.example      - Environment template
docker-compose.yml - Container orchestration
Makefile          - Root automation (Podman/Docker)
```

## Technology Stack
- **Backend**: Go 1.24+, Fiber v2, PostgreSQL, Redis, JWT authentication
- **Frontend**: React 18, TypeScript, Vite 5, pnpm 10, Zustand state management
- **Encryption**: XChaCha20-Poly1305 (client-side), Argon2id (password hashing)
- **Infrastructure**: Docker/Podman, PostgreSQL 15, Redis 7

## Quick Troubleshooting

### Build Issues
1. Check Go/Node versions match requirements
2. Run `go mod download` and `pnpm install`
3. Clear caches: `go clean -cache` and `pnpm store prune`

### Runtime Issues  
1. Verify `.env` file has proper database/Redis configuration
2. Check if PostgreSQL/Redis services are running
3. Test health endpoint: `curl http://localhost:8080/api/v1/health`

### Development Workflow
1. Always start with local development setup
2. Use container setup only if local fails
3. Run validation commands after every change
4. Test manual user scenarios when changing UI components

**Remember: These instructions are based on extensive validation. Follow them precisely for reliable development experience.**