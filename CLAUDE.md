# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a secure notes application with end-to-end encryption, featuring a Go backend with Fiber framework and a React TypeScript frontend. The application uses PostgreSQL for data storage, Redis for session management, and implements zero-knowledge architecture where the server never sees plaintext data.

## Development Commands

### Backend (Go)
```bash
cd backend
go mod download              # Install dependencies
go build -o app .           # Build binary
go run main.go              # Run development server
go test -v ./...            # Run tests
```

### Frontend (React + TypeScript)
```bash
cd frontend
pnpm install                # Install dependencies
pnpm run dev                # Start development server (Vite)
pnpm run build              # Build for production
pnpm run lint               # Run ESLint
pnpm test                   # Run tests (Vitest)
```

### Container Operations (Podman-first)
```bash
make up                    # Start all services with Podman
make down                  # Stop all containers
make build                 # Build container images
make logs                  # View backend logs
make status                # Check container status
make clean                 # Clean containers and volumes
```

### Docker Compose Alternative
```bash
docker compose up -d       # Start all services
docker compose down        # Stop services
docker compose logs -f     # View logs
```

## Architecture Overview

### Directory Structure
- `backend/` - Go backend with Fiber framework (main.go is the entry point)
- `frontend/` - React 18 + TypeScript frontend with Vite
- `docker-compose.yml` - Primary orchestration file
- `podman-compose.yml` - Podman-specific configuration
- `Makefile` - Podman-first automation commands

### Technology Stack
- **Backend**: Go 1.23+ with Fiber v2, PostgreSQL (pgx driver), Redis, JWT authentication
- **Frontend**: React 18, TypeScript, Vite 5, Zustand (state management), TipTap (editor)
- **Encryption**: XChaCha20-Poly1305 (client-side), Argon2id (password hashing)
- **Infrastructure**: Podman/Docker, PostgreSQL 15, Redis 7

### Key Dependencies
- Backend: `github.com/gofiber/fiber/v2`, `github.com/jackc/pgx/v5`, `github.com/redis/go-redis/v9`
- Frontend: `libsodium-wrappers` (encryption), `@tanstack/react-query`, `zustand`

## Environment Setup

### Required Environment Variables
Copy `.env.example` to `.env` and configure:
- `POSTGRES_PASSWORD` - Database password
- `REDIS_PASSWORD` - Redis password  
- `JWT_SECRET` - 64-character JWT signing key
- `SERVER_ENCRYPTION_KEY` - 32-character server encryption key
- `CORS_ORIGINS` - Allowed frontend origins

### Service Ports
- Frontend: http://localhost:3000
- Backend API: http://localhost:8080
- Health check: http://localhost:8080/api/v1/health

## Security Considerations

This application implements end-to-end encryption with zero-knowledge architecture:
- All note content is encrypted client-side using XChaCha20-Poly1305
- Server never sees plaintext data
- Passwords use Argon2id hashing (64MB memory, 3 iterations)
- JWT tokens with refresh rotation for session management

## CI/CD Pipeline

The project uses GitHub Actions (`.github/workflows/ci.yml`) with:
- Go backend testing with PostgreSQL/Redis services
- Frontend build testing with Node.js 20
- Docker build verification
- Integration testing with health checks

## Container-First Development

This project prioritizes Podman but supports Docker:
- Makefile commands use Podman by default
- `podman-compose.yml` is the primary compose file
- `docker-compose.yml` available as fallback
- Kubernetes deployment ready (`secure-notes-kube.yaml`)

## Common Development Tasks

### Running Single Tests
```bash
# Backend specific test
cd backend && go test -v ./path/to/package

# Frontend specific test  
cd frontend && pnpm test -- --run specific-test
```

### Building for Production
```bash
# Build both services
make build

# Or individually
cd backend && go build -o app .
cd frontend && pnpm run build
```

### Database Operations
The application uses PostgreSQL with encrypted fields. Database migrations and schema are handled within the Go backend code.