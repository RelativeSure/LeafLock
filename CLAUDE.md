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
- Kubernetes deployment can be generated with `make kube`

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

## Startup Performance Optimization

### Fast Startup Configuration
LeafLock is optimized for fast startup times on containerized deployments like Coolify. The application includes several performance optimizations that are **enabled by default**:

#### **Progressive Health Checks**
- **`/api/v1/health/live`**: Basic server health (responds in 3-5 seconds)
- **`/api/v1/health/ready`**: Full initialization status (responds in 15-30 seconds)

#### **Startup Optimization Environment Variables**
```bash
SKIP_MIGRATION_CHECK=false    # Always run database migrations (default: false)

# Only set this if you want to override the default:
SKIP_MIGRATION_CHECK=true     # Skip migration checks (NOT recommended)
```

#### **Expected Startup Performance**
- **Container startup**: 15-30 seconds (down from 90+ seconds)
- **Basic health check**: 3-5 seconds (`/health/live`)
- **Full readiness**: 15-30 seconds (`/health/ready`)
- **Database ready**: 5-10 seconds
- **All services operational**: 25-30 seconds

#### **Health Check Endpoints**
```bash
# Quick liveness check (for container orchestration)
curl https://your-domain.com/api/v1/health/live

# Full readiness check (for load balancers)
curl https://your-domain.com/api/v1/health/ready

# Example ready response
{
  "status": "ready",
  "timestamp": "2024-12-25T10:30:00Z",
  "uptime": "15s"
}
```

## Admin User Management

### Default Admin User
The application creates a default admin user automatically if none exists:
- **Email**: Configured via `DEFAULT_ADMIN_EMAIL` (default: admin@leaflock.app)
- **Password**: Configured via `DEFAULT_ADMIN_PASSWORD` (supports complex passwords with special characters)
- **Creation**: Automatic on first startup if no users exist
- **Validation**: Full password complexity validation with special character support

### Admin Password Requirements
The system supports and validates complex passwords including:
- Minimum 8 characters, maximum 128 characters
- Must contain: uppercase, lowercase, digit, and special character
- **Special characters fully supported**: `!@#$%^&*()_+-=[]{}|;':"\\,.<>?`
- Complex passwords with special characters like `#wmR8xWxZ&#JHZPd8HTYmafctWSe0N*jgPG%bYS@` work correctly

### Admin Configuration Environment Variables
```bash
ENABLE_DEFAULT_ADMIN=true                    # Enable/disable default admin creation
DEFAULT_ADMIN_EMAIL=admin@leaflock.app       # Admin email address
DEFAULT_ADMIN_PASSWORD=YourComplexPassword   # Admin password (supports all special chars)
```

### Testing Admin Login
```bash
# Via API
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@leaflock.app","password":"YourPassword"}'

# Via Frontend UI
# Navigate to http://localhost:3000 and use the login form
```

### Admin System Architecture
- **Admin Service**: Modularized in `backend/services/admin.go`
- **Password Security**: Argon2id hashing with 64MB memory, 3 iterations, 4 parallelism
- **Validation**: Comprehensive password complexity and email format validation
- **Logging**: Detailed admin user creation and login logging for debugging
- **Error Handling**: Graceful handling of encryption key mismatches and database issues

### Admin Troubleshooting Guide

#### Password Requirements
Admin passwords **must contain all four character types**:
- Uppercase letter (A-Z)
- Lowercase letter (a-z)
- Digit (0-9)
- Special character: `!@#$%^&*()_+-=[]{}|;':"\\,.<>?`

**Example valid passwords**:
- `AdminPass123!` (from .env.example)
- `AdminTest123!` (local development)
- `29Dt54fbT0TTjAeAH9102DCqwQSZd1!` (production with added special char)

#### Common Issues and Solutions

**Issue**: Admin login fails with "Invalid request"
**Cause**: Password lacks special characters or JSON parsing issues
**Solution**:
1. Check password meets all requirements above
2. Verify environment variables are set correctly
3. Check server logs for password validation failures

**Issue**: "user_count: 0" in health endpoint
**Cause**: Admin user creation failed during startup
**Solution**:
1. Check server logs for admin creation errors
2. Verify `ENABLE_DEFAULT_ADMIN=true`
3. Ensure password meets complexity requirements
4. Restart services after fixing environment variables

**Issue**: "password must contain at least one special character"
**Cause**: Production password missing special characters
**Solution**: Add special character to `DEFAULT_ADMIN_PASSWORD` (e.g., append `!`)

#### Debugging Steps
1. **Check Health Endpoint**: `curl http://localhost:8080/api/v1/health`
   - Look for `user_count: 1` (indicates admin user exists)
   - Verify `status: "healthy"` for database/redis

2. **Check Server Logs**: `docker compose logs backend | grep -i admin`
   - Look for admin user creation success/failure messages
   - Check for password validation errors

3. **Test API Login**:
   ```bash
   # Note: Shell may escape special characters - test through web UI if needed
   curl -X POST http://localhost:8080/api/v1/auth/login \
     -H "Content-Type: application/json" \
     -d '{"email":"admin@leaflock.app","password":"YourPassword"}'
   ```

4. **Environment Variable Check**:
   ```bash
   # Verify admin settings
   echo "Email: $DEFAULT_ADMIN_EMAIL"
   echo "Password length: ${#DEFAULT_ADMIN_PASSWORD}"
   echo "Admin enabled: $ENABLE_DEFAULT_ADMIN"
   ```

#### Production vs Development Differences
- **Local (.env)**: Uses `AdminTest123!` with explicit special character
- **Production (Coolify)**: Must set secure password with special characters
- **Environment**: Production requires all admin variables to be explicitly set

- When modifying the docker compose file remember the coolify docker compose
- Remember to build the setup when docker-compose and coolify docker compose files and the frontendDockerfile/entrypoint when testing/verifying
- When needing to push to the repo, make a branch and then push to that branch. DO NOT EVER IN ANY CIRCUMSTANCE PUSH TO HEAD BRANCH