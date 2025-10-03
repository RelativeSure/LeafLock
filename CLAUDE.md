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
- Frontend: <http://localhost:3000>
- Backend API: <http://localhost:8080>
- Health check: <http://localhost:8080/api/v1/health>

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

**⚠️ CRITICAL: Migration Version Management**

When modifying database schema files, you **MUST** bump the migration version:

1. **File to modify**: `backend/database/database.go`
2. **Constant to update**: `MigrationSchemaVersion` (line 21)
3. **Format**: `YYYY.MM.DD.NNN` (increment the last number)
4. **Example**: `2024.12.25.002` → `2024.12.25.003`

**Files that require version bump:**
- `backend/database/schema.go` - Any ALTER TABLE, CREATE TABLE, CREATE INDEX
- Any file adding/modifying database structure

**Why critical**: Existing deployments skip migrations if version matches. Without a version bump, new columns/tables will never be created on existing databases, causing runtime query failures.

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
- **Email**: Configured via `DEFAULT_ADMIN_EMAIL` (default: <admin@leaflock.app>)
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
- When modifying the docker compose file remember the coolify docker compose
- Remember to build the setup when docker-compose and coolify docker compose files and the frontendDockerfile/entrypoint when testing/verifying

## IPv4/IPv6 Dual-Stack Support

LeafLock fully supports both IPv4 and IPv6 networking with automatic dual-stack configuration.

### Local Development IPv6 Support

#### Backend IPv6 Configuration
The backend automatically binds to IPv6 dual-stack `[::]:{PORT}`:
- **Accepts both IPv4 and IPv6 connections** (e.g., `127.0.0.1` and `::1`)
- **Automatic fallback** to IPv4-only `0.0.0.0:{PORT}` if IPv6 unavailable
- **Zero configuration** - works out of the box on any system

**Implementation**: `backend/server/listener.go`
```go
// Tries IPv6 dual-stack first with IPV6_V6ONLY=0
ListenWithIPv6Fallback(app, port, startupStart)
// Falls back to IPv4 if IPv6 not available
```

#### Frontend IPv6 Configuration
The frontend supports both IPv4 and IPv6 with smart auto-detection:

**Development (Vite dev server)**:
- Binds to `::` by default (dual-stack IPv4+IPv6)
- Proxy auto-detects backend from `VITE_DEV_BACKEND_HOST`
- Supports `localhost`, `127.0.0.1`, `::1`, or custom hosts

**Production Build**:
- Auto-detects from browser's `window.location`
- Falls back to environment variables (`VITE_API_URL`, `VITE_WS_URL`)
- Supports both IPv4 and IPv6 URLs with automatic bracket wrapping

**Implementation**: `frontend/src/utils/network.ts`
```typescript
// Auto-detects and normalizes IPv6 addresses
resolveApiBaseUrl()  // Returns http://localhost:8080 or http://[::1]:8080
resolveWsBaseUrl()   // Returns ws://localhost:8080 or ws://[::1]:8080
```

### Testing IPv6 Connectivity

#### Quick Verification
```bash
# Run the IPv6 integration test suite
bash scripts/test-ipv6.sh

# Check network configuration
bash scripts/verify-network.sh
```

#### Manual Testing

**Backend IPv6 binding**:
```bash
cd backend && go run main.go
# Should see: "✅ [IPv6] Successfully bound to [::]:8080"
# or: "✅ [IPv4] Successfully bound to 0.0.0.0:8080" (fallback)

# Test IPv4 connection
curl http://127.0.0.1:8080/api/v1/health

# Test IPv6 connection
curl http://[::1]:8080/api/v1/health
```

**Frontend development server**:
```bash
cd frontend && pnpm run dev
# Vite binds to :: (dual-stack) by default

# Access via IPv4
# Browser: http://localhost:3000

# Access via IPv6
# Browser: http://[::1]:3000
```

**WebSocket testing**:
```bash
# IPv4 WebSocket
wscat -c ws://localhost:8080/ws

# IPv6 WebSocket
wscat -c ws://[::1]:8080/ws
```

### Environment Configuration

See `.env.example` for comprehensive IPv4/IPv6 configuration examples:

```bash
# Auto-detect (recommended for most cases)
# VITE_API_URL=
# VITE_WS_URL=

# IPv4 explicit
VITE_API_URL=http://localhost:8080
VITE_WS_URL=ws://localhost:8080

# IPv6 explicit (for IPv6-only networks)
# VITE_API_URL=http://[::1]:8080
# VITE_WS_URL=ws://[::1]:8080

# Dev server dual-stack binding
VITE_DEV_HOST=::  # Recommended: accepts both IPv4 and IPv6
```

### Common IPv6 Issues & Solutions

| Issue | Cause | Solution |
|-------|-------|----------|
| "Connection refused" on IPv6 | System doesn't have IPv6 enabled | Backend automatically falls back to IPv4 |
| WebSocket fails on IPv6 | Browser doesn't support IPv6 | Set `VITE_API_URL` and `VITE_WS_URL` to IPv4 addresses |
| Docker containers can't communicate | Docker's default bridge is IPv4-only | Use service names (`postgres`, `redis`, `backend`) not IP addresses |
| Frontend can't reach backend | Mixed IPv4/IPv6 environment | Set explicit `VITE_API_URL` in `.env` |
| CORS errors with IPv6 | Missing IPv6 origins in CORS | Add `http://[::1]:3000` to `CORS_ORIGINS` |

### Docker Compose IPv6 Support

Docker Compose can be configured for dual-stack networking:

```yaml
networks:
  default:
    enable_ipv6: true
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/16
        - subnet: fd00:dead:beef::/48
```

**Note**: IPv6 in Docker is optional for local development. Service name resolution works on both IPv4 and IPv6.

### Trusted Proxies Configuration

The backend trusts the following proxy IP ranges (configured in `backend/server/app.go`):

**IPv4 Private Ranges**:
- `10.0.0.0/8` - Class A private
- `172.16.0.0/12` - Class B private
- `192.168.0.0/16` - Class C private
- `127.0.0.1` - Localhost

**IPv6 Ranges**:
- `fd00::/8` - Unique Local Addresses (Railway private network)
- `::1` - IPv6 localhost

This ensures proper client IP detection when behind proxies like Cloudflare, NGINX, or Railway's internal routing.

---

## Railway IPv6 Private Network Support

### Current Railway Configuration
LeafLock is **fully compatible** with Railway's IPv6-only private network architecture:

**Service Names:**
- Backend Private: `motivated-energy.railway.internal` (internal only, no public access)
- Frontend Public: `leaflock-frontend-production.up.railway.app`
- Frontend Private: `leaflock-frontend.railway.internal`

### IPv6 Compatibility Status
✅ **Backend**: Implements `ListenWithIPv6Fallback()` that binds to `[::]:{port}` (IPv6) first
✅ **Frontend**: Auto-detects Railway service discovery with IPv6 address normalization
✅ **Network**: Supports Railway's IPv6-only private mesh network via WireGuard
✅ **Security**: Backend is private-only, accessible exclusively through frontend proxy

### Required Railway Environment Variables
**Backend Service:**
```bash
# Only allow requests from frontend domains (no public backend access)
CORS_ORIGINS=https://leaflock-frontend-production.up.railway.app,https://app.yourdomain.com
```

**Frontend Service:**
```bash
# Internal backend communication (private network only)
BACKEND_INTERNAL_URL=http://motivated-energy.railway.internal:8080
# Frontend serves as proxy - browser makes requests to frontend
VITE_API_URL=/api/v1
```

### Verification
- Use `bash scripts/test-ipv6.sh` to test IPv6 connectivity
- Check logs for `🌐 HTTP server starting on [::]:8080` (IPv6 binding success)
- Frontend service discovery automatically handles Railway's internal hostnames
- Backend should NOT have a public domain configured in Railway dashboard