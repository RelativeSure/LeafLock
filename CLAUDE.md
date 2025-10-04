# CLAUDE.md

This file provides guidance to Claude Code when working with this repository.

## Project Overview

Secure notes application with end-to-end encryption:
- **Backend**: Go 1.23+ with Fiber v2, PostgreSQL (pgx), Redis, JWT auth
- **Frontend**: React 18, TypeScript, Vite 5, Zustand, TipTap editor
- **Encryption**: XChaCha20-Poly1305 (client-side), Argon2id (passwords)
- **Infrastructure**: Podman/Docker, PostgreSQL 15, Redis 7
- **Architecture**: Zero-knowledge - server never sees plaintext data

## Essential Commands

### Backend
```bash
cd backend
go run main.go              # Run dev server
go test -v ./...            # Run all tests
golangci-lint run ./...     # Lint (required after complex changes)
```

### Frontend
```bash
cd frontend
pnpm run dev                # Run dev server
pnpm test                   # Run tests
pnpm run lint               # ESLint
```

### Containers
```bash
make up                     # Start all services (Podman)
make down                   # Stop containers
docker compose up -d        # Alternative: Docker Compose
```

## Critical Development Rules

### 1. DO NOT add verbose test documentation to CLAUDE.md
- Test files are self-documenting
- Only mention test file paths, not detailed test cases
- Keep test sections minimal (file locations only)

### 2. Database Migration Version - MUST BUMP

**⚠️ CRITICAL**: When modifying database schema, you **MUST** bump the migration version:

- **File**: `backend/database/database.go`
- **Constant**: `MigrationSchemaVersion` (line 21)
- **Format**: `YYYY.MM.DD.NNN` (increment last number)
- **Example**: `2024.12.25.002` → `2024.12.25.003`

**Why**: Existing deployments skip migrations if version matches. Without bump, new columns/tables won't be created, causing runtime failures.

**Files requiring version bump**:
- `backend/database/schema.go` - Any ALTER TABLE, CREATE TABLE, CREATE INDEX
- Any file modifying database structure

### 3. Verify After Complex Programming Tasks

After completing complex features, **ALWAYS** run:
```bash
# Backend verification
cd backend && golangci-lint run ./...

# Frontend verification
cd frontend && pnpm run lint
# Or use megalinter for comprehensive check
```

### 4. Docker Compose Sync

When modifying `docker-compose.yml`, remember to sync:
- Regular `docker-compose.yml`
- Coolify `docker-compose.yml`
- `frontendDockerfile` and entrypoint scripts if affected

## Key Features & Architecture

### E2E Encryption
- Client-side encryption: XChaCha20-Poly1305 via libsodium-wrappers
- Server never sees plaintext (zero-knowledge architecture)
- Password hashing: Argon2id (64MB memory, 3 iterations)

### Collaboration Features

**Direct User Sharing**:
- Share notes with specific users by email
- Handlers: `backend/handlers/collaboration.go`
- Frontend: `frontend/src/stores/collaborationStore.ts`

**Share Links** (Redis-cached public sharing):
- Create shareable links with read/write permissions
- Optional: password protection, expiration (1h/24h/7d/30d), usage limits
- **⚠️ Security**: Share links bypass E2E encryption (server-side decryption)
- **Backend**:
  - `backend/handlers/share_links.go` - CRUD endpoints
  - `backend/middleware/share_link.go` - Token validation
  - `backend/services/share_links.go` - Redis caching (<1ms lookups)
  - `backend/database/schema.go` - share_links table
- **Frontend**:
  - `frontend/src/stores/shareLinksStore.ts` - State management
  - `frontend/src/components/ShareDialog.tsx` - UI (tabbed interface)
  - `frontend/src/components/settings/ShareLinksTab.tsx` - Global management
- **Tests**: See `*_test.go` and `*.test.tsx` files (self-documenting)
- **Migration**: `2025.10.04.001`

### Admin System
- Auto-creates default admin if no users exist
- Email: `DEFAULT_ADMIN_EMAIL` (default: admin@leaflock.app)
- Password: `DEFAULT_ADMIN_PASSWORD` (supports all special chars)
- Implementation: `backend/services/admin.go`

### IPv4/IPv6 Support
- Backend auto-binds to `[::]:{PORT}` (dual-stack) with IPv4 fallback
- Frontend auto-detects from `window.location` or env vars
- Implementation: `backend/server/listener.go`, `frontend/src/utils/network.ts`

### Rate Limiting
**Architecture**: Redis-backed distributed rate limiting using fixed window algorithm

**Implementation**:
- `backend/middleware/rate_limit.go` - Tiered limiter configuration
- `backend/middleware/rate_limit_test.go` - Test coverage
- Storage: `github.com/gofiber/storage/redis/v3` (managed by Renovate)

**Rate Limit Tiers** (hardcoded, not configurable):

**Tier 1 - Auth Endpoints** (Strictest - Prevent brute force):
- Login: 10 requests/5 min
- Register: 5 requests/15 min
- MFA Verify: 10 requests/5 min
- Admin Recovery: 3 requests/15 min
- MFA Setup/Enable/Disable: 10 requests/5 min

**Tier 2 - Public Share Links** (Aggressive - Prevent abuse):
- Public share link access: 20 requests/5 min
- Share link creation: 10 requests/15 min

**Tier 3 - Heavy Operations** (Resource intensive):
- Search: 30 requests/min
- Import/Export: 10 requests/5 min
- Bulk import: 5 requests/15 min
- Attachments upload: 20 requests/5 min
- Account deletion: 10 requests/5 min

**Tier 4 - Standard CRUD** (Normal usage):
- Notes/Tags/Folders/Templates CRUD: 100 requests/min
- Collaboration: 50 requests/min
- Share link management: 100 requests/min

**Tier 5 - Read-Only/Lightweight** (Liberal):
- Settings GET, MFA status, Storage info: 200 requests/min

**Excluded from rate limiting**:
- Health checks (`/health`, `/health/live`, `/health/ready`)
- Swagger/docs endpoints
- WebSocket connections

**Key Generator**: IP-based using `utils.ClientIP` (supports IPv4/IPv6)

## Environment Setup

Copy `.env.example` to `.env` and configure:
- `POSTGRES_PASSWORD` - Database password
- `REDIS_PASSWORD` - Redis password
- `JWT_SECRET` - 64-char JWT key
- `SERVER_ENCRYPTION_KEY` - 32-char encryption key
- `CORS_ORIGINS` - Allowed frontend origins

**Service Ports**:
- Frontend: http://localhost:3000
- Backend: http://localhost:8080
- Health: http://localhost:8080/api/v1/health

## Testing

### Backend Tests
```bash
cd backend
go test -v ./...                          # All tests
go test -v ./handlers/share_links_test.go # Specific test
go test -v -cover ./...                   # With coverage
```

### Frontend Tests
```bash
cd frontend
pnpm test                                 # All tests
pnpm test ShareDialog.test.tsx            # Specific test
pnpm test --coverage                      # With coverage
```

## Deployment

### Health Checks
- `/api/v1/health/live` - Basic health (3-5s)
- `/api/v1/health/ready` - Full readiness (15-30s)

### Railway Compatibility
- Backend binds to `[::]:{PORT}` (IPv6-first with IPv4 fallback)
- Frontend auto-detects Railway internal hostnames
- Backend should be private-only (no public domain)

### Startup Performance
- Container startup: 15-30 seconds
- Database ready: 5-10 seconds
- All services operational: 25-30 seconds
- Optimization: `SKIP_MIGRATION_CHECK=false` (default, don't change)

## Common Issues

### Docker containers can't communicate
- Use service names (`postgres`, `redis`, `backend`) not IPs
- Docker's default bridge is IPv4-only

### Frontend can't reach backend
- Check `VITE_API_URL` in `.env`
- For IPv6: Use `http://[::1]:8080` format

### Migration didn't run
- Check if `MigrationSchemaVersion` was bumped
- Existing deployments skip if version unchanged

### Share link not working
- Check expiration, active status, usage limits in database
- Verify Redis cache: `redis-cli GET share_link:{token}`
- Clear cache if inconsistent: `redis-cli DEL share_link:{token}`

### Rate limit errors (429 Too Many Requests)
- **Check IP**: Rate limits are IP-based using `X-Forwarded-For` header
- **Different tiers**: Each endpoint has different limits (see Rate Limiting section)
- **Redis storage**: Rate limit state is stored in Redis with automatic expiration
- **Debugging**: Check Redis keys: `redis-cli KEYS *limiter*`
- **Reset**: Clear specific IP limit: `redis-cli DEL limiter:{ip}:{endpoint}`
- **Multiple IPs**: If behind proxy/load balancer, ensure `X-Forwarded-For` is properly set
