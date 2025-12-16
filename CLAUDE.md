# CLAUDE.md

This file provides guidance to Claude Code when working with this repository.

## Project Overview

Secure notes application with end-to-end encryption:
- **Backend**: Go 1.25+ with Fiber v2, PostgreSQL (pgx), Redis, JWT auth
- **Frontend**: React 18, TypeScript, Vite 5, Zustand, Quill 2.0 editor
- **Encryption**: XChaCha20-Poly1305 (client-side), Argon2id (passwords)
- **Infrastructure**: Podman/Docker, PostgreSQL 15, Redis 7
- **Architecture**: Zero-knowledge - server never sees plaintext data

**⚠️ CRITICAL**: Frontend is 100% TypeScript - **NEVER create `.jsx` files**. All React files must use `.tsx` extension. This is enforced by `scripts/check-no-jsx.sh` which runs on build and lint.

## Essential Commands

### Backend
```bash
cd backend
go run main.go              # Run dev server
go test -v ./...            # Run all tests
golangci-lint run ./...     # Lint (required after complex changes)
```text

### Frontend
```bash
cd frontend
pnpm run dev                # Run dev server
pnpm test                   # Run tests
pnpm run lint               # ESLint
```text

### Containers
```bash
make up                     # Start all services (Podman)
make down                   # Stop containers
docker compose up -d        # Alternative: Docker Compose
```text

## Critical Development Rules

### 1. Documentation File Policy

**NEVER create standalone documentation files** (.md, .txt, .rst files) unless explicitly requested by the user.

**Rationale**:
- Documentation should be added to existing files (CLAUDE.md, README.md, etc.)
- Standalone docs create clutter and maintenance burden
- Keep documentation centralized and minimal

**Exception: AstroJS Documentation**
When significant architectural changes, new features, or design patterns are introduced that benefit developers and end users, update the AstroJS documentation in `docs/src/content/docs/`.

**AstroJS Documentation Guidelines**:
- Write for both developers and end users
- Use clear, technical language without emojis
- Be concise and easily readable
- Focus on facts and actionable information
- Include code examples with proper syntax highlighting
- Use Astro components (Aside, Code, Tabs, CardGrid) for better readability
- Document architecture patterns, component structure, and design decisions
- Keep examples practical and copy-paste ready
- Use proper MDX frontmatter with title, description, and sidebar order

**When to update AstroJS docs**:
- Major component refactoring or new component patterns
- New features that affect user workflow
- Architectural changes that developers need to understand
- Design pattern changes or new patterns introduced
- Breaking changes or migration guides needed

**Test documentation**:
- Test files are self-documenting
- Only mention test file paths, not detailed test cases
- Keep test sections minimal (file locations only)

### 1.1. AstroJS Documentation Content Philosophy

**⚠️ CRITICAL PRINCIPLE**: Documentation must be **LeafLock-specific**, not general technology tutorials.

**DO NOT include**:
- General technology explanations (how Docker/K8s/React/MFA works)
- Framework/platform documentation that belongs in official docs
- Marketing-style "benefits" or "why use X" sections
- Step-by-step tutorials for standard tools (authenticator apps, Git, etc.)
- Cryptography theory or algorithm explanations
- Generic best practices not tied to LeafLock's implementation
- Emoji-heavy formatting or conversational tone

**DO include**:
- LeafLock-specific configuration files and values
- LeafLock-specific commands and file paths with line numbers
- Unique architectural decisions in LeafLock
- LeafLock-specific troubleshooting for known issues
- References to LeafLock source code locations
- Environment variables and their LeafLock-specific usage
- Actual deployment commands for LeafLock

**Content Quality Rules**:
1. **DRY Principle**: Never repeat information across multiple docs
2. **50% Rule**: If a file could be 50% shorter without losing LeafLock-specific info, it's too verbose
3. **Reference Test**: Every paragraph must reference LeafLock code, config, or behavior
4. **Copy-Paste Test**: Code blocks should be immediately usable for LeafLock deployment
5. **No Fluff**: Remove all introductory "what is X" sections that explain general concepts
6. **Line Count**: Target maximum line counts per category (see below)

**File Size Targets** (after cleanup):
- Deployment docs: 200-400 lines max
- Reference/Architecture docs: 150-300 lines max
- Feature docs: 50-150 lines max
- Operations docs: 100-200 lines max

**Examples of BAD vs GOOD content**:

❌ **BAD** (general explanation):
```text
Multi-Factor Authentication (MFA) requires two forms of verification to access your account:
1. Something you know - Your password
2. Something you have - Your authentication device

This provides an additional layer of security...
```

✅ **GOOD** (LeafLock-specific):
```text
LeafLock MFA: TOTP stored encrypted in `mfa_secret_encrypted` column,
Argon2id hashed backup codes, rate limit: 5 attempts/15min.
Implementation: `backend/middleware/rate_limit.go:45`
```

❌ **BAD** (platform tutorial):
```text
Kubernetes uses Pods to run containers. A Pod is the smallest deployable
unit in Kubernetes. StatefulSets provide stable network identities...
```

✅ **GOOD** (LeafLock deployment):
```text
Backend pod: `resources.requests.memory: 256Mi`, dual-stack IPv6 on `[::]:8080`
PostgreSQL StatefulSet: 10Gi PVC, connection pool in `backend/database/database.go:89`
Deploy: `helm install leaflock ./helm -f values-prod.yaml`
```

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

### 3. Testing Requirements - ALWAYS RUN AFTER CHANGES

**⚠️ CRITICAL**: After **EVERY** code change, you **MUST** run verification commands before committing.

**Frontend Changes**:
```bash
cd frontend
pnpm run lint           # ESLint + check-no-jsx.sh (REQUIRED)
pnpm test              # Run all tests (REQUIRED)
pnpm run typecheck     # TypeScript type checking (REQUIRED)
pnpm run build         # Verify build succeeds (REQUIRED for significant changes)
```

**Backend Changes**:
```bash
cd backend
go test -v ./...                # Run all tests (REQUIRED)
golangci-lint run ./...         # Lint (REQUIRED after complex changes)
go build -o /dev/null ./...     # Verify build succeeds (REQUIRED for significant changes)
```

**When to run**:
- ✅ Before every commit
- ✅ After modifying any component
- ✅ After adding/updating dependencies
- ✅ After refactoring code
- ✅ After fixing bugs

**DO NOT commit** if any verification command fails.

**Note on Integration Tests**:
- Backend integration tests require PostgreSQL (port 5433) and Redis (port 6380)
- Unit tests that require services will skip gracefully if unavailable locally
- GitHub Actions workflows automatically provide these services
- To run integration tests locally: `make test-db-up` (requires Docker)

### 4. Docker Compose Sync

When modifying `docker-compose.yml`, remember to sync:
- Regular `docker-compose.yml`
- Coolify `docker-compose.yml`
- `frontendDockerfile` and entrypoint scripts if affected

### 5. Pre-commit Hooks

Pre-commit hooks are configured in `.pre-commit-config.yaml` and automatically run on commit.

**Installation**:
```bash
python3 -m pip install --user pre-commit
~/.local/bin/pre-commit install
```

**Configured hooks**:
- General: trailing whitespace, end-of-file, YAML/JSON validation, merge conflicts, large files
- Security: detect-secrets, private key detection, .env file prevention
- Go: go-fmt, go-vet, go test, go mod tidy, gosec (optional)
- Frontend: check-no-jsx, pnpm lint, pnpm test, pnpm audit
- Docker: hadolint (optional)

**Usage**:
```bash
# Automatic on commit
git commit -m "message"

# Manual run
~/.local/bin/pre-commit run --all-files

# Skip (not recommended)
git commit --no-verify -m "message"
```

**Key files**:
- `.pre-commit-config.yaml` - Configuration
- `.secrets.baseline` - Secrets detection baseline
- `.git/hooks/pre-commit` - Installed hook script

### 6. Scripts Policy

**Keep scripts minimal** - maximum 2-3 in `scripts/` directory. More creates maintenance burden.

**Current scripts**:
- `scripts/dev-setup.sh` - Developer onboarding (checks versions, installs tools)
- `scripts/backup.sh` - Manual database backups (for non-Helm deployments)
- `frontend/scripts/check-no-jsx.sh` - TypeScript .tsx enforcement

**Use instead of scripts**:
- Docker: `make up`, `make down`, `docker compose` commands
- Kubernetes: `helm install/upgrade` commands directly
- Health checks: `curl http://localhost:8080/api/v1/health`
- Tests: `cd backend && go test -v ./...` or `cd frontend && pnpm test`

**Rules**:
- Never create wrapper scripts that just call other tools
- Use Makefile targets for common docker-compose commands
- Consolidate similar functionality into single script
- Delete scripts when tools/Makefile can do the job

## Key Features & Architecture

### Rich Text Editor
- **Editor**: Quill 2.0 (battle-tested, used by Slack/LinkedIn/Figma)
- **Features**: WYSIWYG/Markdown modes, tables, code blocks, file uploads
- **Implementation**: `frontend/src/components/RichTextEditor.tsx`
- **Markdown**: Bidirectional conversion via `marked` and `turndown`
- **Security**: DOMPurify sanitization on all HTML content
- **Styling**: Custom CSS in `frontend/src/index.css` (Quill section)

### E2E Encryption
- Client-side encryption: XChaCha20-Poly1305 via libsodium-wrappers
- Server never sees plaintext (zero-knowledge architecture)
- Password hashing: Argon2id (64MB memory, 3 iterations)
- **Zero-Knowledge Architecture**: No global `SERVER_ENCRYPTION_KEY`
  - User notes: E2E encrypted with password-derived keys
  - MFA/Sessions/Share links: JWT-derived encryption (`auth/service.go:NewService`)
  - Emails: Plaintext (operational necessity for password reset)
  - Audit logs: SHA-256 hashed IP/UserAgent (privacy-preserving)

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

### Modern Auth Package
**Architecture**: Clean, modular Go authentication system (2,125 lines)

**Package Structure** (`backend/auth/`):
- `models.go` - Type-safe models, structured error codes
- `session.go` - Redis-backed session management (encrypted)
- `password.go` - Argon2id hashing, password reset flow
- `mfa.go` - TOTP + backup codes implementation
- `clerk_*.go` - Clerk authentication integration
- `service.go` - Coordinating service layer
- `handlers.go` - HTTP API (13 endpoints)
- `middleware.go` - JWT validation, auth guards

**Features**:
- User registration with validation
- Login with MFA support
- Password reset (1-hour tokens)
- TOTP MFA with QR codes
- 10 backup codes (XXXX-XXXX-XXXX format)
- Account locking (5 attempts = 15min lock)
- Session management (24-hour duration)
- Encrypted sessions (XChaCha20-Poly1305)

**Clerk Authentication**:
- Modern authentication using Clerk service
- Handles user registration, login, MFA, and session management
- No default admin accounts - all users managed through Clerk
- Enhanced security with Clerk's infrastructure

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
- Password Reset: 10 requests/5 min
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
- Frontend: <http://localhost:3000>
- Backend: <http://localhost:8080>
- Health: <http://localhost:8080/api/v1/health>

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
