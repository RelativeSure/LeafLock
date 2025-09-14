## E2E Verify Workflow

Workflow: `.github/workflows/e2e-verify.yml`

### What it does
- Runs frontend lint, typecheck, tests.
- Builds and starts Postgres, Redis, backend, frontend via `docker compose`.
- Waits for readiness and tests API flow (register + list notes).
- Smoke tests frontend (index + asset).
- Runs backend tests with coverage gate.
- Verifies Swagger access with `ADMIN_USER_IDS` fallback, then via RBAC grant.

### Admin panel in E2E
- Sets `VITE_ENABLE_ADMIN_PANEL=true` so the UI contains the Admin section.

