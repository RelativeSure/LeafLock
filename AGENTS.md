# Repository Guidelines

## Project Structure & Module Organization
- Go backend in `backend/`; handlers in `handlers/`, domain logic in `services/`, helpers in `utils/`, realtime in `websocket/`, tests `_test.go` beside code.
- React/TypeScript frontend in `frontend/src`; UI in `components/`, stores in `stores/`, API helpers in `lib/`, e2e specs in `frontend/e2e`. pnpm is the supported package manager.
- Deployment tooling spans `docker-compose.yml`, `helm/`, and `leaflock-kube.yaml`. Docs live in `docs/`; automation in repo `scripts/` and service `scripts/`.

## Build, Test, and Development Commands
- `make up` — build and start the full stack via Docker Compose (`make down` stops it).
- `cd backend && make dev-setup` — install Go tooling and launch local Postgres/Redis for integration tests.
- `cd backend && make test` — format, vet, and execute the Go unit suite; `make test-coverage-check` enforces the 72% coverage floor.
- `cd frontend && pnpm install` (first run) then `pnpm dev` for Vite dev server.
- `cd frontend && pnpm check-all` — type-check, lint, format-check, and run Vitest.
- After each run, confirm `pnpm lint` (ESLint) and `pre-commit run --all-files` both pass.

## Coding Style & Naming Conventions
- Run `make fmt` or `gofmt` before committing Go changes; exported identifiers use CamelCase, private helpers stay lowercase, and interfaces follow `SomethingService`.
- Author React components in `.tsx` only (convert any legacy `.jsx` before editing); `scripts/check-no-jsx.sh` enforces this. Frontend styling follows Prettier (2-space indent, single quotes, no semicolons) and Tailwind.
- Lint locally with `make lint` (backend) and `pnpm run lint` (frontend).

## Testing Guidelines
- Backend unit tests live beside code (`*_test.go`); flag integration suites with `Integration` in the test name and start dependencies via `make test-db-up`. Run `make test-ci` before submitting PRs.
- Keep coverage artifacts (`coverage.out`, `coverage.html`) in `backend/` and review them when touching auth, crypto, or storage flows.
- Frontend uses Vitest (`pnpm test`, `pnpm test:coverage`) and Playwright (`pnpm test:pw`); name specs `<feature>.test.tsx` and keep snapshots stable.

## Commit & Pull Request Guidelines
- Favor Conventional Commit prefixes (`feat:`, `fix:`, `chore(deps):`) and scopes that mirror directories, e.g., `feat(frontend): add passkey modal`.
- Squash noisy work-in-progress commits; each PR should focus on one change, link issues, list manual checks, and attach screenshots for UI updates.
- Highlight configuration changes (env vars, secrets, helm values) in the PR body and reference `SECURITY.md` for disclosure or hardening tasks.

## Additional References
- Check `CLAUDE.md` for automation rules, documentation policy, and environment expectations.
