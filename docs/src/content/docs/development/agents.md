# Repository Guidelines

This repository contains LeafLock, a full‑stack app with a Go backend and a Vite/React frontend. Use this guide to develop, test, and contribute consistently.

## Project Structure & Module Organization
- `backend/` Go service (`main.go`, tests `*_test.go`, `Makefile`)
- `frontend/` Vite + React + TS/JS (`src/`, tests `*.test.{js,jsx,ts,tsx}`)
- `docs/` documentation; `helm/` deployment charts; `scripts/` tooling
- Root `Makefile`, `docker-compose.yml`/`podman-compose.yml`, `.github/` CI

## Build, Test, and Development Commands
- Local stack: `make up` (Podman Compose or generated kube), `make down`, `make logs`
- Containers: `make build` builds backend and frontend images
- Backend: `make -C backend test` (all), `... test-coverage-check` (>=72%), `... fmt`, `... vet`
- Frontend: `cd frontend && pnpm install && pnpm test`, `pnpm dev`, `pnpm build`
- Git hooks: `bash scripts/setup-git-hooks.sh` to enable pre-commit/push and commit-msg checks

## Coding Style & Naming Conventions
- EditorConfig enforces LF, UTF‑8, trim whitespace
- Go: tabs, `gofmt -s` formatting; package names lowercase; exported identifiers PascalCase
- Frontend: 2‑space indent, Prettier (semi: false, singleQuote: true); ESLint configured; React component exports PascalCase
- Filenames: Go `*.go`; tests `*_test.go`; frontend tests `*.test.*`

## Testing Guidelines
- Backend: unit/integration with `go test`; run `make -C backend test-local` for a full local suite; coverage via `... test-coverage`
  - Coverage gate is set to 72% (CI passes above this)
- Frontend: Vitest + RTL; `pnpm test` (watch `pnpm test:watch`), coverage `pnpm test:coverage`
- Keep tests near code (frontend `src/**`), prefer deterministic, fast tests; add integration tags in Go if needed

## Commit & Pull Request Guidelines
- Commit messages: conventional style `type(scope): summary` (e.g., `feat(backend): add tags API`); a commit-msg hook validates format and 72‑char subject
- Pre-commit runs format, lint, tests, secret scans; ensure `pre-commit`/hooks are installed (`scripts/setup-git-hooks.sh`)
- PRs: include concise description, linked issues (`Closes #123`), test coverage notes; add screenshots/GIFs for UI changes; pass CI and security checks

## Security & Configuration
- Never commit secrets; `.env` is ignored—use `.env.example`
- For local DB/Redis in integration tests, see `backend/Makefile` targets `test-db-up`/`test-db-down`
