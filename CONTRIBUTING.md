# Contributing to LeafLock

Thanks for your interest in improving LeafLock! We welcome bug fixes, new features, documentation, and tests.

## Ways to Contribute

- Issues: Use the GitHub templates to report bugs or request features.
- Discussions: Use Discussions for questions, ideas, and design feedback.
- Pull Requests: Implement fixes or features with tests and docs.

## Development Quick Start

- Backend: `make -C backend test` (see backend/Makefile). Coverage gate: 72%.
- Frontend: `cd frontend && pnpm install && pnpm test`
- Local stack: `docker compose up -d` or `./scripts/leaflock.sh docker:up`
- Icons: `./scripts/leaflock.sh icons`
- Railway: `./scripts/leaflock.sh railway`

## Style & Quality

- Commits: conventional style (e.g., `feat(backend): add tags API`).
- Go: `gofmt -s`, `make -C backend fmt vet` before PR.
- Frontend: Prettier + ESLint (`pnpm format`, `pnpm lint`).
- Tests: Add/adjust tests for your changes; keep them fast and deterministic.
- Security: Never commit secrets. Use `.env.example` as reference.

## Pull Requests

- Title follows conventional commits.
- Describe the change and link issues (e.g., `Closes #123`).
- Include tests and docs where applicable.
- For UI changes, include a screenshot/GIF.

## Discuss First (Recommended)

For significant changes, open a Discussion to align on approach before implementation. This reduces rework and speeds up review.

## Code of Conduct

We follow the Contributor Covenant. See `CODE_OF_CONDUCT.md`.

