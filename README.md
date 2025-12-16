# LeafLock

> [!IMPORTANT]  
>THIS PROJECT IS A PRODUCT OF VIBE CODING AND TESTING AI/LLMS.

## Badges

[![Unit Tests](https://img.shields.io/github/actions/workflow/status/RelativeSure/LeafLock/unit-tests.yml?branch=main&label=unit%20tests)](https://github.com/RelativeSure/LeafLock/actions/workflows/unit-tests.yml)
[![Code Coverage](https://img.shields.io/github/actions/workflow/status/RelativeSure/LeafLock/ci-code-coverage.yml?branch=main&label=coverage)](https://github.com/RelativeSure/LeafLock/actions/workflows/ci-code-coverage.yml)
[![codecov](https://codecov.io/gh/RelativeSure/LeafLock/branch/main/graph/badge.svg?token=YOUR_CODECOV_TOKEN)](https://codecov.io/gh/RelativeSure/LeafLock)
[![Backend Coverage](https://codecov.io/gh/RelativeSure/LeafLock/branch/main/graph/badge.svg?token=YOUR_CODECOV_TOKEN&flag=backend)](https://codecov.io/gh/RelativeSure/LeafLock?flags%5B%5D=backend)
[![Frontend Coverage](https://codecov.io/gh/RelativeSure/LeafLock/branch/main/graph/badge.svg?token=YOUR_CODECOV_TOKEN&flag=frontend)](https://codecov.io/gh/RelativeSure/LeafLock?flags%5B%5D=frontend)
[![Backend Lint](https://img.shields.io/github/actions/workflow/status/RelativeSure/LeafLock/ci-backend-lint.yml?branch=main&label=backend%20lint)](https://github.com/RelativeSure/LeafLock/actions/workflows/ci-backend-lint.yml)
[![Frontend Quality](https://img.shields.io/github/actions/workflow/status/RelativeSure/LeafLock/ci-frontend-quality.yml?branch=main&label=frontend%20quality)](https://github.com/RelativeSure/LeafLock/actions/workflows/ci-frontend-quality.yml)
[![MegaLinter](https://img.shields.io/github/actions/workflow/status/RelativeSure/LeafLock/mega-linter.yml?branch=main&label=mega%20linter)](https://github.com/RelativeSure/LeafLock/actions/workflows/mega-linter.yml)
[![Frontend Lighthouse](https://img.shields.io/github/actions/workflow/status/RelativeSure/LeafLock/ci-frontend-lighthouse.yml?branch=main&label=lighthouse)](https://github.com/RelativeSure/LeafLock/actions/workflows/ci-frontend-lighthouse.yml)
[![Container Build](https://img.shields.io/github/actions/workflow/status/RelativeSure/LeafLock/ci-container-build.yml?branch=main&label=container%20build)](https://github.com/RelativeSure/LeafLock/actions/workflows/ci-container-build.yml)
[![Dependency Review](https://img.shields.io/github/actions/workflow/status/RelativeSure/LeafLock/ci-dependency-review.yml?branch=main&label=dependency%20review)](https://github.com/RelativeSure/LeafLock/actions/workflows/ci-dependency-review.yml)
[![Docs](https://img.shields.io/badge/docs-reference-blue)](./docs)
[![Go Version](https://img.shields.io/badge/go-1.25-00ADD8?logo=go)](https://go.dev/dl/)
[![pnpm](https://img.shields.io/badge/pnpm-10.x-ffd831?logo=pnpm)](https://pnpm.io/)
[![License: PolyForm Noncommercial](https://img.shields.io/badge/License-PolyForm_Noncommercial-blue.svg)](https://polyformproject.org/licenses/noncommercial/1.0.0)

LeafLock is a privacy-first notes application with end-to-end encryption, real-time collaboration, and a Go backend. Everything can be self-hosted and kept under your control.

## Features

- **Modern Authentication**: Pure Clerk authentication with social logins, MFA, and enterprise features
- End-to-end encryption handled on the client
- Zero-knowledge architecture for the backend
- Real-time collaboration with WebSockets
- Rich text editor with Markdown and code blocks
- Offline support with automatic sync when connectivity returns

## Requirements

- Docker or Podman with Compose support
- Linux, macOS, or Windows with WSL2
- At least 2GB RAM (4GB recommended)
- Go toolchain (if you develop the backend)
- Node.js 18+ and pnpm 10 (if you develop the frontend)

## Getting Started

1. Clone the repository:

   ```bash
   git clone https://github.com/RelativeSure/LeafLock.git
   cd LeafLock
   ```

2. (Optional) Override defaults:

   ```bash
   cp .env.example .env
   # tweak anything you want and docker compose will pick it up automatically
   ```

3. Start the full stack:

   ```bash
   docker compose up --build
   ```

   - Frontend UI: <http://localhost:3000>
   - Backend API: <http://localhost:8080>
   - API health check: <http://localhost:8080/api/v1/health>
   - Built assets are rebuilt automatically each time you rerun with `--build`

4. Stop everything when finished:

   ```bash
   docker compose down
   ```

5. **Set up Clerk Authentication**:
   - Get your Clerk keys from [Clerk Dashboard](https://dashboard.clerk.com)
   - Add to your `.env` file:
     ```bash
     VITE_CLERK_PUBLISHABLE_KEY=pk_test_your_key_here
     CLERK_PUBLISHABLE_KEY=pk_test_your_key_here  
     CLERK_SECRET_KEY=sk_test_your_key_here
     ```
   - Visit `/login` to access Clerk's authentication components
   - Create your first account or sign in

   **Note**: Clerk handles all authentication - no default admin account is created.

## Project Structure

- `backend/`: Go service, tests, and supporting Make targets
- `frontend/`: Vite + React app managed with pnpm
- `docs/`: User and operator documentation
- `helm/`: Helm charts for Kubernetes deployments
- `scripts/`: Local tooling, including git hook setup

## Development

### Backend (Go)

- Format and lint: `make -C backend fmt` and `make -C backend vet`
- Run tests: `make -C backend test`
- Coverage check: `make -C backend test-coverage-check`

### Frontend (React + Vite)

1. Install dependencies with pnpm:

   ```bash
   cd frontend
   corepack use pnpm@10
   pnpm install
   ```

2. Start the dev server:

   ```bash
   pnpm dev
   ```

3. Run the test suite:

   ```bash
   pnpm test
   ```

Return to the repository root before using make targets again: `cd ..`.

### Tooling

- Install git hooks once per machine: `pre-commit install`
- Build container images locally: `make build`

## Deployment

- Run `docker compose up --build` (or `make up`) for local deployments
- Helm charts under `helm/` support Kubernetes clusters

## Documentation

- [docs/ADMIN.md](docs/ADMIN.md): operational guide for provisioning, upgrades, and backups
- [docs/admin-panel.md](docs/admin-panel.md): UI walkthrough for administrators
- [docs/rbac.md](docs/rbac.md) and [docs/rate-limiting.md](docs/rate-limiting.md): security controls and traffic management
- [docs/swagger.md](docs/swagger.md): OpenAPI generation and API reference pointers
- [docs/SCRIPTS.md](docs/SCRIPTS.md): utility scripts used by automation and CI tasks

## Troubleshooting

- Inspect logs for all services: `make logs`
- Check backend health: `curl http://localhost:8080/api/v1/health`
- Recreate containers if needed: run `make down` followed by `docker compose build --no-cache` or `podman compose build --no-cache`

## Contributing

We welcome contributions of any size. Review `CONTRIBUTING.md` and run the provided checks before opening a pull request. Discussions and issues are tracked in GitHub.

## License

LeafLock is released under the PolyForm Noncommercial License 1.0.0. See `LICENSE` for details.
