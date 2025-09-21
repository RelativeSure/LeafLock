# LeafLock

[![CI/CD Pipeline](https://github.com/RelativeSure/LeafLock/actions/workflows/ci.yml/badge.svg)](https://github.com/RelativeSure/LeafLock/actions/workflows/ci.yml)
[![Build Containers](https://img.shields.io/github/actions/workflow/status/RelativeSure/LeafLock/build-containers.yml?branch=main&label=build%20containers)](https://github.com/RelativeSure/LeafLock/actions/workflows/build-containers.yml)
[![E2E Verify](https://img.shields.io/github/actions/workflow/status/RelativeSure/LeafLock/e2e-verify.yml?branch=main&label=e2e%20verify)](https://github.com/RelativeSure/LeafLock/actions/workflows/e2e-verify.yml)
[![Docs](https://img.shields.io/badge/docs-reference-blue)](./docs)
[![Go Version](https://img.shields.io/badge/go-1.24-00ADD8?logo=go)](https://go.dev/dl/)
[![pnpm](https://img.shields.io/badge/pnpm-10.x-ffd831?logo=pnpm)](https://pnpm.io/)
[![Coverage](https://img.shields.io/badge/coverage-72%25-brightgreen)](./backend)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

LeafLock is a privacy-first notes application with end-to-end encryption, real-time collaboration, and a Go backend. Everything can be self-hosted and kept under your control.

## Features

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

2. Configure environment variables:

   ```bash
   cp .env.example .env
   # Fill in the required values to match your environment
   ```

3. Start the full stack with Docker or Podman Compose:

   ```bash
   make up
   ```

   - Frontend: http://localhost:3000
   - Backend API: http://localhost:8080
   - API health check: http://localhost:8080/api/v1/health
   - API documentation: http://localhost:8080/api/v1/docs (admin users only)

4. **First-time login**: Use the default admin credentials (⚠️ **Change immediately after first login!**):
   - Email: `admin@leaflock.local` (configurable via `DEFAULT_ADMIN_EMAIL`)
   - Password: `AdminPass123!` (configurable via `DEFAULT_ADMIN_PASSWORD`)

5. Stop the stack when you are done:

   ```bash
   make down
   ```

## Default Admin Account

When starting LeafLock for the first time, a default admin user is automatically created if no users exist in the database:

- **Email**: `admin@leaflock.local` (default)
- **Password**: `AdminPass123!` (default)
- **Admin privileges**: Yes

### Configuration

You can customize the default admin account using environment variables:

```bash
# Enable/disable default admin creation
ENABLE_DEFAULT_ADMIN=true

# Customize admin credentials
DEFAULT_ADMIN_EMAIL=your-admin@domain.com
DEFAULT_ADMIN_PASSWORD=YourSecurePassword123!
```

To disable automatic admin creation entirely, set `ENABLE_DEFAULT_ADMIN=false` in your `.env` file.

⚠️ **SECURITY WARNING**: Change the default password immediately after your first login! These credentials are publicly documented and should never be used in production.

For user management instructions, see [USER_MANAGEMENT.md](./USER_MANAGEMENT.md).

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

- Install git hooks once per machine: `bash scripts/setup-git-hooks.sh`
- Build container images locally: `make build`

## Deployment

- Use `make up` in combination with your Compose implementation for local deployments
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

LeafLock is released under the MIT License. See `LICENSE` for details.
