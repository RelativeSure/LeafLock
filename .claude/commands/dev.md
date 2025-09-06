# Development Commands

Quick development environment management commands for Secure Notes.

## dev-setup
Set up the complete development environment automatically.

```bash
./scripts/dev-setup.sh
```

**What it does:**
- Checks system requirements (Node.js, Go, Docker/Podman)
- Creates .env file with secure random values
- Installs all dependencies (backend and frontend)
- Sets up development tools
- Configures Git hooks
- Starts development services
- Performs health checks

**Time to complete:** 2-5 minutes

## dev-start
Start development servers with hot reload.

```bash
./scripts/dev-watch.sh
```

**Features:**
- Go backend with automatic rebuild on file changes
- React frontend with Vite hot module replacement
- Real-time process monitoring
- Centralized logging to `/tmp/secure-notes-dev.log`
- Automatic database health checks

**With test watchers:**
```bash
./scripts/dev-watch.sh --with-tests
```

## dev-test
Run comprehensive test suites.

```bash
# Backend tests
cd backend && make test

# Frontend tests  
cd frontend && npm test

# All tests with coverage
cd backend && make test-coverage
```

## dev-lint
Code quality and formatting checks.

```bash
# Backend formatting and linting
cd backend && make fmt lint vet

# Frontend linting
cd frontend && npm run lint
```

## dev-clean
Clean up development environment.

```bash
# Stop all services
make down

# Clean build artifacts
cd backend && make clean
cd frontend && npm run clean # if available

# Clean containers and volumes
make clean
```

## dev-reset
Complete environment reset.

```bash
# Stop services
make down

# Clean everything
make clean

# Remove .env (will be regenerated)
rm -f .env

# Re-run setup
./scripts/dev-setup.sh
```

## Quick Commands

| Command | Description |
|---------|-------------|
| `make up` | Start all services |
| `make down` | Stop all services |
| `make logs` | View backend logs |
| `make status` | Check container status |
| `make build` | Build container images |

## URLs

- **Frontend:** http://localhost:3000
- **Backend:** http://localhost:8080  
- **Health Check:** http://localhost:8080/api/v1/health

## Troubleshooting

### Service won't start
```bash
# Check status
make status

# View logs
make logs

# Restart services
make restart
```

### Port conflicts
If ports 3000, 8080, 5432, or 6379 are in use:

```bash
# Find processes using ports
sudo lsof -i :3000
sudo lsof -i :8080
sudo lsof -i :5432
sudo lsof -i :6379

# Kill processes or modify docker-compose.yml ports
```

### Database connection issues
```bash
# Check database status
make status

# Reset database
make down && make clean && make up
```