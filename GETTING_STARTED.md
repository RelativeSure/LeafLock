# Getting Started with Secure Notes

## Table of Contents

1. [Quick Start](#quick-start)
2. [Prerequisites](#prerequisites)  
3. [Environment Setup](#environment-setup)
4. [Development Workflow](#development-workflow)
5. [Configuration Guide](#configuration-guide)
6. [Testing](#testing)
7. [Building for Production](#building-for-production)
8. [Common Issues](#common-issues)

## Quick Start

Get Secure Notes running in 5 minutes:

```bash
# 1. Clone the repository
git clone <repository-url>
cd secure-notes

# 2. Copy environment configuration
cp .env.example .env

# 3. Start all services with Docker Compose
make up
# Or alternatively: docker compose up -d

# 4. Access the application
# Frontend: http://localhost:3000
# Backend API: http://localhost:8080
# Health Check: http://localhost:8080/api/v1/health
```

**First User Registration:**
1. Open http://localhost:3000
2. Click "Need an account? Register"
3. Enter email and a strong password (12+ characters)
4. Your first encrypted workspace will be created automatically
5. Start creating secure, encrypted notes!

## Prerequisites

### System Requirements

**Minimum Requirements:**
- **OS**: Linux, macOS, or Windows with WSL2
- **RAM**: 4GB available
- **Storage**: 2GB free space
- **Network**: Internet access for downloading dependencies

**Recommended Requirements:**
- **OS**: Linux or macOS (better Docker performance)
- **RAM**: 8GB or more
- **Storage**: 5GB free space (for development)
- **CPU**: 4+ cores (for faster builds)

### Required Software

**Container Runtime (Choose One):**
```bash
# Option 1: Podman (Recommended)
# RHEL/Fedora
sudo dnf install podman podman-compose

# Ubuntu/Debian
sudo apt install podman podman-compose

# macOS
brew install podman

# Option 2: Docker
# Install Docker Desktop or Docker Engine
curl -fsSL https://get.docker.com -o get-docker.sh
sh get-docker.sh
```

**Development Tools:**
```bash
# Go 1.23+ (for backend development)
# Download from: https://golang.org/dl/
go version  # Should show 1.23 or higher

# Node.js 20+ and npm (for frontend development)
# Download from: https://nodejs.org/
node --version  # Should show v20 or higher
npm --version   # Should show 10+ 

# Make (for convenience commands)
# Usually pre-installed on Linux/macOS
# Windows: install via chocolatey or WSL
make --version
```

**Optional Tools:**
```bash
# kubectl (for Kubernetes deployment)
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
chmod +x kubectl && sudo mv kubectl /usr/local/bin/

# Helm (for Kubernetes package management)
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash

# jq (for JSON processing in scripts)
sudo apt install jq  # Ubuntu/Debian
sudo dnf install jq  # RHEL/Fedora
brew install jq      # macOS
```

## Environment Setup

### 1. Clone and Configure

```bash
# Clone the repository
git clone <repository-url>
cd secure-notes

# Copy environment template
cp .env.example .env

# Edit environment variables
nano .env  # or your preferred editor
```

### 2. Environment Variables

**Required Variables (for production):**
```bash
# Database
POSTGRES_PASSWORD=GenerateSecurePasswordHere123!

# Redis
REDIS_PASSWORD=GenerateSecureRedisPasswordHere123!

# JWT Secret (64 characters minimum)
JWT_SECRET=GenerateRandom64CharacterStringHereForJWTSigning!

# Server Encryption Key (32 characters)
SERVER_ENCRYPTION_KEY=GenerateRandom32CharStringHere!

# CORS Origins (comma-separated)
CORS_ORIGINS=http://localhost:3000,https://yourdomain.com
```

**Optional Variables:**
```bash
# API URL for frontend
VITE_API_URL=http://localhost:8080

# Database URL (if not using default)
DATABASE_URL=postgres://postgres:password@localhost:5432/notes?sslmode=disable

# Redis URL (if not using default)
REDIS_URL=localhost:6379

# Application port
PORT=8080
```

### 3. Generate Secure Keys

**Quick Key Generation:**
```bash
# Generate secure passwords and keys
openssl rand -base64 32  # For POSTGRES_PASSWORD
openssl rand -base64 32  # For REDIS_PASSWORD
openssl rand -base64 64  # For JWT_SECRET (64 chars)
openssl rand -base64 32  # For SERVER_ENCRYPTION_KEY (32 chars)
```

**Using the Provided Script:**
```bash
# Auto-generate secure environment file
./setup-docker.sh  # Generates .env with secure random values
```

## Development Workflow

### Container-First Development (Recommended)

**Start Development Environment:**
```bash
# Start all services with hot reload
make up

# View logs
make logs

# Check service status
make status

# Stop all services
make down

# Clean up containers and volumes
make clean
```

**Individual Service Management:**
```bash
# Backend only
docker compose up postgres redis backend

# Frontend only (requires backend running)
docker compose up frontend

# Database only
docker compose up postgres redis
```

### Local Development Setup

**Backend Development:**
```bash
cd backend

# Install dependencies
go mod download

# Run database migrations (requires running PostgreSQL)
export DATABASE_URL="postgres://postgres:password@localhost:5432/notes?sslmode=disable"
go run main.go  # Will run migrations automatically

# Run with auto-reload (install air first)
go install github.com/cosmtrek/air@latest
air  # Hot reload for Go

# Run tests
go test -v ./...

# Build binary
go build -o app .
```

**Frontend Development:**
```bash
cd frontend

# Install dependencies
npm install

# Start development server with hot reload
npm run dev  # Available at http://localhost:5173

# Run linting
npm run lint

# Run tests
npm test

# Build for production
npm run build

# Preview production build
npm run preview
```

### Development URLs

| Service | URL | Description |
|---------|-----|-------------|
| **Frontend** | http://localhost:3000 | React application |
| **Backend API** | http://localhost:8080 | Go API server |
| **Health Check** | http://localhost:8080/api/v1/health | API health status |
| **Ready Check** | http://localhost:8080/api/v1/ready | Service readiness |
| **PostgreSQL** | localhost:5432 | Database (internal) |
| **Redis** | localhost:6379 | Cache/sessions (internal) |

### Development Commands

**Makefile Commands:**
```bash
make up          # Start all services
make down        # Stop all services  
make build       # Build all images
make logs        # View service logs
make status      # Check container status
make clean       # Clean containers and volumes
make test        # Run all tests
make lint        # Run code linting
```

**Package Scripts:**
```bash
# Backend (in backend/ directory)
go run main.go              # Run server
go test -v ./...            # Run tests
go build -o app .           # Build binary
go mod tidy                 # Clean dependencies

# Frontend (in frontend/ directory) 
npm run dev                 # Development server
npm run build              # Production build
npm run test               # Run tests
npm run lint               # Code linting
npm run preview            # Preview build
```

## Configuration Guide

### Backend Configuration

**Environment Variables:**
```go
// Load from environment with defaults
type Config struct {
    DatabaseURL      string  // DATABASE_URL
    RedisURL         string  // REDIS_URL
    RedisPassword    string  // REDIS_PASSWORD
    JWTSecret        []byte  // JWT_SECRET
    EncryptionKey    []byte  // SERVER_ENCRYPTION_KEY
    Port             string  // PORT
    AllowedOrigins   []string // CORS_ORIGINS
    MaxLoginAttempts int     // MAX_LOGIN_ATTEMPTS (default: 5)
    LockoutDuration  time.Duration // LOCKOUT_DURATION (default: 15m)
    SessionDuration  time.Duration // SESSION_DURATION (default: 24h)
}
```

**Database Configuration:**
```bash
# PostgreSQL optimized settings (in docker-compose.yml)
max_connections=100
shared_buffers=256MB
effective_cache_size=512MB
maintenance_work_mem=64MB
checkpoint_completion_target=0.7
wal_buffers=16MB
```

**Redis Configuration:**
```bash
# Redis optimized settings
appendonly yes              # Persistence
appendfsync everysec       # Sync frequency
maxmemory-policy allkeys-lru # Memory management
```

### Frontend Configuration

**Build-time Variables:**
```javascript
// Available in Vite build process
const config = {
  VITE_API_URL: import.meta.env.VITE_API_URL || '/api/v1',
  VITE_APP_NAME: import.meta.env.VITE_APP_NAME || 'Secure Notes',
  VITE_MAX_FILE_SIZE: import.meta.env.VITE_MAX_FILE_SIZE || '10485760'
}
```

**Runtime Configuration:**
```javascript
// Client-side crypto settings
const CRYPTO_CONFIG = {
  PBKDF2_ITERATIONS: 600000,      // Key derivation iterations
  SALT_LENGTH: 32,                // Salt length in bytes
  KEY_LENGTH: 32,                 // Encryption key length
  NONCE_LENGTH: 24,               // XChaCha20-Poly1305 nonce
  PASSWORD_MIN_LENGTH: 12,        // Minimum password length
}
```

### Security Configuration

**JWT Settings:**
```go
// JWT token configuration
claims := jwt.MapClaims{
    "user_id": userID.String(),
    "exp":     time.Now().Add(24 * time.Hour).Unix(),  // 24h expiration
    "iat":     time.Now().Unix(),                       // Issued at
}
token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)  // HS512 algorithm
```

**Password Hashing:**
```go
// Argon2id configuration
hash := argon2.IDKey(
    []byte(password),  // Password
    salt,              // 32-byte salt
    3,                 // Time parameter (iterations)
    64*1024,          // Memory parameter (64MB)
    4,                // Parallelism parameter (4 threads)
    32,               // Key length (32 bytes)
)
```

**Rate Limiting:**
```go
// Rate limiter configuration
limiter.Config{
    Max:        100,                    // 100 requests
    Expiration: 1 * time.Minute,       // Per minute
    KeyGenerator: func(c *fiber.Ctx) string {
        return c.IP()                   // Per IP address
    },
}
```

## Testing

### Unit Tests

**Backend Tests:**
```bash
cd backend

# Run all tests with verbose output
go test -v ./...

# Run specific test
go test -v ./auth_test.go

# Run with coverage
go test -v -cover ./...

# Run with race detection
go test -v -race ./...

# Generate coverage report
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

**Frontend Tests:**
```bash
cd frontend

# Run all tests
npm test

# Run tests with coverage
npm test -- --coverage

# Run specific test file
npm test -- LoginView.test.jsx

# Run tests in watch mode
npm test -- --watch
```

### Integration Tests

**API Testing:**
```bash
# Test health endpoints
curl http://localhost:8080/api/v1/health
curl http://localhost:8080/api/v1/ready

# Test registration
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"securepassword123"}'

# Test login  
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"securepassword123"}'
```

**Database Tests:**
```bash
# Connect to test database
docker compose exec postgres psql -U postgres -d notes

# Check tables
\dt

# Check sample data
SELECT id, email, created_at FROM users;
SELECT id, created_at FROM notes LIMIT 5;
```

### End-to-End Tests

**Manual Testing Workflow:**
1. **Registration**: Create new account with strong password
2. **Login**: Authenticate with created credentials
3. **Note Creation**: Create encrypted note with title/content
4. **Note Editing**: Modify existing note and verify persistence
5. **Note Deletion**: Delete note and verify removal
6. **Logout/Login**: Verify notes decrypt properly after re-login
7. **Security**: Verify encryption indicators and security headers

**Automated E2E Tests:**
```bash
# Install Playwright (if not already installed)
cd frontend
npm install --save-dev @playwright/test

# Run E2E tests
npm run test:e2e

# Run E2E tests in headed mode
npm run test:e2e -- --headed
```

## Building for Production

### Docker Production Build

**Multi-stage Production Build:**
```bash
# Build production images
docker compose -f docker-compose.prod.yml build

# Start production stack
docker compose -f docker-compose.prod.yml up -d

# Verify production deployment
curl https://localhost/api/v1/health
```

**Image Optimization:**
```dockerfile
# Backend production Dockerfile
FROM golang:1.23-alpine AS builder
RUN apk add --no-cache git ca-certificates
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o app .

FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /app/app /app
EXPOSE 8080
ENTRYPOINT ["/app"]
```

### Binary Production Build

**Backend Binary:**
```bash
cd backend

# Build for current platform
go build -ldflags="-w -s" -o secure-notes-backend .

# Cross-compile for Linux
GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o secure-notes-backend-linux .

# Cross-compile for Windows  
GOOS=windows GOARCH=amd64 go build -ldflags="-w -s" -o secure-notes-backend.exe .

# Cross-compile for macOS
GOOS=darwin GOARCH=amd64 go build -ldflags="-w -s" -o secure-notes-backend-macos .
```

**Frontend Build:**
```bash
cd frontend

# Production build
npm run build

# Build output in dist/ directory
ls -la dist/

# Serve with static file server (for testing)
npx serve dist/
```

### Kubernetes Production Deployment

**Using Helm:**
```bash
# Add required Helm repositories
helm repo add bitnami https://charts.bitnami.com/bitnami
helm repo update

# Install with production values
helm install secure-notes ./helm/secure-notes \
  --namespace secure-notes \
  --create-namespace \
  --values ./helm/secure-notes/values-production.yaml

# Verify deployment
kubectl get pods -n secure-notes
kubectl get services -n secure-notes
```

## Common Issues

### Container Issues

**"Port already in use" Error:**
```bash
# Find process using port
sudo lsof -i :8080
sudo lsof -i :3000

# Kill process or change port
sudo kill -9 <PID>

# Or use different ports in docker-compose.yml
```

**"Permission denied" Errors:**
```bash
# Fix Docker permissions (Linux)
sudo usermod -aG docker $USER
newgrp docker

# Fix Podman permissions
sudo setsebool -P container_manage_cgroup true
```

**Database Connection Issues:**
```bash
# Check PostgreSQL logs
docker compose logs postgres

# Verify database is ready
docker compose exec postgres pg_isready -U postgres

# Connect manually
docker compose exec postgres psql -U postgres -d notes
```

### Development Issues

**Go Module Issues:**
```bash
cd backend
go clean -modcache    # Clear module cache
go mod download       # Re-download dependencies
go mod tidy          # Clean up go.mod
```

**Node.js Issues:**
```bash
cd frontend
rm -rf node_modules package-lock.json  # Clear cache
npm install                            # Reinstall
npm audit fix                         # Fix vulnerabilities
```

**Build Issues:**
```bash
# Clear Docker build cache
docker system prune -a

# Rebuild from scratch
docker compose build --no-cache

# Check available disk space
df -h
```

### Runtime Issues

**Memory Issues:**
```bash
# Check container memory usage
docker stats

# Increase Docker memory limit (Docker Desktop)
# Settings > Resources > Memory > Increase limit

# Optimize PostgreSQL memory settings
# Reduce shared_buffers if system has limited RAM
```

**Performance Issues:**
```bash
# Check container resource usage
docker compose exec backend top
docker compose exec postgres top

# Monitor database performance
docker compose exec postgres psql -U postgres -d notes \
  -c "SELECT * FROM pg_stat_activity;"

# Check Redis performance
docker compose exec redis redis-cli info stats
```

### Security Issues

**JWT Token Issues:**
```bash
# Check JWT secret length (must be 64+ characters)
echo $JWT_SECRET | wc -c

# Regenerate JWT secret
openssl rand -base64 64
```

**Encryption Key Issues:**
```bash
# Check server encryption key length (must be 32+ characters)
echo $SERVER_ENCRYPTION_KEY | wc -c

# Regenerate encryption key
openssl rand -base64 32
```

**HTTPS/Certificate Issues:**
```bash
# Generate self-signed certificates for development
./init-ssl.sh

# Check certificate validity
openssl x509 -in ssl/cert.pem -text -noout

# Verify HTTPS configuration
curl -k https://localhost/api/v1/health
```

For additional support, check the [troubleshooting guide](TROUBLESHOOTING.md) or create an issue in the project repository.