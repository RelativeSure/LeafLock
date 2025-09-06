# Secure Notes Deployment Guide

Complete deployment guide for the Secure Notes application with foolproof one-command deployments.

## 🚀 Quick Start

The fastest way to deploy Secure Notes is using our master deployment script:

```bash
# Interactive deployment menu
./deploy.sh

# Or use specific commands
./deploy.sh dev          # Development environment
./deploy.sh docker       # Docker Compose (development)
./deploy.sh docker-prod  # Docker Compose (production)
./deploy.sh k8s          # Kubernetes (development)
./deploy.sh k8s-prod     # Kubernetes (production)
```

## 📋 Table of Contents

1. [Prerequisites](#prerequisites)
2. [Deployment Options](#deployment-options)
3. [Development Environment](#development-environment)
4. [Docker Deployment](#docker-deployment)
5. [Kubernetes Deployment](#kubernetes-deployment)
6. [Production Considerations](#production-considerations)
7. [Health Monitoring](#health-monitoring)
8. [Troubleshooting](#troubleshooting)
9. [Security Configuration](#security-configuration)

## Prerequisites

### Common Requirements

- **Operating System**: Linux, macOS, or Windows with WSL2
- **Memory**: At least 4GB RAM (8GB recommended for Kubernetes)
- **Disk Space**: At least 10GB free space
- **Network**: Internet connection for downloading images and dependencies

### Platform-Specific Requirements

#### Development Environment
- **Go**: Version 1.21 or higher
- **Node.js**: Version 18 or higher
- **npm**: Comes with Node.js
- **Docker**: For database services only

#### Docker Deployment
- **Docker**: Version 20.10 or higher
- **Docker Compose**: Version 2.0 or higher (comes with Docker)

#### Kubernetes Deployment
- **kubectl**: Compatible with your cluster version
- **Helm**: Version 3.8 or higher
- **Docker**: For building images
- **Kubernetes Cluster**: Local (kind, minikube, Docker Desktop) or remote

## Deployment Options

### 🔧 Development Environment

Best for: Active development, debugging, hot reload

**Features:**
- Backend and frontend run on host machine
- Databases run in Docker containers
- Hot reload for both Go and React
- Fast iteration cycle
- Easy debugging

**Command:**
```bash
./deploy.sh dev
```

**Access:**
- Frontend: http://localhost:5173 (Vite dev server)
- Backend API: http://localhost:8080
- PostgreSQL: localhost:5432
- Redis: localhost:6379

### 🐳 Docker Compose (Development)

Best for: Testing full stack, CI/CD pipelines, local production simulation

**Features:**
- Complete application stack in containers
- Production-like environment
- Easy to start/stop
- Isolated from host system

**Commands:**
```bash
# Development configuration
./deploy.sh docker

# Or manually
./scripts/deploy-docker.sh
```

**Access:**
- Frontend: http://localhost:3000
- Backend API: http://localhost:8080
- Health Check: http://localhost:8080/api/v1/health

### 🐳 Docker Compose (Production)

Best for: Small-scale production, single-server deployments

**Features:**
- Hardened security configuration
- SSL/TLS support
- Resource limits
- Production logging
- Backup-ready volumes

**Commands:**
```bash
# Production configuration with SSL
./deploy.sh docker-prod

# Or manually
./scripts/deploy-docker.sh --prod
```

**Access:**
- Frontend: https://localhost (port 443)
- Backend API: https://localhost/api
- Nginx Status: http://localhost:8090/nginx-status

### ☸️ Kubernetes (Local)

Best for: Testing Kubernetes deployment, learning K8s, staging environment

**Features:**
- Full Kubernetes deployment
- Helm charts for easy management
- Service mesh ready
- Scalable architecture

**Commands:**
```bash
# Deploy to local Kubernetes
./deploy.sh k8s

# Or manually
./scripts/deploy-k8s.sh
```

**Access:**
```bash
# Port forward to access services
kubectl port-forward svc/secure-notes-frontend -n secure-notes 3000:80
kubectl port-forward svc/secure-notes-backend -n secure-notes 8080:8080
```

### ☸️ Kubernetes (Production)

Best for: Production deployments, high availability, enterprise environments

**Features:**
- High availability with multiple replicas
- Ingress with SSL termination
- Network policies for security
- Resource quotas and limits
- Monitoring integration ready

**Commands:**
```bash
# Deploy to production Kubernetes
./deploy.sh k8s-prod your-domain.com

# Or manually
./scripts/deploy-k8s.sh --prod --domain your-domain.com
```

## Development Environment Setup

### 1. Quick Setup

```bash
# One command setup
./deploy.sh dev
```

This will:
- Check all dependencies
- Set up environment configuration
- Install backend dependencies (Go modules)
- Install frontend dependencies (npm packages)
- Start database services in Docker
- Start backend with hot reload
- Start frontend with hot reload

### 2. Manual Setup

If you prefer manual control:

```bash
# Setup environment
./scripts/env-setup.sh setup

# Install dependencies only
./scripts/dev-setup.sh install

# Start databases only
./scripts/dev-setup.sh db

# Then start backend and frontend in separate terminals
cd backend && go run main.go
cd frontend && npm run dev
```

### 3. Available Commands

```bash
./scripts/dev-setup.sh start    # Start everything
./scripts/dev-setup.sh stop     # Stop all services
./scripts/dev-setup.sh restart  # Restart services
./scripts/dev-setup.sh install  # Install dependencies only
./scripts/dev-setup.sh db       # Start databases only
```

## Docker Deployment

### 1. Environment Configuration

First, set up your environment:

```bash
# Interactive setup
./scripts/env-setup.sh setup

# Or generate specific environment
./scripts/env-setup.sh generate prod
./scripts/env-setup.sh generate dev
```

### 2. Development Deployment

```bash
# Quick deployment with auto-generated secrets
./scripts/deploy-docker.sh --auto-generate-secrets

# Or manual deployment after configuring .env
./scripts/deploy-docker.sh
```

### 3. Production Deployment

```bash
# Set required environment variables first
export POSTGRES_PASSWORD="your-secure-password"
export REDIS_PASSWORD="your-redis-password"
export JWT_SECRET="your-64-character-jwt-secret"
export SERVER_ENCRYPTION_KEY="your-32-character-encryption-key"
export CORS_ORIGINS="https://your-domain.com"

# Deploy to production
./scripts/deploy-docker.sh --prod
```

### 4. SSL Configuration

For production with custom SSL certificates:

```bash
# Place your SSL certificates
mkdir -p ssl-certs
cp your-cert.crt ssl-certs/server.crt
cp your-private.key ssl-certs/server.key

# Deploy with SSL
./scripts/deploy-docker.sh --prod
```

### 5. Useful Commands

```bash
# View logs
docker compose logs -f

# Check service status
docker compose ps

# Restart services
docker compose restart

# Update deployment
./scripts/deploy-docker.sh --update

# Stop services
docker compose down
```

## Kubernetes Deployment

### 1. Prerequisites

Ensure you have a Kubernetes cluster and required tools:

```bash
# Check cluster connectivity
kubectl cluster-info

# Check Helm
helm version

# Check Docker for building images
docker version
```

### 2. Local Kubernetes Deployment

For local clusters (kind, minikube, Docker Desktop):

```bash
# Deploy with automatic image building and loading
./scripts/deploy-k8s.sh

# Or with specific options
./scripts/deploy-k8s.sh --no-namespace --version v1.2.3
```

### 3. Production Kubernetes Deployment

For production clusters:

```bash
# Deploy with custom registry and domain
./scripts/deploy-k8s.sh \
  --prod \
  --registry your-registry.com \
  --domain your-app.com \
  --version v1.2.3
```

### 4. Helm Configuration

You can customize the deployment using Helm values:

```bash
# Create custom values file
cp helm/secure-notes/values-prod.yaml my-values.yaml

# Edit your values
vim my-values.yaml

# Deploy with custom values
helm upgrade --install secure-notes helm/secure-notes \
  --namespace secure-notes \
  --create-namespace \
  --values my-values.yaml
```

### 5. Image Management

Build and manage images:

```bash
# Build images locally
./scripts/build.sh build

# Build and push to registry
REGISTRY=your-registry.com ./scripts/build.sh all

# Load images into kind cluster
kind load docker-image secure-notes/backend:latest
kind load docker-image secure-notes/frontend:latest
```

### 6. Useful Commands

```bash
# Check deployment status
kubectl get pods -n secure-notes
kubectl get services -n secure-notes
kubectl get ingress -n secure-notes

# View logs
kubectl logs -f deployment/secure-notes-backend -n secure-notes

# Port forward for local access
kubectl port-forward svc/secure-notes-frontend -n secure-notes 3000:80

# Update deployment
helm upgrade secure-notes helm/secure-notes -n secure-notes

# Delete deployment
helm uninstall secure-notes -n secure-notes
```

## Production Considerations

### 1. Security Checklist

- [ ] **Environment Variables**: Use strong, unique passwords and secrets
- [ ] **SSL/TLS**: Configure proper SSL certificates (not self-signed)
- [ ] **CORS**: Restrict CORS origins to your production domains
- [ ] **Database**: Enable SSL for database connections
- [ ] **Redis**: Use authentication and consider SSL
- [ ] **Network**: Implement network policies (Kubernetes) or firewall rules
- [ ] **Updates**: Keep all components updated

### 2. SSL Certificate Setup

#### Option 1: Let's Encrypt (Recommended)

```bash
# For Kubernetes with cert-manager
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.13.0/cert-manager.yaml

# Configure cluster issuer (see helm values)
```

#### Option 2: Custom Certificates

```bash
# For Docker Compose
mkdir -p ssl-certs
cp your-cert.crt ssl-certs/server.crt
cp your-private.key ssl-certs/server.key
chmod 600 ssl-certs/server.key
```

### 3. Backup Strategy

#### Database Backups

```bash
# Docker Compose backup
docker compose exec postgres pg_dump -U postgres notes > backup-$(date +%Y%m%d).sql

# Kubernetes backup
kubectl exec -n secure-notes deployment/secure-notes-postgresql -- \
  pg_dump -U postgres notes > backup-$(date +%Y%m%d).sql
```

#### Redis Backups

```bash
# Docker Compose
docker compose exec redis redis-cli BGSAVE

# Copy Redis data
cp -r /var/lib/docker/volumes/secure-notes_redis_data/_data/ redis-backup-$(date +%Y%m%d)/
```

### 4. Monitoring and Logging

#### Application Logs

```bash
# Docker Compose
docker compose logs -f backend
docker compose logs -f frontend

# Kubernetes
kubectl logs -f deployment/secure-notes-backend -n secure-notes
kubectl logs -f deployment/secure-notes-frontend -n secure-notes
```

#### Health Monitoring

```bash
# Use built-in health check
./scripts/health-check.sh full

# Continuous monitoring
./scripts/health-check.sh monitor 30 docker

# Performance testing
./scripts/health-check.sh performance
```

## Health Monitoring

### 1. Built-in Health Checks

The application includes comprehensive health monitoring:

```bash
# Full health check
./deploy.sh health

# Or directly
./scripts/health-check.sh full
```

### 2. Service-Specific Checks

```bash
# Check specific services
./scripts/health-check.sh api
./scripts/health-check.sh frontend
./scripts/health-check.sh docker
./scripts/health-check.sh k8s
```

### 3. Continuous Monitoring

```bash
# Monitor every 30 seconds
./scripts/health-check.sh monitor 30 docker

# Monitor Kubernetes deployment
./scripts/health-check.sh monitor 60 k8s
```

### 4. Health Endpoints

- **Backend Health**: `GET /api/v1/health`
- **Frontend Health**: `GET /health` (if configured)
- **Nginx Status**: `GET /nginx-status` (production only)

## Troubleshooting

### 1. Quick Diagnostics

```bash
# Run full diagnostic scan
./deploy.sh troubleshoot

# Or specific diagnostics
./scripts/troubleshoot.sh docker
./scripts/troubleshoot.sh k8s
./scripts/troubleshoot.sh network
./scripts/troubleshoot.sh service backend
```

### 2. Common Issues and Fixes

#### Issue: Services won't start

```bash
# Check Docker daemon
sudo systemctl status docker

# Check port conflicts
sudo netstat -tulpn | grep :8080

# Recreate services
docker compose down && docker compose up -d
```

#### Issue: Environment configuration errors

```bash
# Regenerate environment
./scripts/env-setup.sh setup

# Validate configuration
./scripts/env-setup.sh validate

# Compare configurations
./scripts/env-setup.sh compare .env .env.example
```

#### Issue: Database connection failures

```bash
# Check database logs
docker logs secure-notes-postgres

# Reset database
docker compose down -v && docker compose up -d

# Test connection manually
docker compose exec postgres psql -U postgres -d notes
```

#### Issue: Kubernetes image pull failures

```bash
# Build and load images
./scripts/build.sh build
kind load docker-image secure-notes/backend:latest

# Check image pull policy
kubectl describe pod <pod-name> -n secure-notes

# Force recreate pods
kubectl delete pods --all -n secure-notes
```

### 3. Diagnostic Report

Generate a comprehensive diagnostic report:

```bash
# Generate report
./scripts/troubleshoot.sh report diagnostic-report.txt

# View recent issues
tail -50 diagnostic-report.txt
```

### 4. Getting Help

If you're still having issues:

1. **Check the logs**: Always check service logs first
2. **Run diagnostics**: Use the troubleshooting tools
3. **Check documentation**: Review this guide and the main README
4. **Search issues**: Check the project's issue tracker
5. **Ask for help**: Create a detailed issue with diagnostic information

## Security Configuration

### 1. Environment Security

```bash
# Generate secure environment
./scripts/env-setup.sh generate prod

# Validate security settings
./scripts/env-setup.sh validate .env.production

# Check file permissions
ls -la .env*
```

### 2. Database Security

#### PostgreSQL Configuration

```yaml
# Production settings
postgres:
  command:
    - postgres
    - -c
    - ssl=on
    - -c
    - ssl_min_protocol_version=TLSv1.2
    - -c
    - ssl_ciphers=HIGH:!aNULL:!MD5
    - -c
    - log_connections=on
    - -c
    - log_disconnections=on
```

#### Redis Configuration

```yaml
redis:
  command:
    - redis-server
    - --requirepass ${REDIS_PASSWORD}
    - --rename-command FLUSHALL ""
    - --rename-command FLUSHDB ""
    - --rename-command DEBUG ""
    - --rename-command CONFIG ""
```

### 3. Network Security

#### Docker Compose

```yaml
networks:
  secure-notes-network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.25.0.0/16
```

#### Kubernetes Network Policies

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: secure-notes-policy
spec:
  podSelector:
    matchLabels:
      app: secure-notes
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: ingress-nginx
```

### 4. SSL/TLS Configuration

#### Nginx SSL Settings

```nginx
# Strong SSL configuration
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305;
ssl_prefer_server_ciphers on;
ssl_session_cache shared:SSL:50m;
ssl_session_timeout 24h;
ssl_session_tickets off;
ssl_stapling on;
ssl_stapling_verify on;

# Security headers
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
```

## Summary

This deployment guide provides multiple deployment options for the Secure Notes application:

1. **Development**: Fast iteration with hot reload
2. **Docker Compose**: Production-ready containers
3. **Kubernetes**: Scalable cloud-native deployment

Each deployment method is designed to be:
- **Foolproof**: One-command deployment with comprehensive validation
- **Secure**: Production-ready security configurations
- **Monitored**: Built-in health checks and diagnostics
- **Maintainable**: Easy updates and troubleshooting

Choose the deployment method that best fits your needs and follow the specific instructions above. All deployments include automated environment setup, health monitoring, and troubleshooting tools to ensure a smooth experience.

For additional help, use the built-in tools:
- `./deploy.sh` - Interactive deployment menu
- `./scripts/health-check.sh` - Comprehensive health monitoring
- `./scripts/troubleshoot.sh` - Diagnostic and troubleshooting tools
- `./scripts/env-setup.sh` - Environment configuration management