# LeafLock Deployment Validation Scripts

This directory contains comprehensive deployment validation scripts to ensure your LeafLock deployment is properly configured and ready for production.

## Overview

The deployment validation suite tests:
- ✅ Docker Compose file syntax and structure
- ✅ Environment variable security and configuration
- ✅ Coolify-specific deployment requirements
- ✅ Container build processes
- ✅ Complete deployment functionality
- ✅ Authentication fixes and admin user setup

## Quick Start

### Basic Validation
```bash
# Run all basic validations
./scripts/validate-deployment.sh

# Run with Coolify validation
./scripts/validate-deployment.sh --coolify

# Run complete test suite (starts containers)
./scripts/validate-deployment.sh --full --coolify
```

### Individual Script Usage
```bash
# Test docker-compose files
./scripts/validate-docker-compose.sh

# Validate environment variables
./scripts/validate-env.sh

# Generate secure environment values
./scripts/validate-env.sh --generate

# Test Coolify configuration
./scripts/validate-coolify.sh

# Run deployment test
./scripts/test-deployment.sh
```

## Script Descriptions

### 1. `validate-deployment.sh` - Main Orchestration Script
**Purpose**: Runs all validation tests and provides comprehensive reporting.

**Features**:
- Orchestrates all validation scripts
- Provides colored output and progress tracking
- Generates deployment checklists
- Security recommendations
- Comprehensive final report

**Usage**:
```bash
./validate-deployment.sh [OPTIONS]

Options:
  --full       Run full deployment tests (starts containers)
  --coolify    Include Coolify-specific validations
  --no-cleanup Don't cleanup containers after tests
  --verbose    Show verbose output
  --help       Show help message
```

### 2. `validate-docker-compose.sh` - Docker Compose Validation
**Purpose**: Validates Docker Compose file syntax and configuration.

**Tests**:
- ✅ Syntax validation using `docker compose config`
- ✅ Environment variable references
- ✅ Service dependencies and health checks
- ✅ Volume and network configurations
- ✅ Port mappings and security settings

**Key Fixes Validated**:
- ✅ `env_file` directive properly configured
- ✅ Environment variable substitution works
- ✅ Service dependencies are correct

### 3. `validate-env.sh` - Environment Variable Validation
**Purpose**: Validates `.env` file security and completeness.

**Tests**:
- ✅ Critical environment variables present
- ✅ Password strength and security
- ✅ JWT secret length and randomness
- ✅ Encryption key format
- ✅ Email and URL format validation
- ✅ Special character handling in Docker

**Key Fixes Validated**:
- ✅ `DEFAULT_ADMIN_PASSWORD` is properly configured
- ✅ Strong, secure passwords are used
- ✅ No default placeholder values remain

**Security Features**:
- Password strength validation (length, complexity)
- Detection of weak/default passwords
- Proper file permissions checking (600)
- Quote handling validation

### 4. `validate-coolify.sh` - Coolify Deployment Validation
**Purpose**: Validates Coolify-specific deployment requirements.

**Tests**:
- ✅ Coolify v4+ compatibility
- ✅ Required parameter substitution (`${VAR:?error message}`)
- ✅ Internal service communication
- ✅ Health check configurations
- ✅ Domain and SSL settings
- ✅ Security best practices

**Coolify-Specific Features**:
- Environment variable error messages
- Internal-only service configuration
- Proper restart policies
- Resource management
- Network isolation

### 5. `test-deployment.sh` - Full Deployment Testing
**Purpose**: Tests complete deployment in containerized environment.

**Tests**:
- ✅ Container startup and health checks
- ✅ Database connectivity (PostgreSQL & Redis)
- ✅ Backend API endpoints
- ✅ Admin user creation and authentication
- ✅ Frontend accessibility
- ✅ Special character handling in environment variables

**Authentication Tests**:
- ✅ Default admin user creation
- ✅ Login with default credentials
- ✅ JWT token generation and validation
- ✅ Authenticated endpoint access

## Key Issues Fixed

### 1. Environment File Loading
**Problem**: Docker Compose wasn't loading `.env` file properly.
**Solution**: Added `env_file` directive to all services in docker-compose.yml.

**Before**:
```yaml
services:
  backend:
    environment:
      DATABASE_URL: postgres://...
```

**After**:
```yaml
services:
  backend:
    env_file:
      - .env
    environment:
      DATABASE_URL: postgres://...
```

### 2. Missing Admin Configuration
**Problem**: `.env` file was missing `DEFAULT_ADMIN_PASSWORD` and related configuration.
**Solution**: Added complete admin user configuration to `.env` with secure defaults.

**Added Configuration**:
```bash
ENABLE_DEFAULT_ADMIN=true
DEFAULT_ADMIN_EMAIL=admin@leaflock.app
DEFAULT_ADMIN_PASSWORD=AdminPass123!
```

### 3. Coolify Deployment Compatibility
**Problem**: Docker Compose wasn't optimized for Coolify platform.
**Solution**: Created `docker-compose.coolify.yml` with Coolify-specific optimizations.

**Key Improvements**:
- Required parameter validation (`${VAR:?error message}`)
- Internal service communication
- Proper health checks
- No external port exposure
- Coolify labels for better integration

### 4. Environment Variable Security
**Problem**: Default/weak passwords and keys in configuration.
**Solution**: Strong password validation and secure value generation.

**Security Enhancements**:
- 32+ character password requirements
- Base64-encoded encryption keys
- 64+ character JWT secrets
- Special character validation
- Placeholder detection and prevention

## Environment Variable Requirements

### Critical Variables (Must be set)
- `POSTGRES_PASSWORD` - Database password (32+ chars, strong)
- `REDIS_PASSWORD` - Redis password (32+ chars, strong)
- `JWT_SECRET` - JWT signing key (64+ chars, random)
- `SERVER_ENCRYPTION_KEY` - Encryption key (32 chars or base64)
- `DEFAULT_ADMIN_PASSWORD` - Admin password (strong with special chars)

### Recommended Variables
- `CORS_ORIGINS` - Allowed domains for CORS
- `VITE_API_URL` - Frontend API URL
- `DEFAULT_ADMIN_EMAIL` - Admin email address
- `ENABLE_DEFAULT_ADMIN` - Enable/disable default admin creation

## Deployment Workflows

### Local Development
1. Run `./scripts/validate-deployment.sh`
2. Fix any validation errors
3. Run `./scripts/validate-deployment.sh --full` for complete test
4. Deploy with `docker compose up -d`

### Coolify Production Deployment
1. Run `./scripts/validate-deployment.sh --coolify`
2. Set environment variables in Coolify UI (not .env file)
3. Configure domain and SSL in Coolify
4. Deploy using `docker-compose.coolify.yml`
5. Run post-deployment verification checklist

## Security Best Practices

### Password Security
- Use 32+ character passwords with mixed case, numbers, and special characters
- Generate passwords with: `openssl rand -base64 32`
- Never use default or placeholder passwords

### Key Management
- JWT secrets should be 64+ characters: `openssl rand -base64 64`
- Encryption keys should be 32 characters: `openssl rand -base64 32`
- Rotate keys regularly in production

### File Security
- Set `.env` file permissions to 600: `chmod 600 .env`
- Never commit `.env` files to version control
- Use separate `.env` files for different environments

### Network Security
- Restrict CORS origins to specific domains
- Use HTTPS in production (set in `VITE_API_URL`)
- Enable SSL for database connections (`sslmode=require`)

## Troubleshooting

### Common Issues

#### Docker Compose Validation Fails
```bash
# Check if docker compose is available
docker compose version

# Test configuration manually
docker compose -f docker-compose.yml config
```

#### Environment Variable Issues
```bash
# Generate new secure values
./scripts/validate-env.sh --generate

# Check specific variable
grep "VARIABLE_NAME" .env
```

#### Container Build Failures
```bash
# Build containers manually
docker build -t test-backend ./backend
docker build -t test-frontend ./frontend
```

#### Coolify Deployment Issues
- Ensure all environment variables are set in Coolify UI (not .env file)
- Check Coolify logs for specific error messages
- Verify domain and SSL configuration
- Use internal service names for communication

### Getting Help
1. Run validation with `--verbose` flag for detailed output
2. Check individual script outputs for specific errors
3. Review the generated deployment checklist
4. Verify all environment variables are properly set

## Files Validated

### Docker Compose Files
- `docker-compose.yml` - Standard deployment
- `docker-compose.coolify.yml` - Coolify-optimized deployment

### Environment Files
- `.env` - Main environment configuration
- `.env.example` - Template with documentation

### Application Files
- `backend/Dockerfile` - Backend container configuration
- `frontend/Dockerfile` - Frontend container configuration

## Success Criteria

All validations pass when:
- ✅ Docker Compose files have valid syntax
- ✅ All critical environment variables are set with secure values
- ✅ Container images build successfully
- ✅ Services start and pass health checks
- ✅ Database connections work
- ✅ API endpoints respond correctly
- ✅ Admin user authentication works
- ✅ Frontend serves content properly

Run the validation suite regularly during development and before any production deployment to ensure your LeafLock deployment is secure and functional.