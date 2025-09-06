#!/bin/bash
# setup-docker.sh - Complete setup script for Docker deployment

set -e

echo "🔐 Secure Notes - Docker Setup"
echo "=============================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Create project structure
create_project_structure() {
    echo -e "${BLUE}Creating project structure...${NC}"
    
    mkdir -p backend
    mkdir -p frontend/src
    mkdir -p ssl
    
    echo -e "${GREEN}✅ Project structure created${NC}"
}

# Generate secure random secrets
generate_env_file() {
    if [ -f .env ]; then
        echo -e "${YELLOW}⚠️  .env file already exists. Skipping...${NC}"
        return
    fi
    
    echo -e "${BLUE}Generating secure .env file...${NC}"
    
    # Generate secure random values
    POSTGRES_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
    REDIS_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
    JWT_SECRET=$(openssl rand -base64 64 | tr -d "\n")
    ENCRYPTION_KEY=$(openssl rand -base64 32 | tr -d "\n")
    
    cat > .env << EOF
# Secure Notes Environment Variables
# Generated: $(date)

# Database
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}

# Redis
REDIS_PASSWORD=${REDIS_PASSWORD}

# JWT Authentication
JWT_SECRET=${JWT_SECRET}

# Server Encryption Key
SERVER_ENCRYPTION_KEY=${ENCRYPTION_KEY}

# CORS Origins (comma-separated)
CORS_ORIGINS=http://localhost:3000,http://localhost,https://localhost

# API URL for frontend
VITE_API_URL=http://localhost:8080

# Node Environment
NODE_ENV=production
EOF
    
    chmod 600 .env
    echo -e "${GREEN}✅ Secure .env file generated${NC}"
    echo -e "${YELLOW}⚠️  Keep .env file secret and never commit to git!${NC}"
}

# Create backend Dockerfile
create_backend_dockerfile() {
    echo -e "${BLUE}Creating backend Dockerfile...${NC}"
    
    cat > backend/Dockerfile << 'EOF'
# Build stage
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Create non-root user
RUN adduser -D -u 10001 appuser

WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s" \
    -o secure-notes-backend \
    main.go

# Final stage
FROM scratch

# Copy from builder
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /build/secure-notes-backend /app/

# Use non-root user
USER appuser

EXPOSE 8080

ENTRYPOINT ["/app/secure-notes-backend"]
EOF
    
    echo -e "${GREEN}✅ Backend Dockerfile created${NC}"
}

# Create frontend Dockerfile
create_frontend_dockerfile() {
    echo -e "${BLUE}Creating frontend Dockerfile...${NC}"
    
    cat > frontend/Dockerfile << 'EOF'
# Build stage
FROM node:20-alpine AS builder

WORKDIR /app

# Copy package files
COPY package*.json ./
RUN npm ci --only=production

# Copy source code
COPY . .

# Build the application
ARG VITE_API_URL=http://localhost:8080
ENV VITE_API_URL=$VITE_API_URL
RUN npm run build

# Production stage
FROM nginx:alpine

# Remove default nginx config
RUN rm -rf /etc/nginx/conf.d/*

# Copy custom nginx config
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Copy built application
COPY --from=builder /app/dist /usr/share/nginx/html

# Add security headers config
RUN echo 'server_tokens off;' > /etc/nginx/conf.d/security.conf

EXPOSE 80

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost/ || exit 1

CMD ["nginx", "-g", "daemon off;"]
EOF
    
    echo -e "${GREEN}✅ Frontend Dockerfile created${NC}"
}

# Create nginx configuration
create_nginx_config() {
    echo -e "${BLUE}Creating nginx configuration...${NC}"
    
    cat > frontend/nginx.conf << 'EOF'
server {
    listen 80;
    server_name _;
    root /usr/share/nginx/html;
    index index.html;

    # Security headers
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Content-Security-Policy "default-src 'self' http://localhost:8080; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_types text/plain text/css text/xml text/javascript application/json application/javascript application/xml+rss application/rss+xml application/atom+xml image/svg+xml text/javascript application/vnd.ms-fontobject application/x-font-ttf font/opentype image/x-icon;

    # API proxy
    location /api {
        proxy_pass http://backend:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }

    # WebSocket support
    location /ws {
        proxy_pass http://backend:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    # SPA support
    location / {
        try_files $uri $uri/ /index.html;
    }

    # Cache static assets
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2)$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
}
EOF
    
    echo -e "${GREEN}✅ Nginx configuration created${NC}"
}

# Create PostgreSQL initialization script
create_postgres_init() {
    echo -e "${BLUE}Creating PostgreSQL init script...${NC}"
    
    cat > init-ssl.sh << 'EOF'
#!/bin/bash
# Generate SSL certificates for PostgreSQL

set -e

SSL_DIR="/var/lib/postgresql"

# Generate self-signed certificate if it doesn't exist
if [ ! -f "$SSL_DIR/server.crt" ]; then
    echo "Generating PostgreSQL SSL certificates..."
    
    openssl req -new -x509 -days 365 -nodes -text \
        -out $SSL_DIR/server.crt \
        -keyout $SSL_DIR/server.key \
        -subj "/CN=postgres"
    
    chmod 600 $SSL_DIR/server.key
    chown postgres:postgres $SSL_DIR/server.key $SSL_DIR/server.crt
    
    echo "SSL certificates generated successfully"
fi

# Ensure PostgreSQL is configured for SSL
echo "SSL configuration complete"
EOF
    
    chmod +x init-ssl.sh
    echo -e "${GREEN}✅ PostgreSQL init script created${NC}"
}

# Create frontend package.json
create_frontend_package() {
    echo -e "${BLUE}Creating frontend package.json...${NC}"
    
    cat > frontend/package.json << 'EOF'
{
  "name": "secure-notes-frontend",
  "version": "1.0.0",
  "private": true,
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "vite build",
    "preview": "vite preview",
    "lint": "eslint src"
  },
  "dependencies": {
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "libsodium-wrappers": "^0.7.13",
    "@tanstack/react-query": "^5.12.0",
    "zustand": "^4.4.7",
    "clsx": "^2.1.0"
  },
  "devDependencies": {
    "@types/react": "^18.2.45",
    "@types/react-dom": "^18.2.18",
    "@vitejs/plugin-react": "^4.2.1",
    "autoprefixer": "^10.4.16",
    "postcss": "^8.4.32",
    "tailwindcss": "^3.4.0",
    "typescript": "^5.3.3",
    "vite": "^5.0.10"
  }
}
EOF
    
    echo -e "${GREEN}✅ Frontend package.json created${NC}"
}

# Create backend go.mod
create_backend_gomod() {
    echo -e "${BLUE}Creating backend go.mod...${NC}"
    
    cat > backend/go.mod << 'EOF'
module secure-notes

go 1.21

require (
    github.com/gofiber/fiber/v2 v2.52.0
    github.com/gofiber/websocket/v2 v2.2.1
    github.com/golang-jwt/jwt/v5 v5.2.0
    github.com/google/uuid v1.5.0
    github.com/jackc/pgx/v5 v5.5.1
    github.com/redis/go-redis/v9 v9.4.0
    golang.org/x/crypto v0.17.0
)

require (
    github.com/andybalholm/brotli v1.0.5 // indirect
    github.com/cespare/xxhash/v2 v2.2.0 // indirect
    github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
    github.com/fasthttp/websocket v1.5.4 // indirect
    github.com/jackc/pgpassfile v1.0.0 // indirect
    github.com/jackc/pgservicefile v0.0.0-20231201235250-de7065d80cb9 // indirect
    github.com/jackc/puddle/v2 v2.2.1 // indirect
    github.com/klauspost/compress v1.17.0 // indirect
    github.com/mattn/go-colorable v0.1.13 // indirect
    github.com/mattn/go-isatty v0.0.20 // indirect
    github.com/mattn/go-runewidth v0.0.15 // indirect
    github.com/rivo/uniseg v0.2.0 // indirect
    github.com/savsgio/dictpool v0.0.0-20221023140959-7bf2e61cea94 // indirect
    github.com/savsgio/gotils v0.0.0-20230208104028-c358bd845dee // indirect
    github.com/tinylib/msgp v1.1.8 // indirect
    github.com/valyala/bytebufferpool v1.0.0 // indirect
    github.com/valyala/fasthttp v1.50.0 // indirect
    github.com/valyala/tcplisten v1.0.0 // indirect
    golang.org/x/sync v0.1.0 // indirect
    golang.org/x/sys v0.15.0 // indirect
    golang.org/x/text v0.14.0 // indirect
)
EOF
    
    echo -e "${GREEN}✅ Backend go.mod created${NC}"
}

# Create Makefile for easy management
create_makefile() {
    echo -e "${BLUE}Creating Makefile...${NC}"
    
    cat > Makefile << 'EOF'
.PHONY: help up down restart logs clean build dev prod backup

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

up: ## Start all services
	docker-compose up -d
	@echo "✅ Secure Notes is running!"
	@echo "📝 Frontend: http://localhost:3000"
	@echo "🔌 Backend API: http://localhost:8080"
	@echo "📊 View logs: make logs"

down: ## Stop all services
	docker-compose down

restart: ## Restart all services
	docker-compose restart

logs: ## View logs
	docker-compose logs -f

clean: ## Clean up everything (including volumes)
	docker-compose down -v
	rm -rf postgres_data redis_data

build: ## Rebuild all containers
	docker-compose build --no-cache

dev: ## Start in development mode
	docker-compose up

prod: ## Start in production mode
	docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d

backup: ## Backup database
	docker-compose exec postgres pg_dump -U postgres notes > backup_$(shell date +%Y%m%d_%H%M%S).sql
	@echo "✅ Database backed up"

restore: ## Restore database from backup
	@read -p "Enter backup file name: " file; \
	docker-compose exec -T postgres psql -U postgres notes < $$file

status: ## Check service status
	@docker-compose ps
	@echo ""
	@echo "Health checks:"
	@docker-compose exec backend wget --spider --quiet http://localhost:8080/api/v1/health && echo "✅ Backend: Healthy" || echo "❌ Backend: Unhealthy"
	@docker-compose exec postgres pg_isready -U postgres > /dev/null && echo "✅ PostgreSQL: Ready" || echo "❌ PostgreSQL: Not ready"
	@docker-compose exec redis redis-cli ping > /dev/null && echo "✅ Redis: Ready" || echo "❌ Redis: Not ready"

init: ## Initialize the project
	@./setup-docker.sh
EOF
    
    echo -e "${GREEN}✅ Makefile created${NC}"
}

# Create docker-compose.prod.yml for production overrides
create_production_compose() {
    echo -e "${BLUE}Creating production docker-compose...${NC}"
    
    cat > docker-compose.prod.yml << 'EOF'
# docker-compose.prod.yml - Production overrides
version: '3.8'

services:
  backend:
    restart: always
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
    deploy:
      resources:
        limits:
          cpus: '1.0'
          memory: 512M
        reservations:
          cpus: '0.25'
          memory: 256M

  frontend:
    restart: always
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: 256M
        reservations:
          cpus: '0.1'
          memory: 128M

  postgres:
    restart: always
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 1G
        reservations:
          cpus: '0.5'
          memory: 512M

  redis:
    restart: always
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: 256M
        reservations:
          cpus: '0.1'
          memory: 128M
EOF
    
    echo -e "${GREEN}✅ Production docker-compose created${NC}"
}

# Main setup function
main() {
    echo ""
    echo -e "${BLUE}🚀 Starting Secure Notes Docker Setup${NC}"
    echo "======================================="
    echo ""
    
    create_project_structure
    generate_env_file
    create_backend_dockerfile
    create_frontend_dockerfile
    create_nginx_config
    create_postgres_init
    create_frontend_package
    create_backend_gomod
    create_makefile
    create_production_compose
    
    echo ""
    echo "======================================="
    echo -e "${GREEN}✅ Setup Complete!${NC}"
    echo "======================================="
    echo ""
    echo "Next steps:"
    echo ""
    echo "1. Copy your backend code to: backend/main.go"
    echo "2. Copy your frontend code to: frontend/src/"
    echo ""
    echo "3. Start the application:"
    echo -e "   ${BLUE}make up${NC}"
    echo ""
    echo "Or manually with docker-compose:"
    echo -e "   ${BLUE}docker-compose up -d${NC}"
    echo ""
    echo "Access the application:"
    echo "  📝 Frontend: http://localhost:3000"
    echo "  🔌 Backend API: http://localhost:8080"
    echo ""
    echo "Other useful commands:"
    echo "  make logs    - View logs"
    echo "  make down    - Stop services"
    echo "  make restart - Restart services"
    echo "  make status  - Check health status"
    echo "  make backup  - Backup database"
    echo ""
    echo -e "${YELLOW}⚠️  Security Note:${NC}"
    echo "The .env file contains sensitive secrets."
    echo "Never commit it to version control!"
    echo ""
}

# Run main function
main

# Make the script executable
chmod +x setup-docker.sh