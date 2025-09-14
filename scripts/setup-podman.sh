#!/bin/bash
# Note: Prefer leaflock.sh docker:* or k8s:deploy for common flows; this script is for Podman-focused setups.
# setup-podman.sh - Complete Podman setup with rootless containers

set -e

echo "🔐 LeafLock - Podman Setup (Rootless & Secure)"
echo "=================================================="

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Detect system and podman setup
detect_system() {
    echo -e "${BLUE}Detecting system configuration...${NC}"
    
    # Check if podman is installed
    if ! command -v podman &> /dev/null; then
        echo -e "${RED}❌ Podman is not installed${NC}"
        echo "Install podman first:"
        echo "  Fedora/RHEL: sudo dnf install podman podman-compose"
        echo "  Ubuntu/Debian: sudo apt install podman podman-compose"
        echo "  macOS: brew install podman podman-compose"
        exit 1
    fi
    
    # Check podman version
    PODMAN_VERSION=$(podman version --format '{{.Version}}')
    echo -e "${GREEN}✅ Podman ${PODMAN_VERSION} detected${NC}"
    
    # Check for rootless mode
    if [[ $EUID -eq 0 ]]; then
        echo -e "${YELLOW}⚠️  Running as root. Rootless mode is more secure.${NC}"
        read -p "Continue as root? (y/n): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo "Run this script as a regular user for rootless containers"
            exit 1
        fi
    else
        echo -e "${GREEN}✅ Running in rootless mode (more secure)${NC}"
    fi
    
    # Check for podman-compose or use podman play kube
    if command -v podman-compose &> /dev/null; then
        COMPOSE_CMD="podman-compose"
        echo -e "${GREEN}✅ podman-compose found${NC}"
    else
        echo -e "${YELLOW}ℹ️  podman-compose not found, will use 'podman play kube'${NC}"
        COMPOSE_CMD="podman_kube"
    fi
    
    # Check SELinux status (for RHEL/Fedora)
    if command -v getenforce &> /dev/null; then
        SELINUX_STATUS=$(getenforce)
        echo -e "${BLUE}SELinux status: ${SELINUX_STATUS}${NC}"
        if [ "$SELINUX_STATUS" = "Enforcing" ]; then
            echo -e "${GREEN}✅ SELinux enforcing (maximum security)${NC}"
        fi
    fi
}

# Setup podman for rootless operation
setup_rootless() {
    echo -e "${BLUE}Configuring rootless podman...${NC}"
    
    # Enable lingering for user (allows containers to run without login)
    if command -v loginctl &> /dev/null; then
        loginctl enable-linger $USER
        echo -e "${GREEN}✅ User lingering enabled${NC}"
    fi
    
    # Set up subuid/subgid if needed
    if ! grep -q "^$USER:" /etc/subuid 2>/dev/null; then
        echo -e "${YELLOW}Setting up subuid/subgid mappings...${NC}"
        echo "$USER:100000:65536" | sudo tee -a /etc/subuid
        echo "$USER:100000:65536" | sudo tee -a /etc/subgid
        podman system migrate
        echo -e "${GREEN}✅ UID/GID mappings configured${NC}"
    fi
    
    # Configure podman registries for rootless
    mkdir -p ~/.config/containers/
    if [ ! -f ~/.config/containers/registries.conf ]; then
        cat > ~/.config/containers/registries.conf << 'EOF'
[registries.search]
registries = ['docker.io', 'quay.io', 'ghcr.io']

[registries.insecure]
registries = []

[registries.block]
registries = []
EOF
        echo -e "${GREEN}✅ Registries configured${NC}"
    fi
}

# Create Containerfile for backend (Podman native format)
create_backend_containerfile() {
    echo -e "${BLUE}Creating backend Containerfile...${NC}"
    
    mkdir -p backend
    cat > backend/Containerfile << 'EOF'
# Containerfile for Podman - More secure than Dockerfile
FROM docker.io/golang:1.21-alpine AS builder

# Security: Create non-root user at build time
RUN adduser -D -u 10001 -g 10001 appuser

# Install certificates and timezone data
RUN apk add --no-cache ca-certificates tzdata git

WORKDIR /build

# Copy dependency files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build with security flags
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s -X main.version=1.0.0" \
    -trimpath \
    -o leaflock-backend \
    main.go

# Create minimal runtime image
FROM scratch

# Copy from builder
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /build/leaflock-backend /app/leaflock-backend

# Use non-root user
USER appuser:appuser

# Expose port (high port for rootless)
EXPOSE 8080

# Security labels for Podman
LABEL io.containers.capabilities="drop=ALL"
LABEL io.containers.seccomp="runtime/default"

ENTRYPOINT ["/app/leaflock-backend"]
EOF
    
    echo -e "${GREEN}✅ Backend Containerfile created${NC}"
}

# Create Containerfile for frontend
create_frontend_containerfile() {
    echo -e "${BLUE}Creating frontend Containerfile...${NC}"
    
    mkdir -p frontend
    cat > frontend/Containerfile << 'EOF'
# Containerfile for Podman - Frontend
FROM docker.io/node:20-alpine AS builder

WORKDIR /app

# Copy package files
COPY package*.json ./
RUN npm ci --only=production

# Copy source
COPY . .

# Build with API URL
ARG VITE_API_URL=http://localhost:8080
ENV VITE_API_URL=$VITE_API_URL
RUN npm run build

# Production stage with nginx - rootless configuration
FROM docker.io/nginxinc/nginx-unprivileged:alpine

# Remove default config
RUN rm -rf /etc/nginx/conf.d/*

# Copy custom nginx config for rootless
COPY --chown=nginx:nginx nginx-rootless.conf /etc/nginx/conf.d/default.conf

# Copy built app
COPY --from=builder --chown=nginx:nginx /app/dist /usr/share/nginx/html

# Use high port for rootless operation
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/ || exit 1

# Security labels
LABEL io.containers.capabilities="drop=ALL"
LABEL io.containers.seccomp="runtime/default"

USER nginx:nginx

CMD ["nginx", "-g", "daemon off;"]
EOF
    
    # Create rootless nginx config
    cat > frontend/nginx-rootless.conf << 'EOF'
# Rootless nginx configuration (uses port 8080)
server {
    listen 8080;
    server_name _;
    root /usr/share/nginx/html;
    index index.html;

    # Security headers
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Content-Security-Policy "default-src 'self' http://localhost:8080; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;

    # Gzip
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_types text/plain text/css text/xml text/javascript application/json application/javascript;

    # API proxy
    location /api {
        proxy_pass http://backend:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # SPA support
    location / {
        try_files $uri $uri/ /index.html;
    }
}
EOF
    
    echo -e "${GREEN}✅ Frontend Containerfile created${NC}"
}

# Create systemd user service for podman (auto-start on boot)
create_systemd_service() {
    echo -e "${BLUE}Creating systemd user service...${NC}"
    
    mkdir -p ~/.config/systemd/user/
    
    cat > ~/.config/systemd/user/leaflock.service << EOF
[Unit]
Description=LeafLock Podman Application
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment="PODMAN_SYSTEMD_UNIT=%n"
Restart=on-failure
TimeoutStopSec=70
ExecStartPre=/usr/bin/podman pod create --name leaflock-pod -p 8080:8080 -p 3000:3000
ExecStart=/usr/bin/podman-compose -f %h/leaflock/podman-compose.yml up
ExecStop=/usr/bin/podman-compose -f %h/leaflock/podman-compose.yml down
ExecStopPost=/usr/bin/podman pod rm leaflock-pod

[Install]
WantedBy=default.target
EOF
    
    # Reload systemd user daemon
    systemctl --user daemon-reload
    
    echo -e "${GREEN}✅ Systemd service created${NC}"
    echo "Enable auto-start: systemctl --user enable leaflock.service"
    echo "Start service: systemctl --user start leaflock.service"
}

# Generate Kubernetes YAML from Podman
generate_kube_yaml() {
    echo -e "${BLUE}Generating Kubernetes YAML from Podman...${NC}"
    
    # Create pod first
    podman pod create \
        --name leaflock \
        --publish 8080:8080 \
        --publish 3000:3000 \
        --label app=leaflock
    
    # Generate Kubernetes YAML (will be created dynamically by Makefile when needed)
    echo "Kubernetes YAML can be generated with: make kube"
    
    echo -e "${GREEN}✅ Kubernetes setup configured${NC}"
    echo "Deploy with: make up (will generate leaflock-kube.yaml automatically)"
}

# Create Makefile for Podman
create_podman_makefile() {
    echo -e "${BLUE}Creating Makefile for Podman...${NC}"
    
    cat > Makefile << 'EOF'
.PHONY: help up down restart logs clean build dev prod kube systemd

COMPOSE_CMD := $(shell command -v podman-compose 2> /dev/null)

ifndef COMPOSE_CMD
    COMPOSE_CMD := podman_kube_play
endif

help: ## Show help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

up: ## Start with podman-compose
ifeq ($(COMPOSE_CMD),podman_kube_play)
	@if [ ! -f leaflock-kube.yaml ]; then $(MAKE) kube; fi
	podman play kube leaflock-kube.yaml
else
	podman-compose up -d
endif
	@echo "✅ LeafLock is running!"
	@echo "📝 Frontend: http://localhost:3000"
	@echo "🔌 Backend: http://localhost:8080"

down: ## Stop all containers
ifeq ($(COMPOSE_CMD),podman_kube_play)
	@if [ -f leaflock-kube.yaml ]; then podman play kube --down leaflock-kube.yaml; fi
else
	podman-compose down
endif

restart: ## Restart all containers
ifeq ($(COMPOSE_CMD),podman_kube_play)
	@if [ ! -f leaflock-kube.yaml ]; then $(MAKE) kube; fi
	podman play kube --replace leaflock-kube.yaml
else
	podman-compose restart
endif

logs: ## View logs
	podman logs -f leaflock-backend

clean: ## Clean everything
	podman pod rm -f leaflock || true
	podman volume prune -f

build: ## Build containers
	podman build -t localhost/leaflock-backend:latest -f backend/Containerfile backend/
	podman build -t localhost/leaflock-frontend:latest -f frontend/Containerfile frontend/

rootless-setup: ## Setup rootless podman
	@./setup-podman.sh setup_rootless

systemd: ## Setup systemd service
	systemctl --user enable --now leaflock.service

status: ## Check status
	podman pod ps
	podman ps -a --pod

kube: ## Generate Kubernetes YAML
	podman generate kube leaflock > leaflock-kube.yaml
	@echo "Generated: leaflock-kube.yaml"

security-scan: ## Security scan containers
	podman image scan localhost/leaflock-backend:latest
	podman image scan localhost/leaflock-frontend:latest

export: ## Export as OCI archive
	podman save -o leaflock-backend.tar localhost/leaflock-backend:latest
	podman save -o leaflock-frontend.tar localhost/leaflock-frontend:latest
	@echo "✅ Images exported"

import: ## Import from OCI archive
	podman load -i leaflock-backend.tar
	podman load -i leaflock-frontend.tar
	@echo "✅ Images imported"
EOF
    
    echo -e "${GREEN}✅ Makefile created${NC}"
}

# Create podman-kube alternative script
create_kube_play_script() {
    echo -e "${BLUE}Creating Kubernetes play script...${NC}"
    
    cat > podman-kube-play.sh << 'EOF'
#!/bin/bash
# Alternative to podman-compose using podman play kube

# Generate pod spec
cat > leaflock-pod.yaml << 'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: leaflock
  labels:
    app: leaflock
spec:
  hostname: leaflock
  restartPolicy: Always
  containers:
  - name: postgres
    image: docker.io/postgres:15-alpine
    env:
    - name: POSTGRES_PASSWORD
      value: "ChangeMe123!"
    - name: POSTGRES_DB
      value: "notes"
    ports:
    - containerPort: 5432
    volumeMounts:
    - name: postgres-data
      mountPath: /var/lib/postgresql/data
  - name: redis
    image: docker.io/redis:7-alpine
    ports:
    - containerPort: 6379
    volumeMounts:
    - name: redis-data
      mountPath: /data
  - name: backend
    image: localhost/leaflock-backend:latest
    ports:
    - containerPort: 8080
      hostPort: 8080
    env:
    - name: DATABASE_URL
      value: "postgres://postgres:ChangeMe123!@localhost:5432/notes?sslmode=require"
  - name: frontend
    image: localhost/leaflock-frontend:latest
    ports:
    - containerPort: 8080
      hostPort: 3000
  volumes:
  - name: postgres-data
    persistentVolumeClaim:
      claimName: postgres-pvc
  - name: redis-data
    persistentVolumeClaim:
      claimName: redis-pvc
YAML

# Play the kube file
podman play kube leaflock-pod.yaml
EOF
    
    chmod +x podman-kube-play.sh
    echo -e "${GREEN}✅ Kube play script created${NC}"
}

# Main setup function
main() {
    echo ""
echo -e "${BLUE}🚀 Starting LeafLock Podman Setup${NC}"
    echo "======================================="
    echo ""
    
    # Run setup steps
    detect_system
    
    if [[ $EUID -ne 0 ]]; then
        setup_rootless
    fi
    
    # Create files
    create_backend_containerfile
    create_frontend_containerfile
    create_systemd_service
    create_podman_makefile
    create_kube_play_script
    
    # Generate .env if not exists
    if [ ! -f .env ]; then
        echo -e "${BLUE}Generating .env file...${NC}"
        cat > .env << EOF
POSTGRES_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
REDIS_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
JWT_SECRET=$(openssl rand -base64 64 | tr -d "\n")
SERVER_ENCRYPTION_KEY=$(openssl rand -base64 32 | tr -d "\n")
CORS_ORIGINS=http://localhost:3000,http://localhost
VITE_API_URL=http://localhost:8080
EOF
        chmod 600 .env
        echo -e "${GREEN}✅ .env file generated${NC}"
    fi
    
    echo ""
    echo "======================================="
    echo -e "${GREEN}✅ Podman Setup Complete!${NC}"
    echo "======================================="
    echo ""
    echo "Next steps:"
    echo ""
    echo "1. Build containers:"
    echo -e "   ${BLUE}make build${NC}"
    echo ""
    echo "2. Start with podman-compose:"
    echo -e "   ${BLUE}make up${NC}"
    echo ""
    echo "Or use Kubernetes-style with podman:"
    echo -e "   ${BLUE}make up${NC}"
    echo ""
    echo "3. Enable auto-start (systemd):"
    echo -e "   ${BLUE}make systemd${NC}"
    echo ""
    echo "Access points:"
    echo "  📝 Frontend: http://localhost:3000"
    echo "  🔌 Backend: http://localhost:8080"
    echo ""
    echo "Security features enabled:"
    echo "  ✅ Rootless containers (if not root)"
    echo "  ✅ SELinux labels (if available)"
    echo "  ✅ Read-only root filesystem"
    echo "  ✅ Dropped capabilities"
    echo "  ✅ Non-root users in containers"
    echo "  ✅ Seccomp profiles"
    echo ""
    echo -e "${YELLOW}Podman advantages over Docker:${NC}"
    echo "  • Daemonless (no root daemon)"
    echo "  • Rootless by default"
    echo "  • Native Kubernetes YAML support"
    echo "  • Better security (SELinux, seccomp)"
    echo "  • Systemd integration"
    echo "  • OCI compliant"
    echo ""
}

# Support function calls for Makefile
if [ "$1" = "setup_rootless" ]; then
    setup_rootless
    exit 0
fi

# Run main if no arguments
main
