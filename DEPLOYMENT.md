# Secure Notes - Deployment Guide

## Table of Contents

1. [Deployment Overview](#deployment-overview)
2. [Docker Compose Deployment](#docker-compose-deployment)
3. [Kubernetes Deployment](#kubernetes-deployment)
4. [Production Considerations](#production-considerations)
5. [SSL/TLS Configuration](#ssltls-configuration)
6. [Monitoring & Logging](#monitoring--logging)
7. [Backup & Recovery](#backup--recovery)
8. [Scaling Guidelines](#scaling-guidelines)

## Deployment Overview

Secure Notes supports multiple deployment strategies to accommodate different environments and requirements:

**Deployment Options:**
- **Docker Compose**: Simple single-host deployment (recommended for small deployments)
- **Kubernetes**: Scalable container orchestration (recommended for production)
- **Helm Charts**: Kubernetes deployment with package management
- **Binary Deployment**: Direct binary execution on servers

**Architecture Components:**
- **Frontend**: React SPA served by Nginx
- **Backend**: Go API server with Fiber framework
- **Database**: PostgreSQL with encrypted storage
- **Cache**: Redis for session management
- **Reverse Proxy**: Nginx for SSL termination and load balancing

## Docker Compose Deployment

### Quick Deployment

**Prerequisites:**
- Docker 20.10+ or Podman 3.4+
- Docker Compose v2.0+ or podman-compose
- 4GB RAM, 2GB disk space

**Basic Setup:**
```bash
# Clone repository
git clone <repository-url>
cd secure-notes

# Copy and configure environment
cp .env.example .env
# Edit .env with secure passwords and keys

# Start all services
make up
# Or: docker compose up -d

# Verify deployment
curl http://localhost:8080/api/v1/health
curl http://localhost:3000
```

### Production Docker Compose

**Production Configuration:**
```yaml
# docker-compose.prod.yml
version: '3.8'

services:
  # Use production-optimized images
  backend:
    image: secure-notes/backend:1.0.0
    environment:
      - NODE_ENV=production
      - DATABASE_URL=postgres://postgres:${POSTGRES_PASSWORD}@postgres:5432/notes?sslmode=require
    deploy:
      replicas: 2
      resources:
        limits:
          memory: 512M
          cpus: '0.5'
    healthcheck:
      test: ["CMD", "wget", "--no-verbose", "--tries=1", "--spider", "http://localhost:8080/api/v1/ready"]
      interval: 30s
      timeout: 10s
      retries: 3

  frontend:
    image: secure-notes/frontend:1.0.0
    deploy:
      replicas: 2
      resources:
        limits:
          memory: 256M
          cpus: '0.25'

  # Production database with SSL
  postgres:
    image: postgres:15-alpine
    environment:
      - POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
      - POSTGRES_DB=notes
    command:
      - postgres
      - -c
      - ssl=on
      - -c
      - max_connections=200
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./ssl/server.crt:/var/lib/postgresql/server.crt:ro
      - ./ssl/server.key:/var/lib/postgresql/server.key:ro
    deploy:
      resources:
        limits:
          memory: 1G
          cpus: '1.0'

  # Production Redis with persistence
  redis:
    image: redis:7-alpine
    command: >
      redis-server 
      --appendonly yes 
      --requirepass ${REDIS_PASSWORD}
      --maxmemory 256mb
      --maxmemory-policy allkeys-lru
    volumes:
      - redis_data:/data
    deploy:
      resources:
        limits:
          memory: 512M
          cpus: '0.25'

  # Nginx reverse proxy with SSL
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./ssl:/etc/nginx/ssl:ro
    depends_on:
      - backend
      - frontend

volumes:
  postgres_data:
    driver: local
  redis_data:
    driver: local

networks:
  default:
    driver: bridge
```

**Production Deployment:**
```bash
# Generate SSL certificates
./init-ssl-prod.sh

# Deploy with production config
docker compose -f docker-compose.prod.yml up -d

# Scale services
docker compose -f docker-compose.prod.yml up -d --scale backend=3 --scale frontend=2
```

### Environment Configuration

**Production .env:**
```bash
# Database (use strong passwords)
POSTGRES_PASSWORD=<64-character-random-password>
POSTGRES_DB=notes

# Redis 
REDIS_PASSWORD=<64-character-random-password>

# JWT Secret (64+ characters)
JWT_SECRET=<secure-random-jwt-secret-64-chars>

# Server Encryption Key (32 characters)
SERVER_ENCRYPTION_KEY=<secure-32-char-encryption-key>

# CORS Origins (production domains)
CORS_ORIGINS=https://notes.yourdomain.com,https://app.yourdomain.com

# API Configuration
VITE_API_URL=https://api.yourdomain.com

# SSL Configuration
SSL_CERT_PATH=/etc/nginx/ssl/cert.pem
SSL_KEY_PATH=/etc/nginx/ssl/key.pem

# Monitoring
LOG_LEVEL=info
METRICS_ENABLED=true
```

**Secure Key Generation:**
```bash
#!/bin/bash
# generate-keys.sh

echo "Generating secure keys for production deployment..."

# Generate PostgreSQL password
POSTGRES_PASSWORD=$(openssl rand -base64 48 | tr -d '\n')

# Generate Redis password  
REDIS_PASSWORD=$(openssl rand -base64 48 | tr -d '\n')

# Generate JWT secret (64 bytes)
JWT_SECRET=$(openssl rand -base64 64 | tr -d '\n')

# Generate server encryption key (32 bytes)
SERVER_ENCRYPTION_KEY=$(openssl rand -base64 32 | tr -d '\n')

# Write to .env file
cat > .env << EOF
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
REDIS_PASSWORD=${REDIS_PASSWORD}
JWT_SECRET=${JWT_SECRET}
SERVER_ENCRYPTION_KEY=${SERVER_ENCRYPTION_KEY}
CORS_ORIGINS=https://notes.yourdomain.com
VITE_API_URL=https://api.yourdomain.com
EOF

echo "Secure .env file generated successfully"
echo "Please review and customize CORS_ORIGINS and VITE_API_URL"
```

## Kubernetes Deployment

### Prerequisites

**Kubernetes Requirements:**
- Kubernetes 1.25+
- kubectl configured for cluster access
- Helm 3.10+
- Ingress controller (nginx-ingress recommended)
- cert-manager for SSL certificates
- Persistent volume provisioner

**Install Prerequisites:**
```bash
# Install nginx-ingress
helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx
helm install ingress-nginx ingress-nginx/ingress-nginx

# Install cert-manager
helm repo add jetstack https://charts.jetstack.io
helm install cert-manager jetstack/cert-manager \
  --namespace cert-manager \
  --create-namespace \
  --set installCRDs=true
```

### Helm Deployment

**Quick Deployment:**
```bash
# Add Helm repositories
helm repo add bitnami https://charts.bitnami.com/bitnami
helm repo update

# Create namespace
kubectl create namespace secure-notes

# Install with default values
helm install secure-notes ./helm/secure-notes \
  --namespace secure-notes \
  --set ingress.hosts[0].host=secure-notes.yourdomain.com

# Check deployment status
kubectl get pods -n secure-notes
kubectl get services -n secure-notes
```

**Production Deployment:**
```bash
# Create production values file
cat > values-production.yaml << EOF
# Production configuration
global:
  storageClass: "fast-ssd"

backend:
  replicaCount: 3
  resources:
    requests:
      memory: "256Mi"
      cpu: "200m"
    limits:
      memory: "512Mi"
      cpu: "500m"
  
  autoscaling:
    enabled: true
    minReplicas: 2
    maxReplicas: 10
    targetCPUUtilizationPercentage: 70

frontend:
  replicaCount: 2
  resources:
    requests:
      memory: "128Mi"
      cpu: "100m"
    limits:
      memory: "256Mi"
      cpu: "200m"

# PostgreSQL configuration
postgresql:
  auth:
    postgresPassword: "$(kubectl get secret -n secure-notes postgresql-secret -o jsonpath='{.data.postgres-password}' | base64 -d)"
    password: "$(kubectl get secret -n secure-notes postgresql-secret -o jsonpath='{.data.password}' | base64 -d)"
  primary:
    persistence:
      size: 100Gi
      storageClass: "fast-ssd"
    resources:
      requests:
        memory: "512Mi"
        cpu: "500m"
      limits:
        memory: "2Gi"
        cpu: "2000m"

# Redis configuration  
redis:
  auth:
    password: "$(kubectl get secret -n secure-notes redis-secret -o jsonpath='{.data.redis-password}' | base64 -d)"
  master:
    persistence:
      size: 20Gi
      storageClass: "fast-ssd"
    resources:
      requests:
        memory: "256Mi"
        cpu: "250m"
      limits:
        memory: "512Mi"
        cpu: "500m"

# Ingress configuration
ingress:
  enabled: true
  className: "nginx"
  annotations:
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
  hosts:
    - host: secure-notes.yourdomain.com
      paths:
        - path: /
          pathType: Prefix
          service:
            name: frontend
            port: 80
        - path: /api
          pathType: Prefix
          service:
            name: backend
            port: 8080
  tls:
    - secretName: secure-notes-tls
      hosts:
        - secure-notes.yourdomain.com

# Security settings
podSecurityStandards:
  enforced: true
  profile: restricted

networkPolicy:
  enabled: true

# Monitoring
monitoring:
  enabled: true
  serviceMonitor:
    enabled: true
EOF

# Deploy with production values
helm install secure-notes ./helm/secure-notes \
  --namespace secure-notes \
  --values values-production.yaml
```

### Manual Kubernetes Manifests

**Namespace and Secrets:**
```yaml
# namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: secure-notes
  labels:
    name: secure-notes
---
# Create secrets first
apiVersion: v1
kind: Secret
metadata:
  name: secure-notes-secrets
  namespace: secure-notes
type: Opaque
data:
  jwt-secret: <base64-encoded-jwt-secret>
  server-encryption-key: <base64-encoded-encryption-key>
---
apiVersion: v1
kind: Secret
metadata:
  name: postgresql-secret
  namespace: secure-notes
type: Opaque
data:
  postgres-password: <base64-encoded-password>
  password: <base64-encoded-password>
---
apiVersion: v1
kind: Secret
metadata:
  name: redis-secret
  namespace: secure-notes
type: Opaque
data:
  redis-password: <base64-encoded-password>
```

**Backend Deployment:**
```yaml
# backend-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: backend
  namespace: secure-notes
  labels:
    app: secure-notes-backend
spec:
  replicas: 3
  selector:
    matchLabels:
      app: secure-notes-backend
  template:
    metadata:
      labels:
        app: secure-notes-backend
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
      containers:
      - name: backend
        image: secure-notes/backend:1.0.0
        ports:
        - containerPort: 8080
          name: http
        env:
        - name: DATABASE_URL
          value: "postgres://postgres:$(POSTGRES_PASSWORD)@postgresql:5432/notes?sslmode=require"
        - name: POSTGRES_PASSWORD
          valueFrom:
            secretKeyRef:
              name: postgresql-secret
              key: postgres-password
        - name: REDIS_URL
          value: "redis:6379"
        - name: REDIS_PASSWORD
          valueFrom:
            secretKeyRef:
              name: redis-secret
              key: redis-password
        - name: JWT_SECRET
          valueFrom:
            secretKeyRef:
              name: secure-notes-secrets
              key: jwt-secret
        - name: SERVER_ENCRYPTION_KEY
          valueFrom:
            secretKeyRef:
              name: secure-notes-secrets
              key: server-encryption-key
        - name: CORS_ORIGINS
          value: "https://secure-notes.yourdomain.com"
        resources:
          requests:
            memory: "256Mi"
            cpu: "200m"
          limits:
            memory: "512Mi" 
            cpu: "500m"
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          runAsNonRoot: true
          capabilities:
            drop:
            - ALL
        livenessProbe:
          httpGet:
            path: /api/v1/health
            port: http
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /api/v1/ready
            port: http
          initialDelaySeconds: 5
          periodSeconds: 5
        volumeMounts:
        - name: tmp
          mountPath: /tmp
      volumes:
      - name: tmp
        emptyDir: {}
---
apiVersion: v1
kind: Service
metadata:
  name: backend
  namespace: secure-notes
spec:
  selector:
    app: secure-notes-backend
  ports:
  - port: 8080
    targetPort: http
    name: http
```

**Deploy to Kubernetes:**
```bash
# Apply all manifests
kubectl apply -f k8s/

# Check deployment
kubectl get all -n secure-notes

# Check logs
kubectl logs -f deployment/backend -n secure-notes
kubectl logs -f deployment/frontend -n secure-notes

# Port forward for testing
kubectl port-forward svc/frontend 3000:80 -n secure-notes
kubectl port-forward svc/backend 8080:8080 -n secure-notes
```

## Production Considerations

### High Availability Setup

**Multi-Zone Deployment:**
```yaml
# Anti-affinity for pods
affinity:
  podAntiAffinity:
    preferredDuringSchedulingIgnoredDuringExecution:
    - weight: 100
      podAffinityTerm:
        labelSelector:
          matchExpressions:
          - key: app
            operator: In
            values:
            - secure-notes-backend
        topologyKey: kubernetes.io/hostname
```

**Database High Availability:**
```yaml
# PostgreSQL with read replicas
postgresql:
  architecture: replication
  auth:
    replicationPassword: "secure-replication-password"
  primary:
    persistence:
      size: 100Gi
  readReplicas:
    replicaCount: 2
    persistence:
      size: 100Gi
```

**Redis High Availability:**
```yaml
# Redis Sentinel configuration
redis:
  architecture: replication
  sentinel:
    enabled: true
  master:
    persistence:
      size: 20Gi
  replica:
    replicaCount: 2
    persistence:
      size: 20Gi
```

### Resource Planning

**Minimum Production Resources:**
```yaml
resources:
  backend:
    instances: 2
    cpu: "500m"
    memory: "512Mi"
    storage: "1Gi" # temporary files
  
  frontend:
    instances: 2
    cpu: "200m" 
    memory: "256Mi"
    
  postgresql:
    instances: 1 + 2 replicas
    cpu: "1000m"
    memory: "2Gi"
    storage: "100Gi"
    
  redis:
    instances: 1 + 2 replicas  
    cpu: "250m"
    memory: "512Mi"
    storage: "20Gi"
```

**Scaling Recommendations:**
```yaml
# Horizontal Pod Autoscaler
autoscaling:
  backend:
    minReplicas: 2
    maxReplicas: 20
    targetCPU: 70%
    targetMemory: 80%
    
  frontend:
    minReplicas: 2
    maxReplicas: 10
    targetCPU: 70%
    targetMemory: 80%
```

### Security Hardening

**Network Policies:**
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: secure-notes-netpol
  namespace: secure-notes
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: secure-notes
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: ingress-nginx
    - podSelector:
        matchLabels:
          app.kubernetes.io/name: secure-notes
    ports:
    - protocol: TCP
      port: 8080
    - protocol: TCP  
      port: 80
  egress:
  - to:
    - podSelector:
        matchLabels:
          app.kubernetes.io/name: postgresql
    ports:
    - protocol: TCP
      port: 5432
  - to:
    - podSelector:
        matchLabels:
          app.kubernetes.io/name: redis
    ports:
    - protocol: TCP
      port: 6379
```

**Pod Security Standards:**
```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: secure-notes
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

## SSL/TLS Configuration

### Let's Encrypt with cert-manager

**ClusterIssuer Configuration:**
```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: admin@yourdomain.com
    privateKeySecretRef:
      name: letsencrypt-prod
    solvers:
    - http01:
        ingress:
          class: nginx
```

**Ingress with SSL:**
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: secure-notes-ingress
  namespace: secure-notes
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
    nginx.ingress.kubernetes.io/hsts: "true"
    nginx.ingress.kubernetes.io/hsts-max-age: "31536000"
spec:
  tls:
  - hosts:
    - secure-notes.yourdomain.com
    secretName: secure-notes-tls
  rules:
  - host: secure-notes.yourdomain.com
    http:
      paths:
      - path: /api
        pathType: Prefix
        backend:
          service:
            name: backend
            port:
              number: 8080
      - path: /
        pathType: Prefix
        backend:
          service:
            name: frontend
            port:
              number: 80
```

### Custom SSL Certificates

**Create SSL Secret:**
```bash
# Generate or obtain SSL certificates
kubectl create secret tls secure-notes-tls \
  --cert=path/to/cert.crt \
  --key=path/to/cert.key \
  --namespace=secure-notes
```

## Monitoring & Logging

### Prometheus Monitoring

**ServiceMonitor Configuration:**
```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: secure-notes
  namespace: secure-notes
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: secure-notes
  endpoints:
  - port: metrics
    path: /metrics
    interval: 30s
```

**Grafana Dashboard:**
```json
{
  "dashboard": {
    "title": "Secure Notes Metrics",
    "panels": [
      {
        "title": "Request Rate",
        "targets": [
          {
            "expr": "rate(http_requests_total[5m])"
          }
        ]
      },
      {
        "title": "Response Time", 
        "targets": [
          {
            "expr": "histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))"
          }
        ]
      },
      {
        "title": "Error Rate",
        "targets": [
          {
            "expr": "rate(http_requests_total{status=~\"5..\"}[5m])"
          }
        ]
      }
    ]
  }
}
```

### Centralized Logging

**Fluentd Configuration:**
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: fluentd-config
  namespace: secure-notes
data:
  fluent.conf: |
    <source>
      @type kubernetes_logs
      path /var/log/containers/secure-notes*.log
      pos_file /var/log/fluentd-secure-notes.log.pos
      tag kubernetes.secure-notes
    </source>
    
    <match kubernetes.secure-notes>
      @type elasticsearch
      host elasticsearch.logging.svc.cluster.local
      port 9200
      index_name secure-notes
    </match>
```

## Backup & Recovery

### Database Backup

**Automated Backup CronJob:**
```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: postgres-backup
  namespace: secure-notes
spec:
  schedule: "0 2 * * *"  # Daily at 2 AM
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: postgres-backup
            image: postgres:15-alpine
            command:
            - /bin/bash
            - -c
            - |
              pg_dump -h postgresql -U postgres -d notes | \
              gzip > /backup/notes-$(date +%Y%m%d_%H%M%S).sql.gz
              
              # Retention: Keep last 30 days
              find /backup -name "notes-*.sql.gz" -mtime +30 -delete
            env:
            - name: PGPASSWORD
              valueFrom:
                secretKeyRef:
                  name: postgresql-secret
                  key: postgres-password
            volumeMounts:
            - name: backup-storage
              mountPath: /backup
          volumes:
          - name: backup-storage
            persistentVolumeClaim:
              claimName: backup-pvc
          restartPolicy: OnFailure
```

**Manual Backup:**
```bash
# Create backup
kubectl exec -n secure-notes deployment/postgresql -- \
  pg_dump -U postgres -d notes | \
  gzip > backup-$(date +%Y%m%d).sql.gz

# Restore from backup
gunzip < backup-20240115.sql.gz | \
kubectl exec -i -n secure-notes deployment/postgresql -- \
  psql -U postgres -d notes
```

### Redis Backup

**Redis Backup Script:**
```bash
#!/bin/bash
# redis-backup.sh

NAMESPACE="secure-notes"
BACKUP_DIR="/backups/redis"

# Create backup directory
mkdir -p $BACKUP_DIR

# Get Redis password
REDIS_PASSWORD=$(kubectl get secret -n $NAMESPACE redis-secret -o jsonpath='{.data.redis-password}' | base64 -d)

# Create Redis dump
kubectl exec -n $NAMESPACE deployment/redis -- \
  redis-cli -a $REDIS_PASSWORD --rdb /tmp/dump.rdb

# Copy dump file
kubectl cp $NAMESPACE/redis-pod:/tmp/dump.rdb $BACKUP_DIR/redis-$(date +%Y%m%d).rdb

# Clean old backups (keep 30 days)
find $BACKUP_DIR -name "redis-*.rdb" -mtime +30 -delete
```

## Scaling Guidelines

### Vertical Scaling

**Resource Adjustment:**
```bash
# Scale up backend resources
kubectl patch deployment backend -n secure-notes -p '
{
  "spec": {
    "template": {
      "spec": {
        "containers": [
          {
            "name": "backend",
            "resources": {
              "requests": {
                "memory": "512Mi",
                "cpu": "500m"
              },
              "limits": {
                "memory": "1Gi",
                "cpu": "1000m"
              }
            }
          }
        ]
      }
    }
  }
}'

# Scale PostgreSQL
helm upgrade secure-notes ./helm/secure-notes \
  --namespace secure-notes \
  --set postgresql.primary.resources.limits.memory=4Gi \
  --set postgresql.primary.resources.limits.cpu=2000m
```

### Horizontal Scaling

**Manual Scaling:**
```bash
# Scale backend pods
kubectl scale deployment backend --replicas=5 -n secure-notes

# Scale frontend pods  
kubectl scale deployment frontend --replicas=3 -n secure-notes

# Scale with Helm
helm upgrade secure-notes ./helm/secure-notes \
  --namespace secure-notes \
  --set backend.replicaCount=5 \
  --set frontend.replicaCount=3
```

**Auto-scaling Setup:**
```bash
# Enable metrics server (if not already installed)
kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml

# Create HPA for backend
kubectl autoscale deployment backend \
  --namespace secure-notes \
  --cpu-percent=70 \
  --min=2 \
  --max=20

# Create HPA for frontend
kubectl autoscale deployment frontend \
  --namespace secure-notes \
  --cpu-percent=70 \
  --min=2 \
  --max=10

# Check HPA status
kubectl get hpa -n secure-notes
```

### Performance Optimization

**Database Optimization:**
```sql
-- PostgreSQL performance tuning
ALTER SYSTEM SET shared_buffers = '256MB';
ALTER SYSTEM SET effective_cache_size = '1GB';
ALTER SYSTEM SET maintenance_work_mem = '64MB';
ALTER SYSTEM SET checkpoint_completion_target = 0.7;
ALTER SYSTEM SET wal_buffers = '16MB';
ALTER SYSTEM SET default_statistics_target = 100;
ALTER SYSTEM SET random_page_cost = 1.1;
ALTER SYSTEM SET effective_io_concurrency = 200;
SELECT pg_reload_conf();
```

**Redis Optimization:**
```bash
# Redis memory optimization
redis-cli CONFIG SET maxmemory-policy allkeys-lru
redis-cli CONFIG SET maxmemory 512mb

# Enable RDB and AOF persistence
redis-cli CONFIG SET save "900 1 300 10 60 10000"
redis-cli CONFIG SET appendonly yes
redis-cli CONFIG SET appendfsync everysec
```

This deployment guide provides comprehensive instructions for deploying Secure Notes in various environments while maintaining security and performance best practices.