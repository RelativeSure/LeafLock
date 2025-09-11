# Deployment Commands

Production deployment workflows and commands for Secure Notes application.

## Quick Deploy Commands

```bash
# Production deployment  
docker compose up -d

# Staging deployment
docker compose up -d

# Build production images
make build
```

## Production Deployment

### SSL Certificate Setup
```bash
# Initialize SSL certificates
./init-ssl.sh

# For production domains
./init-ssl-prod.sh
```

### Production Environment
```bash
# Copy production environment template
cp .env.example .env.prod

# Edit production values
nano .env.prod

# Deploy with production config
docker compose --env-file .env.prod up -d
```

### Health Checks
```bash
# Verify deployment
curl -k https://your-domain.com/api/v1/health

# Check SSL certificate
openssl s_client -connect your-domain.com:443 -servername your-domain.com
```

## Container Registry

### Build and Push Images
```bash
# Build images
make build

# Tag for registry
podman tag localhost/secure-notes-backend:latest your-registry/secure-notes-backend:v1.0.0
podman tag localhost/secure-notes-frontend:latest your-registry/secure-notes-frontend:v1.0.0

# Push to registry
podman push your-registry/secure-notes-backend:v1.0.0
podman push your-registry/secure-notes-frontend:v1.0.0
```

### Pull and Deploy
```bash
# Pull latest images
podman pull your-registry/secure-notes-backend:v1.0.0
podman pull your-registry/secure-notes-frontend:v1.0.0

# Deploy with specific versions
VERSION=v1.0.0 docker compose up -d
```

## Kubernetes Deployment

### Generate Kubernetes YAML
```bash
# Generate from Pod and apply to cluster
make kube && kubectl apply -f secure-notes-kube.yaml
```

### Helm Deployment
```bash
# Install with Helm
cd helm
helm install secure-notes ./secure-notes/

# Upgrade deployment
helm upgrade secure-notes ./secure-notes/

# View status
helm status secure-notes
```

### Kubernetes Management
```bash
# Check pod status
kubectl get pods -l app=secure-notes

# View logs
kubectl logs -f deployment/secure-notes-backend

# Scale deployment
kubectl scale deployment/secure-notes-backend --replicas=3

# Rolling update
kubectl set image deployment/secure-notes-backend backend=your-registry/secure-notes-backend:v1.1.0
```

## Database Migration

### Production Database Setup
```bash
# Create backup before migration
pg_dump -h localhost -U postgres notes > backup-$(date +%Y%m%d).sql

# Run migrations (if applicable)
cd backend
go run main.go --migrate

# Verify database schema
psql -h localhost -U postgres -d notes -c "\dt"
```

### Database Backup and Restore
```bash
# Backup production database
docker exec secure-notes-postgres pg_dump -U postgres notes > notes-backup.sql

# Restore from backup
docker exec -i secure-notes-postgres psql -U postgres notes < notes-backup.sql

# Automated backups
echo "0 2 * * * docker exec secure-notes-postgres pg_dump -U postgres notes > /backups/notes-$(date +\%Y\%m\%d).sql" | crontab -
```

## Monitoring and Logging

### Production Logging
```bash
# Configure log rotation
sudo tee /etc/logrotate.d/secure-notes << EOF
/var/log/secure-notes/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    create 0644 secure-notes secure-notes
    postrotate
        docker restart secure-notes-backend || true
    endscript
}
EOF
```

### Health Monitoring
```bash
# Setup health check script
cat > /usr/local/bin/secure-notes-health << 'EOF'
#!/bin/bash
if ! curl -sf http://localhost:8080/api/v1/health; then
    echo "Health check failed at $(date)" | mail -s "Secure Notes Down" admin@yourcompany.com
    systemctl restart secure-notes
fi
EOF

chmod +x /usr/local/bin/secure-notes-health

# Add to cron
echo "*/5 * * * * /usr/local/bin/secure-notes-health" | crontab -
```

### Metrics Collection
```bash
# Enable metrics endpoint (if implemented)
curl http://localhost:8080/metrics

# Prometheus configuration (if using)
# Add to prometheus.yml:
# - job_name: 'secure-notes'
#   static_configs:
#     - targets: ['localhost:8080']
```

## Performance Optimization

### Production Optimization
```bash
# Optimize Go binary
cd backend
CGO_ENABLED=0 GOOS=linux go build -a -ldflags '-extldflags "-static"' -o app main.go

# Optimize frontend bundle
cd frontend
npm run build -- --minify

# Optimize container images
podman build --squash -t secure-notes-backend-prod .
```

### Resource Limits
```yaml
# In docker-compose.yml
services:
  backend:
    deploy:
      resources:
        limits:
          cpus: '1.0'
          memory: 512M
        reservations:
          cpus: '0.5'
          memory: 256M
```

## Security Hardening

### Production Security
```bash
# Scan for vulnerabilities
make security-scan

# Update dependencies
cd backend && go get -u ./...
cd frontend && npm audit fix

# Harden container
# Use distroless or scratch base images
# Run as non-root user
# Remove debug tools from production images
```

### Secrets Management
```bash
# Use Docker secrets (Swarm mode)
echo "secret_value" | docker secret create jwt_secret -

# Or use external secret management
# - HashiCorp Vault
# - AWS Secrets Manager  
# - Azure Key Vault
# - Google Secret Manager
```

## Rollback Procedures

### Quick Rollback
```bash
# Stop current deployment
docker compose down

# Deploy previous version
VERSION=v0.9.0 docker compose up -d

# Verify rollback
curl -k https://your-domain.com/api/v1/health
```

### Database Rollback
```bash
# Restore from backup
docker exec -i secure-notes-postgres psql -U postgres notes < notes-backup-previous.sql

# Restart services
docker compose restart
```

## Blue-Green Deployment

### Blue-Green Setup
```bash
# Deploy to green environment
COMPOSE_PROJECT_NAME=secure-notes-green docker compose up -d

# Test green environment
curl -H "Host: your-domain.com" http://green-server:8080/api/v1/health

# Switch traffic (update load balancer)
# Then stop blue environment
COMPOSE_PROJECT_NAME=secure-notes-blue docker compose down
```

## Maintenance Mode

### Enable Maintenance Mode
```bash
# Create maintenance page
echo "<h1>Under Maintenance</h1><p>We'll be back shortly!</p>" > /var/www/html/maintenance.html

# Update nginx config to serve maintenance page
# nginx -s reload

# Or use environment variable
MAINTENANCE_MODE=true docker compose up -d
```

### Disable Maintenance Mode
```bash
MAINTENANCE_MODE=false docker compose up -d
```

## CI/CD Integration

### GitHub Actions Deployment
```yaml
# .github/workflows/deploy.yml
name: Deploy to Production
on:
  push:
    branches: [main]
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Deploy
        run: |
          # Add deployment commands
          ssh user@server 'cd /app && git pull && make build && docker compose up -d'
```

### Automated Testing in Production
```bash
# Post-deployment tests
./test-production-health.sh

# Smoke tests
curl -f https://your-domain.com/api/v1/health
curl -f https://your-domain.com/
```

## Scaling

### Horizontal Scaling
```bash
# Scale backend services
docker compose up -d --scale backend=3

# With Kubernetes
kubectl scale deployment/secure-notes-backend --replicas=3
```

### Load Balancing
```bash
# Configure nginx load balancing
upstream backend {
    server 127.0.0.1:8080;
    server 127.0.0.1:8081;
    server 127.0.0.1:8082;
}
```

## Disaster Recovery

### Backup Strategy
```bash
# Full system backup
./backup-production.sh

# Database backup
pg_dump -h postgres -U postgres notes > db-backup.sql

# File system backup
tar -czf files-backup.tar.gz /var/lib/secure-notes/
```

### Recovery Procedures
```bash
# Restore from backup
./restore-production.sh backup-20240101.tar.gz

# Verify integrity
./verify-production-health.sh
```