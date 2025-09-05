# Secure Notes Helm Chart

A production-ready Helm chart for deploying the Secure Notes application with end-to-end encryption, zero-knowledge architecture, and enterprise-grade security features.

## Features

- **Zero-Knowledge Architecture**: Server never sees plaintext data
- **End-to-End Encryption**: XChaCha20-Poly1305 client-side encryption
- **Bitnami PostgreSQL & Redis**: Reliable, hardened database and cache components
- **Production-Ready**: Auto-scaling, pod disruption budgets, network policies
- **Security First**: RBAC, security contexts, network isolation
- **GitOps Ready**: Environment-specific configurations and monitoring integration

## Prerequisites

- Kubernetes cluster 1.24+
- Helm 3.8+
- NGINX Ingress Controller (for ingress)
- Cert-Manager (for TLS certificates)
- Container registry with backend and frontend images

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        SECURE NOTES                             │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐        │
│  │   Ingress   │    │  Frontend   │    │   Backend   │        │
│  │  (NGINX)    │───▶│   (React)   │───▶│    (Go)     │        │
│  └─────────────┘    └─────────────┘    └─────────────┘        │
│                             │                   │              │
│                             │                   ▼              │
│                             │          ┌─────────────┐        │
│                             │          │ PostgreSQL  │        │
│                             │          │  (Bitnami)  │        │
│                             │          └─────────────┘        │
│                             │                   │              │
│                             ▼                   ▼              │
│                    ┌─────────────┐    ┌─────────────┐        │
│                    │    Redis    │    │   Secrets   │        │
│                    │  (Bitnami)  │    │   Manager   │        │
│                    └─────────────┘    └─────────────┘        │
└─────────────────────────────────────────────────────────────────┘
```

## Quick Start

### 1. Add Bitnami Repository

```bash
helm repo add bitnami https://charts.bitnami.com/bitnami
helm repo update
```

### 2. Create Namespace

```bash
kubectl create namespace secure-notes
```

### 3. Install the Chart

#### Development Installation

```bash
helm install secure-notes ./helm/secure-notes \
  --namespace secure-notes \
  --values ./helm/secure-notes/values-dev.yaml \
  --set secrets.jwtSecret="$(openssl rand -base64 64)" \
  --set secrets.serverEncryptionKey="$(openssl rand -base64 32)"
```

#### Production Installation

```bash
# Create production secrets first
kubectl create secret generic secure-notes-secret \
  --from-literal=jwt-secret="$(openssl rand -base64 64)" \
  --from-literal=server-encryption-key="$(openssl rand -base64 32)" \
  --namespace secure-notes

kubectl create secret generic secure-notes-postgresql-prod \
  --from-literal=postgres-password="$(openssl rand -base64 32)" \
  --from-literal=password="$(openssl rand -base64 32)" \
  --namespace secure-notes

kubectl create secret generic secure-notes-redis-prod \
  --from-literal=redis-password="$(openssl rand -base64 32)" \
  --namespace secure-notes

# Install with production values
helm install secure-notes ./helm/secure-notes \
  --namespace secure-notes \
  --values ./helm/secure-notes/values-prod.yaml \
  --set ingress.hosts[0].host="secure-notes.yourdomain.com" \
  --set config.backend.corsOrigins="https://secure-notes.yourdomain.com"
```

### 4. Verify Installation

```bash
# Check deployment status
kubectl get pods -n secure-notes

# Run tests
helm test secure-notes -n secure-notes

# Check ingress
kubectl get ingress -n secure-notes
```

## Configuration

### Environment-Specific Values

The chart includes pre-configured values files for different environments:

- `values.yaml` - Base configuration
- `values-dev.yaml` - Development overrides (minimal resources, no TLS)
- `values-prod.yaml` - Production overrides (high availability, security hardening)

### Key Configuration Areas

#### Application Images

```yaml
backend:
  image:
    repository: your-registry/secure-notes/backend
    tag: "1.0.0"

frontend:
  image:
    repository: your-registry/secure-notes/frontend  
    tag: "1.0.0"
```

#### Security Configuration

```yaml
secrets:
  # Base64 encoded JWT signing secret (64 bytes recommended)
  jwtSecret: ""
  # Base64 encoded server encryption key (32 bytes required)  
  serverEncryptionKey: ""

# RBAC and security contexts are enabled by default
rbac:
  create: true

networkPolicy:
  enabled: true  # Restrict network traffic between pods
```

#### Database Configuration

```yaml
postgresql:
  enabled: true
  auth:
    database: "notes"
    username: "notes"
    # Use existing secret in production
    existingSecret: "secure-notes-postgresql-prod"
  
  primary:
    persistence:
      size: 20Gi
      storageClass: "fast-ssd"  # Production recommendation
```

#### Redis Configuration

```yaml
redis:
  enabled: true
  auth:
    enabled: true
    # Use existing secret in production
    existingSecret: "secure-notes-redis-prod"
  
  master:
    persistence:
      size: 8Gi
```

#### Ingress and TLS

```yaml
ingress:
  enabled: true
  className: "nginx"
  annotations:
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
  hosts:
    - host: secure-notes.example.com
      paths:
        - path: /
          pathType: Prefix
          service:
            name: frontend
        - path: /api
          pathType: Prefix
          service:
            name: backend
  tls:
    - secretName: secure-notes-tls
      hosts:
        - secure-notes.example.com
```

### Production Scaling

```yaml
backend:
  replicaCount: 3
  autoscaling:
    enabled: true
    minReplicas: 3
    maxReplicas: 20
    targetCPUUtilizationPercentage: 60
  
  resources:
    requests:
      cpu: 200m
      memory: 512Mi
    limits:
      cpu: 1000m
      memory: 1Gi

frontend:
  replicaCount: 3
  autoscaling:
    enabled: true
    minReplicas: 3
    maxReplicas: 10
```

## Security Best Practices

### 1. Secret Management

Never store secrets in values files. Use one of these approaches:

#### External Secret Management
```bash
# Using external-secrets operator
kubectl apply -f - <<EOF
apiVersion: external-secrets.io/v1beta1
kind: SecretStore
metadata:
  name: vault-backend
  namespace: secure-notes
spec:
  vault:
    server: "https://vault.example.com"
    path: "secret"
    version: "v2"
    auth:
      kubernetes:
        mountPath: "kubernetes"
        role: "secure-notes"
EOF
```

#### Sealed Secrets
```bash
# Using sealed-secrets
kubectl create secret generic secure-notes-secret \
  --from-literal=jwt-secret="..." \
  --dry-run=client -o yaml | \
  kubeseal -o yaml > sealed-secret.yaml
```

### 2. Network Security

The chart implements defense-in-depth networking:

- **Ingress**: Only allows HTTPS traffic
- **Frontend**: Can only communicate with backend
- **Backend**: Can only access database and cache
- **Database/Cache**: Only accept connections from backend

### 3. Pod Security

All pods run with:
- Non-root user
- Read-only root filesystem
- Dropped capabilities
- Security context constraints

### 4. TLS Everywhere

- Ingress terminates TLS
- PostgreSQL uses SSL
- Backend validates certificates

## Monitoring and Observability

### Prometheus Integration

```yaml
monitoring:
  enabled: true
  serviceMonitor:
    enabled: true
    namespace: monitoring
  
  prometheusRule:
    enabled: true
    rules:
      - alert: SecureNotesDown
        expr: up{job="secure-notes-backend"} == 0
```

### Health Checks

The chart includes comprehensive health checks:

- **Liveness Probes**: Detect hung processes
- **Readiness Probes**: Traffic routing control  
- **Startup Probes**: Handle slow initialization

### Logging

Structured logging is enabled by default:

```bash
# View backend logs
kubectl logs -l app.kubernetes.io/component=backend -n secure-notes

# View frontend logs  
kubectl logs -l app.kubernetes.io/component=frontend -n secure-notes
```

## Troubleshooting

### Common Issues

#### 1. Backend Won't Start
```bash
# Check database connectivity
kubectl exec -it deployment/secure-notes-backend -n secure-notes -- \
  wget -q --spider http://secure-notes-postgresql:5432 && echo "DB reachable"
```

#### 2. Frontend 502 Errors
```bash
# Check backend health
kubectl port-forward svc/secure-notes-backend 8080:8080 -n secure-notes
curl http://localhost:8080/api/v1/health
```

#### 3. TLS Certificate Issues
```bash
# Check cert-manager status
kubectl get certificaterequests -n secure-notes
kubectl describe certificate secure-notes-tls -n secure-notes
```

### Debug Mode

Enable debug logging:

```yaml
backend:
  env:
    LOG_LEVEL: debug

postgresql:
  primary:
    extendedConfiguration: |
      log_statement = 'all'
```

## Upgrade Guide

### Minor Version Upgrades

```bash
helm upgrade secure-notes ./helm/secure-notes \
  --namespace secure-notes \
  --values ./helm/secure-notes/values-prod.yaml
```

### Major Version Upgrades

1. **Backup Data**
   ```bash
   kubectl exec -it secure-notes-postgresql-0 -n secure-notes -- \
     pg_dump -U notes notes > backup.sql
   ```

2. **Test in Staging**
   ```bash
   helm install secure-notes-staging ./helm/secure-notes \
     --namespace secure-notes-staging
   ```

3. **Rolling Update**
   ```bash
   helm upgrade secure-notes ./helm/secure-notes \
     --namespace secure-notes \
     --values ./helm/secure-notes/values-prod.yaml
   ```

## Development

### Local Development

```bash
# Install development version
helm install secure-notes ./helm/secure-notes \
  --namespace secure-notes-dev \
  --values ./helm/secure-notes/values-dev.yaml \
  --create-namespace

# Port forward for local access
kubectl port-forward svc/secure-notes-frontend 3000:80 -n secure-notes-dev
kubectl port-forward svc/secure-notes-backend 8080:8080 -n secure-notes-dev
```

### Template Testing

```bash
# Render templates
helm template secure-notes ./helm/secure-notes \
  --values ./helm/secure-notes/values-dev.yaml \
  --debug

# Validate manifests
helm template secure-notes ./helm/secure-notes | kubectl apply --dry-run=client -f -
```

## Contributing

1. Fork the repository
2. Create feature branch
3. Update chart version in `Chart.yaml`
4. Test changes with `helm template` and `helm lint`
5. Submit pull request

## Support

For issues and questions:

- **Documentation**: Check this README and inline comments
- **Issues**: Open GitHub issue with debug output
- **Security**: Email security@secure-notes.com for vulnerabilities

## License

This Helm chart is licensed under the MIT License. See LICENSE file for details.