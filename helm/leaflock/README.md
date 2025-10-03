# LeafLock Helm Chart

A production-ready Helm chart for deploying the LeafLock application with end-to-end encryption, zero-knowledge architecture, and enterprise-grade security features.

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

```plaintext
┌─────────────────────────────────────────────────────────────────┐
│                         LEAFLOCK                                │
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
kubectl create namespace leaflock
```

### 3. Install the Chart

#### Development Installation

```bash
helm install leaflock ./helm/leaflock \
  --namespace leaflock \
  --values ./helm/leaflock/values-dev.yaml \
  --set secrets.jwtSecret="$(openssl rand -base64 64)" \
  --set secrets.serverEncryptionKey="$(openssl rand -base64 32)"
```

#### Production Installation

```bash
# Create production secrets first
kubectl create secret generic leaflock-secret \
  --from-literal=jwt-secret="$(openssl rand -base64 64)" \
  --from-literal=server-encryption-key="$(openssl rand -base64 32)" \
  --namespace leaflock

kubectl create secret generic leaflock-postgresql-prod \
  --from-literal=postgres-password="$(openssl rand -base64 32)" \
  --from-literal=password="$(openssl rand -base64 32)" \
  --namespace leaflock

kubectl create secret generic leaflock-redis-prod \
  --from-literal=redis-password="$(openssl rand -base64 32)" \
  --namespace leaflock

# Install with production values
helm install leaflock ./helm/leaflock \
  --namespace leaflock \
  --values ./helm/leaflock/values-prod.yaml \
  --set ingress.hosts[0].host="leaflock.yourdomain.com" \
  --set config.backend.corsOrigins="https://leaflock.yourdomain.com"
```

### 4. Verify Installation

```bash
# Check deployment status
kubectl get pods -n leaflock

# Run tests
helm test leaflock -n leaflock

# Check ingress
kubectl get ingress -n leaflock
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
    repository: your-registry/leaflock/backend
    tag: "1.0.0"

frontend:
  image:
    repository: your-registry/leaflock/frontend  
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
    existingSecret: "leaflock-postgresql-prod"
  
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
    existingSecret: "leaflock-redis-prod"
  
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
    - host: leaflock.example.com
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
    - secretName: leaflock-tls
      hosts:
        - leaflock.example.com
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
  namespace: leaflock
spec:
  vault:
    server: "https://vault.example.com"
    path: "secret"
    version: "v2"
    auth:
      kubernetes:
        mountPath: "kubernetes"
        role: "leaflock"
EOF
```

#### Sealed Secrets
```bash
# Using sealed-secrets
kubectl create secret generic leaflock-secret \
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
      - alert: LeafLockDown
        expr: up{job="leaflock-backend"} == 0
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
kubectl logs -l app.kubernetes.io/component=backend -n leaflock

# View frontend logs  
kubectl logs -l app.kubernetes.io/component=frontend -n leaflock
```

## Troubleshooting

### Common Issues

#### 1. Backend Won't Start
```bash
# Check database connectivity
kubectl exec -it deployment/leaflock-backend -n leaflock -- \
  wget -q --spider http://leaflock-postgresql:5432 && echo "DB reachable"
```

#### 2. Frontend 502 Errors
```bash
# Check backend health
kubectl port-forward svc/leaflock-backend 8080:8080 -n leaflock
curl http://localhost:8080/api/v1/health
```

#### 3. TLS Certificate Issues
```bash
# Check cert-manager status
kubectl get certificaterequests -n leaflock
kubectl describe certificate leaflock-tls -n leaflock
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
helm upgrade leaflock ./helm/leaflock \
  --namespace leaflock \
  --values ./helm/leaflock/values-prod.yaml
```

### Major Version Upgrades

1. **Backup Data**
   ```bash
   kubectl exec -it leaflock-postgresql-0 -n leaflock -- \
     pg_dump -U notes notes > backup.sql
   ```

2. **Test in Staging**
   ```bash
   helm install leaflock-staging ./helm/leaflock \
     --namespace leaflock-staging
   ```

3. **Rolling Update**
   ```bash
   helm upgrade leaflock ./helm/leaflock \
     --namespace leaflock \
     --values ./helm/leaflock/values-prod.yaml
   ```

## Development

### Local Development

```bash
# Install development version
helm install leaflock ./helm/leaflock \
  --namespace leaflock-dev \
  --values ./helm/leaflock/values-dev.yaml \
  --create-namespace

# Port forward for local access
kubectl port-forward svc/leaflock-frontend 3000:80 -n leaflock-dev
kubectl port-forward svc/leaflock-backend 8080:8080 -n leaflock-dev
```

### Template Testing

```bash
# Render templates
helm template leaflock ./helm/leaflock \
  --values ./helm/leaflock/values-dev.yaml \
  --debug

# Validate manifests
helm template leaflock ./helm/leaflock | kubectl apply --dry-run=client -f -
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
- **Security**: Email <security@leaflock.app> for vulnerabilities

## License

This Helm chart is licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE file for details.
