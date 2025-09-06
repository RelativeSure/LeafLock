# Debugging Commands

Comprehensive debugging tools and workflows for Secure Notes development.

## Quick Debug Commands

```bash
# View live logs
make logs

# Check service status
make status

# Health check all services
curl http://localhost:8080/api/v1/health
```

## Backend Debugging (Go)

### Debug Server
```bash
cd backend

# Run with debug output
GOMAXPROCS=1 go run -race main.go

# Run with verbose logging
LOG_LEVEL=debug go run main.go

# Run with profiling enabled
go run main.go -cpuprofile=cpu.prof -memprofile=mem.prof
```

### Delve Debugger
```bash
cd backend

# Install delve if not available
go install github.com/go-delve/delve/cmd/dlv@latest

# Debug with delve
dlv debug main.go

# Remote debugging
dlv debug --listen=:2345 --headless=true main.go
```

### Memory Analysis
```bash
cd backend

# Generate memory profile
go test -memprofile=mem.prof -bench=.

# Analyze memory profile
go tool pprof mem.prof
```

### CPU Profiling
```bash
cd backend

# Generate CPU profile
go test -cpuprofile=cpu.prof -bench=.

# Analyze CPU profile
go tool pprof cpu.prof
```

### Race Condition Detection
```bash
cd backend

# Run with race detector
go run -race main.go

# Test with race detection
go test -race ./...
```

## Frontend Debugging (React)

### Development Server with Debug
```bash
cd frontend

# Start with debugging enabled
npm run dev -- --debug

# Start with source maps
npm run dev -- --sourcemap
```

### Browser DevTools Integration
```bash
# React Developer Tools
# Install browser extension: React Developer Tools

# Redux DevTools (if using Redux)
# Install browser extension: Redux DevTools Extension
```

### Console Debugging
```javascript
// Add to components for debugging
console.log('Debug:', { props, state });
console.table(data);
console.trace('Call stack');

// Performance timing
console.time('operation');
// ... code ...
console.timeEnd('operation');
```

### Vite Debugging
```bash
cd frontend

# Debug Vite itself
npx vite --debug

# Clear Vite cache
rm -rf node_modules/.vite
```

## Database Debugging

### PostgreSQL Connection
```bash
# Connect directly to database
podman exec -it secure-notes-postgres psql -U postgres -d notes

# Or with Docker
docker exec -it secure-notes-postgres psql -U postgres -d notes

# View database logs
podman logs secure-notes-postgres
```

### Redis Connection
```bash
# Connect to Redis
podman exec -it secure-notes-redis redis-cli

# Or with Docker
docker exec -it secure-notes-redis redis-cli

# Monitor Redis commands
podman exec -it secure-notes-redis redis-cli monitor
```

### Database Query Debugging
```sql
-- In PostgreSQL, enable query logging
ALTER SYSTEM SET log_statement = 'all';
SELECT pg_reload_conf();

-- View slow queries
SELECT query, mean_time, calls 
FROM pg_stat_statements 
ORDER BY mean_time DESC 
LIMIT 10;
```

## Network Debugging

### API Request Debugging
```bash
# Test API endpoints
curl -v http://localhost:8080/api/v1/health

# Test with authentication
curl -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"data":"test"}' \
     http://localhost:8080/api/v1/notes

# Test CORS
curl -H "Origin: http://localhost:3000" \
     -H "Access-Control-Request-Method: POST" \
     -H "Access-Control-Request-Headers: Content-Type" \
     -X OPTIONS \
     http://localhost:8080/api/v1/notes
```

### Network Traffic Analysis
```bash
# Install tcpdump if needed
# sudo apt install tcpdump

# Monitor localhost traffic
sudo tcpdump -i lo port 8080

# Monitor specific connections
netstat -tlnp | grep :8080
ss -tlnp | grep :8080
```

## Container Debugging

### Container Inspection
```bash
# Inspect backend container
podman inspect secure-notes-backend

# View container processes
podman top secure-notes-backend

# Execute commands in container
podman exec -it secure-notes-backend /bin/sh
```

### Container Logs
```bash
# Follow all logs
podman logs -f secure-notes-backend

# Show last 100 lines
podman logs --tail=100 secure-notes-backend

# Show logs with timestamps
podman logs -t secure-notes-backend
```

### Container Resource Usage
```bash
# Monitor resource usage
podman stats

# Detailed container info
podman system df
podman system info
```

## Performance Debugging

### Backend Performance
```bash
cd backend

# HTTP request tracing
go run main.go -httptrace

# Memory usage monitoring
watch -n 1 'ps aux | grep secure-notes'

# File descriptor monitoring
lsof -p $(pidof secure-notes)
```

### Frontend Performance
```bash
cd frontend

# Bundle analysis
npm run build -- --analyze

# Performance profiling
# Use browser DevTools > Performance tab
```

### Database Performance
```bash
# PostgreSQL performance
podman exec -it secure-notes-postgres psql -U postgres -d notes -c "
SELECT schemaname,tablename,attname,n_distinct,correlation 
FROM pg_stats 
WHERE tablename = 'notes';
"

# Redis performance
podman exec -it secure-notes-redis redis-cli info stats
```

## Error Analysis

### Application Error Logs
```bash
# Backend error logs (structured JSON)
tail -f /var/log/secure-notes/backend.log | jq .

# Frontend error logs (browser console)
# Check browser DevTools > Console

# System error logs
journalctl -u secure-notes -f
```

### Error Patterns
```bash
# Search for specific errors
grep -r "ERROR" backend/
grep -r "panic" backend/
grep -r "fatal" backend/

# Database connection errors
grep -r "connection refused" /var/log/
grep -r "authentication failed" /var/log/
```

## Security Debugging

### Authentication Issues
```bash
# JWT token inspection
echo $JWT_TOKEN | cut -d. -f2 | base64 -d | jq .

# Session debugging
podman exec -it secure-notes-redis redis-cli keys "session:*"
```

### CORS Issues
```bash
# Test CORS headers
curl -I -H "Origin: http://localhost:3000" http://localhost:8080/api/v1/health

# Debug preflight requests
curl -X OPTIONS \
     -H "Origin: http://localhost:3000" \
     -H "Access-Control-Request-Method: POST" \
     http://localhost:8080/api/v1/notes
```

### Encryption Debugging
```bash
# Test encryption/decryption in backend
cd backend
go test -run TestEncryption -v
```

## Development Tools Integration

### VS Code Debugging
```json
// .vscode/launch.json
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "Debug Backend",
            "type": "go",
            "request": "launch",
            "mode": "debug",
            "program": "${workspaceFolder}/backend/main.go",
            "cwd": "${workspaceFolder}/backend"
        }
    ]
}
```

### GoLand/IntelliJ Debugging
- Set breakpoints in Go code
- Use "Debug" run configuration
- Enable "Build with -race flag" for race detection

## Log Analysis Tools

### Structured Log Analysis
```bash
# Parse JSON logs with jq
cat /tmp/secure-notes-dev.log | jq 'select(.level == "error")'

# Real-time log monitoring
tail -f /tmp/secure-notes-dev.log | jq --color-output .
```

### Log Aggregation
```bash
# Combine all service logs
{
    echo "=== Backend Logs ===";
    podman logs secure-notes-backend;
    echo "=== Frontend Logs ===";
    podman logs secure-notes-frontend;
    echo "=== Database Logs ===";
    podman logs secure-notes-postgres;
} > debug-session-$(date +%Y%m%d-%H%M%S).log
```

## Troubleshooting Common Issues

### "Connection Refused" Errors
```bash
# Check if services are running
make status

# Check port bindings
netstat -tlnp | grep -E ":(3000|8080|5432|6379)"

# Restart services
make restart
```

### "Permission Denied" Errors
```bash
# Check file permissions
ls -la .env backend/app frontend/dist/

# Fix common permission issues
chmod +x backend/app
chown -R $USER:$USER .
```

### Memory/Performance Issues
```bash
# Monitor resource usage
top -p $(pgrep -f secure-notes)

# Check disk space
df -h

# Clean up resources
make clean
docker/podman system prune
```