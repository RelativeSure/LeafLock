#!/bin/sh
set -eu

# Default to port 80 for Coolify compatibility (with CAP_NET_BIND_SERVICE)
: "${PORT:=80}"

# Add debugging output for Coolify troubleshooting
echo "=== Frontend Container Startup ==="
echo "PORT: $PORT"
echo "BACKEND_INTERNAL_URL: ${BACKEND_INTERNAL_URL:-NOT_SET}"
echo "==================================="

# Optimized startup with faster config generation
# Require BACKEND_INTERNAL_URL (e.g., http://backend:8080). Fail fast if missing.
if [ -z "${BACKEND_INTERNAL_URL:-}" ]; then
  echo "ERROR: BACKEND_INTERNAL_URL is not set (expected like http://backend:8080)" >&2
  echo "Available environment variables:" >&2
  env | grep -E "(BACKEND|PORT)" >&2
  exit 1
fi

# Generate nginx config with better performance
envsubst '$PORT $BACKEND_INTERNAL_URL' < /etc/nginx/nginx.conf.template > /tmp/nginx.conf

# Pre-test nginx configuration to catch errors early
echo "Testing nginx configuration..."
nginx -t -c /tmp/nginx.conf

echo "Starting nginx on port $PORT..."
# Start nginx in foreground with optimized settings
exec nginx -g 'daemon off; worker_processes auto;' -c /tmp/nginx.conf
