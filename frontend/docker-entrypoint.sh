#!/bin/sh
set -eu

# Default to port 80 for Coolify compatibility (with CAP_NET_BIND_SERVICE)
: "${PORT:=80}"

# Add debugging output for Coolify troubleshooting
echo "=== Frontend Container Startup ==="
echo "PORT: $PORT"
echo "BACKEND_INTERNAL_URL: ${BACKEND_INTERNAL_URL:-NOT_SET}"
echo "==================================="

# Attempt to auto-populate BACKEND_INTERNAL_URL if it's missing.
if [ -z "${BACKEND_INTERNAL_URL:-}" ]; then
  if [ -n "${RAILWAY_SERVICE_LEAFLOCK_BACKEND_URL:-}" ]; then
    BACKEND_INTERNAL_URL="https://${RAILWAY_SERVICE_LEAFLOCK_BACKEND_URL}"
  else
    # Try to discover any Railway backend URL envs dynamically
    detected_url=$(env | awk -F= '/^RAILWAY_SERVICE_.*_BACKEND_URL=/{print $2; exit}')
    if [ -n "$detected_url" ]; then
      BACKEND_INTERNAL_URL="https://${detected_url}"
    elif [ -n "${VITE_API_URL:-}" ]; then
      BACKEND_INTERNAL_URL="${VITE_API_URL}"
    fi
  fi
  export BACKEND_INTERNAL_URL
  echo "Detected BACKEND_INTERNAL_URL: ${BACKEND_INTERNAL_URL:-NOT_SET}"
fi

# Normalize BACKEND_INTERNAL_URL to scheme://host[:port]
if [ -n "${BACKEND_INTERNAL_URL:-}" ] && printf '%s' "$BACKEND_INTERNAL_URL" | grep -q '://'; then
  scheme="${BACKEND_INTERNAL_URL%%://*}"
  rest="${BACKEND_INTERNAL_URL#*://}"
  host="${rest%%/*}"
  BACKEND_INTERNAL_URL="${scheme}://${host}"
  export BACKEND_INTERNAL_URL
fi

# Optimized startup with faster config generation
# Require BACKEND_INTERNAL_URL (e.g., http://backend:8080). Fail fast if missing.
if [ -z "${BACKEND_INTERNAL_URL:-}" ]; then
  echo "ERROR: BACKEND_INTERNAL_URL is not set (expected like http://backend:8080)" >&2
  echo "Available environment variables:" >&2
  env | grep -E "(BACKEND|PORT|VITE_API_URL|RAILWAY_SERVICE_.*_URL)" >&2 || true
  exit 1
fi

# Generate nginx config with better performance
envsubst '$PORT $BACKEND_INTERNAL_URL' < /etc/nginx/nginx.conf.template > /tmp/nginx.conf

# Pre-test nginx configuration to catch errors early
echo "Testing nginx configuration..."
if ! nginx -t -c /tmp/nginx.conf; then
  echo "WARNING: nginx config test failed; backend may not be resolvable yet. Continuing startup." >&2
fi

echo "Starting nginx on port $PORT..."
# Start nginx in foreground with optimized settings
exec nginx -g 'daemon off; worker_processes auto;' -c /tmp/nginx.conf
