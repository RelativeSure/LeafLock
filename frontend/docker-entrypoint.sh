#!/bin/sh
set -eu

# Default to port 80 for Coolify compatibility (with CAP_NET_BIND_SERVICE)
: "${PORT:=80}"

# Add debugging output for Coolify troubleshooting
echo "=== Frontend Container Startup ==="
echo "🚀 [STARTUP] Frontend container initializing..."
echo "🔧 [CONFIG] PORT: $PORT"
echo "🔧 [CONFIG] BACKEND_INTERNAL_URL: ${BACKEND_INTERNAL_URL:-NOT_SET}"
echo "🔍 [NETWORK] Deployment environment detection:"
echo "  - Railway: ${RAILWAY_TCP_PROXY_PORT:+DETECTED}${RAILWAY_TCP_PROXY_PORT:-NOT_DETECTED}"
echo "  - Kubernetes: ${KUBERNETES_SERVICE_HOST:+DETECTED}${KUBERNETES_SERVICE_HOST:-NOT_DETECTED}"
echo "  - Docker Compose: ${COMPOSE_PROJECT_NAME:+DETECTED}${COMPOSE_PROJECT_NAME:-NOT_DETECTED}"
echo "==================================="

# Attempt to auto-populate BACKEND_INTERNAL_URL if it's missing.
if [ -z "${BACKEND_INTERNAL_URL:-}" ]; then
  echo "🔍 [SERVICE_DISCOVERY] Attempting auto-detection of backend service..."

  # Try common container orchestration patterns
  # 1. Docker Compose / Docker Swarm - service name resolution
  if [ -n "${BACKEND_SERVICE_NAME:-}" ]; then
    echo "✅ [SERVICE_DISCOVERY] Using BACKEND_SERVICE_NAME: ${BACKEND_SERVICE_NAME}"
    BACKEND_INTERNAL_URL="http://${BACKEND_SERVICE_NAME}:${BACKEND_PORT:-8080}"

  # 2. Kubernetes - service discovery via environment variables
  elif [ -n "${BACKEND_SERVICE_HOST:-}" ] && [ -n "${BACKEND_SERVICE_PORT:-}" ]; then
    echo "✅ [SERVICE_DISCOVERY] Found Kubernetes service: ${BACKEND_SERVICE_HOST}:${BACKEND_SERVICE_PORT}"
    BACKEND_INTERNAL_URL="http://${BACKEND_SERVICE_HOST}:${BACKEND_SERVICE_PORT}"

  # 3. Railway specific patterns (only if Railway environment detected)
  elif [ -n "${RAILWAY_TCP_PROXY_PORT:-}" ]; then
    echo "🔍 [SERVICE_DISCOVERY] Railway environment detected..."

    # Try Railway-specific service discovery patterns
    if [ -n "${RAILWAY_SERVICE_LEAFLOCK_BACKEND_TCP_URL:-}" ]; then
      echo "✅ [RAILWAY] Found RAILWAY_SERVICE_LEAFLOCK_BACKEND_TCP_URL"
      BACKEND_INTERNAL_URL="${RAILWAY_SERVICE_LEAFLOCK_BACKEND_TCP_URL}"
    elif [ -n "${RAILWAY_SERVICE_LEAFLOCK_BACKEND_URL:-}" ]; then
      echo "✅ [RAILWAY] Found RAILWAY_SERVICE_LEAFLOCK_BACKEND_URL"
      BACKEND_INTERNAL_URL="https://${RAILWAY_SERVICE_LEAFLOCK_BACKEND_URL}"
    else
      # Generic Railway service discovery
      backend_tcp=$(env | grep -E '^RAILWAY_SERVICE_.*BACKEND.*_TCP_URL=' | head -1 | cut -d= -f2)
      backend_url=$(env | grep -E '^RAILWAY_SERVICE_.*BACKEND.*_URL=' | head -1 | cut -d= -f2)

      if [ -n "$backend_tcp" ]; then
        echo "✅ [RAILWAY] Found backend TCP URL: $backend_tcp"
        BACKEND_INTERNAL_URL="$backend_tcp"
      elif [ -n "$backend_url" ]; then
        echo "✅ [RAILWAY] Found backend URL: $backend_url"
        BACKEND_INTERNAL_URL="https://${backend_url}"
      else
        echo "❌ [RAILWAY] No Railway backend service found"
      fi
    fi

  # 4. Generic container networking - try common service names
  elif command -v nslookup >/dev/null 2>&1; then
    echo "🔍 [SERVICE_DISCOVERY] Trying common backend service names..."
    for service_name in backend leaflock-backend api server app; do
      if nslookup "$service_name" >/dev/null 2>&1; then
        echo "✅ [SERVICE_DISCOVERY] Found resolvable service: $service_name"
        BACKEND_INTERNAL_URL="http://${service_name}:8080"
        break
      fi
    done

  # 5. Fallback to VITE_API_URL if available
  elif [ -n "${VITE_API_URL:-}" ]; then
    echo "✅ [SERVICE_DISCOVERY] Fallback to VITE_API_URL: ${VITE_API_URL}"
    BACKEND_INTERNAL_URL="${VITE_API_URL}"

  else
    echo "❌ [SERVICE_DISCOVERY] No backend service could be auto-detected"
    echo "💡 [SERVICE_DISCOVERY] Set BACKEND_INTERNAL_URL manually for your deployment"
  fi

  export BACKEND_INTERNAL_URL
  echo "🎯 [SERVICE_DISCOVERY] Final BACKEND_INTERNAL_URL: ${BACKEND_INTERNAL_URL:-NOT_SET}"
fi

# Normalize BACKEND_INTERNAL_URL to scheme://host[:port]
if [ -n "${BACKEND_INTERNAL_URL:-}" ]; then
  echo "🔧 [URL_NORMALIZATION] Processing URL: ${BACKEND_INTERNAL_URL}"
  case "$BACKEND_INTERNAL_URL" in
    tcp://*)
      rest="${BACKEND_INTERNAL_URL#tcp://}"
      hostport="${rest%%/*}"
      host="${hostport%:*}"
      port="${hostport##*:}"
      if [ "$host" = "$port" ]; then
        port=""
        host="$hostport"
      fi
      if printf '%s' "$host" | grep -q ':'; then
        echo "🔵 [IPv6] Detected IPv6 address, adding brackets: [$host]"
        host="[$host]"
      fi
      if [ -n "$port" ]; then
        BACKEND_INTERNAL_URL="http://${host}:$port"
      else
        # Default to port 8080 for backend service when no port specified
        BACKEND_INTERNAL_URL="http://${host}:8080"
      fi
      echo "🔧 [URL_NORMALIZATION] TCP URL converted to: ${BACKEND_INTERNAL_URL}"
      ;;
    http://*|https://*)
      scheme="${BACKEND_INTERNAL_URL%%://*}"
      rest="${BACKEND_INTERNAL_URL#*://}"
      hostport="${rest%%/*}"
      host="${hostport%:*}"
      port="${hostport##*:}"
      if [ "$host" = "$port" ]; then
        port=""
        host="$hostport"
      fi
      if printf '%s' "$host" | grep -q ':' && ! printf '%s' "$host" | grep -q '\['; then
        echo "🔵 [IPv6] Detected IPv6 address in HTTP URL, adding brackets: [$host]"
        host="[$host]"
      fi
      if [ -n "$port" ]; then
        BACKEND_INTERNAL_URL="${scheme}://${host}:$port"
      else
        BACKEND_INTERNAL_URL="${scheme}://${host}"
      fi
      echo "🔧 [URL_NORMALIZATION] HTTP/HTTPS URL normalized to: ${BACKEND_INTERNAL_URL}"
      ;;
    *)
      echo "🔧 [URL_NORMALIZATION] Adding HTTP scheme to: ${BACKEND_INTERNAL_URL}"
      BACKEND_INTERNAL_URL="http://${BACKEND_INTERNAL_URL}"
      ;;
  esac
  export BACKEND_INTERNAL_URL
  echo "✅ [URL_NORMALIZATION] Final normalized URL: ${BACKEND_INTERNAL_URL}"
fi

# Optimized startup with faster config generation
# Require BACKEND_INTERNAL_URL (e.g., http://backend:8080). Fail fast if missing.
if [ -z "${BACKEND_INTERNAL_URL:-}" ]; then
  echo "ERROR: BACKEND_INTERNAL_URL is not set (expected like http://backend:8080)" >&2
  echo "" >&2
  echo "Railway Service Discovery Debug Information:" >&2
  echo "Available Railway service environment variables:" >&2
  env | grep -E "^RAILWAY_SERVICE_.*_(TCP_)?URL=" >&2 || echo "  (No Railway service URLs found)" >&2
  echo "" >&2
  echo "Other relevant environment variables:" >&2
  env | grep -E "(BACKEND|PORT|VITE_API_URL|RAILWAY_TCP_PROXY_PORT|RAILWAY_SERVICE_NAME)" >&2 || echo "  (No other relevant variables found)" >&2
  echo "" >&2
  echo "To fix this issue:" >&2
  echo "1. Set BACKEND_INTERNAL_URL manually in Railway dashboard" >&2
  echo "2. Ensure backend service has Railway environment variables like RAILWAY_SERVICE_*_BACKEND_*_TCP_URL" >&2
  echo "3. Check that backend and frontend services are in the same Railway project" >&2
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
