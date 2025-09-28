#!/bin/sh
set -eu

# Helper to locate Railway service discovery variables that reference the backend
find_backend_service_line() {
  suffix_pattern="$1"
  env | awk -v keys="${RAILWAY_BACKEND_KEYWORDS}" -v suffix="$suffix_pattern" '
    BEGIN { pattern = "^RAILWAY_SERVICE_.*(" keys ").*" }
    $0 ~ pattern && index($0, suffix) > 0 { print; exit }
  '
}

# Default to port 80 for Coolify compatibility (with CAP_NET_BIND_SERVICE)
: "${PORT:=80}"

# Determine default backend port with user overrides first
DEFAULT_BACKEND_PORT="${BACKEND_PORT:-}"
if [ -z "$DEFAULT_BACKEND_PORT" ]; then
  DEFAULT_BACKEND_PORT="${RAILWAY_BACKEND_PORT:-}"
fi
if [ -z "$DEFAULT_BACKEND_PORT" ]; then
  DEFAULT_BACKEND_PORT=8080
fi

# Track whether we auto-detected the backend URL (used for safe port overrides later)
BACKEND_AUTODETECTED=0
BACKEND_SOURCE_VAR=""

# Determine if we're running on Railway using a broader set of hints
RAILWAY_DETECTED_VIA=""
for detection_var in \
  RAILWAY_PROJECT_ID RAILWAY_PROJECT_NAME \
  RAILWAY_ENVIRONMENT_ID RAILWAY_ENVIRONMENT_NAME \
  RAILWAY_SERVICE_ID RAILWAY_SERVICE_NAME \
  RAILWAY_PUBLIC_DOMAIN RAILWAY_PRIVATE_DOMAIN \
  RAILWAY_STATIC_URL RAILWAY_TCP_PROXY_PORT
do
  eval "candidate=\"\${${detection_var}:-}\""
  if [ -n "$candidate" ]; then
    RAILWAY_DETECTED_VIA="$detection_var"
    break
  fi
done

if [ -n "$RAILWAY_DETECTED_VIA" ]; then
  IS_RAILWAY_ENV=1
  RAILWAY_DETECTION_STATUS="DETECTED (via ${RAILWAY_DETECTED_VIA})"
else
  IS_RAILWAY_ENV=0
  RAILWAY_DETECTION_STATUS="NOT_DETECTED"
fi

# Allow overriding which service names are considered "backend"
RAILWAY_BACKEND_KEYWORDS="${RAILWAY_BACKEND_KEYWORDS:-BACKEND|API|SERVER|APP|SERVICE}"

# Add debugging output for deployment troubleshooting
echo "=== Frontend Container Startup ==="
echo "🚀 [STARTUP] Frontend container initializing..."
echo "🔧 [CONFIG] PORT: $PORT"
echo "🔧 [CONFIG] BACKEND_INTERNAL_URL: ${BACKEND_INTERNAL_URL:-NOT_SET}"
echo "🔧 [CONFIG] DEFAULT_BACKEND_PORT: ${DEFAULT_BACKEND_PORT}"
echo "🔍 [NETWORK] Deployment environment detection:"
echo "  - Railway: ${RAILWAY_DETECTION_STATUS}"
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
    BACKEND_INTERNAL_URL="http://${BACKEND_SERVICE_NAME}:${DEFAULT_BACKEND_PORT}"
    BACKEND_AUTODETECTED=1
    BACKEND_SOURCE_VAR="BACKEND_SERVICE_NAME"

  # 2. Kubernetes - service discovery via environment variables
  elif [ -n "${BACKEND_SERVICE_HOST:-}" ] && [ -n "${BACKEND_SERVICE_PORT:-}" ]; then
    echo "✅ [SERVICE_DISCOVERY] Found Kubernetes service: ${BACKEND_SERVICE_HOST}:${BACKEND_SERVICE_PORT}"
    BACKEND_INTERNAL_URL="http://${BACKEND_SERVICE_HOST}:${BACKEND_SERVICE_PORT}"
    BACKEND_AUTODETECTED=1
    BACKEND_SOURCE_VAR="KUBERNETES_SERVICE"

  # 3. Railway specific patterns (only if Railway environment detected)
  elif [ "$IS_RAILWAY_ENV" -eq 1 ]; then
    echo "🔍 [SERVICE_DISCOVERY] Railway environment detected (via ${RAILWAY_DETECTED_VIA})..."

    # Direct overrides take precedence so users can fully control the endpoint
    if [ -n "${RAILWAY_BACKEND_INTERNAL_URL:-}" ]; then
      echo "✅ [RAILWAY] Found RAILWAY_BACKEND_INTERNAL_URL"
      BACKEND_INTERNAL_URL="${RAILWAY_BACKEND_INTERNAL_URL}"
      BACKEND_AUTODETECTED=1
      BACKEND_SOURCE_VAR="RAILWAY_BACKEND_INTERNAL_URL"
    elif [ -n "${RAILWAY_BACKEND_TCP_URL:-}" ]; then
      echo "✅ [RAILWAY] Found RAILWAY_BACKEND_TCP_URL"
      BACKEND_INTERNAL_URL="${RAILWAY_BACKEND_TCP_URL}"
      BACKEND_AUTODETECTED=1
      BACKEND_SOURCE_VAR="RAILWAY_BACKEND_TCP_URL"
    else
      backend_line=$(find_backend_service_line "_TCP_URL=")
      if [ -z "$backend_line" ]; then
        backend_line=$(find_backend_service_line "_TCP_PROXY_URL=")
      fi
      if [ -z "$backend_line" ]; then
        backend_line=$(find_backend_service_line "_HTTP_URL=")
      fi
      if [ -z "$backend_line" ]; then
        backend_line=$(find_backend_service_line "_URL=")
        case "$backend_line" in
          *_TCP_URL=*|*_TCP_PROXY_URL=*|*_HTTP_URL=*)
            backend_line=""
            ;;
        esac
      fi

      if [ -n "$backend_line" ]; then
        backend_var=${backend_line%%=*}
        backend_value=${backend_line#*=}
        echo "✅ [RAILWAY] Found ${backend_var}"
        BACKEND_INTERNAL_URL="$backend_value"
        BACKEND_AUTODETECTED=1
        BACKEND_SOURCE_VAR="$backend_var"
      else
        host_line=$(find_backend_service_line "_HOST=")
        if [ -n "$host_line" ]; then
          backend_var=${host_line%%=*}
          backend_host=${host_line#*=}
          backend_base=${backend_var%_HOST}
          backend_port_var="${backend_base}_PORT"
          eval "backend_port_value=\"\${${backend_port_var}:-}\""
          if [ -n "$backend_port_value" ]; then
            echo "✅ [RAILWAY] Found ${backend_port_var}: ${backend_port_value}"
          else
            backend_port_value="$DEFAULT_BACKEND_PORT"
            echo "🟡 [RAILWAY] ${backend_port_var} missing; defaulting to port ${backend_port_value}"
          fi
          BACKEND_INTERNAL_URL="http://${backend_host}:${backend_port_value}"
          BACKEND_AUTODETECTED=1
          BACKEND_SOURCE_VAR="$backend_var"
        elif [ -n "${RAILWAY_BACKEND_PRIVATE_DOMAIN:-}" ]; then
          echo "✅ [RAILWAY] Found RAILWAY_BACKEND_PRIVATE_DOMAIN"
          BACKEND_INTERNAL_URL="http://${RAILWAY_BACKEND_PRIVATE_DOMAIN}:${DEFAULT_BACKEND_PORT}"
          BACKEND_AUTODETECTED=1
          BACKEND_SOURCE_VAR="RAILWAY_BACKEND_PRIVATE_DOMAIN"
        elif [ -n "${RAILWAY_PRIVATE_DOMAIN_BACKEND:-}" ]; then
          echo "✅ [RAILWAY] Found RAILWAY_PRIVATE_DOMAIN_BACKEND"
          BACKEND_INTERNAL_URL="http://${RAILWAY_PRIVATE_DOMAIN_BACKEND}:${DEFAULT_BACKEND_PORT}"
          BACKEND_AUTODETECTED=1
          BACKEND_SOURCE_VAR="RAILWAY_PRIVATE_DOMAIN_BACKEND"
        else
          private_line=$(find_backend_service_line "_PRIVATE_DOMAIN=")
          if [ -n "$private_line" ]; then
            backend_var=${private_line%%=*}
            backend_host=${private_line#*=}
            echo "✅ [RAILWAY] Found ${backend_var}"
            BACKEND_INTERNAL_URL="http://${backend_host}:${DEFAULT_BACKEND_PORT}"
            BACKEND_AUTODETECTED=1
            BACKEND_SOURCE_VAR="$backend_var"
          else
            echo "❌ [RAILWAY] No Railway backend service found"
          fi
        fi
      fi
    fi

  # 4. Generic container networking - try common service names
  elif command -v nslookup >/dev/null 2>&1; then
    echo "🔍 [SERVICE_DISCOVERY] Trying common backend service names..."
    for service_name in backend leaflock-backend api server app; do
      if nslookup "$service_name" >/dev/null 2>&1; then
        echo "✅ [SERVICE_DISCOVERY] Found resolvable service: $service_name"
        BACKEND_INTERNAL_URL="http://${service_name}:${DEFAULT_BACKEND_PORT}"
        BACKEND_AUTODETECTED=1
        BACKEND_SOURCE_VAR="nslookup:${service_name}"
        break
      fi
    done

  # 5. Fallback to VITE_API_URL if available
  elif [ -n "${VITE_API_URL:-}" ]; then
    echo "✅ [SERVICE_DISCOVERY] Fallback to VITE_API_URL: ${VITE_API_URL}"
    BACKEND_INTERNAL_URL="${VITE_API_URL}"
    BACKEND_AUTODETECTED=1
    BACKEND_SOURCE_VAR="VITE_API_URL"

  else
    echo "❌ [SERVICE_DISCOVERY] No backend service could be auto-detected"
    echo "💡 [SERVICE_DISCOVERY] Set BACKEND_INTERNAL_URL manually for your deployment"
  fi

  export BACKEND_INTERNAL_URL
  if [ -n "${BACKEND_INTERNAL_URL:-}" ] && [ "$BACKEND_AUTODETECTED" -eq 1 ] && [ -n "$BACKEND_SOURCE_VAR" ]; then
    echo "🎯 [SERVICE_DISCOVERY] Final BACKEND_INTERNAL_URL: ${BACKEND_INTERNAL_URL} (source: ${BACKEND_SOURCE_VAR})"
  else
    echo "🎯 [SERVICE_DISCOVERY] Final BACKEND_INTERNAL_URL: ${BACKEND_INTERNAL_URL:-NOT_SET}"
  fi
fi

# Normalize BACKEND_INTERNAL_URL to scheme://host[:port]
if [ -n "${BACKEND_INTERNAL_URL:-}" ]; then
  echo "🔧 [URL_NORMALIZATION] Processing URL: ${BACKEND_INTERNAL_URL}"
  if [ "$BACKEND_AUTODETECTED" -eq 1 ]; then
    BACKEND_SOURCE_LABEL="${BACKEND_SOURCE_VAR:-auto}"
  else
    BACKEND_SOURCE_LABEL="${BACKEND_SOURCE_VAR:-manual}"
  fi
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
      normalized_port="$port"
      if [ -z "$normalized_port" ]; then
        normalized_port="$DEFAULT_BACKEND_PORT"
        echo "🟡 [URL_NORMALIZATION] No port in TCP URL; defaulting to ${normalized_port} (source: ${BACKEND_SOURCE_LABEL})"
      elif [ "$BACKEND_AUTODETECTED" -eq 1 ] && [ "$normalized_port" = "80" ] && [ "$DEFAULT_BACKEND_PORT" != "80" ]; then
        echo "🛠️ [URL_NORMALIZATION] Overriding TCP port 80 with ${DEFAULT_BACKEND_PORT} (source: ${BACKEND_SOURCE_LABEL})"
        normalized_port="$DEFAULT_BACKEND_PORT"
      fi
      BACKEND_INTERNAL_URL="http://${host}:${normalized_port}"
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
      normalized_port="$port"
      if [ "$scheme" = "http" ]; then
        if [ -z "$normalized_port" ] && [ "$BACKEND_AUTODETECTED" -eq 1 ]; then
          normalized_port="$DEFAULT_BACKEND_PORT"
          echo "🟡 [URL_NORMALIZATION] No port in HTTP URL; defaulting to ${normalized_port} (source: ${BACKEND_SOURCE_LABEL})"
        elif [ "$normalized_port" = "80" ] && [ "$DEFAULT_BACKEND_PORT" != "80" ] && [ "$BACKEND_AUTODETECTED" -eq 1 ]; then
          echo "🛠️ [URL_NORMALIZATION] Overriding HTTP port 80 with ${DEFAULT_BACKEND_PORT} (source: ${BACKEND_SOURCE_LABEL})"
          normalized_port="$DEFAULT_BACKEND_PORT"
        fi
      fi
      if [ -n "$normalized_port" ]; then
        BACKEND_INTERNAL_URL="${scheme}://${host}:${normalized_port}"
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
