#!/bin/sh
set -eu

: "${PORT:=80}"
: "${RAILWAY_BACKEND_KEYWORDS:=BACKEND|API|SERVER|APP|SERVICE}"
DEFAULT_BACKEND_PORT="${RAILWAY_BACKEND_PORT:-${BACKEND_PORT:-8080}}"
BACKEND_SOURCE="provided"

log() {
  printf '%s\n' "$*"
}

wrap_ipv6() {
  case "$1" in
    *:* )
      case "$1" in
        \[*\] ) printf '%s' "$1" ;;
        * ) printf '[%s]' "$1" ;;
      esac ;;
    * ) printf '%s' "$1" ;;
  esac
}

is_placeholder() {
  value=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')
  case "$value" in
    ""|"http://backend"|"http://backend/"|"http://backend:80"|"http://backend:8080"|\
    "https://backend"|"https://backend/"|"https://backend:80"|"https://backend:8080"|\
    "http://leaflock-backend"|"http://leaflock-backend:8080"|\
    "https://leaflock-backend"|"https://leaflock-backend:8080"|\
    "tcp://backend"|"tcp://backend:80"|"tcp://backend:8080"|\
    "http://localhost"|"http://localhost:80"|"http://localhost:8080"|\
    "https://localhost"|"https://localhost:80"|"https://localhost:8080")
      return 0 ;;
  esac
  case "$value" in
    *your-backend*|*placeholder*|*changeme*|*example.com*)
      return 0 ;;
  esac
  return 1
}

normalize_backend_url() {
  raw="$1"
  case "$raw" in
    tcp://*)
      rest=${raw#tcp://}
      host=${rest%:*}
      port=${rest##*:}
      if [ "$host" = "$rest" ]; then
        port="$DEFAULT_BACKEND_PORT"
      elif [ -z "$port" ] || [ "$port" = "$host" ]; then
        port="$DEFAULT_BACKEND_PORT"
      fi
      host=$(wrap_ipv6 "$host")
      printf 'http://%s:%s' "$host" "$port"
      ;;
    http://*|https://*)
      printf '%s' "$raw"
      ;;
    *)
      host_part="$raw"
      port="$DEFAULT_BACKEND_PORT"
      case "$host_part" in
        \[*\]:*)
          port=${host_part##*:}
          host_part=${host_part%:*}
          host_part=${host_part#[}
          host_part=${host_part%]}
          ;;
        \[*\])
          # bracketed IPv6 without port
          ;;
        *:*)
          colon_count=$(printf '%s\n' "$host_part" | awk -F: '{print NF-1}')
          if [ "$colon_count" -eq 1 ]; then
            last_segment=${host_part##*:}
            if printf '%s' "$last_segment" | grep -Eq '^[0-9]+$'; then
              port="$last_segment"
              host_part=${host_part%:$last_segment}
            fi
          fi
          ;;
      esac
      host=$(wrap_ipv6 "$host_part")
      printf 'http://%s:%s' "$host" "$port"
      ;;
  esac
}

find_backend_env_line() {
  suffix="$1"
  env | awk -v keys="$RAILWAY_BACKEND_KEYWORDS" -v suffix="$suffix" '
    BEGIN {
      IGNORECASE = 1
      pattern = "^RAILWAY_SERVICE_.*(" keys ").*" suffix
    }
    $0 ~ pattern { print; exit }
  '
}

BACKEND_INTERNAL_URL="${BACKEND_INTERNAL_URL:-}"

if [ -n "$BACKEND_INTERNAL_URL" ]; then
  BACKEND_SOURCE="BACKEND_INTERNAL_URL"
fi

if [ -z "$BACKEND_INTERNAL_URL" ] && [ -n "${RAILWAY_BACKEND_INTERNAL_URL:-}" ]; then
  BACKEND_INTERNAL_URL="$RAILWAY_BACKEND_INTERNAL_URL"
  BACKEND_SOURCE="RAILWAY_BACKEND_INTERNAL_URL"
fi

if [ -z "$BACKEND_INTERNAL_URL" ] && [ -n "${RAILWAY_BACKEND_TCP_URL:-}" ]; then
  BACKEND_INTERNAL_URL="$RAILWAY_BACKEND_TCP_URL"
  BACKEND_SOURCE="RAILWAY_BACKEND_TCP_URL"
fi

if [ -z "$BACKEND_INTERNAL_URL" ]; then
for suffix in "_HTTP_URL=" "_URL=" "_TCP_PROXY_URL=" "_TCP_URL="; do
  line=$(find_backend_env_line "$suffix")
  if [ -n "$line" ]; then
    candidate=${line#*=}
    if is_placeholder "$candidate"; then
      continue
    fi
    if [ "$suffix" = "_URL=" ] && ! printf '%s' "$candidate" | grep -q '://'; then
      candidate="https://$candidate"
    fi
    if [ "$suffix" = "_TCP_URL=" ] || [ "$suffix" = "_TCP_PROXY_URL=" ]; then
      # Prefer HTTP/HTTPS endpoints when available. Skip raw TCP unless nothing else found.
      if [ -n "$BACKEND_INTERNAL_URL" ]; then
        continue
      fi
    fi
    BACKEND_INTERNAL_URL="$candidate"
    BACKEND_SOURCE=${line%%=*}
    break
  fi
done
fi

if [ -z "$BACKEND_INTERNAL_URL" ]; then
  host_line=$(find_backend_env_line "_HOST=")
  if [ -n "$host_line" ]; then
    backend_host=${host_line#*=}
    backend_base=${host_line%%=*}
    backend_base=${backend_base%_HOST}
    port_var="${backend_base}_PORT"
    eval "backend_port=\"\${${port_var}:-}\""
    if [ -z "$backend_port" ]; then
      backend_port="$DEFAULT_BACKEND_PORT"
    fi
    backend_host=$(wrap_ipv6 "$backend_host")
    BACKEND_INTERNAL_URL="http://${backend_host}:${backend_port}"
    BACKEND_SOURCE="$backend_base"
  fi
fi

if [ -z "$BACKEND_INTERNAL_URL" ]; then
  for var in RAILWAY_BACKEND_PRIVATE_DOMAIN RAILWAY_PRIVATE_DOMAIN_BACKEND RAILWAY_PRIVATE_DOMAIN; do
    eval "candidate=\"\${${var}:-}\""
    if [ -n "$candidate" ]; then
      candidate=$(wrap_ipv6 "$candidate")
      BACKEND_INTERNAL_URL="http://${candidate}:${DEFAULT_BACKEND_PORT}"
      BACKEND_SOURCE="$var"
      break
    fi
  done
fi

if [ -z "$BACKEND_INTERNAL_URL" ]; then
  for var in RAILWAY_BACKEND_PUBLIC_DOMAIN RAILWAY_PUBLIC_DOMAIN_BACKEND RAILWAY_PUBLIC_DOMAIN; do
    eval "candidate=\"\${${var}:-}\""
    if [ -n "$candidate" ]; then
      BACKEND_INTERNAL_URL="https://${candidate}"
      BACKEND_SOURCE="$var"
      break
    fi
  done
fi

if [ -z "$BACKEND_INTERNAL_URL" ] && [ -n "${VITE_API_URL:-}" ]; then
  BACKEND_INTERNAL_URL="$VITE_API_URL"
  BACKEND_SOURCE="VITE_API_URL"
fi

if [ -z "$BACKEND_INTERNAL_URL" ] && command -v nslookup >/dev/null 2>&1; then
  for service_name in backend leaflock-backend api server app; do
    if nslookup "$service_name" >/dev/null 2>&1; then
      BACKEND_INTERNAL_URL="http://${service_name}:${DEFAULT_BACKEND_PORT}"
      BACKEND_SOURCE="dns:${service_name}"
      break
    fi
  done
fi

if [ -z "$BACKEND_INTERNAL_URL" ]; then
  BACKEND_INTERNAL_URL="http://backend:${DEFAULT_BACKEND_PORT}"
  BACKEND_SOURCE="fallback"
fi

BACKEND_INTERNAL_URL=$(normalize_backend_url "$BACKEND_INTERNAL_URL")
export BACKEND_INTERNAL_URL

log "Frontend listening on port ${PORT}"
log "Proxying API to ${BACKEND_INTERNAL_URL} (source: ${BACKEND_SOURCE})"

envsubst '$PORT $BACKEND_INTERNAL_URL' < /etc/nginx/nginx.conf.template > /tmp/nginx.conf

exec nginx -g 'daemon off;' -c /tmp/nginx.conf
