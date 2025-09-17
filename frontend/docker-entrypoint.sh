#!/bin/sh
set -eu

# Default port to 80 for standard web service deployment
: "${PORT:=80}"

# Render nginx config to a writable location
# Require BACKEND_INTERNAL_URL (e.g., http://backend:8080). Fail fast if missing.
if [ -z "${BACKEND_INTERNAL_URL:-}" ]; then
  echo "ERROR: BACKEND_INTERNAL_URL is not set (expected like http://backend:8080)" >&2
  exit 1
fi

envsubst '$PORT $BACKEND_INTERNAL_URL' < /etc/nginx/nginx.conf.template > /tmp/nginx.conf

# Start nginx in foreground with generated config
exec nginx -g 'daemon off;' -c /tmp/nginx.conf
