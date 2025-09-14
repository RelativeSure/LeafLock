#!/bin/sh
set -eu

# Default port if not provided by platform
: "${PORT:=8080}"

# Render nginx config to a writable location
envsubst '$PORT' < /etc/nginx/nginx.conf.template > /tmp/nginx.conf

# Start nginx in foreground with generated config
exec nginx -g 'daemon off;' -c /tmp/nginx.conf

