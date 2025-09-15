#!/usr/bin/env bash
set -euo pipefail

# Coolify API bootstrap script (template)
# - Attaches a Postgres resource to a backend app
# - Sets frontend env vars to proxy to the private backend via Nginx
# - Triggers redeploys
#
# Requirements
# - Coolify v4+ with API enabled
# - An API token with permissions for the target project/resources
# - Resource IDs (or names) for backend app, frontend app, and Postgres database
#
# Usage
#   Export the variables below and run: bash scripts/coolify-setup.sh
#   This script prints the curl commands it runs. Adjust endpoints if your Coolify version differs.

: "${COOLIFY_URL:?Set COOLIFY_URL, e.g. https://coolify.example.com}"
: "${COOLIFY_TOKEN:?Set COOLIFY_TOKEN with a Coolify API token}"

# Resource UUIDs (preferred) or numeric IDs depending on your instance.
# You can also set *_NAME and adapt the lookup logic below.
: "${BACKEND_ID:?Set BACKEND_ID (backend application resource ID/UUID)}"
: "${FRONTEND_ID:?Set FRONTEND_ID (frontend application resource ID/UUID)}"
: "${POSTGRES_ID:?Set POSTGRES_ID (Postgres database resource ID/UUID)}"

# Frontend envs
: "${BACKEND_INTERNAL_URL:?Set BACKEND_INTERNAL_URL (e.g., http://backend:8080)}"
VITE_API_URL="/api"

auth_header=("Authorization: Bearer ${COOLIFY_TOKEN}")
json_header=("Content-Type: application/json")

echo "Coolify URL: ${COOLIFY_URL}"

api_get() {
  local path="$1"
  echo curl -sS -H "${auth_header}" "${COOLIFY_URL}${path}" 1>&2
  curl -sS -H "${auth_header}" "${COOLIFY_URL}${path}"
}

api_post() {
  local path="$1"; shift
  local body="$1"
  echo curl -sS -X POST -H "${auth_header}" -H "${json_header}" -d "${body}" "${COOLIFY_URL}${path}" 1>&2
  curl -sS -X POST -H "${auth_header}" -H "${json_header}" -d "${body}" "${COOLIFY_URL}${path}"
}

api_put() {
  local path="$1"; shift
  local body="$1"
  echo curl -sS -X PUT -H "${auth_header}" -H "${json_header}" -d "${body}" "${COOLIFY_URL}${path}" 1>&2
  curl -sS -X PUT -H "${auth_header}" -H "${json_header}" -d "${body}" "${COOLIFY_URL}${path}"
}

echo "\n==> Attaching Postgres to backend (private)"
# NOTE: Endpoint path can vary slightly across Coolify versions. If this 404s, check your version's API docs.
# Expected behavior: creates an attachment so DB env vars (POSTGRESQL_*) inject into the backend app.
api_post "/api/v1/resources/${BACKEND_ID}/attachments" "$(jq -n --arg db "${POSTGRES_ID}" '{database_id: $db}')" || {
  echo "Attachment endpoint may differ on your Coolify version. Please adjust the path." >&2
}

echo "\n==> Upserting frontend env vars (VITE_API_URL, BACKEND_INTERNAL_URL)"
# Upsert environment variables for the frontend app. On some versions, the endpoint is /environment-variables, others /secrets.
# The payload shape may differ; two common patterns are shown below. The script tries PUT first, then POST.

ENV_PAYLOAD=$(jq -n \
  --arg k1 "VITE_API_URL" --arg v1 "${VITE_API_URL}" \
  --arg k2 "BACKEND_INTERNAL_URL" --arg v2 "${BACKEND_INTERNAL_URL}" \
  '{variables: [ { key: $k1, value: $v1, is_build_time: true }, { key: $k2, value: $v2, is_build_time: false } ] }')

# Try PUT bulk upsert
if ! api_put "/api/v1/resources/${FRONTEND_ID}/environment-variables" "${ENV_PAYLOAD}"; then
  echo "PUT environment-variables failed, trying POST alternative..." >&2
  # Alternative single upserts
  api_post "/api/v1/resources/${FRONTEND_ID}/environment-variables" "$(jq -n --arg key "VITE_API_URL" --arg value "${VITE_API_URL}" '{key:$key, value:$value, is_build_time:true}')" || true
  api_post "/api/v1/resources/${FRONTEND_ID}/environment-variables" "$(jq -n --arg key "BACKEND_INTERNAL_URL" --arg value "${BACKEND_INTERNAL_URL}" '{key:$key, value:$value, is_build_time:false}')" || true
fi

echo "\n==> Triggering redeploys (backend then frontend)"
# Redeploy endpoints can be /api/v1/resources/{id}/deploy or /api/v1/applications/{id}/deploy
api_post "/api/v1/resources/${BACKEND_ID}/deploy" '{}' || echo "Fallback: try /api/v1/applications/${BACKEND_ID}/deploy" >&2
api_post "/api/v1/resources/${FRONTEND_ID}/deploy" '{}' || echo "Fallback: try /api/v1/applications/${FRONTEND_ID}/deploy" >&2

echo "\nAll requests attempted. If any step failed, please check your Coolify version and adjust endpoint paths accordingly."

