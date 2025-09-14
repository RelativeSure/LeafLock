#!/usr/bin/env bash
set -euo pipefail

echo "LeafLock Railway bootstrap"

require() {
  command -v "$1" >/dev/null 2>&1 || { echo "Missing required command: $1"; exit 1; }
}

require railway
require openssl

PROJECT_NAME=${PROJECT_NAME:-leaflock}

echo "Linking to Railway project (run 'railway login' first if needed)..."
railway link || true

echo "Creating services (if they don't exist)"
railway service:create backend || true
railway service:create frontend || true

echo "Generating secrets"
JWT_SECRET=$(openssl rand -base64 64 | tr -d '\n')
SERVER_ENCRYPTION_KEY=$(openssl rand -base64 32 | tr -d '\n')

echo "Configuring backend variables"
railway service backend
railway variables set JWT_SECRET="$JWT_SECRET"
railway variables set SERVER_ENCRYPTION_KEY="$SERVER_ENCRYPTION_KEY"
# DATABASE_URL, REDIS_URL, REDIS_PASSWORD are best provided by Railway plugins
echo "Note: Attach Postgres and Redis plugins to backend service in Railway UI for DATABASE_URL/REDIS_URL."
ENABLE_REGISTRATION=${ENABLE_REGISTRATION:-false}
railway variables set ENABLE_REGISTRATION="$ENABLE_REGISTRATION"

echo "Deploying backend (root ./backend)"
railway up --service backend --root backend

echo "Configuring frontend variables"
railway service frontend
# Try to auto-detect backend domain via Railway CLI; fallback to env
BACKEND_PUBLIC_URL=${BACKEND_PUBLIC_URL:-""}
if [[ -z "$BACKEND_PUBLIC_URL" ]]; then
  # Attempt to read a domain from backend service
  if railway service backend >/dev/null 2>&1; then
    CANDIDATE=$(railway domains 2>/dev/null | awk '/\.up\.railway\.app/ {print $1; exit}') || true
    if [[ -n "$CANDIDATE" ]]; then
      BACKEND_PUBLIC_URL="https://$CANDIDATE"
    fi
  fi
fi
if [[ -z "$BACKEND_PUBLIC_URL" ]]; then
  echo "WARNING: Could not auto-detect backend domain. Set BACKEND_PUBLIC_URL env and re-run if needed."
  BACKEND_PUBLIC_URL="https://YOUR-BACKEND.up.railway.app"
fi
railway variables set VITE_API_URL="$BACKEND_PUBLIC_URL"

echo "Deploying frontend (root ./frontend)"
railway up --service frontend --root frontend

echo "Attempting to configure backend CORS_ORIGINS to include frontend domain..."

# Try to detect frontend domain
railway service frontend
FRONTEND_PUBLIC_URL=${FRONTEND_PUBLIC_URL:-""}
if [[ -z "$FRONTEND_PUBLIC_URL" ]]; then
  CANDIDATE_F=$(railway domains 2>/dev/null | awk '/\.up\.railway\.app/ {print $1; exit}') || true
  if [[ -n "$CANDIDATE_F" ]]; then
    FRONTEND_PUBLIC_URL="https://$CANDIDATE_F"
  fi
fi

railway service backend
if [[ -n "$FRONTEND_PUBLIC_URL" ]]; then
  ORIGINS="https://leaflock.app,$FRONTEND_PUBLIC_URL"
  railway variables set CORS_ORIGINS="$ORIGINS"
  echo "Set backend CORS_ORIGINS to: $ORIGINS"
else
  echo "WARNING: Could not detect frontend domain. Set backend CORS_ORIGINS manually to include your frontend URL."
fi

echo "Done. Verify VITE_API_URL and CORS_ORIGINS reflect your actual Railway domains."
