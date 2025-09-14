# Deploy LeafLock on Railway

This repo is ready to deploy on Railway as two services: Backend (Go) and Frontend (Vite + Nginx). Below are recommended setups for a simple production deployment.

## Prerequisites

- Railway account and the Railway CLI installed (`npm i -g @railway/cli`)
- A Railway project created (via the UI or CLI)

## Services

### 1) Backend Service (Go)

- Root: `backend/`
- Build: Dockerfile (already present)
- Port: set env var `PORT` (Railway sets this automatically)
- Required environment variables:
  - `JWT_SECRET` (64+ random bytes)
  - `SERVER_ENCRYPTION_KEY` (32 random bytes)
  - `DATABASE_URL` (Provision Railway Postgres; variable auto-populates)
  - `REDIS_URL` (Provision Railway Redis; variable auto-populates)
  - `REDIS_PASSWORD` (from Redis plugin)
  - `ENABLE_REGISTRATION` (set to `false` to disable public sign-ups in production)
  - Optional: `CORS_ORIGINS` (comma‑separated allowed origins, e.g. `https://leaflock.app,https://<frontend-subdomain>.up.railway.app`)

### 2) Frontend Service (Vite + Nginx)

- Root: `frontend/`
- Build: Dockerfile (already present)
- Port: Nginx listens on `$PORT` (templated at runtime)
- Required env vars:
  - `VITE_API_URL` (Backend public URL, e.g. `https://<backend-subdomain>.up.railway.app`)
  - Optional: `VITE_ENABLE_ADMIN_PANEL` (`true|false`)

## Steps (UI)

1. Create a new Railway project.
2. “New Service” → “Deploy from repo” → select this repo.
3. Create Backend service:
   - Select `backend/` as the service root.
   - Keep Dockerfile.
   - Add Railway Postgres and Redis plugins; they will set `DATABASE_URL`, `REDIS_URL`, `REDIS_PASSWORD` automatically.
   - Add `JWT_SECRET` and `SERVER_ENCRYPTION_KEY` secrets.
4. Create Frontend service:
   - Select `frontend/` as the service root; keep Dockerfile.
   - Set `VITE_API_URL` to the Backend’s public URL.
5. For both services, enable a custom domain or use the provided `*.up.railway.app` domain.

## Steps (CLI)

```
# Login and link project
railway login
railway link

# Create services (do once per service)
railway service:create backend
railway service:create frontend

# Set service roots
railway service backend
railway up --service backend --root backend
railway service frontend
railway up --service frontend --root frontend

# Set variables (examples)
railway variables set JWT_SECRET=$(openssl rand -base64 64)
railway variables set SERVER_ENCRYPTION_KEY=$(openssl rand -base64 32)
railway variables set VITE_API_URL=https://<backend>.up.railway.app
# Optional: lock registration in production
railway variables set ENABLE_REGISTRATION=false
```

Or run the helper script to bootstrap everything (requires logged-in CLI):

```
bash scripts/railway-setup.sh

# Or using the root helper CLI
./leaflock.sh railway
```

## Deploy from GitHub (Manual)

You can deploy to Railway from a manual GitHub Action run:

1. Go to Actions → “🚄 Railway Deploy (Manual)”
2. Click “Run workflow” and choose target: backend | frontend | both
3. Ensure repo secret `RAILWAY_TOKEN` is set (Railway account → Tokens)
4. Optionally set `vite_enable_admin_panel` and `enable_registration`

This workflow only runs when manually triggered (workflow_dispatch); it does not run on push.

Required GitHub Secrets
- RAILWAY_TOKEN (use a Project Token from Railway → Project → Settings → Tokens, NOT an account token)
- Optional: RAILWAY_PROJECT_ID (Project → Settings → Developer → Project ID) — not required if your token is a Project Token

Alternatively, you can pass the `project_id` when clicking “Run workflow”.

### Deploy Button (Template)

You can also use Railway's deploy button to start from this repository template. You may still need to adjust service roots (backend/, frontend/) in the Railway UI after creation.

[![Deploy on Railway](https://railway.app/button.svg)](https://railway.app/template/new?template=https://github.com/RelativeSure/notes&plugins=postgresql,redis&envs=JWT_SECRET,SERVER_ENCRYPTION_KEY,ENABLE_REGISTRATION,VITE_API_URL)


## Notes

- Backend already binds to `$PORT` (default 8080). Frontend Nginx now binds to `$PORT` using a templated nginx config.
- For production, set `CORS_ORIGINS` on backend to include your frontend domain(s).
- You can run both services under one project or separate them into two projects.
