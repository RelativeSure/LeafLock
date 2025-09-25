#!/usr/bin/env bash
set -euo pipefail

cmd=${1:-help}
shift || true

here() { cd "$(dirname "$0")"/..; }
here

usage() {
  cat <<EOF
LeafLock helper CLI

Usage: ./leaflock.sh <command> [args]

Common commands:
  icons             Regenerate all favicons and PWA icons
  railway           Bootstrap Railway services (backend+frontend)
  docker:up         Start local stack via docker compose
  docker:down       Stop local stack
  docker:build      Build images via compose
  k8s:deploy        Deploy Helm chart to Kubernetes (scripts/deploy-k8s.sh)
  health            Run health checks (scripts/health-check.sh)
  troubleshoot      Run troubleshooting (scripts/troubleshoot.sh)
  test              Run full test automation (scripts/test-automation.sh)
  help              Show this help

Environment:
  BACKEND_PUBLIC_URL, FRONTEND_PUBLIC_URL (railway)
  ENABLE_REGISTRATION=true|false (railway backend)
EOF
}

case "$cmd" in
  icons)
    node scripts/generate-icons.mjs ;;
  railway)
    bash scripts/railway-setup.sh "$@" ;;
  docker:up)
    docker compose up -d --build ;;
  docker:down)
    docker compose down ;;
  docker:build)
    docker compose build ;;
  k8s:deploy)
    bash scripts/deploy-k8s.sh "$@" ;;
  health)
    bash scripts/health-check.sh full ;;
  troubleshoot)
    bash scripts/troubleshoot.sh "$@" ;;
  test)
    bash scripts/test-automation.sh "$@" ;;
  help|-h|--help|*)
    usage ;;
esac
