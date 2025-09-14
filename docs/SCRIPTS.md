# Scripts Overview

Use `./leaflock.sh` for common tasks:

```
./leaflock.sh help
./leaflock.sh icons          # regenerate icons
./leaflock.sh railway        # bootstrap Railway backend+frontend
./leaflock.sh docker:up      # compose up -d --build
./leaflock.sh docker:down
./leaflock.sh docker:build
./leaflock.sh k8s:deploy     # wrapper for deploy-k8s.sh
./leaflock.sh health         # wrapper for health-check.sh
./leaflock.sh troubleshoot   # wrapper for troubleshoot.sh
./leaflock.sh test           # wrapper for test-automation.sh
```

Specialized/advanced scripts (kept for CI or niche flows):
- `deploy-k8s.sh`, `deploy.sh`, `deploy-docker.sh`, `deploy-from-ghcr.sh`
- `setup-docker.sh`, `setup-podman.sh`, `podman-kube-play.sh`
- `health-check.sh`, `troubleshoot.sh`, `test-automation.sh`
- `env-setup.sh`, `dev-setup.sh`, `dev-watch.sh`, `init-ssl*.sh`

Recommendation: start with `leaflock.sh`. Use the specialized scripts when you need fine‑grained control or CI integration.
