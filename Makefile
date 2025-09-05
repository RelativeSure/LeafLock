.PHONY: help up down restart logs clean build dev prod kube systemd

COMPOSE_CMD := $(shell command -v podman-compose 2> /dev/null)

ifndef COMPOSE_CMD
    COMPOSE_CMD := podman_kube_play
endif

help: ## Show help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

up: ## Start with podman-compose
ifeq ($(COMPOSE_CMD),podman_kube_play)
	podman play kube secure-notes-kube.yaml
else
	podman-compose up -d
endif
	@echo "✅ Secure Notes is running!"
	@echo "📝 Frontend: http://localhost:3000"
	@echo "🔌 Backend: http://localhost:8080"

down: ## Stop all containers
ifeq ($(COMPOSE_CMD),podman_kube_play)
	podman play kube --down secure-notes-kube.yaml
else
	podman-compose down
endif

restart: ## Restart all containers
ifeq ($(COMPOSE_CMD),podman_kube_play)
	podman play kube --replace secure-notes-kube.yaml
else
	podman-compose restart
endif

logs: ## View logs
	podman logs -f secure-notes-backend

clean: ## Clean everything
	podman pod rm -f secure-notes || true
	podman volume prune -f

build: ## Build containers
	podman build -t localhost/secure-notes-backend:latest -f backend/Containerfile backend/
	podman build -t localhost/secure-notes-frontend:latest -f frontend/Containerfile frontend/

rootless-setup: ## Setup rootless podman
	@./setup-podman.sh setup_rootless

systemd: ## Setup systemd service
	systemctl --user enable --now secure-notes.service

status: ## Check status
	podman pod ps
	podman ps -a --pod

kube: ## Generate Kubernetes YAML
	podman generate kube secure-notes > secure-notes-kube.yaml
	@echo "Generated: secure-notes-kube.yaml"

security-scan: ## Security scan containers
	podman image scan localhost/secure-notes-backend:latest
	podman image scan localhost/secure-notes-frontend:latest

export: ## Export as OCI archive
	podman save -o secure-notes-backend.tar localhost/secure-notes-backend:latest
	podman save -o secure-notes-frontend.tar localhost/secure-notes-frontend:latest
	@echo "✅ Images exported"

import: ## Import from OCI archive
	podman load -i secure-notes-backend.tar
	podman load -i secure-notes-frontend.tar
	@echo "✅ Images imported"
