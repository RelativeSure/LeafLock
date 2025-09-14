.PHONY: help up down down-prune up-again restart logs clean build build-all build-frontend build-backend rebuild-all rebuild-frontend rebuild-backend rebuild-up dev prod kube systemd status

# Compose driver selection (override with: COMPOSE_DRIVER=docker|docker-compose|podman-compose|kube)
COMPOSE_DRIVER ?= auto

# Detection of available tools
DOCKER                 := $(shell command -v docker 2>/dev/null)
DOCKER_COMPOSE_PLUGIN  := $(shell [ -n "$(DOCKER)" ] && docker compose version >/dev/null 2>&1 && echo yes)
DOCKER_COMPOSE_BIN     := $(shell command -v docker-compose 2>/dev/null)
PODMAN_COMPOSE_BIN     := $(shell command -v podman-compose 2>/dev/null)

# Resolve compose command with preference: docker compose -> docker-compose -> podman-compose -> kube
# Also determine the underlying engine for pruning helpers
ifeq ($(COMPOSE_DRIVER),docker)
  COMPOSE_CMD := docker compose
  ENGINE := docker
else ifeq ($(COMPOSE_DRIVER),docker-compose)
  COMPOSE_CMD := docker-compose
  ENGINE := docker
else ifeq ($(COMPOSE_DRIVER),podman-compose)
  COMPOSE_CMD := podman-compose
  ENGINE := podman
else ifeq ($(COMPOSE_DRIVER),kube)
  COMPOSE_CMD := podman_kube_play
  ENGINE := podman
else
  ifeq ($(DOCKER_COMPOSE_PLUGIN),yes)
    COMPOSE_CMD := docker compose
    ENGINE := docker
  else ifneq ($(DOCKER_COMPOSE_BIN),)
    COMPOSE_CMD := docker-compose
    ENGINE := docker
  else ifneq ($(PODMAN_COMPOSE_BIN),)
    COMPOSE_CMD := podman-compose
    ENGINE := podman
  else
    COMPOSE_CMD := podman_kube_play
    ENGINE := podman
  endif
endif

help: ## Show help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

up: ## Start stack (prefers Docker, falls back to Podman/kube)
ifeq ($(COMPOSE_CMD),podman_kube_play)
	@if [ ! -f leaflock-kube.yaml ]; then $(MAKE) kube; fi
	podman play kube leaflock-kube.yaml
else
	$(COMPOSE_CMD) up -d --build
endif
	@echo "✅ LeafLock is running!"
	@echo "📝 Frontend: http://localhost:3000"
	@echo "🔌 Backend: http://localhost:8080"

down: ## Stop all containers
ifeq ($(COMPOSE_CMD),podman_kube_play)
	@if [ -f leaflock-kube.yaml ]; then podman play kube --down leaflock-kube.yaml; fi
else
	$(COMPOSE_CMD) down
endif

down-prune: ## Stop stack and prune all related artifacts (DANGEROUS)
ifeq ($(ENGINE),docker)
	$(COMPOSE_CMD) down -v --remove-orphans --rmi local || true
	-docker system prune -af --volumes
else
ifeq ($(COMPOSE_CMD),podman_kube_play)
	@if [ -f leaflock-kube.yaml ]; then podman play kube --down leaflock-kube.yaml; fi
else
	$(COMPOSE_CMD) down -v || true
endif
	-podman system prune -af
	-podman volume prune -f
endif

up-again: ## Bring stack up without rebuilding (after DB becomes healthy)
ifeq ($(COMPOSE_CMD),podman_kube_play)
	@if [ ! -f leaflock-kube.yaml ]; then $(MAKE) kube; fi
	podman play kube leaflock-kube.yaml
else
	$(COMPOSE_CMD) up -d
endif

restart: ## Restart all containers
ifeq ($(COMPOSE_CMD),podman_kube_play)
	@if [ ! -f leaflock-kube.yaml ]; then $(MAKE) kube; fi
	podman play kube --replace leaflock-kube.yaml
else
	$(COMPOSE_CMD) restart
endif

logs: ## View backend logs
ifeq ($(COMPOSE_CMD),podman_kube_play)
	podman logs -f leaflock-backend
else
	$(COMPOSE_CMD) logs -f backend
endif

clean: ## Clean everything
	podman pod rm -f leaflock || true
	podman volume prune -f

build: ## Build containers/images
ifeq ($(COMPOSE_CMD),podman_kube_play)
	podman build -t localhost/leaflock-backend:latest -f backend/Containerfile backend/
	podman build -t localhost/leaflock-frontend:latest -f frontend/Containerfile frontend/
else
	$(COMPOSE_CMD) build
endif

build-all: ## Build both frontend and backend images
ifeq ($(COMPOSE_CMD),podman_kube_play)
	podman build -t localhost/leaflock-backend:latest -f backend/Containerfile backend/
	podman build -t localhost/leaflock-frontend:latest -f frontend/Containerfile frontend/
else
	$(COMPOSE_CMD) build
endif

build-frontend: ## Build only the frontend image
ifeq ($(COMPOSE_CMD),podman_kube_play)
	podman build -t localhost/leaflock-frontend:latest -f frontend/Containerfile frontend/
else
	$(COMPOSE_CMD) build frontend
endif

build-backend: ## Build only the backend image
ifeq ($(COMPOSE_CMD),podman_kube_play)
	podman build -t localhost/leaflock-backend:latest -f backend/Containerfile backend/
else
	$(COMPOSE_CMD) build backend
endif

rebuild-frontend: ## Rebuild frontend without cache
ifeq ($(COMPOSE_CMD),podman_kube_play)
	podman build --no-cache -t localhost/leaflock-frontend:latest -f frontend/Containerfile frontend/
else
	$(COMPOSE_CMD) build --no-cache frontend
endif

rebuild-backend: ## Rebuild backend without cache
ifeq ($(COMPOSE_CMD),podman_kube_play)
	podman build --no-cache -t localhost/leaflock-backend:latest -f backend/Containerfile backend/
else
	$(COMPOSE_CMD) build --no-cache backend
endif

rebuild-all: ## Rebuild both frontend and backend without cache
ifeq ($(COMPOSE_CMD),podman_kube_play)
	podman build --no-cache -t localhost/leaflock-backend:latest -f backend/Containerfile backend/
	podman build --no-cache -t localhost/leaflock-frontend:latest -f frontend/Containerfile frontend/
else
	$(COMPOSE_CMD) build --no-cache
endif

rebuild-up: ## Rebuild all without cache and start the stack
	@if [ ! -f leaflock-kube.yaml ]; then $(MAKE) kube; fi
	$(MAKE) rebuild-all
	podman play kube --replace leaflock-kube.yaml
else
	$(COMPOSE_CMD) down || true
	$(COMPOSE_CMD) build --no-cache
	$(COMPOSE_CMD) up -d
endif

rootless-setup: ## Setup rootless podman
	@./setup-podman.sh setup_rootless

systemd: ## Setup systemd service
	systemctl --user enable --now leaflock.service

status: ## Check status
ifeq ($(COMPOSE_CMD),podman_kube_play)
	podman pod ps
	podman ps -a --pod
else
	$(COMPOSE_CMD) ps
endif

kube: ## Generate Kubernetes YAML
	podman generate kube leaflock > leaflock-kube.yaml
	@echo "Generated: leaflock-kube.yaml"

security-scan: ## Security scan containers
	podman image scan localhost/leaflock-backend:latest
	podman image scan localhost/leaflock-frontend:latest

export: ## Export as OCI archive
	podman save -o leaflock-backend.tar localhost/leaflock-backend:latest
	podman save -o leaflock-frontend.tar localhost/leaflock-frontend:latest
	@echo "✅ Images exported"

import: ## Import from OCI archive
	podman load -i leaflock-backend.tar
	podman load -i leaflock-frontend.tar
	@echo "✅ Images imported"
