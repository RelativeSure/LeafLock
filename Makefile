.PHONY: help up down restart logs ps clean rm clean-caches

COMPOSE ?= docker compose

help:
	@echo "LeafLock helper targets:"
	@echo "  make up       # docker compose up --build"
	@echo "  make down     # docker compose down"
	@echo "  make restart  # rebuild and restart the stack"
	@echo "  make logs     # follow logs for all services"
	@echo "  make ps       # list running containers"
	@echo "  make clean    # down + remove volumes"
	@echo "  make rm       # remove stopped containers created by compose"
	@echo "  make clean-caches # remove local build/tool caches"

up:
	$(COMPOSE) up --build

down:
	$(COMPOSE) down

restart:
	$(COMPOSE) down
	$(COMPOSE) up --build

logs:
	$(COMPOSE) logs -f

ps:
	$(COMPOSE) ps

clean:
	$(COMPOSE) down -v

rm:
	$(COMPOSE) rm -sf

clean-caches:
	@echo "Cleaning local caches (Playwright, pnpm, go, npm, docker, apt)..."
	rm -rf $$HOME/.cache/ms-playwright $$HOME/.cache/pnpm $$HOME/.cache/pre-commit $$HOME/.cache/act $$HOME/.cache/go-build 2>/dev/null || true
	rm -rf $$HOME/.cache/actcache $$HOME/.cache/uv $$HOME/.cache/claude-cli-nodejs $$HOME/.cache/google-chrome 2>/dev/null || true
	go clean -cache -modcache >/dev/null 2>&1 || true
	npm cache clean --force >/dev/null 2>&1 || true
	docker system prune -af --volumes >/dev/null 2>&1 || true
	sudo apt-get clean >/dev/null 2>&1 || true
	@echo "Cache cleanup complete."
