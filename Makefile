.PHONY: help up down restart logs ps clean

COMPOSE ?= docker compose

help:
	@echo "LeafLock helper targets:"
	@echo "  make up       # docker compose up --build"
	@echo "  make down     # docker compose down"
	@echo "  make restart  # rebuild and restart the stack"
	@echo "  make logs     # follow logs for all services"
	@echo "  make ps       # list running containers"
	@echo "  make clean    # down + remove volumes"

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
