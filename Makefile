# Keygate developer commands. Run `make help` for the list.

SHELL := /bin/bash
.DEFAULT_GOAL := help

# Load .env (if present) so host-run tests use the same credentials as docker compose.
-include .env
export

API_DIR := apps/api
WEB_DIR := apps/web
COMPOSE := docker compose

# Host-side URLs for the compose Postgres/Redis (published on 127.0.0.1 only).
HOST_DATABASE_URL := postgresql+asyncpg://$(POSTGRES_USER):$(POSTGRES_PASSWORD)@127.0.0.1:$(or $(POSTGRES_PORT),5432)/$(POSTGRES_DB)
HOST_REDIS_URL := redis://:$(REDIS_PASSWORD)@127.0.0.1:$(or $(REDIS_PORT),6379)/0

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

.env:
	cp .env.example .env
	@echo "Created .env from .env.example (local development values)."

# ---------------------------------------------------------------- setup

.PHONY: install
install: .env ## Install local toolchains, deps and git hooks
	cd $(API_DIR) && uv sync
	cd $(WEB_DIR) && pnpm install --frozen-lockfile && pnpm exec playwright install chromium
	pre-commit install

# ---------------------------------------------------------------- run

.PHONY: dev
dev: .env ## Start the full stack (http://localhost)
	$(COMPOSE) up --build

.PHONY: up
up: .env ## Start the full stack in the background and wait until healthy
	$(COMPOSE) up --build --detach --wait

.PHONY: down
down: ## Stop the stack (keeps data volumes)
	$(COMPOSE) down

.PHONY: reset
reset: ## Stop the stack and DELETE local database/redis volumes
	$(COMPOSE) down --volumes

.PHONY: logs
logs: ## Tail logs from all services
	$(COMPOSE) logs -f

.PHONY: migrate
migrate: ## Apply database migrations
	$(COMPOSE) exec api alembic upgrade head

.PHONY: migration
migration: ## Create a migration: make migration m="add users table"
	@test -n "$(m)" || (echo 'usage: make migration m="message"' && exit 1)
	$(COMPOSE) exec api alembic revision --autogenerate -m "$(m)"

# ---------------------------------------------------------------- quality

.PHONY: services
services: .env
	$(COMPOSE) up --detach --wait postgres redis

.PHONY: test
test: test-api test-web ## Run all tests

.PHONY: test-api
test-api: services ## API tests (unit + integration against compose Postgres/Redis)
	cd $(API_DIR) && KEYGATE_DATABASE_URL='$(HOST_DATABASE_URL)' KEYGATE_REDIS_URL='$(HOST_REDIS_URL)' \
		uv run pytest --cov --cov-report=term

.PHONY: test-web
test-web: ## Web end-to-end tests (Playwright, production build)
	cd $(WEB_DIR) && pnpm test

.PHONY: lint
lint: lint-api lint-web ## Lint, format-check and type-check everything

.PHONY: lint-api
lint-api:
	cd $(API_DIR) && uv run ruff check . && uv run ruff format --check . && uv run mypy

.PHONY: lint-web
lint-web:
	cd $(WEB_DIR) && pnpm lint && pnpm format:check && pnpm typecheck

.PHONY: format
format: ## Auto-format all code
	cd $(API_DIR) && uv run ruff check --fix . && uv run ruff format .
	cd $(WEB_DIR) && pnpm format

.PHONY: secrets-scan
secrets-scan: ## Scan the working tree and git history for secrets
	gitleaks git . --no-banner --redact
	gitleaks dir . --no-banner --redact
