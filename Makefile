SHELL := bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help

PY := services/api

.PHONY: help setup fmt lint test check scan build up down logs clean
.PHONY: prereqs reset smoke

help: ## Show available commands
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-8s\033[0m %s\n", $$1, $$2}'

prereqs: ## Check that docker (with compose), uv and pre-commit are installed
	@missing=0; \
	for tool in docker uv pre-commit; do \
	  command -v "$$tool" >/dev/null 2>&1 || { echo "missing: $$tool (CONTRIBUTING.md, Set up, says how to install it)"; missing=1; }; \
	done; \
	if command -v docker >/dev/null 2>&1 && ! docker compose version >/dev/null 2>&1; then \
	  echo "missing: the docker compose plugin (Compose v2, docs/local-development.md)"; missing=1; \
	fi; \
	exit "$$missing"

setup: prereqs ## Install dependencies and the git hooks (needs docker, uv and pre-commit)
	cd $(PY) && uv sync
	pre-commit install

fmt: ## Format all code
	cd $(PY) && uv run ruff format . && uv run ruff check --fix .

lint: ## Lint, type-check and check the import layers (same as CI)
	cd $(PY) && uv run ruff format --check . && uv run ruff check . && uv run mypy && uv run lint-imports

test: ## Run all tests with the coverage gates (same as CI)
	cd $(PY) && uv run pytest

check: lint test ## Everything CI runs before building images

scan: ## Secret and vulnerability scans (needs gitleaks and trivy)
	gitleaks git --redact --no-banner .
	trivy fs --scanners vuln,misconfig,secret --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 .

build: ## Build all container images
	docker compose build

up: ## Run the API (:8000) and the local stack, and wait until all are healthy
	docker compose up --build --detach --wait
	docker compose ps

down: ## Stop and remove local containers (keeps the local data)
	docker compose down --remove-orphans

reset: ## Stop everything and delete the local data (database, S3 objects)
	docker compose down --volumes --remove-orphans

smoke: ## One round trip to every local stack service (after make up)
	uv run --script local/smoke.py

logs: ## Follow logs of all services
	docker compose logs --follow

clean: ## Remove build, test and cache artifacts
	rm -rf $(PY)/.venv $(PY)/.pytest_cache $(PY)/.mypy_cache $(PY)/.ruff_cache $(PY)/.coverage
