SHELL := bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help

PY := services/api

.PHONY: help setup fmt lint test check scan build up down logs clean

help: ## Show available commands
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-8s\033[0m %s\n", $$1, $$2}'

setup: ## Install dependencies and the git hooks (needs uv and pre-commit)
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

up: ## Run all services locally (API on :8000)
	docker compose up --build --detach --wait
	docker compose ps

down: ## Stop and remove local containers
	docker compose down --remove-orphans

logs: ## Follow logs of all services
	docker compose logs --follow

clean: ## Remove build, test and cache artifacts
	rm -rf $(PY)/.venv $(PY)/.pytest_cache $(PY)/.mypy_cache $(PY)/.ruff_cache $(PY)/.coverage

# Terraform under infra/ (infra/README.md). The tools run from pinned container images, so only Docker is needed.
.PHONY: infra-fmt infra-check

infra-fmt: ## Format the Terraform under infra/
	infra/scripts/check.sh fmt-fix

infra-check: ## Check infra/: conventions, fmt, validate, tflint and Trivy (same as CI)
	infra/scripts/check.sh all
