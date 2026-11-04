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

# The API contract checks, as .github/workflows/contract.yml runs them (docs/api/README.md section 11).
# The breaking-change check compares the working tree's contract with the one at the merge base of
# HEAD and CONTRACT_BASE. OASDIFF_IMAGE is the workflow's: keep the two in step.
CONTRACT_BASE ?= origin/main
OASDIFF_IMAGE := tufin/oasdiff:v1.34.1@sha256:67a23cfea7d251e2ae34ee703ac8733c5d96bc2e7b90fd0f4d475ec99367b85f

.PHONY: contract
contract: ## API contract checks (same as CI): generated spec and breaking changes (needs Docker)
	cd $(PY) && uv run python -m tools.contract_check
	@base="$$(git merge-base $(CONTRACT_BASE) HEAD)"; \
	echo "Breaking-change check: docs/api/openapi.yaml against $(CONTRACT_BASE) at $${base:0:12}"; \
	status=0; \
	git show "$$base:docs/api/openapi.yaml" | docker run --rm --interactive --network none --read-only \
	  --cap-drop ALL --security-opt no-new-privileges --user "$$(id -u):$$(id -g)" \
	  --volume "$(CURDIR)/docs/api:/contract:ro" $(OASDIFF_IMAGE) \
	  breaking - /contract/openapi.yaml --fail-on WARN \
	  --allow-external-refs=false --flatten-allof --flatten-params || status=$$?; \
	case "$$status" in \
	  0) echo "No breaking changes." ;; \
	  1) echo "Breaking: make the change backwards compatible, or the pull request needs the breaking label."; exit 1 ;; \
	  *) echo "oasdiff couldn't read a contract (exit status $$status)."; exit 1 ;; \
	esac

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
