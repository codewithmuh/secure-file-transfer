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

# While the local stack runs, the database tests default to its superuser; they make and drop their
# own databases there (services/api/README.md). Set TEST_DATABASE_URL to use another server.
LOCAL_TEST_DATABASE_URL := postgresql://sft:sft-local-only@127.0.0.1:5432/postgres

test: ## Run all tests with the coverage gates (same as CI); uses the local stack's PostgreSQL if it runs
	@url="$${TEST_DATABASE_URL:-}"; \
	if [[ -z "$$url" ]] && docker compose ps --status running --quiet postgres 2>/dev/null | grep -q .; then \
	  url="$(LOCAL_TEST_DATABASE_URL)"; echo "TEST_DATABASE_URL: the local stack's PostgreSQL"; \
	fi; \
	cd $(PY) && TEST_DATABASE_URL="$$url" uv run pytest

check: lint test web-check ## Everything CI runs before building images

# The web app's CI job, run the same way (needs Node, the version in web/.nvmrc).
.PHONY: web-check
web-check: ## Web app: clean install, type check, lint, tests and build (same as CI)
	@want="v$$(cat web/.nvmrc)"; have="$$(node --version)"; \
	  [[ "$$have" == "$$want" ]] || echo "warning: CI uses Node $$want (web/.nvmrc), this is $$have" >&2
	cd web && npm ci --ignore-scripts && npm run check && npm run build

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

up: ## Run the API (:8000) and the local stack, and wait until all are healthy
	docker compose up --build --detach --wait
	docker compose ps

down: ## Stop and remove local containers (keeps the local data)
	docker compose down --remove-orphans

reset: ## Stop everything and delete the local data (database, S3 objects)
	docker compose down --volumes --remove-orphans

smoke: ## One round trip to every local stack service, and sft_api's row-level security (after make up)
	uv run --script local/smoke.py

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
