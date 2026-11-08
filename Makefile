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
web-check: ## Web app: clean install, type check, lint, tests, build and generated API client (same as CI)
	@want="v$$(cat web/.nvmrc)"; have="$$(node --version)"; \
	  [[ "$$have" == "$$want" ]] || echo "warning: CI uses Node $$want (web/.nvmrc), this is $$have" >&2
	cd web && npm ci --ignore-scripts && npm run check && npm run build
	@before="$$(mktemp)"; trap 'rm -f "$$before"' EXIT; cp web/src/api/schema.ts "$$before"; \
	  (cd web && npm run --silent gen:api >/dev/null); \
	  cmp -s "$$before" web/src/api/schema.ts || { echo "error: web/src/api/schema.ts was out of date with" \
	    "docs/api/openapi.yaml; it is regenerated now: review it and commit it with the contract" >&2; exit 1; }

# axe accessibility checks in English and Japanese (NFR-22, FR-33), as CI's web-a11y job runs them. Install, build,
# `vite preview` and the browser all run in the pinned Playwright image, so no browser is installed on the host. web/
# is mounted read-only and copied, without node_modules, dist and test-results, to a path inside the container, so the
# run writes nothing to the host: no root-owned files on a Linux host, and the host's node_modules is untouched.
# PLAYWRIGHT_VERSION must equal @playwright/test in web/package.json: the target checks that first.
PLAYWRIGHT_VERSION := 1.64.0
PLAYWRIGHT_IMAGE := mcr.microsoft.com/playwright:v$(PLAYWRIGHT_VERSION)-noble@sha256:06a9939e57531807f8d5fd76ce44b53165ffb7d7501d87ab10e285c20b1e971f
.PHONY: web-a11y
web-a11y: ## Web app: axe accessibility checks on every page, in English and Japanese (needs Docker)
	docker run --rm --init --ipc=host --volume "$(CURDIR)/web:/src/web:ro" --workdir /web \
	  $(PLAYWRIGHT_IMAGE) bash -euo pipefail -c 'tar -C /src/web --exclude=./node_modules --exclude=./dist \
	    --exclude=./test-results -cf - . | tar -xf - \
	    && npm ci --ignore-scripts \
	    && test "$$(npx playwright --version)" = "Version $(PLAYWRIGHT_VERSION)" \
	    && npm run build && npx playwright test'

# Browser flows against the running stack (#195 to #200; after `make up` and `make seed`), in the same pinned
# Playwright image, so no browser is installed on the host: #200's M3 journey in English and Japanese, and the other
# flows in English. The browser must see the stack as a person does, at http://localhost:3000, :8000, :8180, :8025 and
# :9090. On Linux (CI) the container shares the host's network. Docker Desktop (macOS) has no host networking by
# default, so there web/e2e/support/forward.mjs listens on those ports inside the container and forwards them to
# host.docker.internal, where the stack's 127.0.0.1 ports are. The journey runs the lifecycle jobs with the clock moved
# on (#181, #182); the container has no Docker, so local/e2e-jobs.sh runs them on the host for it, through request
# files in a temporary folder. The report, traces and screenshots are copied to web/test-results/ (owned by you).
# E2E_ARGS passes options on, e.g. E2E_ARGS='e2e/admin.e2e.ts' or E2E_ARGS='--project ja'.
E2E_ARGS ?=
ifeq ($(shell uname -s),Linux)
E2E_NETWORK := --network host
E2E_FORWARD := true
else
E2E_NETWORK :=
E2E_FORWARD := (node e2e/support/forward.mjs &) && sleep 1
endif
.PHONY: web-e2e
web-e2e: ## Web app: browser flows and the M3 journey against the running local stack (needs make up and make seed, and Docker)
	@mkdir -p web/test-results
	@jobs="$$(mktemp -d)"; runner=""; \
	trap '[[ -z "$$runner" ]] || kill "$$runner" 2>/dev/null; rm -rf "$$jobs"' EXIT; \
	local/e2e-jobs.sh "$$jobs" & runner=$$!; \
	docker run --rm --init --ipc=host $(E2E_NETWORK) --volume "$(CURDIR)/web:/src/web:ro" \
	  --volume "$$jobs:/jobs" --env E2E_JOBS_DIR=/jobs --volume "$(CURDIR)/web/test-results:/out" \
	  --env HOST_IDS="$$(id -u):$$(id -g)" --workdir /web \
	  $(PLAYWRIGHT_IMAGE) bash -euo pipefail -c 'tar -C /src/web --exclude=./node_modules --exclude=./dist \
	    --exclude=./test-results -cf - . | tar -xf - \
	    && npm ci --ignore-scripts \
	    && test "$$(npx playwright --version)" = "Version $(PLAYWRIGHT_VERSION)" \
	    && $(E2E_FORWARD) && status=0 \
	    && { npx playwright test --config playwright.e2e.config.ts $(E2E_ARGS) || status=$$?; } \
	    && { cp -a test-results/. /out/ 2>/dev/null || true; chown -R "$$HOST_IDS" /out; exit "$$status"; }'

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

# The local seed (#182): the local-keycloak connection, a tenant, an admin and a member who sign in
# through the stack's Keycloak. Idempotent; refuses anything but the local stack.
.PHONY: seed jobs field-keys e2e
seed: ## Seed the local stack with a tenant, an admin and a member, and print how to sign in (after make up)
	uv run --script local/seed.py

# The lifecycle jobs (#181), one-shot as M4's CronJobs: JOB=expiry|deletion|reconciliation|storage-audit|cleanup.
# --build: `make up` builds only the services it starts, so the jobs' image would otherwise be stale.
JOB ?= reconciliation
jobs: ## Run one lifecycle job against the local stack: make jobs JOB=deletion (after make up)
	docker compose --profile jobs run --build --rm --no-deps jobs $(JOB)

# The field key job (#236), as the API's workload: STEP=backfill|rotate|rewrap|purge.
STEP ?= backfill
field-keys: ## Run one field key job step against the local stack: make field-keys STEP=backfill (after make up)
	docker compose --profile jobs run --build --rm --no-deps field-keys $(STEP)

# The M2 journey test (#182) against `make up` and `make seed`: one test, steps 1 to 9 of the M2 exit
# criterion, through the public API, Mailpit's API, S3's API, the job commands and the clock hook.
e2e: ## The M2 end-to-end journey test against the local stack (after make up and make seed)
	cd $(PY) && SFT_E2E=1 uv run pytest -m e2e --no-cov -p no:cacheprovider tests/test_journey.py

logs: ## Follow logs of all services
	docker compose logs --follow

clean: ## Remove build, test and cache artifacts
	rm -rf $(PY)/.venv $(PY)/.pytest_cache $(PY)/.mypy_cache $(PY)/.ruff_cache $(PY)/.coverage

# Terraform under infra/ (infra/README.md). The tools run from pinned container images, so only Docker is needed.
.PHONY: infra-fmt infra-check

infra-fmt: ## Format the Terraform under infra/
	infra/scripts/check.sh fmt-fix

infra-check: ## Check infra/: conventions, fmt, validate, tflint, Trivy and terraform test (same as CI)
	infra/scripts/check.sh all

# The deploy config under deploy/ (deploy/README.md): needs helm 3, kubeconform and Docker, at the versions in ci.yml.
.PHONY: deploy-check
deploy-check: ## Check deploy/: helm lint, template and kubeconform per cluster, the runtime contract, the admission policies, the alert rules (same as CI)
	deploy/check.sh
	uv run --project $(PY) --locked pytest -p no:cacheprovider deploy/tests
	deploy/policies.sh
	deploy/alerts/test.sh
