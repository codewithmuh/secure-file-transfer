# syntax=docker/dockerfile:1

FROM ghcr.io/astral-sh/uv:0.13.7 AS uv

# ---- build: resolve the locked dependencies into a virtualenv ----
FROM python:3.13-slim-trixie AS build
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never UV_PROJECT_ENVIRONMENT=/app/.venv
WORKDIR /app
# Dependencies first: this layer stays cached until uv.lock changes.
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --locked --no-dev --no-install-project
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
# The bank and branch code list behind jp_bank_account's high confidence (DLP detectors 4.4, #146).
# No licence for its data could be confirmed, so git holds only its header and the image fetches it
# here: zengin-code/source-data at one commit, refused unless the codes' digest is the pinned one.
# The refresh steps are in the README ("DLP bank and branch codes"). BANK_CODES=none builds without
# it, for an image that is published publicly or built offline: jp_bank_account then stays medium.
ARG BANK_CODES=zengin-code
ARG BANK_CODES_REF=658711c701f40189d5a4fb131a7ccb57fb7d04ba
ARG BANK_CODES_DATE=2026-08-24
ARG BANK_CODES_SHA256=7efd7f8b8b690e5e0560b151337b31e0fbb92c1d5da8769f99e88ce829229c6f
COPY tools/__init__.py tools/bank_codes.py ./tools/
RUN case "${BANK_CODES}" in \
      zengin-code) PYTHONPATH=src /app/.venv/bin/python -m tools.bank_codes zengin-code \
          --ref "${BANK_CODES_REF}" --retrieved "${BANK_CODES_DATE}" --sha256 "${BANK_CODES_SHA256}" \
          --output src/sft/dlp/detect/bank_codes.txt ;; \
      none) ;; \
      *) echo "BANK_CODES is zengin-code or none" >&2; exit 1 ;; \
    esac
RUN --mount=type=cache,target=/root/.cache/uv uv sync --locked --no-dev --no-editable

# ---- runtime: slim image, only the virtualenv, non-root ----
FROM python:3.13-slim-trixie
ARG APP_VERSION=0.0.0
ENV PATH="/app/.venv/bin:${PATH}" PYTHONUNBUFFERED=1 APP_VERSION=${APP_VERSION} BIND_HOST=0.0.0.0
# Debian's fixes go in at build time, not when the base image is next rebuilt upstream: the scan
# fails on any fixed HIGH or CRITICAL. pip is only needed to build, and its bundled libraries
# (urllib3, msgpack, …) show up in CVE scans.
RUN apt-get update && apt-get upgrade --yes --no-install-recommends \
 && rm -rf /var/lib/apt/lists/* \
 && python -m pip uninstall --yes pip \
 && groupadd --system --gid 10001 app && useradd --system --uid 10001 --gid app --no-create-home app
WORKDIR /app
# Owned by root: the app user can read and run its code but not change it.
COPY --from=build /app/.venv /app/.venv
USER 10001:10001
# 8000: the API (PUBLIC_PORT). 8001: /healthz, /readyz and /metrics (INTERNAL_PORT), never routed
# by the public load balancer (architecture 8).
EXPOSE 8000 8001
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import os, sys, urllib.request; port = os.environ.get('INTERNAL_PORT', '8001'); sys.exit(urllib.request.urlopen(f'http://127.0.0.1:{port}/healthz', timeout=2).status != 200)"]
# On SIGTERM: readiness fails, in-flight requests get up to 20 s, exit 0 (src/sft/api/server.py).
# The workers run from this image with another command, e.g. the outbox relay:
# `python -m sft.workers.relay` (probes and metrics on INTERNAL_PORT only, src/sft/workers/).
CMD ["python", "-m", "sft.api"]
