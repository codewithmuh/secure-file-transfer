# syntax=docker/dockerfile:1

FROM ghcr.io/astral-sh/uv:0.13.0 AS uv

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
CMD ["python", "-m", "sft.api"]
