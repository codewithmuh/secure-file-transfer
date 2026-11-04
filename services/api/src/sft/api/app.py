"""The public API app: the routes of the API contract, docs/api/openapi.yaml.

It has no routes yet; the first arrive in M1. Probes and metrics live on the internal port
(internal.py). The interactive docs and the OpenAPI document aren't served either: ADR-0002 keeps
them off the public load balancer, and CI builds the document from `create_app().openapi()`.
"""

from __future__ import annotations

from fastapi import FastAPI

# The contract's `info`, so the document generated from the code compares with it (ADR-0002).
API_TITLE = "secure-file-transfer API"
API_VERSION = "1.0.0-draft"


def create_app() -> FastAPI:
    return FastAPI(
        title=API_TITLE,
        version=API_VERSION,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
