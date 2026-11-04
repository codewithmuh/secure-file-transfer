"""Data layer: PostgreSQL through SQLAlchemy 2.0 with async sessions (ADR-0002, ADR-0011).

No query runs without an explicit scope: a tenant, a single resource reached through a verified
link, or a named system job (ADR-0003, architecture 5.1). Row-level security is the second layer
behind it (ADR-0020). The database foundation arrives in #48.

It may import `sft.core` only: never `sft.service` or `sft.api`, and never FastAPI, Starlette or
uvicorn (enforced by `lint-imports`).
"""
