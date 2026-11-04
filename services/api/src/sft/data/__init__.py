"""Data layer: PostgreSQL through SQLAlchemy 2.0 with async sessions (ADR-0002, ADR-0011).

No query runs without an explicit scope: a tenant, a single resource reached through a verified
link, or a named system job (ADR-0003, architecture 5.1). Row-level security is the second layer
behind it (ADR-0020).

- `database`: the pool, and `Database.transaction(scope)`, the only way to open a transaction. It
  sets `app.scope` and `app.tenant_id` for that transaction alone.
- `scope`: `Scope`, the database half of a scope: its kind and, for tenant and resource scopes,
  the tenant.
- `models`: the tables, for queries; a test keeps them in step with the migrations.
- `roles`: the PostgreSQL roles. `bootstrap` creates them (`python -m sft.data.bootstrap`).
- `rls`: generates the grants and policies a migration pastes in as literal SQL.
- `migrations`: the Alembic revisions. `migrate` runs them: the migration job
  (`python -m sft.data.migrate`).

It may import `sft.core` only: never `sft.service` or `sft.api`, and never FastAPI, Starlette or
uvicorn (enforced by `lint-imports`).
"""
