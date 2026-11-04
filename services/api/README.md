# api

The API service: FastAPI on uvicorn, Python 3.13 (ADR-0002). The workers will join this codebase and image with their
own entry points (architecture 2). It has no API routes yet; M1 adds the first ones from
[the API contract](../../docs/api/openapi.yaml).

## Layout

One package, `sft`, in layers. A layer imports only the layers below it, and `lint-imports` fails the build otherwise
(rules in `pyproject.toml`).

```
src/sft/
  api/          FastAPI routes and the dependencies that work out who the caller is; the runtime contract
    app.py            the public app (the API routes)
    errors.py         every error as an RFC 9457 problem; problem_responses() for a route's errors
    internal.py       /healthz, /readyz, /metrics on the internal port
    observability.py  request and trace IDs, request metrics, one log line per request
    server.py         both listeners in one process, and the graceful shutdown
    __main__.py       python -m sft.api
  (workers/)    later, beside api: asyncio workers that use the service layer without HTTP
  service/      business rules and permission checks
  data/         PostgreSQL: SQLAlchemy, the scope of every transaction, roles, migrations
    database.py       the pool, and Database.transaction(scope), the only way to open a transaction
    scope.py          Scope: tenant, resource, system, platform, lookup or recovery
    access.py         the rules on top: who opens which scope, in_scope(), TenantOwned
    tenants.py        data-access functions for tenants (one module per table or aggregate)
    models.py         the tables, for queries
    roles.py          the PostgreSQL roles; bootstrap.py creates them
    rls.py            grants and row-level security policies, for migrations
    audit.py          audit events, written in the transaction of the change; partition upkeep
    audit_required.py the fail-closed trigger for migrations, and the tables exempt from it
    migrations/       the Alembic revisions; migrate.py is the migration job
  core/         settings and logging, used by every layer
    errors.py         the errors any layer raises (NotFound, Conflict, RateLimited ...), without HTTP
```

`service`, `data` and `core` never import FastAPI, Starlette or uvicorn.

## Run and check

From the repository root, `make check` runs what CI runs: ruff, mypy (strict), `lint-imports` and pytest with the
80 % coverage gate. The data layer's tests need a real PostgreSQL 17 server (below). `make up` runs the image with the
production hardening, after the jobs that create the database roles and run the migrations. To run it from source
against the stack's database (`docker compose stop api` first: it holds the ports):

```bash
cd services/api
uv sync
DATABASE_URL=postgresql://sft_api:test-only-password@127.0.0.1:5432/sft uv run python -m sft.api
curl -s localhost:8001/readyz   # API on 127.0.0.1:8000, probes and metrics on 127.0.0.1:8001
```

The API needs `DATABASE_URL` to start, but opens no connection until a request needs one, and `/readyz` never checks
the database: an outage mustn't take every pod out of the load balancer at once.

## Settings

Environment variables only, typed and checked at startup (`src/sft/core/settings.py`). The process exits with status
2 and one log line naming the bad settings, never their values. Secrets are `SecretStr` fields with no default.

| Variable | Default | Meaning |
|---|---|---|
| `LOG_LEVEL` | `info` | `debug`, `info`, `warning`, `error` or `critical` |
| `APP_VERSION` | `0.0.0` | Set by the image build |
| `BIND_HOST` | `127.0.0.1` | The image sets `0.0.0.0` |
| `PUBLIC_PORT` | `8000` | The API, behind the load balancer |
| `INTERNAL_PORT` | `8001` | `/healthz`, `/readyz` and `/metrics`; the public load balancer never routes it |
| `SHUTDOWN_DRAIN_SECONDS` | `20` | How long in-flight requests get after SIGTERM (1 to 120) |
| `DATABASE_URL` | none, required | The workload's own login role, `postgresql://` or `postgresql+psycopg://`; a secret |
| `DATABASE_POOL_SIZE` | `5` | Connections per process, with no overflow (1 to 50) |

The migration job reads `MIGRATION_DATABASE_URL` (the `sft_migrate` role) and the bootstrap job reads
`BOOTSTRAP_DATABASE_URL` (the master user) and `BOOTSTRAP_IAM_AUTH`, with no defaults. Each also reads `LOG_LEVEL`.

## Runtime contract

Architecture section 8, as built here:

- **Two listeners.** The public port serves only the API; the internal port serves the probes and metrics, so a
  routing mistake on the public side can't expose them and probe traffic stays out of the request metrics. The docs
  pages and the OpenAPI document aren't served at all (ADR-0002); `create_app().openapi()` generates the document.
- **Logs.** One JSON line per event on stdout. Every line logged while a request runs carries its `request_id`, which
  the service always generates (`req_…`, also sent as `X-Request-Id`), and its `trace_id`, from a valid W3C
  `traceparent` header or new. Requests are logged by route template, never with query strings.
- **Metrics.** `http_requests_total` and `http_request_duration_seconds` by method, route template and status, with
  bucket edges at 0.3 s and 1 s for NFR-2, plus the process and Python metrics.
- **Shutdown.** On SIGTERM or SIGINT, `/readyz` answers 503, the public listener closes, in-flight requests get up to
  `SHUTDOWN_DRAIN_SECONDS`, the internal listener closes, and the process exits 0. uvicorn closes the public listener
  the moment the signal arrives, so the app can't keep accepting while the load balancer catches up. In Kubernetes,
  a `preStop` sleep in the pod spec holds the signal back for that time (`src/sft/api/server.py` has the details).
  Ctrl+C during the drain (a second SIGINT) cuts it short and cancels in-flight requests, as in uvicorn; a repeated
  SIGTERM changes nothing.

## Database

PostgreSQL 17 (ADR-0011), one schema for every tenant (ADR-0003), with row-level security as the second isolation
layer (ADR-0020, data model 4.2).

### Transactions run in a scope

```python
from sft.data.database import Database
from sft.data.scope import Scope

database = Database.connect(
    settings.database_url.get_secret_value(), pool_size=settings.database_pool_size
)
async with database.transaction(Scope.tenant(tenant_id)) as session:
    ...  # commits when the block ends, rolls back on an exception
```

`transaction()` starts every transaction with `set_config('app.scope', …, true)` and
`set_config('app.tenant_id', …, true)`. Both end at commit or rollback, so a connection back in the pool carries no
tenant; a test checks it, and another fails the build if any code sets them for a whole session. There is no other way
to get a session: one without a scope is refused before its first statement reaches the database. Tenant and resource
scopes set a tenant; system, platform, lookup and recovery scopes set none, so every tenant policy matches nothing in
them. In the API, the app's lifespan creates the `Database` and a route gets it with `Depends(get_database)`.

### Scoped data access

`DATABASE_URL` names the workload's own role, and the pool opens only that role's scopes
(`sft.data.access.SCOPES_BY_ROLE`, authentication and authorization 7.3): `sft_api` tenant, resource, platform and
lookup; `sft_jobs` system and tenant; and so on. Any other scope raises `ScopeNotAllowedError` before it reaches the
database. A URL naming any other user, a superuser included, is refused at `connect`, and so is one whose query
could change who logs in (`user`, `options`, `service`, …; TLS settings, `connect_timeout` and `application_name`
pass); every new connection also checks `current_user`. A resource scope names its subject, the link session's
recipient or upload request: `Scope.resource(tenant_id, Subject.recipient(id))`.

Every data-access function filters with `in_scope`, never with a tenant of its own, and writes the scope's tenant:

```python
from sft.data.access import in_scope, tenant_of

async def get_widget(session: AsyncSession, widget_id: UUID) -> Widget | None:
    statement = select(Widget).where(Widget.id == widget_id, in_scope(Widget, session))
    return await session.scalar(statement)

session.add(Widget(id=uuid7(), tenant_id=tenant_of(session), ...))
```

Every tenant-owned model mixes in `TenantOwned`. Its `reach(subject)` says which rows a link session reaches; the
default is none. Row-level security keeps tenants apart; within a tenant the resource rule is this layer's alone.

In system scope the session refuses any `INSERT`, `UPDATE`, `DELETE` or flush that touches a tenant table, before it
reaches the database, unless the role is the relay: a job finds its work across tenants and changes each item in its
tenant's scope. There is no flag to forget. A row the scope doesn't reach is `NotFoundError`, which the service
answers with 404.

### Roles

Created by the bootstrap job, `python -m sft.data.bootstrap`, never by a migration (`sft.data.roles`):

- `sft_api`, `sft_operator`, `sft_scan`, `sft_notify`, `sft_relay`, `sft_jobs`, `sft_archive`, `sft_recovery`: one
  login role per workload, each granted only its tables. Every transaction ends within 30 s (statements and idle
  waits within 10 s).
- `sft_migrate`: the migration job's login role. It has no privileges of its own; it becomes `sft_owner` with
  `SET ROLE`.
- `sft_owner` owns every table and `sft_lookup` owns the credential lookup functions. Nobody logs in as either.
  `sft_owner` may become `sft_lookup` (`SET ROLE`, no inheritance), so a migration can hand it a function.
- No role of ours has `BYPASSRLS`, superuser, `CREATEROLE` or `CREATEDB`; the catalog tests check it.

**In AWS** the bootstrap job (`sft-{env}-db-bootstrap`, M4) runs as the master user with `BOOTSTRAP_IAM_AUTH=true`.
Every login role gets `rds_iam` and no password: each pod's IAM role (`sft-{env}-api`, …) signs a 15-minute token for
each new connection, over TLS with `sslmode=verify-full` (encryption and keys 2.2, 6.3), so `DATABASE_URL` holds a user
name and a host, never a password. The master password lives only in Secrets Manager (`sft/{env}/db/master`), set by
Terraform's write-only arguments; the bootstrap job reads it once and after that only break-glass does. **Locally and
in CI** there is no IAM: run the bootstrap with `BOOTSTRAP_IAM_AUTH=false` as a superuser, and give the login roles an
obviously fake password yourself (`ALTER ROLE sft_api PASSWORD '…'`), as the tests do.

### Migrations

```bash
export MIGRATION_DATABASE_URL=postgresql://sft_migrate:…@127.0.0.1:5432/sft
uv run python -m sft.data.migrate                                 # what the Argo CD PreSync job runs
uv run alembic history                                            # the alembic command line works too
uv run alembic revision --rev-id 0002 -m "add widgets"            # then write upgrade() by hand
```

The migration job (data model 7, ADR-0005) upgrades when the image's head is newer than the database's, does nothing
when they match, and when the database is ahead, after a rollback, skips only if the database's revision lists the
image's head as compatible; otherwise it exits 1 and the sync stops. It never runs a down-migration. Each statement has
a 2-second lock timeout and a run that hits it is retried; an advisory lock keeps two jobs apart.

Each revision:

- is numbered in sequence (`0001`, `0002`, …), one line with no branches;
- expands only, towards the previous release (data model 7: `CREATE INDEX CONCURRENTLY`, `NOT VALID` then
  `VALIDATE`);
- sets `compatible_with`, the earlier revisions whose code still runs on its schema, usually the previous release's
  head. The job records it in `schema_compatibility` in the same transaction;
- gives every tenant-owned table its row-level security in the same migration;
- **keeps literal SQL.** The `sft.data.rls` helpers generate the grants and policies when you write the revision;
  the revision holds the statements they printed, never a call to the helpers, so changing a helper later can't
  change what an old revision does to a fresh database. A test fails if a revision imports anything from `sft`.

```python
from sft.data.rls import policy_sql, tenant_rls_sql

# At authoring time, print the statements …
print(
    *tenant_rls_sql("widgets", grants={"sft_api": "SELECT, INSERT, UPDATE", "sft_jobs": "SELECT"}),
    sep="\n",
)
print(
    policy_sql(
        "jobs_find", "widgets", roles=["sft_jobs"], command="SELECT", using="app_scope() = 'system'"
    )
)
```

```python
# … and paste them into the revision, which runs them as they are.
WIDGETS_RLS = (
    "ALTER TABLE widgets ENABLE ROW LEVEL SECURITY",
    "GRANT SELECT, INSERT, UPDATE ON widgets TO sft_api",
    "GRANT SELECT ON widgets TO sft_jobs",
    "CREATE POLICY tenant_isolation ON widgets FOR ALL TO sft_api, sft_jobs "
    "USING (tenant_id = app_tenant_id()) WITH CHECK (tenant_id = app_tenant_id())",
    "CREATE POLICY jobs_find ON widgets FOR SELECT TO sft_jobs USING (app_scope() = 'system')",
)


def upgrade() -> None:
    op.create_table("widgets", sa.Column("tenant_id", sa.Uuid, nullable=False), ...)
    for statement in WIDGETS_RLS:
        op.execute(statement)
```

- gives every tenant-owned table `tenant_id` referencing `tenants (id)` and a unique key `(tenant_id, id)`, and refers
  to a parent by both columns, so the database refuses a reference to another tenant's row (data model 4.2). The
  statements come from `tenant_keys_sql(table)` and `tenant_foreign_key_sql(table, column, parent)`, pasted the same
  way:

```python
WIDGET_PARTS_KEYS = (
    "ALTER TABLE widget_parts ADD CONSTRAINT widget_parts_tenant_id_fkey "
    "FOREIGN KEY (tenant_id) REFERENCES tenants (id)",
    "ALTER TABLE widget_parts ADD CONSTRAINT widget_parts_tenant_id_id_key UNIQUE (tenant_id, id)",
    "ALTER TABLE widget_parts ADD CONSTRAINT widget_parts_tenant_id_widget_id_fkey "
    "FOREIGN KEY (tenant_id, widget_id) REFERENCES widgets (tenant_id, id) ON DELETE CASCADE",
)
```

- puts a credential lookup (data model 4.2) in a `SECURITY DEFINER` function owned by `sft_lookup`, for `sft_api`
  only. `lookup_read_sql(table, columns)` gives `sft_lookup` those columns and a policy that matches in lookup scope
  only; `lookup_function_sql` writes the function, pins its `search_path`, grants `sft_api` alone and hands it to
  `sft_lookup`:

```python
from sft.data.rls import lookup_function_sql, lookup_read_sql

print(*lookup_read_sql("api_keys", ["id", "tenant_id", "key_hash", "revoked_at"]), sep="\n")
print(
    *lookup_function_sql(
        "lookup_api_key(p_key_hash bytea)",
        returns="TABLE (key_id uuid, owner_tenant_id uuid, revoked_at timestamptz)",
        body="SELECT id, tenant_id, revoked_at FROM public.api_keys WHERE key_hash = p_key_hash",
    ),
    sep="\n",
)
```

  Call it in a lookup-scope transaction of its own, after `require_scope(session, ScopeKind.LOOKUP)`, and continue in
  the tenant or resource scope it returns.

- decides whether changes to each new tenant-owned table need an audit event (FR-27, NFR-15). Either it pastes in the
  `audit_required` trigger, which refuses to commit a change by a workload role without an audit event in the same
  transaction, or the table goes in `NOT_AUDITED` in `sft/data/audit_required.py`, with the reason. The trigger's SQL
  comes from the helper at authoring time, like the policies:

```python
from sft.data.audit_required import require_audit_sql

print(
    require_audit_sql("widgets")
)  # or narrower: commands=("INSERT", "UPDATE"), update_of=("state",)
# CREATE CONSTRAINT TRIGGER audit_required AFTER INSERT OR UPDATE OR DELETE ON widgets
#     DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION audit_required()
```

Add the table to `sft/data/models.py` too: a test compares the models with the migrated schema. The catalog tests fail
if a tenant table has no row-level security or neither the audit trigger nor a `NOT_AUDITED` entry, a role is granted
a table or a column without a policy for it, `TRUNCATE` is granted, anyone but `sft_owner` owns a table, a foreign
key between tenant tables leaves out `tenant_id`, or a `SECURITY DEFINER` function isn't a pinned lookup for `sft_api`
alone.

### Audit events

Every security-relevant change writes its audit event in its own transaction, through `sft.data.audit.record`:

```python
async with database.transaction(Scope.tenant(tenant_id)) as session:
    ...  # the change
    await audit.record(
        session,
        action="transfer.revoked",
        actor=Actor(ActorType.MEMBER, user_id),
        target=Target("transfer", transfer_id),
        origin=Origin(source_ip=client_ip, user_agent=user_agent),
        security_critical=True,
    )
```

The tenant comes from the scope, the request and trace IDs from the log context, `tx_id` and `occurred_at` from the
database: workload roles may insert audit events, but not set those two columns, nor change or delete an event.
`details` takes IDs, `StrEnum` and `IntEnum` members, numbers, flags and aware times only, never free text; control
characters are stripped from the user agent. `audit_events` is partitioned by UTC month, with a default partition
for a month that has none; the lifecycle job's step, `sft.service.audit_partitions.maintain_audit_partitions`, keeps
three months ahead and exports `sft_audit_default_partition_rows`, `sft_audit_partition_months_covered` and
`sft_audit_partition_last_success_timestamp_seconds`.

### Tests against PostgreSQL

The data layer's tests need a PostgreSQL 17 superuser URL in `TEST_DATABASE_URL`. They make their own databases there
and drop them afterwards; the roles, which are cluster-wide, stay. In CI it is a service container on the Python job.
Without it the database tests are skipped locally; in CI (`CI` set) they fail instead, so they can't be skipped
there by accident. While the local stack runs (`make up`), `make test` sets it to the stack's superuser for you
([local development](../../docs/local-development.md) 1); otherwise start a server of your own:

```bash
docker run --detach --name sft-test-postgres --publish 127.0.0.1:55432:5432 \
  --env POSTGRES_PASSWORD=test-only postgres:17.11-trixie
TEST_DATABASE_URL=postgresql://postgres:test-only@127.0.0.1:55432/postgres uv run pytest
```

### The isolation suite

NFR-12, delivery plan 2 point 3: every new data-access function, and later every endpoint, gets a case in
`tests/test_isolation.py`. A case calls the function in one tenant's scope ("mine") with the other tenant's IDs
("theirs"):

```python
@cases.add(scopes={API: [TENANT, RESOURCE], OPERATOR: [TENANT]})
async def get_tenant_of_another_tenant(session: AsyncSession, tenants: Tenants) -> object:
    return await get_tenant(session, tenants.theirs.tenant_id)
```

`scopes` lists, per workload role, the scopes the function is used in; the harness also tries the platform and lookup
scopes the role may open. A resource-scope case passes `subject=` to give mine's link session its item. Each case runs
three ways (ADR-0020): as built; with row-level security disabled in a database of its own, so `in_scope` must hold
alone; and with `in_scope`'s tenant filter removed, so the policies must hold alone. An attempt fails the build if
its result holds any of theirs' IDs or the marker in their text columns, if any of their rows changed, or if a row of
another tenant now refers to one of their IDs. A refusal is fine: no row, `None`, a policy, privilege or foreign key
error, or the data layer's `NotFoundError` or `ScopeNotAllowedError`; anything else, a `KeyError` included, fails.
In system scope, and in lookup scope when the case names it, reading across tenants is the point, so only the
"nothing changed" checks apply.

A new tenant table also gets its rows in `seed_tenant` (`tests/isolation.py`), which seeds as the superuser so the
code under test never seeds itself. `tests/isolation_fixture.py` holds stand-in tables, a parent with a credential and
a child, that prove the harness, the composite keys and the lookup mechanism until the real tables arrive;
`tests/test_isolation_harness.py` breaks each layer in turn and checks that the suite fails.
