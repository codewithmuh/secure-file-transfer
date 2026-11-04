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
    internal.py       /healthz, /readyz, /metrics on the internal port
    observability.py  request IDs, the request span, request metrics, one log line per request
    server.py         both listeners in one process, and the graceful shutdown
    __main__.py       python -m sft.api
  (workers/)    later, beside api: asyncio workers that use the service layer without HTTP
  service/      business rules and permission checks
  data/         PostgreSQL: SQLAlchemy, the scope of every transaction, roles, migrations
    database.py       the pool, and Database.transaction(scope), the only way to open a transaction
    scope.py          Scope: tenant, resource, system, platform, lookup or recovery
    models.py         the tables, for queries
    roles.py          the PostgreSQL roles; bootstrap.py creates them
    rls.py            grants and row-level security policies, for migrations
    audit.py          audit events, written in the transaction of the change; partition upkeep
    audit_required.py the fail-closed trigger for migrations, and the tables exempt from it
    migrations/       the Alembic revisions; migrate.py is the migration job
  core/         settings, logging and tracing, used by every layer
    telemetry.py      OpenTelemetry setup, the span attribute allowlist, trace context for messages
```

`service`, `data` and `core` never import FastAPI, Starlette or uvicorn.

## Run and check

From the repository root, `make check` runs what CI runs: ruff, mypy (strict), `lint-imports` and pytest with the
80 % coverage gate. The data layer's tests need a real PostgreSQL 17 server (below). `make up` runs the image with the
production hardening. To run it from source:

```bash
cd services/api
uv sync
DATABASE_URL=postgresql://sft_api@127.0.0.1:5432/sft uv run python -m sft.api
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
| `OTEL_EXPORTER_OTLP_ENDPOINT` | none | The collector's OTLP/HTTP base URL, e.g. `http://<node>:4318`; spans go to `<endpoint>/v1/traces`. Unset or empty: nothing is exported |

The migration job reads `MIGRATION_DATABASE_URL` (the `sft_migrate` role) and the bootstrap job reads
`BOOTSTRAP_DATABASE_URL` (the master user) and `BOOTSTRAP_IAM_AUTH`, with no defaults. Each also reads `LOG_LEVEL`.

## Runtime contract

Architecture section 8, as built here:

- **Two listeners.** The public port serves only the API; the internal port serves the probes and metrics, so a
  routing mistake on the public side can't expose them and probe traffic stays out of the request metrics. The docs
  pages and the OpenAPI document aren't served at all (ADR-0002); `create_app().openapi()` generates the document.
- **Logs.** One JSON line per event on stdout. Every line logged while a request runs carries its `request_id`, which
  the service always generates (`req_…`, also sent as `X-Request-Id`), and its `trace_id`, the trace ID of the
  request's span. Requests are logged by route template, never with query strings.
- **Traces.** OpenTelemetry (ADR-0009, `src/sft/core/telemetry.py`). Each request is one SERVER span, named by
  route template (`GET /v1/transfers/{transfer_id}`); it continues the caller's trace when the request has exactly
  one valid `traceparent`, and starts a new one otherwise. Every SQL statement is a CLIENT span under it, with the
  SQL text but never the parameter values, and so is every call of a boto3 client passed to `trace_aws_client`.
  The service records every span; the collector gateway's tail sampling decides what is kept, so a caller's
  "not sampled" flag is ignored. Only the attributes in `ALLOWED_ATTRIBUTES` are exported; never paths, query
  strings, headers, client addresses or exception messages (T-49, T-88). A caller's `tracestate` and baggage are
  dropped. FastAPI's own telemetry is off, so a request has one span, not two. Probes and scrapes on the internal
  port aren't traced.
- **Trace context in messages.** `current_trace_context()` returns `{"traceparent": "00-…"}` (or `{}` outside a
  span) to store in a message; the consumer runs its work in `with continued_trace(carrier, name):`, so the API
  request, the queue and the worker share one trace, and its log lines carry that trace ID (architecture 5.3).
- **Metrics.** `http_requests_total` and `http_request_duration_seconds` by method, route template and status, with
  bucket edges at 0.3 s and 1 s for NFR-2, plus the process and Python metrics. Metrics stay with the Prometheus
  client, scraped from `/metrics`; the OpenTelemetry SDK carries traces only, so nothing is counted twice.
- **Shutdown.** On SIGTERM or SIGINT, `/readyz` answers 503, the public listener closes, in-flight requests get up to
  `SHUTDOWN_DRAIN_SECONDS`, the internal listener closes, the spans still buffered are exported (a few seconds at
  most), and the process exits 0. uvicorn closes the public listener
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

### Roles

Created by the bootstrap job, `python -m sft.data.bootstrap`, never by a migration (`sft.data.roles`):

- `sft_api`, `sft_operator`, `sft_scan`, `sft_notify`, `sft_relay`, `sft_jobs`, `sft_archive`, `sft_recovery`: one
  login role per workload, each granted only its tables. Every transaction ends within 30 s (statements and idle
  waits within 10 s).
- `sft_migrate`: the migration job's login role. It has no privileges of its own; it becomes `sft_owner` with
  `SET ROLE`.
- `sft_owner` owns every table and `sft_lookup` will own the credential lookup functions. Nobody logs in as either.
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
a table without a policy for it, `TRUNCATE` is granted, anyone but `sft_owner` owns a table, or a `SECURITY DEFINER`
function leaves its `search_path` open or is executable by every role.

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
there by accident.

```bash
docker run --detach --name sft-test-postgres --publish 127.0.0.1:55432:5432 \
  --env POSTGRES_PASSWORD=test-only postgres:17.11-trixie
TEST_DATABASE_URL=postgresql://postgres:test-only@127.0.0.1:55432/postgres uv run pytest
```
