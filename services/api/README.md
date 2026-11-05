# api

The API service and the workers: FastAPI on uvicorn for the API, asyncio for the workers, Python 3.13 (ADR-0002). They
share this codebase and image, each with its own entry point (architecture 2). The API's routes come from [the API
contract](../../docs/api/openapi.yaml); the member routes (#112) are the first. The first worker is the outbox relay
(ADR-0013).

## Layout

One package, `sft`, in layers. A layer imports only the layers below it, and `lint-imports` fails the build otherwise
(rules in `pyproject.toml`).

```
src/sft/
  api/          FastAPI routes and the dependencies that work out who the caller is; the runtime contract
    app.py            the public app (the API routes)
    members.py        the member routes: invite, list, read, change and deactivate users (FR-22)
    caller.py         get_caller, the request's Caller (a placeholder until #113's sessions)
    errors.py         every error as an RFC 9457 problem; problem_responses() for a route's errors
    observability.py  request and trace IDs, the request span, request metrics, one log line per request
    rate_limits.py    rate_limit(bundle): the route dependency; 401 counting and the IP block
    client_ip.py      the client's address by ADR-0002's rule
    server.py         both listeners in one process, and the graceful shutdown
    __main__.py       python -m sft.api
  workers/      beside api: asyncio workers that use the service layer without HTTP
    relay.py          the outbox relay: python -m sft.workers.relay
    consumer.py       Consumer, the idempotent consumer base class, and ConsumerLoop
    queues.py         SQS behind a thin adapter (boto3 in a thread pool)
    process.py        WorkerProcess: probes, SIGTERM and the drain for every worker
  runtime/      what api and workers both need to run as a pod
    internal.py       /healthz, /readyz, /metrics on the internal port
  service/      business rules and permission checks
    caller.py         Caller: who is calling and how they signed in; its audit actor and rate-limit keys
    permissions.py    the permission registry (authn and authz 6.3) and authorize()
    members.py        the member rules: the last active admin, invitations, role and approver changes
    email/            every email, rendered in English and Japanese as text and HTML (Email below)
    rate_limits/      the limits as data, the limiter and its per-pod fallback
  data/         PostgreSQL: SQLAlchemy, the scope of every transaction, roles, migrations; Valkey counters
    database.py       the pool, and Database.transaction(scope), the only way to open a transaction
    scope.py          Scope: tenant, resource, system, platform, lookup or recovery
    access.py         the rules on top: who opens which scope, in_scope(), TenantOwned
    tenants.py        data-access functions for tenants (one module per table or aggregate)
    users.py          data-access functions for users and their invitations
    models.py         the tables, for queries
    roles.py          the PostgreSQL roles; bootstrap.py creates them
    rls.py            grants and row-level security policies, for migrations
    audit.py          audit events, written in the transaction of the change; partition upkeep
    audit_required.py the fail-closed trigger for migrations, and the tables exempt from it
    outbox.py         the transactional outbox: enqueue(), the message contract, the relay's queries
    processed.py      processed-message records, which make consumers idempotent
    migrations/       the Alembic revisions; migrate.py is the migration job
    counters.py       Valkey: the rate-limit counter scripts, with a timeout and a rest after failures
    mail/             the mail adapter: SES API v2 in AWS, SMTP to Mailpit locally (Email below)
  dlp/          beside data: the DLP detectors, pure code with no I/O, for the service and the inspector (ADR-0022)
    units.py          text units, keyword lists and findings: what goes in and what comes out
    detect/           the built-in detectors of docs/design/dlp-detectors.md and tenant detectors, on RE2
  core/         settings, logging, tracing and UUIDv7 IDs, used by every layer
    errors.py         the errors any layer raises (NotFound, Conflict, RateLimited ...), without HTTP
    pseudonyms.py     email pseudonyms for logs and rate-limit keys, with the rotation overlap
    telemetry.py      OpenTelemetry setup, the span attribute allowlist, trace context for messages
```

`api` and `workers` never import each other. `service`, `data` and `core` never import FastAPI, Starlette or uvicorn;
`runtime` sits between them and the entry points, so both entry points share the probes without either knowing the
other. `data` and `dlp` never import each other, and `dlp` imports no database, counter store, AWS, HTTP, metrics or
tracing client, because the inspector's sandbox has none of them.

## Run and check

From the repository root, `make check` runs what CI runs: ruff, mypy (strict), `lint-imports` and pytest with the
80 % coverage gate. The data layer's tests need a real PostgreSQL 17 server (below). `make up` runs the image with the
production hardening, after the jobs that create the database roles and run the migrations. To run it from source
against the stack's database (`docker compose stop api` first: it holds the ports):

```bash
cd services/api
uv sync
DATABASE_URL=postgresql://sft_api:test-only-password@127.0.0.1:5432/sft \
  VALKEY_URL=redis://sft-local:local-only-valkey-password@127.0.0.1:6379/0 uv run python -m sft.api
curl -s localhost:8001/readyz   # API on 127.0.0.1:8000, probes and metrics on 127.0.0.1:8001
```

The API needs `DATABASE_URL` and `VALKEY_URL` to start, but opens no connection until a request needs one, and
`/readyz` checks neither: an outage mustn't take every pod out of the load balancer at once.

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
| `VALKEY_URL` | none, required | The rate-limit counter store with its credentials, `redis://`, `rediss://`, `valkey://` or `valkeys://`; a secret |
| `TRUSTED_PROXIES` | empty | Our load balancer's subnets, comma-separated; only their requests have the client address read from `X-Forwarded-For` (ADR-0002) |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | none | The collector's OTLP/HTTP base URL, e.g. `http://<node>:4318`; spans go to `<endpoint>/v1/traces`. Unset or empty: nothing is exported |

Whatever sends email (the notification worker) also reads `MailSettings`:

| Variable | Default | Meaning |
|---|---|---|
| `MAIL_BACKEND` | none, required | `ses` in AWS; `smtp` only for the local stack's Mailpit |
| `MAIL_FROM_ADDRESS` | none, required | The `From` address on our sending subdomain, e.g. `no-reply@mail.<domain>` |
| `MAIL_FROM_NAME` | `Secure File Transfer` | The `From` display name (ASCII) |
| `WEB_APP_URL` | none, required | The web app's origin, the only place emails link to; `https`, or `http` for localhost |
| `SES_REGION` | `ap-northeast-1` | Tokyo, or `ap-northeast-3` (Osaka) after a failover; nothing else (NFR-21) |
| `SES_CONFIGURATION_SET` | none | The region's configuration set; required for `ses` |
| `SES_TENANTS` | `true` | Name the tenant's SES tenant on every send (ADR-0015); `false` only where SES has no tenant management |
| `SMTP_HOST`, `SMTP_PORT` | `127.0.0.1`, `1025` | Mailpit, for `smtp` |

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
- **Trace context in messages.** `enqueue()` writes each outbox message in a `create <queue>` PRODUCER span under
  the current one and stores that span's `{"traceparent": "00-…"}` in the message's `trace_context`. The relay sends
  it on in the body unchanged, and `ConsumerLoop` handles the message in a `process <queue>` CONSUMER span that
  continues it (`continued_trace`), so the API request, the queue and the worker share one trace, and the worker's
  log lines carry that trace ID (architecture 5.3). The relay's batches are traces of their own, linked to the
  messages they carry (The outbox relay, below). Message spans carry the queue, the consumer and the outbox ID, never
  the tenant or the payload.
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

## Rate limits

The limits of the abuse design (section 2.2) are data in `sft/service/rate_limits/limits.py`, one `Limit` per row, and
each operation's bundle is listed there, narrowest first. A route applies its bundle in one line:

```python
@router.post("/v1/auth/sign-in", dependencies=[rate_limit(SIGN_IN_START)])
@router.get("/v1/me", dependencies=[rate_limit(TENANT_OPERATION, caller=member_session)])
```

`caller` is the route's authentication dependency; its result's `rate_limit_keys()` gives the account, API key or
tenant. Limits on keys a handler finds itself (a link's subject, an invited address as `EmailPseudonyms`) run there:
`await limiter.check(REQUEST_CODE, keys)`, with `limiter = Depends(get_rate_limiter)`. A refusal is `429 rate_limited`
with `Retry-After`; while Valkey is unavailable, groups A and B answer `503` with `Retry-After: 5` and the rest count
in the pod at a third of each limit (abuse design 4.5). Every `401` counts against the client's IP (group H), and an
IP blocked after 100 of them gets `429` on every route, checked before routing and authentication.

The counter store (`sft/data/counters.py`) runs GCRA for rates and a sliding log for small quotas, one Lua script per
key, with 50 ms per call and a 10-second rest after 5 failures in a row (ADR-0014). A rate of N per period admits a
burst of N // 2 + 1, then the rest evenly spaced, so no window of one period holds more than N. The client is
[valkey-py](https://github.com/valkey-io/valkey-py), the Valkey project's asyncio client: pure Python, the redis-py
API, standalone and cluster clients, and a credential provider for the IAM tokens of M4.

### Tests against PostgreSQL and Valkey

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

The rate-limit tests need a Valkey 9 URL with credentials in `TEST_VALKEY_URL`, skipped locally without it and failing
in CI the same way. They empty database 0 there before each test, so never point it at the local stack's Valkey.

```bash
docker run --detach --name sft-test-valkey --publish 127.0.0.1:56379:6379 \
  --env "VALKEY_EXTRA_FLAGS=--save '' --requirepass test-only" valkey/valkey:9.1.3-alpine
TEST_VALKEY_URL=redis://:test-only@127.0.0.1:56379/0 uv run pytest
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

## Email

Every email the PRD names, in English and Japanese, as plain text and HTML (FR-33, abuse 7.1), and one adapter to
send them (ADR-0015).

```python
from sft.data.mail import mailer_from_settings
from sft.service.email import EmailRenderer, Locale
from sft.service.email.catalog import VerificationCode

renderer = EmailRenderer(settings.web_app_url)
email = renderer.compose(
    VerificationCode(tenant_name=tenant.name, code=code), Locale.JA, to=address, tenant_id=tenant.id
)
message_id = mailer_from_settings(settings).send(email)  # blocks: call it from a thread pool
```

- **One class per email** in `sft/service/email/catalog.py`. Its fields are all its templates get. Links are built
  there from `WEB_APP_URL`, never written in a template; tokens go in the fragment (`/t#…`, `/u#…`, `/invite#…`).
- **Templates** in `sft/service/email/templates/<locale>/<type>.txt` and `.html`; the text file holds the subject in
  its `subject` block, and both extend the locale's `_layout`. Jinja2 escapes every value in `.html` and nothing in
  `.txt`, and a missing key is an error (`StrictUndefined`). Tests check that every template of both languages uses
  exactly its email's keys, that each secret (link token, code, temporary password) appears only in its own email,
  and that every URL points to the web app.
- **No personal data in logs.** Rendering logs nothing. The adapters log the email type, the provider and its message
  ID, or an error code. Their `MailError` carries a kind (`throttled`, `unavailable`, `paused`, `misconfigured`,
  `rejected`) and the provider's error code, raised `from None`, because a provider's message can quote the address.
  Only `rejected` drops an email, and only for an error about that message; our own setup being wrong (credentials,
  permissions, a missing configuration set or SES tenant) is `misconfigured`, which holds every email, and an unknown
  error is retried. `OutgoingEmail`, `RenderedEmail` and the email classes keep addresses and secrets out of their
  reprs.
- **SES** (`sft/data/mail/ses.py`): `SendEmail` with the region's configuration set, the SES tenant named by our
  tenant ID, and the tags `tenant_id` and `email_type`, plus any the caller adds, so delivery events find their row.
  Tested with botocore's Stubber; nothing calls AWS.
- **SMTP** (`sft/data/mail/smtp.py`): plain SMTP to Mailpit, tags as `X-Sft-Tag-*` headers. Its integration test runs
  against Mailpit in CI's mail job, and locally after `make up` with
  `TEST_MAIL_CATCHER_URL=http://127.0.0.1:8025 TEST_SMTP_PORT=1025 uv run pytest tests/test_mail_mailpit.py`.

## Workers

Each worker runs from the same image as the API with its own command, logs in as its own database role, and has one
port, the internal one (`/healthz`, `/readyz`, `/metrics`). `WorkerProcess` gives every worker the runtime contract
(architecture 8): ready once its loop starts, never checking dependencies; on SIGTERM, readiness fails, the batch in
hand gets `SHUTDOWN_DRAIN_SECONDS` (15) to finish and is cancelled after that, and the process exits 0. A loop that
fails exits 1, so Kubernetes restarts the pod.

### The transactional outbox

A service function hands work to a worker by writing an outbox row in its own transaction (architecture 5.3):

```python
from sft.data.outbox import enqueue

async with database.transaction(Scope.tenant(tenant_id)) as session:
    ...  # the state change and its audit event
    await enqueue(session, SCAN_SMALL_FILE, {"file_id": file.id})
    await enqueue(session, RESCAN, {"file_id": file.id}, delay=timedelta(seconds=30))
```

The message commits with the change or not at all. The tenant is the transaction's own. The payload takes UUIDs (or
lists of them) only, so a token, a code, an address or a file name can't reach a queue (T-49); the worker re-reads the
rest. A delay holds the message back by up to 15 minutes, counted from the write. Topics are `Topic(name, queue)`
values listed in `sft.data.outbox.TOPICS`; M0 has none, and each feature adds its own with the queue that carries it.

### The outbox relay

`python -m sft.workers.relay`, as `sft_relay`. In one short transaction per batch it claims up to `RELAY_BATCH_SIZE`
due rows with `FOR UPDATE SKIP LOCKED`, sends them to SQS (10 per call, the calls side by side, each with the delay
that is left and, on the scan queues, the tenant as the message group), marks the sent rows published, and gives each
refused row its own backoff (2 s doubling to 5 minutes). If SQS refuses a whole batch for one bad message, the rows go
one by one (at most 20 rows a batch), so only that row waits. The whole send phase ends within a 6-second budget,
well inside the 10-second idle limit, and queue URLs are looked up at startup. A crash before the commit loses nothing: the rows stay unpublished and their locks
end with the connection. A crash after the send sends them twice, which consumers skip. Replicas run side by side.
Its claim and its marks filter with `in_scope(Outbox, session)`, and every UPDATE starts from one helper in
`sft.data.outbox`. In system scope the session lets only `sft_relay` write tenant rows (`SYSTEM_WRITERS`), its role
opens no other scope, and its policies match system scope alone. The isolation suite checks that no other role reads
or marks a row.

Each batch is a `relay batch` span, with its claim and marks under it and a `send <queue>` PRODUCER span for each
SQS call, which links to the `create` span of every message the call carries: a batch holds messages from many
traces, so it belongs to none of them. An idle batch is a small trace too, with `messaging.batch.message_count` 0.
The age measurement is a `relay outbox age` span. A send that SQS refuses, in whole or in part, is an error span with
SQS's code as its `error.type`.

| Metric | Meaning |
|---|---|
| `outbox_oldest_unpublished_age_seconds` | Age of the oldest unpublished row after the last batch; ADR-0013 alerts above 120 s |
| `outbox_messages_published_total{queue}` | Rows sent and marked published |
| `outbox_publish_failures_total{queue}` | Sends refused or failed; `queue="unknown"` for a topic the relay doesn't know |
| `outbox_relay_batch_duration_seconds` | One batch: claim, send and mark |

Settings, besides `LOG_LEVEL`, `APP_VERSION`, `BIND_HOST`, `INTERNAL_PORT` (8001) and `SHUTDOWN_DRAIN_SECONDS` (15):

| Variable | Default | Meaning |
|---|---|---|
| `DATABASE_URL` | none, required | `sft_relay`'s URL; a secret |
| `DATABASE_POOL_SIZE` | `2` | Connections per process |
| `SQS_QUEUE_PREFIX` | none, required | The environment's queue names. In AWS `sft-<env>-<region-short>-`: `sft-dev-apne1-` gives `sft-dev-apne1-notify` (infra/modules/queues); locally `sft-local-` |
| `SQS_ENDPOINT_URL` | none | Local only, for ElasticMQ; in AWS the SDK finds SQS's endpoint |
| `AWS_REGION` | `ap-northeast-1` | |
| `RELAY_BATCH_SIZE` | `50` | Rows per transaction (1 to 100) |
| `RELAY_POLL_INTERVAL_SECONDS` | `1.0` | The wait after a batch that wasn't full |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | none | As for the API: spans go to `<endpoint>/v1/traces`; unset or empty, nothing is exported |

In AWS the pod's IAM role is the SQS identity; locally ElasticMQ takes any credentials, and Compose gives obviously fake
ones.

### Idempotent consumers

```python
from sft.workers.consumer import Consumer, ConsumerLoop, ConsumerMetrics, Delivery


class ScanConsumer(Consumer):
    name = "scan-small"  # its processed_messages key: never rename it
    queue = Queue.SCAN_SMALL

    async def handle(self, session: AsyncSession, delivery: Delivery) -> None:
        file_id = delivery.message.payload["file_id"]
        ...  # re-read the file in this tenant's scope and act; raise to have SQS deliver it again


loop = ConsumerLoop(ScanConsumer(database), SqsQueues.create(..., read_timeout=25), metrics)
await process.run(loop.run)
```

`Consumer.process` runs `handle` in one transaction in the message's tenant scope, and records
`(name, outbox ID)` in `processed_messages` first, in the same transaction. A duplicate (an SQS redelivery, a relay
retry, a re-publish after a failover) finds the record and is skipped, so its work is done once; two copies at the
same time wait on each other's record. On shutdown `ConsumerLoop` abandons a long poll in flight at once. It deletes a message once it is processed or skipped, and leaves one
that failed or doesn't parse for SQS to deliver again, until the redrive policy moves it to the dead-letter queue.
`delivery.receive_count` lets the last attempt record a terminal state first. A handler whose effect is an email
records after the send instead (ADR-0013); the notification worker does that itself. Each message that parses is
handled, and deleted, in its own `process <queue>` span, the child of the message's `create` span; a failure marks
it as an error with the exception's type, never its message.

### SQS client

`SqsQueues` (`src/sft/workers/queues.py`) wraps boto3, the only code that touches it, so tests use an in-memory fake
and the integration tests use ElasticMQ. boto3 is synchronous, so each call runs in a small thread pool the adapter
owns. aiobotocore, the async alternative, pins botocore a few releases behind boto3, and the service needs boto3 anyway
(M4's IAM database tokens); the relay's load, about one call a second, is far too light for threads to matter. Each
call runs in a copy of the caller's context, so its AWS span (`trace_aws_client`) is the child of the span it was made
in. A long poll (`ReceiveMessage`) gets no span: it lasts up to 20 s with or without a message, and the gateway keeps
every slow trace.

### Tests against ElasticMQ

The adapter's integration tests and the relay's entry-point tests need an ElasticMQ URL in `TEST_SQS_ENDPOINT_URL`.
They make their own queues under a fresh prefix and delete them. As with PostgreSQL, they are skipped locally without
it and fail in CI, where ElasticMQ is a service container on the Python job.

```bash
docker run --detach --name sft-test-elasticmq --publish 127.0.0.1:59324:9324 softwaremill/elasticmq-native:1.7.1
TEST_SQS_ENDPOINT_URL=http://127.0.0.1:59324 TEST_DATABASE_URL=… uv run pytest
```
