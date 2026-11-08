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
    dependencies.py   get_database, get_objects and the other dependencies for what the lifespan opens
    members.py        the member routes: invite, list, read, change and deactivate users (FR-22)
    transfers.py      the transfer and file routes; transfer_schemas.py holds their bodies (#114, #174 to #176)
    tenant_policy.py  the tenant policy routes (#174)
    caller.py         get_caller, the request's Caller (a placeholder until #113's sessions)
    errors.py         every error as an RFC 9457 problem; problem_responses() for a route's errors
    observability.py  request and trace IDs, the request span, request metrics, one log line per request
    rate_limits.py    rate_limit(bundle): the route dependency; 401 counting and the IP block
    client_ip.py      the client's address by ADR-0002's rule
    server.py         both listeners in one process, and the graceful shutdown
    __main__.py       python -m sft.api
  workers/      beside api: asyncio workers that use the service layer without HTTP
    relay.py          the outbox relay: python -m sft.workers.relay
    scan.py           the scan worker, one per pool: python -m sft.workers.scan (#175, #176)
    clamd.py          clamd's INSTREAM, and its answers mapped to results (ADR-0019)
    scan_sweep.py     the scan sweep: scan_failed past the deadline (scheduled with the lifecycle jobs)
    consumer.py       Consumer, the idempotent consumer base class, and ConsumerLoop
    queues.py         SQS behind a thin adapter (boto3 in a thread pool)
    process.py        WorkerProcess: probes, SIGTERM and the drain for every worker
  runtime/      what api and workers both need to run as a pod
    internal.py       /healthz, /readyz, /metrics on the internal port
    s3.py             the files buckets behind ObjectStore (boto3 in a thread pool)
  service/      business rules and permission checks
    caller.py         Caller: who is calling and how they signed in; its audit actor and rate-limit keys
    permissions.py    the permission registry (authn and authz 6.3) and authorize()
    members.py        the member rules: the last active admin, invitations, role and approver changes
    transfers.py      transfers and their views; uploads.py: declare, part URLs, complete, remove
    sending.py        sendTransfer and cancelTransfer; evaluation.py the locked evaluation (data model 3.2)
    scans.py          recording a scan and an inspection; the sweep; scan_timing.py routing and deadlines
    file_reads.py     getFile and getFileInspection; tenant_policy.py the tenant's policy (FR-23)
    objects.py        ObjectStore, the object storage the service sees; fields.py seals names and messages
    email/            every email, rendered in English and Japanese as text and HTML (Email below)
    rate_limits/      the limits as data, the limiter and its per-pod fallback
  data/         PostgreSQL: SQLAlchemy, the scope of every transaction, roles, migrations; Valkey counters
    database.py       the pool, and Database.transaction(scope), the only way to open a transaction
    scope.py          Scope: tenant, resource, system, platform, lookup or recovery
    access.py         the rules on top: who opens which scope, in_scope(), TenantOwned
    tenants.py        data-access functions for tenants (one module per table or aggregate)
    users.py          data-access functions for users and their invitations
    transfers.py      transfers and recipients; files.py the files' state changes; usage.py the quota
    findings.py       DLP findings, counts only; suppressions.py the tenant's suppression list
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
  dlp/          beside data: DLP (ADR-0022), the detectors for the service and the inspector, and the inspector itself
    units.py          text units, keyword lists and findings: what goes in and what comes out
    detect/           the built-in detectors of docs/design/dlp-detectors.md and tenant detectors, on RE2
    extract/          text from every ADR-0022 format, with the per-file limits (limits.py) and a reason for the rest
    inspector.py      the inspector service (`python -m sft.dlp.inspector`): one fresh child per file
    child.py          the child: rlimits and a seccomp filter (sandbox.py, seccomp.py), then extract and detect
    protocol.py       the strict-schema frames between scan worker, inspector and child; client.py is the worker's side
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
set -a; source ../../.env; set +a   # the local sign-in settings, from .env.example
DATABASE_URL=postgresql://sft_api:test-only-password@127.0.0.1:5432/sft uv run python -m sft.api
curl -s localhost:8001/readyz   # API on 127.0.0.1:8000, probes and metrics on 127.0.0.1:8001
```

The API needs `DATABASE_URL`, `VALKEY_URL` and the sign-in settings to start, but opens no connection until a request
needs one, and `/readyz` checks none of them: an outage mustn't take every pod out of the load balancer at once.

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
| `PUBLIC_TLS` | `off` | TLS on `PUBLIC_PORT` (encryption and keys 2.2, #184): `generated` (in AWS, a certificate the pod makes at start), `files` (`PUBLIC_TLS_CERT_FILE` and `PUBLIC_TLS_KEY_FILE`), or `off` (locally). The internal port is always plain HTTP |
| `DATABASE_IAM_AUTH` | `false` | In AWS: sign an IAM token for each new connection as `DATABASE_URL`'s role, which holds no password and needs `sslmode=verify-full` (`sft.data.iam_auth`). Every entry point that connects reads it |
| `VALKEY_IAM_CACHE` | none | In AWS: the serverless cache's name, `sft-<env>-<region-short>-valkey`; each new Valkey connection signs an IAM token as `VALKEY_URL`'s user (ADR-0014). Unset locally, where the URL holds a password |
| `TRUSTED_PROXIES` | empty | Our load balancer's subnets, comma-separated; only their requests have the client address read from `X-Forwarded-For` (ADR-0002) |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | none | The collector's OTLP/HTTP base URL, e.g. `http://<node>:4318`; spans go to `<endpoint>/v1/traces`. Unset or empty: nothing is exported |
| `WEB_ORIGIN` | none, required | The web app's origin; CORS and the CSRF `Origin` check allow only it (authn and authz 3.4) |
| `OIDC_ISSUER` | none, required | The user pool's issuer; an ID token's `iss` must equal it (ADR-0016) |
| `OIDC_DISCOVERY_URL` | under the issuer | Where to read the OpenID configuration, if not under the issuer (locally the in-network address) |
| `OIDC_CLIENT_ID` | none, required | The confidential app client |
| `OIDC_CLIENT_SECRET` | none, required | Its secret (`sft/{env}/app/idp-client/<region>`); a secret |
| `OIDC_REDIRECT_URI` | none, required | This API's `/v1/auth/callback`, as registered with the client |
| `OIDC_LOGOUT_URL` | none, required | The pool's logout URL that `signOut` returns |
| `OIDC_REVOCATION_URL` | from discovery | The token revocation endpoint (Cognito's isn't in its discovery document) |
| `OIDC_PROVIDER_NAME` | none, required | The pool's `idp_connections.provider_name` (`local-keycloak` locally) |
| `CSRF_KEYRING` | none, required | K_csrf (`sft/{env}/app/csrf-hmac`): a JSON list of `{id, state, key}`, exactly one `active`; or, in AWS, `secretsmanager:<secret id>`, read at start and every 5 minutes (`sft.runtime.secrets`, #184). The same holds for every keyring setting; a secret |
| `EMAIL_HMAC_KEYRING` | none, required | The `email-hmac` keyring (`sft/{env}/app/email-hmac`), the shape of `CSRF_KEYRING` with `activated_at` on the active key: per-address rate limits count under its pseudonyms, never an address; a secret |
| `ADMIN_PASSKEY_RULE` | `false` | ADR-0016's launch switch: a local admin acts as an admin only after a passkey sign-in |
| `AWS_REGION` | `ap-northeast-1` | The region of the files buckets |
| `S3_FILES_BUCKET` | none, required | The files bucket for files up to 2 GB |
| `S3_LARGE_FILES_BUCKET` | none, required | The files bucket for files over 2 GB, which GuardDuty scans (ADR-0019) |
| `S3_FILES_KMS_KEY_ID` | none, required | The files key for SSE-KMS; S3Mock takes only the bare key ID |
| `S3_ENDPOINT_URL` | none | Local only, for S3Mock; in AWS the SDK finds S3's endpoint |
| `S3_PRESIGN_ENDPOINT_URL` | none | Local only: the S3 stand-in as the browser reaches it (`http://localhost:9090`), used only to sign part URLs; refused without `S3_ENDPOINT_URL` (#195) |
| `TENANT_STORAGE_QUOTA_BYTES` | `2000000000000` | Each tenant's storage quota (abuse and rate limits 6.1) |
| `AUDIT_ARCHIVE_TOKYO_BUCKET` | none, required | The audit archive bucket in Tokyo, which every security-critical record reaches before a `2xx` (#177) |
| `AUDIT_ARCHIVE_OSAKA_BUCKET` | none | The audit archive bucket in Osaka; unset only where there is no Osaka (dev), and records then go to Tokyo's alone |
| `AUDIT_ARCHIVE_TOKYO_ENDPOINT_URL`, `AUDIT_ARCHIVE_OSAKA_ENDPOINT_URL` | none | Local only, for S3Mock; in AWS the SDK finds each region's S3 endpoint |
| `CODE_HMAC_KEYRING` | none, required | K_code (`sft/{env}/app/code-hmac`), the shape of `CSRF_KEYRING`: the API checks verification codes' HMACs with it (#179); a secret |

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

The DLP inspector (`python -m sft.dlp.inspector`) reads `InspectorSettings`, which hold no secret:

| Variable | Default | Meaning |
|---|---|---|
| `BIND_HOST` | `127.0.0.1` | The pod sets `0.0.0.0`; its network policy admits only the scan workers |
| `INSPECTOR_PORT` | `8070` | Where scan workers connect, one file per connection |
| `INSPECTOR_SCRATCH_DIR` | none, required | The 4 GiB scratch volume, the only writable path |
| `INSPECTOR_IO_TIMEOUT_SECONDS` | `60` | How long a connection may stay idle before it is dropped (1 to 900) |
| `INTERNAL_PORT` | `8001` | `/healthz` and `/readyz` only, plain HTTP from a thread, so a probe never reaches the framed protocol (#184) |

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
  a `preStop` sleep in the pod spec ([deploy/](../../deploy/README.md)) holds the signal back for that time
  (`src/sft/api/server.py` has the details).
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
each new connection, over TLS with `sslmode=verify-full` (encryption and keys 2.2, 6.3; `DATABASE_IAM_AUTH`,
`sft.data.iam_auth`, #184), so `DATABASE_URL` holds a user name and a host, never a password. The master password
lives only in Secrets Manager (`sft/{env}/db/master`), set by Terraform's write-only arguments; the bootstrap job
reads it once and after that only break-glass does. **Locally and in CI** there is no IAM: run the bootstrap with `BOOTSTRAP_IAM_AUTH=false` as a superuser, and give the login roles an
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
in the pod at a third of each limit (abuse design 4.5). Every failed authentication, a `401 credentials_invalid` (a
credential presented that matches no live one), counts against the client's IP (group H); no credential, an ended
session and a step-up don't. An IP blocked after 100 of them gets `429` on every route, checked before routing and
authentication.

The counter store (`sft/data/counters.py`) runs GCRA for rates and a sliding log for small quotas, one Lua script per
key, with 50 ms per call and a 10-second rest after 5 failures in a row (ADR-0014). A rate of N per period admits a
burst of N // 2 + 1, then the rest evenly spaced, so no window of one period holds more than N. The client is
[valkey-py](https://github.com/valkey-io/valkey-py), the Valkey project's asyncio client: pure Python, the redis-py
API, standalone and cluster clients, and a credential provider, which signs the IAM tokens in AWS (#184).

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

## DLP

### Tenant pattern budget

Each tenant pattern has a scan-time budget per file (`PatternBudget` in `src/sft/dlp/detect/tenant.py`, #147): 0.5 s
of CPU plus 50 ms per MiB of text it scans, and 100,000 matches, checked after every 64 KiB chunk. A pattern past it
stops for the rest of the file, the others carry on, and the inspector's result lists it in `budget_exceeded`, by
detector ID only. The file's state doesn't change. An RE2 memory budget at save time (`max_mem`) was tried as a
tighter check and doesn't refuse the slow patterns: the issue's example compiles even at 64 KiB.

### DLP bank and branch codes

`jp_bank_account` is high when a valid bank and branch code pair is near the account
([DLP detectors 4.4](../../docs/design/dlp-detectors.md)). The pairs live in `src/sft/dlp/detect/bank_codes.txt`: a
header with `source`, `licence` and `retrieved`, then one 7-digit code per line (bank, then branch), sorted, each
once. The file's retrieval
date is part of `DETECTORS_VERSION`, so every file records which list inspected it.

**Nothing is bundled yet (#146)**: no source whose licence allows redistribution has been confirmed, so the file holds
only its header and the detector stays at medium. To bundle or refresh a list, before each release and at least every
three months:

1. Obtain the list from a source whose terms allow redistributing it inside the inspector image, and record the terms.
   A list compiled from a site whose terms are silent on reuse doesn't qualify.
2. Save it as UTF-8 CSV with `bank_code` (4 digits) and `branch_code` (3 digits) columns, leading zeros kept.
3. `uv run python -m tools.bank_codes codes.csv --source "<publisher, URL>" --licence "<terms>" --retrieved YYYY-MM-DD`
   rewrites the file, sorted and checked.
4. Run `uv run pytest tests/test_dlp_bank_codes.py tests/test_dlp_detect.py tests/test_dlp_corpus.py` and record the
   source and licence in the pull request. The corpus uses its own synthetic list (`tests/bank_codes_fixture.txt`),
   so its results don't depend on the bundled one.

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

### The notification worker

`python -m sft.workers.notify` (#178, #179) reads the notify queue and sends every email of a recipient or a member
(`sft.service.notifications`): each recipient's link once a transfer is sent (one `recipient.link_due` message per
recipient, written by the worker itself), the verification codes recipients ask for, the lockout notice, and the
held and back-to-draft notices. It records each message after the send, in a transaction of its own, so a failed send
is delivered again and a recorded success is never sent twice. A retry rebuilds the same link: the token is derived
from the recipient's ID and `link_issued_at` with `link-hmac`, and only its SHA-256 is stored. It checks the
suppression list first, then the cross-tenant cap (100 link emails a day to one address, abuse 7.2), which holds the
email back with a delayed message and leaves the recipient `queued`. `member.invited` and `member.sign_in_reset`
(#197) create the member's user in the user pool with a temporary password, record the identity, then send the
invitation: through Cognito's admin API in AWS (`sft.runtime.cognito`, #193), Keycloak's locally. Cognito sends
nothing itself (`MessageAction=SUPPRESS`); the invitation is the catalog's, in the tenant's language. Without a pool
adapter (`USER_POOL_BACKEND=none`) they are recorded and send nothing. Metrics: `emails_sent_total{type}`,
`email_caps_hit_total{cap}`, `worker_messages_total`.

Beside the notify queue it reads **SES's events** from the `ses-events` queue (#185, ADR-0015,
`sft.service.ses_events`): SNS's envelope around each event of the region's configuration set. A permanent bounce
suppresses the address for the sending tenant for 90 days, or for good when it bounced before; a complaint suppresses
it for good; a bounce or reject of a link email leaves its recipient `bounced`. Each change writes its audit event. The
tenant comes from the send's `tenant_id` tag, so an event without one (Cognito's own mail) changes nothing and is
deleted; so are deliveries, delays and transient bounces. A copy is handled once: its ID is derived from SES's message
ID, the event type and its time. An entry found under an older `email-hmac` key moves to the active key.

`python -m sft.workers.invite_backlog` (the same as `python -m sft.workers.notify invite-backlog`) is the one-off pass
that invites, through the pool, every member left `invited` before the pool existed (#193): a new `member.invited`
message each, skipping members who already have an identity on the pool's connection. It reads the worker's settings,
lists the users across tenants in the system scope, read only (revision 0017), and exits 0 when done, 1 on a failure;
running it again is safe. The chart has it as a suspended CronJob, run by hand once (deploy/README.md).

It reads a worker's settings (as the relay's below, its role `sft_notify`), `MailSettings` above, and:

| Variable | Default | Meaning |
|---|---|---|
| `VALKEY_URL` | none, required | The counter store, for the cross-tenant cap; unreachable, the cap counts in this pod; a secret |
| `EMAIL_HMAC_KEYRING` | none, required | As the API's: the suppression list's pseudonyms and the cap's key; a secret |
| `LINK_HMAC_KEYRING` | none, required | K_link (`sft/{env}/app/link-hmac`), which only this worker reads; keep an old key 14 days after a rotation (data model 2.2); a secret |
| `CODE_HMAC_KEYRING` | none, required | K_code: each new code's HMAC; a secret |
| `USER_POOL_BACKEND` | `none` | The user pool's admin side (#197, #193, authn-authz 2.5): `cognito` in AWS and `keycloak` in the local stack, where the worker creates an invited member's pool user with a temporary password and records the identity before the invitation; `none` records invitations and sends nothing |
| `USER_POOL_PROVIDER_NAME` | none | With a pool: its `idp_connections.provider_name` (the API's `OIDC_PROVIDER_NAME`); for Cognito, the pool's ID |
| `COGNITO_USER_POOL_ID` | none | With `USER_POOL_BACKEND=cognito`, required: this region's pool, `ap-northeast-1_…`, the same as `USER_POOL_PROVIDER_NAME`. The worker's role may call only the `Admin*` user calls it makes |
| `KEYCLOAK_URL`, `KEYCLOAK_REALM`, `KEYCLOAK_CLIENT_ID`, `KEYCLOAK_CLIENT_SECRET` | none | With `USER_POOL_BACKEND=keycloak`, all required: Keycloak's in-network address, the realm, and the client whose service account may manage the realm's users; the secret is a secret. Local only |

Its tests (`tests/test_notify.py`) run it against PostgreSQL with every email recorded; one sends through the SMTP
adapter to Mailpit when `TEST_MAIL_CATCHER_URL` and `TEST_SMTP_PORT` are set, and the cross-tenant cap's counts in
Valkey (`TEST_VALKEY_URL`).

## Security-critical records

`sft.service.audit_archive` (#177) writes a security-critical record (a deactivation, a demotion, a lockout, an
unlock, and the revocations and download grants to come) straight to the audit archive bucket of each region, through
`sft.runtime.archive.S3AuditArchive`. A record is the event's IDs, enums, times and `details` (`ArchivedEvent`), at
`security-critical/v1/<tenant>/<yyyy>/<mm>/<dd>/<event ID>.json`, written once with `If-None-Match: *`.

- **Commit, then archive**: `await archive.confirm([event])` after the change commits; a failed region raises
  `RecordNotConfirmed`, a `503` that means "done, not yet confirmed". A retry finds the change made, reads its event
  with `audit.latest_critical_event` and confirms it again, which rewrites nothing that is there.
- **Intent first**, for download grants (#180): `intent_first(archive, intent, commit)` writes the intent to both
  regions (a `503` there changes nothing), runs the commit, then writes the committed record in the background until
  both regions confirm.

Failed writes are counted in `audit_archive_write_failures_total{region}`. The tests use an in-memory store
(`tests/archive_fixtures.py`); `tests/test_audit_archive.py` runs the S3 adapter against S3Mock.

## Links, codes and link sessions

`sft.service.links` (#179) holds the link steps (`resolveLink`, `requestVerificationCode`, `createLinkSession`) and the
`/session` routes. The link steps apply group A's per-IP limits before the token lookup and fail closed (`503`)
without the counter store; a code is checked in the five steps of data model 2.4; a lockout is a security-critical
record. A browser's link sessions live in the `__Host-sft_link` cookie (up to 10 tokens), and `X-Link-Session` picks
one; the `/session` routes run in that session's resource scope. `sft.service.recipients` holds
`listTransferRecipients` and `unlockRecipient`. Tests: `tests/test_links.py` (with Valkey), `tests/test_notify.py`.

## Idempotency keys

A creating `POST` that the contract gives `Idempotency-Key` takes `IdempotencyDep` (`sft.api.idempotency`) and runs
its work through `sft.service.idempotency.once`, in the transaction that creates the resource (architecture 5.4, API
README 5). The key's row in `idempotency_keys` (revision 0007) keeps the request's fingerprint (method, path, canonical
body), the status and the created resource's ID for 24 hours, never a response body. A retry with the same request
gets the first status and the resource as it is now, and creates, audits and charges nothing; another request with
the key gets `409 idempotency_conflict`; one sent while the first still runs gets `409 idempotency_in_progress`,
from a transaction-scoped advisory lock. `inviteUser`, `createTransfer` and `addTransferFile` use it; an operation
that works outside its transaction first (`addTransferFile` starts an S3 upload) checks for a stored answer with
`replay` before that work. `delete_expired_keys` is the daily job's step,
as `sft_jobs`; the jobs worker that schedules it comes later.

## Transfers and uploads

`src/sft/api/transfers.py` serves `createTransfer`, `addTransferFile`, `requestUploadPartUrls`, `listUploadedParts`,
`completeUpload` and `deleteFile` (#114), and `listTransfers`, `getTransfer`, `sendTransfer`, `cancelTransfer`,
`getFile` and `getFileInspection` (#174 to #176, below). The routes only translate; `sft.service.transfers` and
`sft.service.uploads` check the caller with `authorize` and then the state, and `sft.runtime.s3` is the S3 adapter
behind `sft.service.objects.ObjectStore`.

- **Who may.** A member session or an API key (`get_tenant_caller`). `createTransfer` is open to every member and to a
  key with `transfers:write`; the file operations are Own: the transfer's sender, or a key of theirs. Anyone else who
  may read every transfer of the tenant (an admin acting as one, a key with `transfers:read`) gets `403`; the rest
  `404`.
- **Rate limits.** `createTransfer` and `deleteFile` are group H. The four upload operations are group F (600 a minute
  per caller, 1,200 per IP) and count in the tenant's group H budget.
- **Idempotency.** `createTransfer` and `addTransferFile` take `Idempotency-Key`. A retried `addTransferFile` is
  answered from the key before any S3 call, so it starts no second upload.
- **Adding a file** reserves its declared size against the tenant's quota and starts a multipart upload, in the
  standard bucket up to 2 GB and the large-files bucket above. The plan is whole-MiB parts of at least 5 MiB, at most
  1,000 of them.
- **Part URLs** are signed for one part's exact size and live 15 minutes (abuse and rate limits 6.2).
- **Completion** runs in three phases (architecture 4.1, data model 3.1): a short transaction under the transfer's row
  lock moves the file to `completing`; then, with no transaction open, S3's own part list is checked against the plan
  and assembled; then a second locked transaction re-checks the transfer and the file. A revocation or removal that
  landed meanwhile, a size mismatch or a vanished upload rejects the file and releases its reservation; missing parts
  send it back to `uploading`. Otherwise it moves to `scanning` and the scan message goes to the outbox in the same
  transaction. A retry is safe at every point.

## Sending and scanning

- **Sending** (`sft.service.sending`, #174) locks the draft, checks its files, the tenant's `max_expiry` and suppression
  list as they are now and group G's email caps, submits it, and runs the evaluation (`sft.service.evaluation`, data
  model 3.2) in the same transaction. Every scan result, removal and rejection runs the same evaluation under the
  transfer's row lock. No DLP rule gates sending before DLP-4.
- **The scan worker** (`python -m sft.workers.scan`, `SCAN_POOL=small|large`, #175, #176) reads the version recorded at
  completion once and tees it to clamd and the DLP inspector; records the scan, the inspection and the findings in one
  transaction; then tags the object and runs the evaluation. A failed attempt is retried by SQS; the 5th records what
  it has. Files go to the small pool up to 100 MB, the large one up to 2 GB; files over 2 GB wait for GuardDuty (M6),
  so completion records them `scan_failed` (`large_file_scanning_unavailable`) at once. The read follows clamd; an
  inspector that falls 64 MiB behind for 30 s is dropped for the attempt. Group G's caps on a send are read before
  the row lock and charged all or nothing, in batched counter calls (`RateLimiter.check_all`).
- **Tests.** `tests/test_send.py`, `tests/test_scan_worker.py` and the others run with stand-ins for clamd and the
  inspector on real sockets (`tests/scan_fixtures.py`). `tests/test_scan_engines.py` runs the worker against the real
  clamd, as the local stack configures it, with `TEST_CLAMD_URL` (skipped without it; CI's Python job runs clamd), and
  against the real inspector and detectors in their sandbox on Linux only:

```bash
docker run --detach --rm --name sft-test-clamd --user 1000:1000 --entrypoint /init-unprivileged \
  --env CLAMAV_NO_FRESHCLAMD=true --publish 127.0.0.1:3310:3310 \
  --volume "$PWD/../../local/clamav/clamd.conf:/etc/clamav/clamd.conf:ro" clamav/clamav:1.5.4-debian
TEST_CLAMD_URL=tcp://127.0.0.1:3310 TEST_DATABASE_URL=… uv run pytest tests/test_scan_engines.py
```

### Tests against S3Mock

`tests/test_transfers.py` runs every route against PostgreSQL with an in-memory object store
(`tests/object_fixtures.py`). `tests/test_s3_s3mock.py` runs the adapter, and one upload end to end, against S3Mock;
it needs `TEST_S3_ENDPOINT_URL`, makes its own versioned buckets, and is skipped locally without it and fails in CI,
where S3Mock is a service container on the Python job.

```bash
docker run --detach --name sft-test-s3mock --publish 127.0.0.1:59090:9090 \
  --env COM_ADOBE_TESTING_S3MOCK_STORE_REGION=ap-northeast-1 \
  --env COM_ADOBE_TESTING_S3MOCK_STORE_VALID_KMS_KEYS=arn:aws:kms:ap-northeast-1:000000000000:key/00000000-0000-4000-8000-000000000001 \
  adobe/s3mock:5.2.3
TEST_S3_ENDPOINT_URL=http://127.0.0.1:59090 TEST_DATABASE_URL=… uv run pytest
```

## Member sign-in and sessions

The OIDC code flow with PKCE against the environment's user pool, Keycloak locally (ADR-0016, authn and authz 2.4 and
3): `startSignIn` (`GET /v1/auth/sign-in`) stores the state, verifier and nonce in Valkey for 10 minutes under the
SHA-256 of a new `__Host-sft_auth` cookie, and `completeSignIn` (`GET /v1/auth/callback`) takes that record once,
exchanges the code, revokes the refresh token, checks the ID token with joserfc and finds the identity by
`(connection, subject)`, never by a claim. Every refusal is audited with its reason; the browser only sees
`error=sign_in_failed`. A sign-in creates a member session: 256 random bits in the `__Host-sft_session` cookie, only
its SHA-256 in `member_sessions`, 12 hours at most, 30 minutes idle, 10 per user (`sft.data.member_sessions`).

Every member route resolves the cookie through `sft.api.caller` (one credential per request, a live session), and an
unsafe method also needs `Origin` equal to `WEB_ORIGIN`, a JSON body and `X-CSRF-Token`, the HMAC of the session
token under `CSRF_KEYRING` that `GET /v1/me` returns. `signOut` ends this session or all of them. A role change, a
deactivation and a tenant's suspension revoke the sessions they affect in the same transaction.

## The operator API

`python -m sft.api.operator`: a second app from the same image (FR-34, architecture 2). It runs as its own Deployment
in `sft-operator`, logs in as `sft_operator`, and sits behind no load balancer; operators reach it by `kubectl
port-forward`. It serves only the contract's operator operations, and the public app serves none of them; the
generated-spec check (`tools/contract_check.py`) holds each app to its own server.

| Operation | What it does |
|---|---|
| `createOperatorToken` | A signed STS `GetCallerIdentity` request in, a 15-minute operator token out (authn and authz 8.2) |
| `createTenant` | Creates the tenant with its settings and invites its first admin, in one transaction |
| `listTenants`, `getTenant` | Reads tenants, newest first, a page at a time, optionally by status |
| `suspendTenant` | Suspends a tenant and revokes every member session it has |

Every call is audited, including refusals; every operation but the token exchange needs the token. Every refused
token exchange answers the same `401 credentials_invalid`, and the audit event records why.

Settings: the server's (the listeners, `DATABASE_URL`, `DATABASE_POOL_SIZE`, `VALKEY_URL`, `TRUSTED_PROXIES`), none of
member sign-in's, and its own. `DATABASE_URL` names `sft_operator`; `OPERATOR_ENVIRONMENT` (`dev`, `staging`,
`prod`; operators sign the audience `operator-api-<env>`); `OPERATOR_AWS_ACCOUNT_ID` and `OPERATOR_ROLE_NAME`, the
account and `Operator` permission set role STS must answer with; `AWS_REGION`; and `OPERATOR_STS_ENDPOINT_URL`, by
default the regional STS endpoint, never taken from a request.

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

### The key rotation job

`python -m sft.workers.key_rotation` (#185; encryption and keys 6.4, 6.5) is the only writer of the
`sft/{env}/app/*` secrets. Terraform creates them without a value, so its first run writes every first version; the
API and the notification worker start only after that. Each hourly run (Tokyo only, `sft.service.key_rotation`) takes
at most one step per secret: a keyring is staged once its active key is older than its period, activated 15 minutes
after staging, and its old key retired after the overlap (6.5's table); an `email-hmac` key is never retired by the job,
because only the database knows when no suppression row uses it, so that stays an operator's step for now. Each pool's
app client gets a second client secret from Cognito once the stored one is a year old or isn't live; the older one is
deleted after 15 minutes (Tokyo's) or a day (Osaka's). A keyring step needs nothing more, because the workloads read
their keyrings every 5 minutes (`sft.runtime.secrets`, #184). After a new client secret in Tokyo, which the API reads at
start through External Secrets, it has External Secrets sync `api-secrets`, waits until it has, then restarts the `api`
Deployment. For that alone it has a projected Kubernetes token, whose Role names those two objects. It logs one report line naming secrets, steps and key IDs, never a value, and exits 0, 1 (the next run
retries) or 2 (bad settings).

| Variable | Default | Meaning |
|---|---|---|
| `ENVIRONMENT` | none, required | `dev`, `staging` or `prod`: the secrets are `sft/<env>/app/*` |
| `AWS_REGION` | `ap-northeast-1` | Tokyo only: the keyrings' primary Region |
| `IDP_CLIENTS` | `[]` | JSON: each pool's app client, `[{region, user_pool_id, client_id}]`; Tokyo's, and Osaka's outside dev |
| `RESTART_DEPLOYMENTS` | `api` | Comma-separated, restarted after a new client secret; empty restarts nothing |
| `EXTERNAL_SECRETS` | `api-secrets` | Comma-separated: synced before the restart |
| `KUBERNETES_NAMESPACE`, `KUBERNETES_URL`, `KUBERNETES_TOKEN_PATH`, `KUBERNETES_CA_PATH` | `sft`, the in-cluster API, the projected token and CA | Where the reload goes |

Its tests (`tests/test_key_rotation.py`) run the rules against fakes, and the adapters against botocore's Stubber and
an in-memory Kubernetes API.
