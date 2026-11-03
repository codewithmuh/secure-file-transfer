# 0002. Use FastAPI with SQLAlchemy and Alembic for the API service

- Status: accepted
- Date: 2026-11-03
- Issue: [#9](https://github.com/codewithmuh/secure-file-transfer/issues/9)

## Context

The [PRD](../prd.md) shapes what the API service has to do:

- **API only.** Everything goes through a public, versioned REST API described in OpenAPI 3.1 (FR-31). Its clients are
  the React + TypeScript web app (FR-30) and tenant API keys (FR-32). The backend renders no pages, but the web app uses
  cookie sessions, so it needs CSRF protection.
- **Security rules on every call.** Tenant isolation (NFR-12), rate limits per IP address, account, tenant and invited
  email address (NFR-14), and a fail-closed audit write before any download is served (NFR-15).
- **Mostly waiting on other systems.** A request typically talks to PostgreSQL, KMS, S3, SES and a rate-limit store,
  with little CPU work in between. File bytes normally don't pass through the API, although the download mechanism in
  open question 8 may stream them through the service.
- **Workers share the data model and the rules.** Scanning, notification, deletion and reconciliation run outside HTTP
  but must apply the same permission and scoping rules.
- **Latency target.** p95 ≤ 300 ms and p99 ≤ 1 s at the design load (NFR-2, PRD section 6.1).

Constraints: one maintainer. The repo template already ships a FastAPI service with CI, Prometheus metrics, JSON logs,
graceful shutdown and `mypy --strict`. The maintainer has years of Django REST framework in production and less FastAPI
experience. As a reference service, the project also aims to show how authentication, sessions, tenant scoping and rate
limiting are built and tested explicitly, rather than inherited from a framework.

## Decision

Build the API service with **FastAPI**, using **Pydantic v2** for request and response models, **SQLAlchemy 2.0** with
async sessions and the **psycopg 3** driver for data access, and **Alembic** for schema migrations. The workers run on
asyncio and import the same service layer, without FastAPI. Authorization lives in that service layer, so HTTP routes
and workers go through the same checks; FastAPI dependencies only work out who the caller is.

## Options considered

| Option | Pros | Cons |
|---|---|---|
| **FastAPI + Pydantic v2 + SQLAlchemy 2.0 + Alembic** (chosen) | The OpenAPI 3.1 document is generated from the type hints for requests and success responses. Async request handling suits an I/O-bound service, and streaming responses if open question 8 needs them. Request and response models are checked by mypy end to end. Dependency injection makes caller resolution explicit and easy to test. SQLAlchemy doesn't depend on the web framework, so workers share the data layer. It is already in the template, with CI. | Not batteries-included: authentication, sessions, CSRF, permissions, rate limiting, operator tooling and tenant scoping are ours to build or choose, with more choices to get right. Error responses, security schemes and headers only appear in the OpenAPI document if each route declares them. Async SQLAlchemy has sharp edges (no implicit lazy loading; session scope has to be managed). boto3 is synchronous, so AWS calls need a thread pool or an async client. |
| **Django + Django Ninja** | The strongest alternative. Django's authentication, sessions, CSRF protection, migrations and admin site, plus Pydantic schemas, OpenAPI generated from type hints, and async views. The maintainer knows Django well. | Django's async ORM can't run transactions in async code yet, so the request path mixes sync and async. Workers have to load Django's settings and app registry to use the ORM. A smaller ecosystem than DRF or FastAPI. It inherits exactly the parts this project means to build and test explicitly. |
| **Django + Django REST framework** | Batteries included: ORM, migrations, authentication, sessions, CSRF, permissions, throttling and an admin site. Mature, well-known security defaults. A large ecosystem (django-tenants, drf-spectacular). The fastest start for the maintainer. | Templates, forms and the admin site for customers go unused with a React app. DRF views are synchronous; async needs a third-party package. OpenAPI comes from drf-spectacular by introspection (3.1 is an opt-in setting), and custom views need manual annotations to stay accurate. Built-in throttling isn't tenant- or email-aware, so NFR-14 needs custom work anyway. Workers have to load Django to use the ORM. |
| **Litestar** | Similar to FastAPI, with more built in (DTOs, a plugin for SQLAlchemy, rate-limiting middleware). | A smaller community and fewer production references, so problems are harder to research. |
| **Flask** | Small, stable and widely known. | No built-in validation or OpenAPI generation; every piece is an extension. Built on WSGI, so async support is limited. |

## Consequences

What we now build and test ourselves:

- **Caller resolution and authorization.** A FastAPI dependency resolves the caller: member session, verified recipient
  or uploader session, API key, or platform operator. Every service function takes that caller, or a named system actor
  for a worker or job, and checks the permission itself. Every route declares either a permission or an explicit
  `public` marker, and a test fails if a route has neither.
- **The public surface.** Only sign-in, the recipient and uploader steps before verification, and the load balancer's
  health check are public. `/metrics` and the interactive docs (`/docs`, `/redoc`) aren't reachable through the public
  load balancer; the OpenAPI document is published from CI instead.
- **Scoped data access.** No query runs without an explicit scope. The scope is a tenant (from a member or API key), a
  single resource (one transfer or request, from a verified link session), or the system (a named, audited job such as
  deletion or reconciliation). There is no default unscoped path. The isolation suite (NFR-12) tests the data-access
  layer directly, not only HTTP endpoints. Security design (phase 3) decides whether PostgreSQL row-level security is
  a second layer.
- **Rate limiting.** Limits keyed by IP address, account, tenant, invited email address and verification proof
  (NFR-14), with counters shared across API replicas. Where the counters live gets its own ADR (for example Redis,
  PostgreSQL, or WAF rate rules for the per-IP part).
- **Client IP.** The client address is taken from the `X-Forwarded-For` entry added by our own load balancer, trusting
  only its addresses and never a header the client sent. Rate limits and audit records (FR-27) both use it.
- **Sessions, CSRF and headers.** Cookie sessions for the web app with CSRF protection, CORS limited to the web app's
  origin, and security headers, all set explicitly.
- **Migrations.** Alembic migrations are reviewed in the pull request, run as a separate job before the deploy, and stay
  backwards compatible with the running version so deploys have no downtime (NFR-18).
- **Async workers.** Workers run on asyncio with async SQLAlchemy; AWS SDK calls run in a thread pool or through an
  async client.
- **The API contract.** Phase 2 writes the OpenAPI contract first. Once code exists, the document generated from the
  code is committed to `docs/`. CI fails if the committed and generated documents differ, and a breaking-change check
  (for example oasdiff) fails the pull request unless it is marked as breaking. Every route declares its error responses
  (401, 403, 404, 409 and 429), so they are part of the contract.
- **Operator tooling.** An operator API (FR-34), used through a small CLI, takes the place of the Django admin site.

What becomes easier:

- The React app gets a TypeScript client, with typed errors, generated from the OpenAPI document.
- Types are checked from the HTTP boundary to the database.
- Workers reuse the service layer and its permission checks instead of duplicating business rules.

When to revisit: at the end of the first vertical slice (phase 5), before the second slice adds more data-access code.
If caller resolution, sessions, CSRF, scoping and rate limiting took more than half of that slice's effort, or the
first load test misses NFR-2 because of the framework layer, we write a superseding ADR. Django with Django Ninja is
the fallback.
