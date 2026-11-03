# 0002. Use FastAPI with SQLAlchemy and Alembic for the API service

- Status: accepted
- Date: 2026-11-03
- Issue: [#9](https://github.com/codewithmuh/secure-file-transfer/issues/9)

## Context

The [PRD](../prd.md) shapes what the API service has to do:

- **API only.** Everything goes through a public, versioned REST API described in OpenAPI 3.1 (FR-31). Its clients are
  the React + TypeScript web app (FR-30) and tenant API keys (FR-32). The backend renders no pages.
- **Security rules on every call.** Tenant isolation (NFR-12), rate limits per IP address, account and tenant (NFR-14),
  and a fail-closed audit write before any download is served (NFR-15).
- **Mostly waiting on other systems.** A request typically talks to PostgreSQL, KMS, S3 (pre-signed URLs), SES and
  Redis. File bytes never pass through the API, and little CPU work happens in the request path.
- **Workers share the data model.** Scanning, notification and deletion workers run outside HTTP but use the same
  tables and rules.
- **Latency target.** p95 ≤ 300 ms at the design load of 150 requests per second, with bursts to 300 (NFR-2, PRD
  section 6.1).

Constraints: one maintainer. The repo template already ships a FastAPI service with CI, Prometheus metrics, JSON logs,
graceful shutdown and `mypy --strict`. The maintainer has years of Django REST framework in production and less FastAPI
experience.

## Decision

Build the API service with **FastAPI**, using **Pydantic v2** for request and response models, **SQLAlchemy 2.0**
(typed ORM, async sessions) for data access and **Alembic** for schema migrations. The workers import the same models
and service layer, without FastAPI.

## Options considered

| Option | Pros | Cons |
|---|---|---|
| **FastAPI + Pydantic v2 + SQLAlchemy 2.0 + Alembic** (chosen) | The OpenAPI 3.1 document is generated from the type hints on each route, so the contract follows the code (FR-31). Async request handling suits an I/O-bound service. Request and response models are checked by mypy end to end. Dependency injection makes the caller, the tenant and the permission check explicit on every route, which is easy to test. SQLAlchemy doesn't depend on the web framework, so the workers share the models. It is already in the template, with CI. | Not batteries-included: authentication, permissions, rate limiting, operator tooling and multi-tenancy are ours to build or choose. There are more choices to get right and less built-in protection against mistakes. Async SQLAlchemy has sharp edges (no implicit lazy loading; session scope has to be managed). boto3 is synchronous, so AWS calls need a thread pool or an async client. |
| **Django + Django REST framework** | Batteries included: ORM, migrations, authentication, permissions, throttling and an admin site. Mature, well-known security defaults. A large ecosystem (django-tenants, drf-spectacular). The maintainer knows it best, so it is the fastest start. | Much of Django goes unused with an API-only backend and a React app (templates, forms, server sessions, the admin site for customers). OpenAPI comes from drf-spectacular, which produces 3.0 by default and builds the document by introspection, so custom views need manual annotations to stay accurate. DRF views are synchronous; async needs a third-party package. DRF's built-in throttling isn't tenant-aware, so NFR-14 needs custom work anyway. Workers have to load Django's settings and app registry to use the ORM. |
| **Litestar** | Similar to FastAPI, with more built in (DTOs, a plugin for SQLAlchemy, rate limiting middleware). | A smaller community and fewer production references, so problems are harder to research. |
| **Flask** | Small, stable and widely known. | No built-in validation or OpenAPI generation. Every piece is an extension, and it is built on WSGI, so async support is limited. |

## Consequences

What we now build and test ourselves, which Django would have given us in part:

- **Authentication and authorization.** One dependency resolves the caller (member session, verified recipient or
  uploader session, API key, platform operator), and every route declares the permission it needs. A test fails if any
  route has no authorization dependency.
- **Tenant isolation.** Every query is scoped to the caller's tenant in the data-access layer, not route by route. The
  isolation suite (NFR-12) covers it. Security design (phase 3) decides whether PostgreSQL row-level security is a
  second layer.
- **Rate limiting.** A Redis-backed limiter for the per-IP, per-account and per-tenant limits (NFR-14), behind the WAF.
- **Migrations.** Alembic migrations are reviewed in the pull request, run as a separate job before the deploy, and
  stay backwards compatible with the running version so deploys have no downtime (NFR-18).
- **Operator tooling.** An operator API and CLI (FR-34) take the place of the Django admin site.
- **Browser security settings.** CORS, CSRF protection for cookie sessions, and security headers are set explicitly
  for the React app.

What becomes easier:

- The React app gets a TypeScript client generated from the OpenAPI document, so a breaking API change fails the web
  app's build.
- Types are checked from the HTTP boundary to the database.
- Workers reuse the service layer instead of duplicating business rules.

How we'll know this was wrong: after the first two vertical slices (phase 5), if the authentication, tenancy and
rate-limit plumbing has taken more effort than the features, or the isolation suite finds leaks that Django's defaults
would have prevented, we revisit this decision with a new ADR. The first load test checks the latency target (NFR-2).
