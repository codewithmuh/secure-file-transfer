# Delivery plan

| | |
|---|---|
| Requirements | [PRD](prd.md) |
| Design | [Architecture](architecture.md), [data model](design/data-model.md), [API contract](api/openapi.yaml), [security](security/), [threat model](threat-model.md), [ADRs](adr/) |
| Tracking | [#43](https://github.com/codewithmuh/secure-file-transfer/issues/43), planning phase 5 |

Planning phases 1–4 decided what to build and how. This page decides the order. The service is built as thin vertical
slices: each milestone ends with something that runs end to end, is tested, and could be shown to someone.

## 1. Principles

- **Walking skeleton first.** M0 builds the bones every later feature hangs on: service layout, database, scoped data
  access, audit, outbox, CI and a local stack. No feature work starts before they exist.
- **Local before AWS.** M0–M3 run entirely on a laptop with `make up`. AWS arrives in M4, so the first deployment
  ships working software, and nothing is applied until the maintainer names the AWS profiles (CLAUDE.md).
- **Vertical, not horizontal.** A slice goes from the API through the workers to the database and back, with its tests,
  rather than building "all models" or "all endpoints" first.
- **Security from the first line.** Tenant scoping, row-level security, the isolation suite and the audit trail are in
  M0, not added later. Every endpoint added afterwards is covered by the isolation suite and the authorization matrix
  test from day one.
- **Operations alongside features.** Every alert a milestone adds ships with its runbook (NFR-17). Phase 6 (SLOs,
  dashboards, drills) is finished in M7, but its pieces arrive with the features they watch.
- **Small PRs.** One issue, one branch, one PR, reviewed before merge (CONTRIBUTING.md). A PR that takes longer than a
  day to review is split.

## 2. Definition of done

An issue is done when its PR:

1. closes the issue and meets its acceptance criteria;
2. has unit and integration tests, and coverage stays at or above 80 %;
3. adds isolation-suite and authorization-matrix cases for every new endpoint or data-access function;
4. writes audit events for every security-relevant action it adds (FR-27);
5. updates the API contract, data model, architecture, ADRs or runbooks it changes, in the same PR;
6. passes CI and its code review, with findings fixed on the same branch, before it is merged.

## 3. Milestones

| Milestone | Goal | Requirements | Exit criteria |
|---|---|---|---|
| **M0 Foundation** | The skeleton every feature needs, running locally | NFR-12, NFR-15 (foundations), NFR-18 (migrations) | `make up` starts the API, the outbox relay and the local stack; `make check` is green; the isolation suite and the fail-closed audit tests run in CI against real PostgreSQL |
| **M1 Tenants and members** | Operators create tenants; admins manage members; members sign in | FR-22, FR-23, FR-25, FR-27, FR-28 (API), FR-31, FR-34 | An operator creates a tenant and its first admin; the admin invites a member who signs in through the local OIDC provider; the authorization matrix test covers every M1 operation |
| **M2 Send a transfer** | The core journey, end to end, locally | FR-1 to FR-7, FR-14 to FR-21, FR-33 (emails), NFR-4, NFR-6, NFR-8, NFR-14 (codes and links) | One automated test sends a transfer, uploads in parts, scans with ClamAV, emails a link, verifies, streams a download with resume, revokes, and checks that expiry deletes every copy |
| **M3 Web app** | Members and recipients use the browser, not curl | FR-30, FR-31 (generated client), FR-33 (pages), NFR-22 | A browser test runs the M2 journey through the React app in English and Japanese; axe accessibility checks pass in CI |
| **M4 AWS dev** | The same software running in AWS | ADR-0004 to ADR-0015, ADR-0021, NFR-13, NFR-19, NFR-21 | Terraform builds the dev account from scratch; Argo CD deploys the M2–M3 build; the synthetic probe passes in dev; `terraform destroy` leaves nothing that bills |
| **M5 Requests and administration** | The rest of the product | FR-8 to FR-13, FR-24, FR-28 (UI), FR-29, FR-32 | The upload-request journey passes end to end in dev; audit search and export work; API keys pass the authorization matrix |
| **M6 Security hardening** | The full security design | FR-26, FR-35, NFR-14 (all limits), ADR-0016 to ADR-0020 | SSO, step-up and break-glass work and are audited; the WAF and every rate limit are tested; files over 2 GB are scanned by GuardDuty; file names and messages are field-encrypted; every test in the threat model's section 6 is automated or scheduled |
| **M7 Production and operations** | Staging, prod with the Osaka pilot light, and measured NFRs | NFR-1 to NFR-3, NFR-5, NFR-9 to NFR-11, NFR-16, NFR-17, NFR-20, #42 | SLO dashboards and alerts with runbooks; a load test at design load; a regional failover drill with measured RTO and RPO; the operating period; a timed teardown |

Every Must requirement in the PRD is placed above. The Should requirements (FR-8, FR-9, FR-24, FR-26, FR-29, FR-32)
sit in M5 and M6 and can move to after v1 if the schedule needs it.

## 4. Milestone details

### M0 Foundation

The issues below are created when this plan merges. Together they give a service that does nothing useful yet, but
already has the shape, the safety rails and the CI of the finished product.

| Issue | Scope | Acceptance criteria |
|---|---|---|
| chore: remove the Go sample | Delete `services/api-go`, its CI job and its release matrix entry, the Go entries in `.editorconfig` and `.gitignore`, and Go in the docs; GHCR publishing stays until M4's ECR push replaces it (ADR-0007, ADR-0010) | CI has no Go job; `grep -ri golang` finds nothing outside the ADRs |
| feat: API service skeleton | Rename the Python sample to `services/api`; layers `api` (FastAPI routes), `service` (business rules and permission checks), `data` (SQLAlchemy); settings from the environment; the runtime contract (architecture 8) | `/healthz`, `/readyz` and `/metrics` work; mypy strict and ruff pass; the layering is enforced by an import-linter rule |
| feat: database foundation | Async SQLAlchemy with psycopg 3, Alembic baseline, the migration job, database roles per workload, row-level security scaffolding and the `app.tenant_id` setting (ADR-0011, ADR-0020) | Migrations run up from empty in CI; a role without `app.tenant_id` reads nothing from a tenant table |
| feat: scoped data access and the isolation suite | Tenant, resource, system and credential-lookup scopes; composite foreign keys; the two-tenant isolation harness (ADR-0003, data model 4.2) | A test that queries another tenant's row through any scope fails the build; the harness is reusable for every later endpoint |
| feat: audit events | Partitioned `audit_events`, the default partition, the insert-only role, a write helper used inside service transactions (FR-27, NFR-15) | A state change without its audit row can't commit; a missing partition is caught by the default partition and an alert metric |
| feat: transactional outbox and relay | `outbox`, `processed_messages`, the relay worker with `FOR UPDATE SKIP LOCKED`, an idempotent consumer base class (ADR-0013) | A crash between the database write and the publish loses nothing; a duplicate message is processed once |
| chore: local development stack | Compose services for PostgreSQL, S3- and SQS-compatible emulators, Valkey, a mail catcher and clamd; the local OIDC provider that stands in for Cognito; `make up` and `make down` | A new clone runs `make setup && make up && make check` with no AWS account |
| ci: Python-only pipeline and contract checks | Remove Go jobs; keep lint, types, tests, coverage gate, images, Trivy and gitleaks; add the OpenAPI lint and, once routes exist, the generated-spec diff and breaking-change check (ADR-0002, ADR-0005) | CI is green on the new layout; a breaking API change fails without the `breaking` label |

### M1 to M3

These are broken into issues when the previous milestone is halfway through, so the issues reflect what was learned.
M1's first issue is the operator API with `createTenant`; M2's first issue is creating a draft transfer and adding a
file with part URLs; M3 starts with the generated TypeScript client and the recipient pages.

### M4 AWS dev

M4 needs three things from the maintainer before anything is applied:

1. the AWS profile names for the management, shared and dev accounts (IAM Identity Center);
2. the domain whose subdomain the service will use (PRD open question 5);
3. an SES production-access request for that subdomain, made once the DNS records exist (AWS takes about a day).

Terraform for every module is written and checked statically (`terraform validate`, tflint, Trivy) during M0–M3, so M4
is mostly applying and fixing what only real AWS shows. dev runs only in working windows and is torn down after each
(capacity model).

### M5 to M7

M5 completes the product on the M4 platform. M6 turns on the parts of the security design that need real AWS (Cognito
SSO, GuardDuty, WAF, KMS field encryption). M7 builds staging and prod, the Osaka pilot light, the SLOs and the drills,
runs the operating period within the $6,500 monthly cap, and ends with a timed teardown that keeps only the audit
archive (NFR-19).

## 5. Risks to the plan

| Risk | Effect | Response |
|---|---|---|
| One maintainer | Reviews and merges wait on one person | Small PRs; agents draft, the maintainer decides; Should requirements move to after v1 first |
| Local emulators differ from AWS | Bugs appear only in M4 | Keep the AWS-specific code behind thin adapters with contract tests; run the M2 test against real AWS in M4 before new features |
| AWS prerequisites arrive late | M4 slips | M0–M3 don't depend on AWS; Terraform is written and checked statically in parallel |
| Design gaps found while coding | Rework | Fix the design document in the same PR as the code (definition of done, point 5); DR gaps are already tracked in #42 |
