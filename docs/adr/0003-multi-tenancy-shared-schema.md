# 0003. Use a shared schema with tenant_id for multi-tenancy

- Status: accepted
- Date: 2026-11-03
- Issue: [#13](https://github.com/codewithmuh/secure-file-transfer/issues/13)

## Context

The service holds confidential files and metadata for many customer companies (tenants). The PRD requires that no API
call, link or token gives access to another tenant's data (NFR-12), and designs for 500 tenants of broadly similar size
(PRD section 6.1). PostgreSQL is the single system of record ([architecture](../architecture.md), section 2), and one
maintainer builds and operates the service, with zero-downtime deploys several times a week (NFR-18).

How tenants are separated in the database shapes every query, migration, backup and test, and is expensive to change
once data exists.

## Decision

Keep all tenants in **one PostgreSQL schema**, with a `tenant_id` column on every tenant-owned row. Enforce isolation in
layers: scoped data access in the service layer (ADR-0002), composite foreign keys that include `tenant_id`, a tenant
isolation test suite on every pull request, and, if phase 3 confirms it, PostgreSQL row-level security as a second
layer. The details are in the [data model](../design/data-model.md), section 4.

## Options considered

| Option | Pros | Cons |
|---|---|---|
| **Shared schema, `tenant_id` on every row** (chosen) | One schema and one migration path, so expand-then-contract deploys stay simple. One connection pool. Cheap per tenant, so 500 tenants cost the same as 5. Cross-tenant reporting for operators is a normal query. Composite foreign keys let the database itself refuse cross-tenant references. | Isolation depends on every query being scoped; one missing condition leaks data. That risk has to be closed by the data-access layer, constraints and tests, and optionally row-level security. A very large tenant shares resources with everyone (noisy neighbour). Per-tenant restore means a filtered export, not a database restore. |
| **Schema per tenant** | A query can't cross tenants by accident unless it names another schema. Per-tenant export is easy. | 500 schemas to migrate on every release, so deploys get slow and partial failures leave tenants on different versions. Connection pooling and prepared statements per schema. Catalog bloat. Operator queries across tenants become unions. |
| **Database or cluster per tenant** | The strongest isolation, per-tenant backup, restore and encryption keys, and no noisy neighbours. | 500 databases or a fleet of clusters: very high cost and operational toil for one maintainer, and the multi-region pilot light multiplied by every tenant. |

## Consequences

- The data-access layer has no unscoped query method. Credential lookups (link tokens, sessions, API keys, identity
  provider subjects) are the one cross-tenant path, and they return only the owning tenant and subject.
- Every tenant-owned table has a unique key `(tenant_id, id)`, and children reference parents by both columns.
- The tenant isolation suite is a required part of CI from the first data-access code onwards (PRD section 9).
- Object keys in S3 start with the tenant ID, so per-tenant KMS keys (PRD open question 3) can come later without
  moving data.
- If a future customer needs physical isolation, the design allows a dedicated deployment of the same stack for that
  customer rather than changing the model for everyone.
- Revisit if the tenant mix changes sharply, for example a few tenants holding most of the data, or a regulated
  customer requiring separate storage.
