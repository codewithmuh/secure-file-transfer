# 0020. Use PostgreSQL row-level security as a second tenant isolation layer

- Status: accepted
- Date: 2026-11-03
- Issue: [#33](https://github.com/codewithmuh/secure-file-transfer/issues/33)

## Context

Tenants share one schema, with `tenant_id` on every tenant-owned row ([ADR-0003](0003-multi-tenancy-shared-schema.md)),
and no API call, link or token may reach another tenant's data ([PRD](../prd.md), NFR-12). The first layer is scoped
data access in the service layer: no query runs without a tenant, resource or system scope
([ADR-0002](0002-api-framework.md)), backed by composite foreign keys that include `tenant_id` and the isolation suite
([data model](../design/data-model.md), section 4.2). A query that misses its scope is still the most likely isolation
bug (threat model T-33), and workers and lifecycle jobs reach the same tables outside HTTP. Connections are pooled, and
credential lookups (sessions, link tokens, API keys, identities) have to search across tenants before the caller's
tenant is known.

ADR-0003 left row-level security to phase 3. [Authentication and authorization](../security/authn-authz.md), section 7,
designs it, and the [threat model](../threat-model.md) covers its bypasses (T-33 to T-35). This ADR records it.

## Decision

Enable **row-level security on every tenant-owned table, in every environment** including dev and CI, as a second
layer behind scoped data access.

- **Scope per transaction.** The data-access layer opens every transaction with
  `SELECT set_config('app.scope', :scope, true), set_config('app.tenant_id', :tenant_id, true)`. Both settings are
  transaction-local, so they can't leak to the next user of a pooled connection. A session-level `SET` is forbidden by
  a lint rule, and a query without a scope is refused before it reaches the database.
- **Tenant policies** compare each row's `tenant_id` with `app.tenant_id` for reads and writes (`USING` and
  `WITH CHECK`). A missing tenant is null and matches nothing.
- **One login role per workload,** through IAM database authentication: `sft_api`, `sft_operator`, `sft_scan`,
  `sft_notify`, `sft_relay`, `sft_jobs`, `sft_archive` and `sft_recovery` for the workloads, and `sft_migrate` for
  migrations. Tables belong to `sft_owner`, which nobody logs in as; `sft_migrate` is the only role that may become it,
  with `SET ROLE`. No workload role owns a table, and no role but the master user, kept for break-glass, has
  `BYPASSRLS`. Every role has explicit policies for its scopes: lifecycle jobs find due work across tenants in system
  scope, read only, then act on each item in its own transaction with its tenant set.
- **A recovery role** for the failover and restore jobs alone. `sft_recovery` (IAM role `sft-{env}-recovery`) runs
  only from the runbooks, before the service or any worker starts, never in a running service. Its `recovery_reapply`
  policies apply only in the `recovery` scope and let it read and update, across tenants, exactly the rows that
  security-critical records change, so it can re-apply them from the audit archive. It may insert the audit events it
  re-imports, and has no grant on the ciphertext columns or any other table.
- **Credential lookup** goes through seven `SECURITY DEFINER` functions owned by `sft_lookup`, which also lacks
  `BYPASSRLS` and reads through policies and column grants of its own. They pin `search_path`, return IDs and status
  only, and only `sft_api` may execute them.
- **Platform events,** which have no tenant, get their own insert policy: the row and the setting have no tenant and
  the scope is `platform`. `IS NOT DISTINCT FROM` isn't used, because it would also accept a row from a transaction
  that forgot its tenant.
- **Tests prove each layer alone:** the isolation suite runs as built, with row-level security off, and with the
  data-access layer's tenant filter removed by a test hook.

## Options considered

| Option | Pros | Cons |
|---|---|---|
| **Scoped data access plus row-level security** (chosen) | A scoping bug returns no rows instead of another tenant's rows. The database enforces it for every workload, workers and jobs included, not only for HTTP routes. Each layer can be tested on its own. Cheap: one `set_config` per transaction, and a `tenant_id` predicate the main indexes already lead with. | Policies for every table and role to write, review and test, and a role granted a table without a policy silently sees nothing. Null semantics need care (platform events). Known bypasses to guard: table owners and `BYPASSRLS` roles, views that run as their owner, partitions queried directly, `TRUNCATE`, and foreign key and unique checks. It trusts `app.tenant_id`, so code that sets the wrong tenant isn't caught here. "No rows" is harder to debug than an error. Migrations run as the owner and see every tenant. |
| Scoped data access only: ADR-0002's scopes, composite foreign keys and the isolation suite | Simplest: no policies, no per-transaction setting, nothing to keep in step with grants | One missing condition leaks another tenant's rows. The protection is only as good as review and the tests' reach, in the API and in every worker and job. |
| A database role per tenant, with policies on `current_user` | The tenant comes from the connection's role rather than a setting | 500 roles to create, grant and authenticate in both Regions; a pool per tenant, or `SET ROLE` per transaction, which code can get wrong just like a setting; cross-tenant jobs and credential lookups still need roles of their own |

## Consequences

- **Guards against the known bypasses:** every view uses `security_invoker = true`; no role has privileges on the
  partitions of `audit_events`; no workload role is granted `TRUNCATE`; composite foreign keys refuse cross-tenant
  references, which row-level security doesn't check; every definer function pins `search_path`.
- **No `FORCE ROW LEVEL SECURITY`.** No workload role owns a table, and the owner is used only by reviewed migrations,
  which must see every tenant; forcing it would leave data migrations with no rows.
- **Where the tenant comes from.** Request scopes take it from the credential row, never from a parameter. Workers take
  it from the outbox message, which only our own workloads can send; sign-in events take it from `custom:tenant_id`,
  which only the notification worker can set; the recovery job takes it from each archived record, which only our own
  workloads write.
- **Tenant boundary only.** Within a tenant, a link session's resource scope and the own-or-tenant rule stay with the
  data-access layer and the service checks.
- **A third layer** catches a wrong tenant that passes both: file names and messages are encrypted with the data key
  of the caller's tenant ([ADR-0017](0017-kms-keys-per-data-class.md)), so another tenant's row fails to decrypt.
- **CI checks the catalog on every pull request:** every table with a `tenant_id` column has row-level security and a
  policy for each command granted to each role; no role but the master user has `BYPASSRLS`; no workload role owns a
  table, and `sft_migrate` is the only member of `sft_owner`; only `sft_recovery` has policies for the `recovery`
  scope; a pooled connection carries no tenant or scope after commit. Policy tests cover the platform audit insert,
  writes outside the tenant set, and the jobs, relay, archive, recovery and lookup roles.
- **Performance budget:** 5 % added p95 latency in the first load test (NFR-2). Above that, indexes and plans are fixed
  first; turning row-level security off would need an ADR.
- The [data model](../design/data-model.md), section 4.2, records the scope setting next to the tenant, the roles and
  their policies.

When to revisit: if the first load test shows more than 5 % added p95 latency that indexes and plans can't remove; if
a connection pooler or proxy is put between the service and the database, which must be shown to keep settings
transaction-local; or if ADR-0003 is revisited, for example for a dedicated deployment per customer.
