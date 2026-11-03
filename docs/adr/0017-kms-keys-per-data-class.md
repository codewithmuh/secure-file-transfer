# 0017. Use shared KMS keys per data class and per-tenant data keys for file names and messages

- Status: accepted
- Date: 2026-11-03
- Issue: [#33](https://github.com/codewithmuh/secure-file-transfer/issues/33)

## Context

PRD open question 3 asks for one KMS key per tenant, or shared keys with per-tenant encryption context. The
[PRD](../prd.md) requires files, database, backups and logs encrypted at rest with KMS keys (NFR-13), no access to
another tenant's data (NFR-12), file contents gone from every copy within 7 days of their deletion trigger (NFR-8),
recovery in Osaka without Tokyo (NFR-10, NFR-11), a teardown that leaves only the audit archive and its key (NFR-19),
and keys and data in Japan only (NFR-21). Tenants share one schema ([ADR-0003](0003-multi-tenancy-shared-schema.md)),
object keys start with `tenants/{tenant_id}/`, and one API role serves every tenant.

Two facts shape the answer. With S3 Bucket Keys, which keep KMS requests and cost low, KMS sees the bucket, not the
object, so a `tenant_id` pair in an object's encryption context would not be enforced. And since the API must serve
every tenant, its role can use every tenant's key in any design: per-tenant keys don't protect tenants from a
compromised service role, only from the service's own scoping bugs, which cheaper controls also catch.

The design is argued in [encryption and key management](../security/encryption-and-keys.md), sections 3.2, 4, 5 and
8; the threats in the [threat model](../threat-model.md) (T-36, T-61). This ADR records it.

## Decision

- **Eight customer managed keys per environment, one per data class:** files, fields, database, audit, logs, secrets,
  platform and tfstate, plus **one registry key** in the shared registry stack for container images. Each is a
  multi-Region key with its primary in Tokyo and, in staging and prod, a replica in Osaka, rotated automatically every
  year.
- **Per-tenant data keys for file names and messages (field encryption).** Each tenant has a data key generated under
  the fields key with encryption context `{"purpose": "field-dek", "tenant_id": "<tenant>"}` and stored only wrapped.
  Values are encrypted with AES-256-GCM, with the tenant, table, column, row and key version as additional
  authenticated data. The service unwraps the data key of the tenant in the **caller's scope**, never the tenant on the
  row, so a row from another tenant fails to decrypt and pages as a possible isolation breach.
- **No per-object tenant encryption context on S3.** Tenant separation for file contents comes from scoped data
  access, row-level security ([ADR-0020](0020-row-level-security.md)), IAM prefix and tag conditions, and the isolation
  suite.
- **No KMS key per tenant in v1.** A dedicated key, ours or held in the tenant's own AWS account, is the opt-in path
  for a tenant whose contract requires one.
- **Key policies** name their principals (no `kms:*` for the account root), keep administrators and users apart, give
  grants only to AWS resources, and allow replicas only in Osaka. A **service control policy** denies
  `kms:PutKeyPolicy`, `kms:DisableKey`, `kms:ScheduleKeyDeletion` and `kms:DeleteImportedKeyMaterial` to every
  principal except the Terraform deploy roles (the retained stack's included), the bootstrap `Admin` role and the
  key-admin role below; BreakGlass and every other role are denied. Key policies repeat the denial of disabling and
  deletion, and prod deletions need the 30-day wait.
- **A key-admin role for key-policy recovery.** Every key policy also names `sft-{env}-keyadmin`, allowed to read and
  put the key policy and nothing else. It is created once in the bootstrap stack with `prevent_destroy`, only
  BreakGlass may assume it, and every use pages. KMS binds a key policy to a role's unique ID, so a deploy role that is
  deleted and re-created no longer matches the policies of its keys; the key-admin role can still put a corrected
  policy, so re-creating a deploy role can't lock the keys.

## Options considered

| Option | Pros | Cons |
|---|---|---|
| **Shared keys per data class, plus per-tenant data keys for names and messages** (chosen) | Binds the most revealing metadata ("Q3 layoffs.xlsx") to its tenant: a scoping bug, SQL injection or a database-only reader gets ciphertext that won't decrypt, a third isolation layer. About $18 a month more in KMS requests at design load and no new moving part. The multi-Region fields key lets Osaka unwrap without Tokyo. Moving a tenant to a dedicated key later needs no data migration. | File contents get no per-tenant cryptographic separation; that rests on the data-access layers and IAM. Names and messages can't be searched or sorted in SQL. A crypto module, a key cache and tests of our own, on a standard AEAD library. A compromised API role still reads every tenant, as in every option. Multi-Region keys put the same key material in both Regions, so either Region's key policy can decrypt the other's ciphertext. |
| Shared keys per data class only | The least effort: eight keys per environment in Terraform; 16 key resources in prod, about $16 a month | No cryptographic separation between tenants at all: one scoping bug exposes names and messages across tenants |
| A KMS key per tenant for files and fields | Per-tenant key policies and CloudTrail usage, freezing one tenant by disabling its key, a crypto-shredding backstop, and the basis for customer-held keys | At 500 tenants, 1,000 key resources: about $1,000 a month, $3,000 after two rotations. Either the running operator API gets `CreateKey`, `PutKeyPolicy` and `ReplicateKey`, or every new tenant is a Terraform change. S3 replication needs one rule per tenant, and a configuration holds at most 1,000. Every upload must name its tenant's key, which a bucket policy can't check for 500 tenants. No stronger isolation from the service's own roles. Deleting a multi-Region key takes at least 14 days, too slow to be NFR-8's mechanism. |
| A dedicated key per tenant, opt-in | The per-tenant benefits for the tenants that ask, at about $2 a month each | A Terraform change and a replication rule per tenant in each files bucket pair. No v1 requirement needs it, so it is deferred. |

## Consequences

- **Cost.** 16 key resources in prod and in staging (each primary and replica is billed), 8 in dev, and 1 or 2 for the
  registry: about $16 a month for prod, $48 after two yearly rotations. KMS requests at design load are about $9 a
  month with Bucket Keys, plus up to $18 for unwrapping field data keys, which stay cached in memory for at most 15
  minutes.
- **Only the API unwraps field data keys.** Emails never contain file names or messages, so the notification worker
  never needs the fields key, and the operator API never returns them. The web app sorts a transfer's at most 50 files
  itself; audit search doesn't use names.
- **Failover needs no re-wrapping:** wrapped data keys reach Osaka with Aurora, and the Osaka API unwraps them with the
  Osaka replica of the fields key. This is the one store where the multi-Region property is required.
- **A dedicated key later** means: Terraform creates the tenant's key pair, a replication rule for its prefix in both
  files bucket pairs, and bucket policy statements that allow that key under its prefix only. The key's policy gives
  the same uses as the files key: the API, the scan worker for files up to 2 GB, GuardDuty's role through S3 for the
  large-file buckets, and the replication role. New uploads name that key, its field data keys are re-wrapped with
  `ReEncrypt`, and old objects age out within 97 days. No copy job.
- **No crypto-shredding per tenant.** Offboarding runs the deletion job over `tenants/{tenant_id}/` in both Regions and
  deletes the tenant's rows and field data keys; database backups age out within the 14-day restore window.
- **The SCP needs AWS Organizations**, which [ADR-0006](0006-aws-account-per-environment.md) sets up. Whoever holds
  the organization's management account can lift it; with one maintainer that is the same person, an accepted risk
  (threat model R-08). Every attempt to change a key policy, disable a key or schedule its deletion outside a deploy
  role pages, and so does every use of the key-admin role.
- **The audit key lives in the retained stack** with the audit archive, so it outlives teardown (NFR-19) with its own
  deletion guards. At the final teardown the key-admin role is first removed from the audit key's policy, then a last
  bootstrap apply lifts its `prevent_destroy` so the bootstrap stack can be destroyed
  ([encryption and keys](../security/encryption-and-keys.md), 8.4).
- The [data model](../design/data-model.md), section 2.1, holds the `tenant_data_keys` table and the ciphertext
  columns `files.display_name_ct`, `transfers.message_ct` and `upload_requests.message_ct`.

When to revisit: when a tenant's contract requires a dedicated or customer-held key; when tenant offboarding needs
cryptographic proof of deletion; or when the tenant mix changes sharply, as in ADR-0003's revisit triggers.
