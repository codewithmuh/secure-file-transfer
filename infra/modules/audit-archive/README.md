# audit-archive module

One Region's audit archive bucket, `sft-<env>-<region-short>-audit-archive-<account-id>`
([ADR-0012](../../../docs/adr/0012-object-storage-s3.md), [encryption and keys](../../../docs/security/encryption-and-keys.md)
3.1 and 8.4, NFR-9, NFR-15). Written by [#102](https://github.com/codewithmuh/secure-file-transfer/issues/102).
Nothing here has been applied (infra/README.md).

| | dev and staging | prod |
|---|---|---|
| Called from | `environments/<env>/<region>/data` | `environments/prod/retained`, both Regions |
| Object Lock | Governance, 1 day | Compliance, 365 days |
| Owner | The environment's deploy role | The retained stack's deploy role |
| Replication role | The files buckets' `sft-<env>-s3-replication`, to which this adds a policy | `sft-prod-retained-s3-replication`, made here |
| Teardown | The deploy role may empty it; `force_destroy` | `prevent_destroy`; nobody deletes a record or changes its retention |

| File | Holds |
|---|---|
| `main.tf` | The bucket with Object Lock, versioning, SSE-KMS with the audit key, and the retention lifecycle rules |
| `policy.tf` | The bucket policy |
| `replication.tf` | Replication to Osaka without RTC, and in prod its own role |

The bucket policy denies requests without TLS 1.2, other encryption, reads to all but the recovery job, the audit
reader and BreakGlass, writes to all but the archive job, the API, the operator API and the lifecycle jobs, replica
writes to all but the replication role, and changes to the bucket's settings to all but the owning deploy role and
Admin.

**Who writes what, in both Regions.** The archive job (#183) writes each batch to Tokyo's and Osaka's bucket itself,
and moves its cursor only once both hold it ([data model](../../../docs/design/data-model.md) 2.5), so "archived" means
both Regions. The API and the operator API write each security-critical record to both too (architecture 5.2).
Replication to Osaka stays as a second copy; it is untimed, and nothing waits for it.

Records leave only through the lifecycle rule: a current version expires at 365 days, when its retention ends, and the
version itself one day after it becomes noncurrent (ADR-0012).
