# data-stack module

The data layer of one environment and Region, written by
[#101](https://github.com/codewithmuh/secure-file-transfer/issues/101), with the keys and buckets of
[#102](https://github.com/codewithmuh/secure-file-transfer/issues/102) in `storage.tf`. Every `data` root calls it once. Nothing here
has been applied (infra/README.md).

It reads the network stack's state, then calls [`aurora`](../aurora/README.md), [`valkey`](../valkey/README.md) and
[`queues`](../queues/README.md) with that stack's isolated subnets and its `main_nodes` and `scan_nodes` security
groups, and [`kms-keys`](../kms-keys/README.md), [`files-buckets`](../files-buckets/README.md),
[`audit-archive`](../audit-archive/README.md) (dev and staging) and
[`events-delivery-role`](../events-delivery-role/main.tf) (Tokyo) for storage. It derives the names (`sft-<env>-aurora`, `sft/<env>/db/master`) and the workload role ARNs from the
conventions module. A change to the layer is made here once, not in five roots. The roots keep the backend, the
provider and the conventions module, and pass only what differs:

| Root | `aurora` | Master secret |
|---|---|---|
| dev, Tokyo | `standalone`, 1 × db.t4g.medium, 7 days of backups | 7-day recovery window, no replica |
| staging, Tokyo | `primary`, 1 × db.r8g.large, 14 days | 7 days; replica under Osaka's replica of the secrets key once `osaka_ready` |
| prod, Tokyo | `primary`, 2 × db.r8g.large (writer and reader in two AZs), 14 days | 30 days; replica as in staging |
| staging, Osaka | `secondary`, Serverless v2 at 1–16 ACUs, 14 days | None: the secondary takes its master user from the primary |
| prod, Osaka | `secondary`, 1 × db.r8g.large, 14 days | None |

Inputs for the two-pass fresh build (infra/README.md, "Apply order"):
- `primary_key_arns`: Osaka only, and required there: Tokyo's `kms_key_arns` output, the primaries its keys replicate.
- `osaka_ready`: Tokyo in staging and prod. False only for the first apply of a fresh build, before Osaka's data stack
  exists; true (the default) turns on S3 replication to Osaka and the master secret's Osaka replica, under Osaka's
  replica of the secrets key, which keeps the Tokyo key's ID (encryption 4.2).
- `osaka_malware_protection_enabled`: Osaka only, off in the pilot light (ADR-0019).

The keys come from `kms-keys` (`module.kms.key_arns`), so no root passes key ARNs any more.
