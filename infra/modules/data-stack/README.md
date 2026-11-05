# data-stack module

The data layer of one environment and Region, written by
[#101](https://github.com/codewithmuh/secure-file-transfer/issues/101). Every `data` root calls it once. Nothing here
has been applied (infra/README.md).

It reads the network stack's state, then calls [`aurora`](../aurora/README.md), [`valkey`](../valkey/README.md) and
[`queues`](../queues/README.md) with that stack's isolated subnets and its `main_nodes` and `scan_nodes` security
groups. It derives the names (`sft-<env>-aurora`, `sft/<env>/db/master`) and the workload role ARNs from the
conventions module. A change to the layer is made here once, not in five roots. The roots keep the backend, the
provider and the conventions module, and pass only what differs:

| Root | `aurora` | Master secret |
|---|---|---|
| dev, Tokyo | `standalone`, 1 × db.t4g.medium, 7 days of backups | 7-day recovery window, no replica |
| staging, Tokyo | `primary`, 1 × db.r8g.large, 14 days | 7 days; replica under `master_secret_replica_kms_key_arn` |
| prod, Tokyo | `primary`, 2 × db.r8g.large (writer and reader in two AZs), 14 days | 30 days; replica as in staging |
| staging, Osaka | `secondary`, Serverless v2 at 1–16 ACUs, 14 days | None: the secondary takes its master user from the primary |
| prod, Osaka | `secondary`, 1 × db.r8g.large, 14 days | None |

Checks on the inputs:
- Every key is a multi-Region key in the stack's Region.
- `kms_key_arns.secrets` is set exactly when the cluster has a master secret, so it is not set in Osaka.
- `master_secret_replica_kms_key_arn` is set for a primary only, and is the Osaka replica of the secrets key: the same
  `mrk-` key ID, in ap-northeast-3.

Until #102 merges, the roots take the keys as variables. Then `kms_key_arns` comes from #102's keys module, in one
line per root.
