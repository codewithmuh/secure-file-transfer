# data-stack module

The data layer of one environment and Region, written by
[#101](https://github.com/codewithmuh/secure-file-transfer/issues/101), with the keys and buckets of
[#102](https://github.com/codewithmuh/secure-file-transfer/issues/102) in `storage.tf`. Every `data` root calls it once. Nothing here
has been applied (infra/README.md).

It reads the network stack's state, then calls [`aurora`](../aurora/README.md), [`valkey`](../valkey/README.md) and
[`queues`](../queues/README.md) with that stack's isolated subnets and its `main_nodes` and `scan_nodes` security
groups, and [`kms-keys`](../kms-keys/README.md), [`files-buckets`](../files-buckets/README.md),
[`audit-archive`](../audit-archive/README.md) (dev and staging) and
[`events-delivery-role`](../events-delivery-role/main.tf) (Tokyo) for storage, and
[`break-glass-role`](../break-glass-role/README.md) for the break-glass database role and its alert (`break-glass.tf`,
#232). `flow-logs.tf` makes the Region's VPC flow log bucket itself (below). It derives the names (`sft-<env>-aurora`,
`sft/<env>/db/master`) and the workload role ARNs from the conventions module. A change to the layer is made here once,
not in five roots. The roots keep the backend, the provider and the conventions module, and pass only what differs:

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

Inputs of the failback and the teardown (docs/operations/disaster-recovery.md section 8):
- `replicate_to_tokyo`: Osaka only, at a failback: the files buckets' `to-tokyo` rule (#262).
- `aurora.global_generation` and Tokyo's `aurora.cluster_role = "secondary"`: a failback after a detach (#261; the
  aurora module's README). Tokyo keeps the master secret whatever its cluster's role.
- `teardown`: also gives prod's files buckets and flow log bucket the teardown rights dev and staging always have,
  from that apply on (#263, #42 gap 11).

The keys come from `kms-keys` (`module.kms.key_arns`), so no root passes key ARNs any more.

## Flow log bucket

`flow-logs.tf` makes `sft-<env>-<region-short>-flow-logs-<account-id>` in every data root, for the network stack's VPC
flow log ([`network`](../network/README.md), capacity A19, T-53). The network is applied before this layer, so a
fresh build applies it a second time with the data root's `flow_log_bucket_arn` output (a plain bucket ARN, no prefix)
as `TF_VAR_flow_log_destination_arn` (infra/README.md, "Apply order").

| Setting | Value |
|---|---|
| Encryption | SSE-KMS with the environment's logs key (in Osaka its replica) and S3 Bucket Keys (encryption 3.1) |
| Access | Block Public Access, `BucketOwnerEnforced`, TLS only. Only `delivery.logs.amazonaws.com` is granted anything: `PutObject` under `AWSLogs/aws-account-id=<account>/` with `bucket-owner-full-control`, and `GetBucketAcl` and `ListBucket` on the bucket, each only for `aws:SourceAccount` this account and `aws:SourceArn` `arn:aws:logs:<region>:<account>:*`. The logs key's `LogDeliveryWritesVendedLogs` statement ([`kms-keys`](../kms-keys/README.md)) lets it encrypt under the same conditions. |
| Retention | Objects expire after 90 days (PRD data lifecycle, capacity A33); versioning is on, and a replaced version goes after a day |
| Replication | None: each Region's flow logs stay in that Region |
| Teardown | `force_destroy` in dev and staging, and in prod from its `teardown` apply on, like the files buckets; the deploy role may empty it in dev and staging (`terraform-oidc-roles`, `permissions-storage.tf`) |
