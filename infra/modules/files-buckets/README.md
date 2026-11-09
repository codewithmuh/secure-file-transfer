# files-buckets module

One Region's files buckets, `sft-<env>-<region-short>-files-<account-id>` for files up to 2 GB and
`...-large-files-...` for larger ones ([ADR-0012](../../../docs/adr/0012-object-storage-s3.md),
[ADR-0019](../../../docs/adr/0019-malware-scanning-clamav-guardduty.md),
[encryption and keys](../../../docs/security/encryption-and-keys.md) 3.1). Written by
[#102](https://github.com/codewithmuh/secure-file-transfer/issues/102). Nothing here has been applied (infra/README.md).

| File | Holds |
|---|---|
| `main.tf` | The buckets: ownership enforced, public access blocked, versioning, SSE-KMS with Bucket Keys, lifecycle safety nets, CORS for the web app |
| `policy.tf` | The bucket policies |
| `replication.tf` | `sft-<env>-s3-replication` and the replication rules to Osaka, with RTC |
| `malware-protection.tf` | `sft-<env>-malware-protection`, the GuardDuty plan on the large-files bucket and the EventBridge rule that sends its results to the scan worker's queue |

Tokyo calls it with `create_iam_roles = true`: IAM is global, so Tokyo makes the roles for both Regions and Osaka names
them by ARN.

## Bucket policy

Deny statements only, principals matched by `aws:PrincipalArn`:

| Statement | Denies |
|---|---|
| Transport | Requests without TLS, or below TLS 1.2 |
| Encryption | Uploads asking for another algorithm, another key or SSE-C. Uploads without an encryption header (the pre-signed parts) get the default (T-60). |
| Reads | `GetObject` to all but the API, the scan worker (`files` only), GuardDuty's role (`large-files` only) and BreakGlass (authn-authz 8.1); to everyone for objects tagged `scan=infected` (FR-17); to the API for objects not tagged `scan=clean` or `scan=unscannable_allowed`; to the scan worker for objects that already have a `scan` tag |
| Writes | `PutObject` to all but the API, and GuardDuty's role for its validation object only (T-32) |
| Tags | Object tagging to all but the scan worker and, on `large-files`, GuardDuty |
| Deletes | `DeleteObject*` to all but the lifecycle jobs, and the deploy role where `teardown_allowed` (dev, staging) |
| Replicas | `Replicate*` to all but the replication role |
| Settings | Policy, versioning, encryption, lifecycle, replication, Object Lock, ownership, public access, CORS, tags and deletion of the bucket to all but the deploy role and Admin. Notifications stay open for GuardDuty. |

## Replication and a fresh build

S3 refuses a replication rule whose destination bucket doesn't exist yet, and the Osaka key replicas need Tokyo's
primaries. So on a fresh staging or prod build: apply Tokyo's data stack, then Osaka's with
`TF_VAR_primary_key_arns` from Tokyo's `kms_key_arns` output, then Tokyo's again with `TF_VAR_osaka_ready=true`.
The replicas' ARNs are known from the start, because a replica keeps its primary's key ID.

## GuardDuty

The plan covers the whole large-files bucket and tags each object with `GuardDutyMalwareScanStatus`. A rule
`sft-<env>-<region-short>-guardduty-scan-results` sends every result to `sft-<env>-<region-short>-guardduty-results`
(#101) through `sft-<env>-events-delivery`. In Osaka the plan, rule and target exist only when
`TF_VAR_malware_protection_enabled=true`, which the failover runbook sets: that apply creates them, and GuardDuty
validates its access to the bucket then (architecture 3.2).

The large pool's scan workers read that queue (#234, `sft.workers.scan.GuardDutyConsumer`): a result is recorded only
for a file still `scanning`, for the version completion recorded, when the object's `GuardDutyMalwareScanStatus` tag
names the same result; the worker then adds its own `scan` tag, keeping GuardDuty's. Running against GuardDuty is
pending the AWS run; locally a stand-in plays it (docs/local-development.md).
