# kms-keys module

The environment's customer managed keys, one per data class
([ADR-0017](../../../docs/adr/0017-kms-keys-per-data-class.md),
[encryption and keys](../../../docs/security/encryption-and-keys.md) 4). Written by
[#102](https://github.com/codewithmuh/secure-file-transfer/issues/102). Nothing here has been applied (infra/README.md).

| File | Holds |
|---|---|
| `main.tf` | The keys (multi-Region primaries in Tokyo, replicas in Osaka), their aliases, the names the policies use |
| `policies.tf` | The key policies: the statements every key shares, then one document per class |

## Who calls it

| Caller | Classes | Mode |
|---|---|---|
| `environments/<env>/ap-northeast-1/data` | files, fields, database, logs, secrets, platform; audit in dev and staging | Primaries. `osaka_key_arns` gives the replicas' ARNs in staging and prod. |
| `environments/<env>/ap-northeast-3/data` | The same | Replicas, from `TF_VAR_primary_key_arns` (the Tokyo stack's `kms_key_arns` output) |
| `environments/prod/retained` | audit | Primary and replica in one stack, with `prevent_destroy`, the retained deploy role and `retained_stack` |

The tfstate key is the bootstrap stack's (`modules/tfstate-backend`) and the registry key the shared stack's.

## Policies

Every key has the statements of 4.4: the owning stack's deploy role administers (rule 1, 2) and replicates only to
Osaka (rule 4); the plan role reads the key's state for plans; AWS Config reads rotation state (9.2); the key-admin role
reads and puts the policy (rule 6); BreakGlass recovers (rule 6); everyone but the deploy role is denied `DisableKey` and
`ScheduleKeyDeletion`, and every deletion needs the environment's wait, 30 days in prod and 7 elsewhere (rule 5).

Then each class adds the uses of table 4.3, each limited by `kms:ViaService` in this Region and by encryption context:

| Key | Users |
|---|---|
| files | API E D, scan worker D (files bucket only), replication D in Tokyo and E D in Osaka, GuardDuty's role E D (large-files only), BreakGlass D, all through S3 for the two buckets; Karpenter V and the EC2 Fleet service-linked role (named) for scan volumes |
| fields | API E D, and `ReEncrypt` for the field key job's re-wrap (#236), with purpose `field-dek` or `dlp-dek`; scan worker E D with `dlp-dek` only; both need `tenant_id` in the context |
| database | The deploy role's grants for RDS |
| audit | Archive job (Tokyo), API and operator API `GenerateDataKey`; recovery job, audit reader and BreakGlass `Decrypt`; replication; all through S3 for the archive bucket. In the retained stack also its state bucket, trail and alert delivery role |
| logs | CloudWatch Logs, CloudTrail and log delivery, each by `aws:SourceAccount` and its context or source; Loki and Tempo through S3; the lifecycle jobs for CloudTrail log files only; audit reader and BreakGlass D |
| secrets | Each reader D for its own secrets (`SecretARN`); the key rotation job E D for the keyrings and client secrets; the deploy role `GenerateDataKey` for the master password and platform secrets and the key-access check; EKS through grants |
| platform | Relay, scan worker, notification worker and sign-in triggers through SQS for their own queues; CloudWatch alarms, SES and SNS by source; EventBridge's delivery role; Karpenter and EBS CSI V, the Auto Scaling and EC2 Fleet service-linked roles (named), for root volumes; the deploy role's grants for ElastiCache |

**Roles are matched by `aws:PrincipalArn` through the account principal**, never named as the principal. KMS refuses a
policy that names a role that doesn't exist yet, and the workload roles come with the cluster layer, after this one.
The account principal with an exact ARN condition gives nothing to anyone else: there is no `kms:*` for the account,
and the role still needs its own IAM policy. A role that is deleted and re-created still matches, so the key-admin
role is only needed for a policy that is broken, not for one that names a stale role ID.

**Except the service-linked roles that create EBS volumes**, Auto Scaling (system nodes) and EC2 Fleet (Karpenter's
launches), which the platform and files keys name as principals with AWS's documented statements for EBS with a
customer managed key (`Encrypt`, `Decrypt`, `ReEncrypt*`, `GenerateDataKey*`, `DescribeKey`; `CreateGrant` for AWS
resources only). A service-linked role has no IAM policy that could allow KMS, so the account principal can't reach
it. `volume_service_linked_role_arns` takes them from the data stack, which creates them in Tokyo first.

**Teardown of prod's retained stack** (`environment_retired`, #263, encryption 8.4): the audit key's writers and the
recovery job leave its policy, so a role re-created later under one of those names matches nothing, and rotation stops
(`enable_key_rotation = false`), since nothing new is written under the key. The audit reader, BreakGlass and the
replication role stay. Admin may use the key for the retained stack's own state, as its deploy role may: the stack's
first apply moves its state into the bucket as Admin, and `ops/teardown.sh` applies it as Admin.

**Since #256 to #263** the platform key also lets SES's receipt rules write the probe mailbox and the synthetic probe and
the load test read it through S3 (#259); the secrets key lets staging's load test read its keys (#259); and Tokyo's
files key lets the replication role re-encrypt the failback's replicas (#262).

Names the policies rely on, all from other issues: workload roles `sft-<env>-<name>` at path `/`, from the conventions module's one list (#103, #172), queues
`sft-<env>-<region-short>-<queue>` (#101), secrets `sft/<env>/...` (6.1), buckets as in infra/README.md, and for the
retained stack the trail `sft-prod-retained` and the role `sft-prod-retained-events-delivery`, which its later issue
must use.
