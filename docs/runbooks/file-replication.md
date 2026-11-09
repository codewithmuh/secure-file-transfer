# Runbook: file replication (`sft-<env>-apne1-<bucket>-replication-failed`, `-replication-latency`)

CloudWatch alarms on S3 replication with Replication Time Control from Tokyo's `files` and `large-files` buckets to
Osaka's ([ADR-0012](../adr/0012-object-storage-s3.md), NFR-10), defined in
[`infra/modules/alarms/replication.tf`](../../infra/modules/alarms/replication.tf). Severity: page. Staging and prod
only.

## Symptoms

- `OperationsFailedReplication` above zero for the rule `to-osaka`, or
- `ReplicationLatency` above 900 seconds for 10 minutes: replicas are later than RTC's 15-minute commitment.

## Impact

Tokyo is unaffected. A failover now would show the files that hadn't reached Osaka as unavailable (NFR-10), and NFR-10
promises at most the last 15 minutes of uploads for 99.99 % of files.

## Confirm

Commands are for the live run; the alarms are pending the AWS run.

```bash
aws s3api get-bucket-replication --bucket sft-<env>-apne1-files-<account id>
# One object's status: COMPLETED, PENDING, FAILED
aws s3api head-object --bucket sft-<env>-apne1-files-<account id> --key <object key> --query ReplicationStatus
# The Osaka replica key and bucket exist and the replication role still has its policy
aws kms describe-key --region ap-northeast-3 --key-id alias/sft/<env>/files
aws iam get-role-policy --role-name sft-<env>-s3-replication --policy-name <policy>
```

S3 also emits `s3:Replication:OperationFailedReplication` events with a failure reason. Check the AWS Health Dashboard
for S3 in both Regions.

## Mitigate

1. **Permissions or keys** (`AccessDenied`, a disabled or pending-deletion Osaka key, a changed bucket policy): fix the
   Terraform drift with an apply of the `data` stacks; never by hand.
2. **Latency only, no failures** (a burst of large uploads, an S3 event in Osaka): wait for it to drain and watch the
   alarm clear; RTC's commitment covers 99.99 % of objects, not every burst.
3. **Objects that failed**: once the cause is fixed, replicate them again with S3 Batch Replication on the failed
   objects (`aws s3control create-job` with a `S3ReplicateObject` operation and the replication-status manifest
   filter `FAILED`).

## Escalate

If failures continue for 30 minutes, escalate to the owner in [CODEOWNERS](../../.github/CODEOWNERS): the DR copy of
new files isn't being made.

## Afterwards

Postmortem with the number of objects affected and how long they were unreplicated.
