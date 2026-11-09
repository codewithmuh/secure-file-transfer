# Runbook: regional failback, Osaka to Tokyo

Moving the service back to Tokyo after a [regional failover](regional-failover.md), once Tokyo is healthy. It is
planned work in an announced window, not an emergency: the database moves by switchover, so nothing is lost, and the
API keeps serving while the workers pause. `ops/regional-failback.sh` runs, times and logs the steps. No NFR sets its
time; the budgets below are a first estimate for the first drill to correct. Decisions:
[disaster-recovery.md](../operations/disaster-recovery.md) (#42 gaps 4 and 10).

> [!IMPORTANT]
> **Pending the AWS run**, like the failover. Steps that wait for Terraform inputs still to come say so.

```bash
ops/regional-failback.sh --env prod --profile sft-prod-admin                                   # dry run
ops/regional-failback.sh --env prod --profile sft-prod-admin --account-id <prod account> --execute \
  --failed-over-at 2026-12-01T03:00:00Z
```

| # | Step | Budget |
|---|---|---|
| 1 | Tokyo ready: stacks applied, database caught up as Osaka's secondary | 30 min |
| 2 | Copy the files written in Osaka back to Tokyo | 30 min |
| 3 | Hold Osaka's workers | 5 min |
| 4 | Switch the database over to Tokyo | 5 min |
| 5 | Fence Osaka; take Tokyo out of pilot light with its workers held | 10 min |
| 6 | New archive generation, the outbox since the hold, Tokyo's workers | 10 min |
| 7 | DNS back to Tokyo | 5 min |
| 8 | Osaka back to its pilot light | 10 min |
| 9 | Verify | 5 min |

## 1. Tokyo ready (30 min)

- AWS Health shows ap-northeast-1 recovered. Apply Tokyo's stacks again in infra/README.md's order, if anything
  drifted or was lost; Tokyo's cluster stays fenced (`pilotLight: true`) until step 5.
- **The database.** After a managed failover, Aurora brings Tokyo's old cluster back into the global database as
  Osaka's secondary by itself, and keeps a snapshot of its volume from before. After a detach, the old cluster is
  never a writer again (T-78): take its final snapshot, delete it, and apply Tokyo's data root as a secondary of
  Osaka's global database (pending the Terraform input that swaps the regions' roles). Either way, wait for
  `AuroraGlobalDBReplicationLag` under a second.
- **Rows only the old Tokyo database had** (#42 gap 10) are the RPO NFR-10 allows. Security-critical ones were
  re-applied from the archive; the rest aren't merged in v1. Keep the snapshot 30 days for support questions.

## 2. Copy the files written in Osaka back to Tokyo (30 min)

Replication runs Tokyo to Osaka, so Osaka's new objects never reached Tokyo (#42 gap 4). Apply Osaka's data root with
the reverse rule on both files bucket pairs (Osaka to Tokyo, with RTC; pending the modules/files-buckets input), so
new uploads during the window replicate too. Then one S3 Batch Replication job per bucket copies everything created
since the failover, tags included, so the `scan` tag comes back with each file:

```bash
aws s3control create-job --region ap-northeast-3 --account-id <account> --no-confirmation-required --priority 10 \
  --operation '{"S3ReplicateObject":{}}' --report '{"Enabled":false}' \
  --role-arn arn:aws:iam::<account>:role/sft-prod-s3-batch-replication \
  --manifest-generator '{"S3JobManifestGenerator":{"SourceBucket":"arn:aws:s3:::sft-prod-apne3-files-<account>",
    "EnableManifestOutput":false,"Filter":{"EligibleForReplication":true,"CreatedAfter":"<failed-over-at>"}}}'
```

Wait for both jobs (`aws s3control describe-job`); their succeeded counts go in the log.

## 3. Hold Osaka's workers (5 min)

```bash
ops/failover-values.sh hold-osaka --env prod --write
git commit -m "ops: hold prod Osaka's workers for the failback" deploy/environments/prod
```

Uploads, downloads and sign-in go on; scans, emails and the lifecycle jobs wait until step 6. Note the time: it is
the outbox window of step 6.

## 4. Switch the database over to Tokyo (5 min)

```bash
aws rds switchover-global-cluster --region ap-northeast-3 --global-cluster-identifier sft-prod-aurora \
  --target-db-cluster-identifier arn:aws:rds:ap-northeast-1:<account>:cluster:sft-prod-apne1-aurora
```

A switchover waits until Tokyo has every change, so nothing is lost (ADR-0011). The API's writes fail for the minute
the writer moves, and its pool reconnects.

## 5. Fence Osaka; Tokyo out of pilot light (10 min)

```bash
ops/failover-values.sh failback --env prod --write
git commit -m "ops: fence prod Osaka and take Tokyo out of pilot light" deploy/environments/prod
```

Osaka goes back to `pilotLight: true`; Tokyo gets `pilotLight: false` with `failover.holdWorkers: true`. Wait for
Tokyo's API.

## 6. New generation, the outbox, Tokyo's workers (10 min)

The recovery job in Tokyo, with `RECOVERY_STEPS=generation,partitions,replay` and both times at step 3's hold: a new
writer region starts a new archive generation, and the replay should find every record present; a re-applied record
here means the switchover lost something, which fails the drill. Then `RECOVERY_STEPS=outbox` from the hold, for the
messages that sat in Osaka's queues, and release Tokyo's workers:

```bash
ops/failover-values.sh release-tokyo --env prod --write
git commit -m "ops: start prod Tokyo's workers after the failback" deploy/environments/prod
```

## 7. DNS back to Tokyo (5 min)

Apply `infra/environments/prod/ap-northeast-1/edge` without `TF_VAR_api_alias_target`. The API's name points at
Tokyo again, and a record a real failover set by hand is back under Terraform.

## 8. Osaka back to its pilot light (10 min)

The `system` node group back to one node; Osaka's data root without `TF_VAR_malware_protection_enabled` (the plan
goes), the heartbeat alarm off, and the reverse replication rule removed. The pilot light's cost is back to
capacity 5.1's.

## 9. Verify (5 min)

The synthetic probe passes from Tokyo; a member without SSO signs in with their original Tokyo credentials ([AUTH]
2.6); a file uploaded during the failover downloads from Tokyo.

[AUTH]: ../security/authn-authz.md
