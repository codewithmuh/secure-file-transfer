# Runbook: regional failback, Osaka to Tokyo

Moving the service back to Tokyo after a [regional failover](regional-failover.md), once Tokyo is healthy. It is
planned work in an announced window, not an emergency: the database moves by switchover, so nothing is lost, and the
API keeps serving while the workers pause. `ops/regional-failback.sh` runs, times and logs the steps. No NFR sets its
time; the budgets below are a first estimate for the first drill to correct. Decisions:
[disaster-recovery.md](../operations/disaster-recovery.md) (#42 gaps 4 and 10).

> [!IMPORTANT]
> **Pending the AWS run**, like the failover. Every Terraform change here is an input of an apply, never an edit of
> the code (#261, #262).

```bash
ops/regional-failback.sh --env prod --profile sft-prod-admin                                   # dry run
ops/regional-failback.sh --env prod --profile sft-prod-admin --account-id <prod account> --execute \
  --failed-over-at 2026-12-01T03:00:00Z [--after-detach]
```

`--after-detach` is for a failover that detached Osaka's cluster rather than failing over (step 1).

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
| 10 | Prove the archive back-fill: Tokyo's archive holds what Osaka's alone held | 10 min |

## 1. Tokyo ready (30 min)

- AWS Health shows ap-northeast-1 recovered. Apply Tokyo's stacks again in infra/README.md's order, if anything
  drifted or was lost; Tokyo's cluster stays fenced (`pilotLight: true`) until step 5.
- **The database after a managed failover.** Aurora brings Tokyo's old cluster back into the global database as
  Osaka's secondary by itself, and keeps a snapshot of its volume from before. Nothing to apply.
- **The database after a detach** (`--after-detach`). The old Tokyo cluster is never a writer again (T-78), and
  Osaka's cluster is standalone. Inputs only (#261):

  ```bash
  # Osaka's cluster becomes a new global database, generation 2.
  aws rds create-global-cluster --region ap-northeast-3 --global-cluster-identifier sft-prod-aurora-2 \
    --source-db-cluster-identifier arn:aws:rds:ap-northeast-3:<account>:cluster:sft-prod-apne3-aurora
  # Osaka's data root records it: no change to the cluster.
  TF_VAR_aurora_global_generation=2 terraform -chdir=infra/environments/prod/ap-northeast-3/data apply
  # The old Tokyo cluster and global database lose their deletion protection, then Tokyo's data root replaces the
  # cluster: the old one goes with its final snapshot, the old global database with it, and a new cluster joins
  # sft-prod-aurora-2 as its secondary. Tokyo keeps the master secret and its Osaka replica.
  aws rds modify-db-cluster --region ap-northeast-1 --db-cluster-identifier sft-prod-apne1-aurora \
    --no-deletion-protection --apply-immediately
  aws rds modify-global-cluster --region ap-northeast-1 --global-cluster-identifier sft-prod-aurora --no-deletion-protection
  TF_VAR_aurora_role=secondary TF_VAR_aurora_global_generation=2 \
    terraform -chdir=infra/environments/prod/ap-northeast-1/data apply
  ```

  Keep `TF_VAR_aurora_role=secondary` and `TF_VAR_aurora_global_generation=2` in both data roots' apply checklist
  until the next rebuild, and `SFT_AURORA_GENERATION=2` for the ops scripts: changing the role again would replace the
  cluster. Terraform's role says how the cluster joined; which Region writes is the switchover's (step 4). The global
  database `sft-prod-aurora-2` was made by the CLI and stays outside Terraform; a teardown deletes it with
  `aws rds delete-global-cluster` after both data stacks.
- Either way, wait for `AuroraGlobalDBReplicationLag` under a second.
- **Rows only the old Tokyo database had** (#42 gap 10) are the RPO NFR-10 allows. Security-critical ones were
  re-applied from the archive; the rest aren't merged in v1. Keep the snapshot 30 days for support questions.

## 2. Copy the files written in Osaka back to Tokyo (30 min)

Replication runs Tokyo to Osaka, so Osaka's new objects never reached Tokyo (#42 gap 4). Apply Osaka's data root with
`TF_VAR_replicate_to_tokyo=true` (and the failover's `TF_VAR_malware_protection_enabled=true`): the rule `to-tokyo` on
both files buckets, Osaka to Tokyo, with RTC (modules/files-buckets, #262), so new uploads during the window replicate
too. S3 never replicates a replica again, so only the objects created in Osaka go back. Then one S3 Batch Replication
job per bucket copies everything created since the failover, tags included, so the `scan` tag comes back with each
file. The jobs run as `sft-prod-s3-batch-replication`, which may only start replication and build the job's manifest;
the copies themselves run as the replication role, under the rule:

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
ops/failover-values.sh both-regions --env prod --write
git commit -m "ops: fence prod Osaka and take Tokyo out of pilot light" deploy/environments/prod
```

Osaka goes back to `pilotLight: true`; Tokyo gets `pilotLight: false` with `failover.holdWorkers: true`. Wait for
Tokyo's API. The same commit sets `auditArchive.survivingRegionOnly: ""` in Osaka's file (Tokyo's never had it), so
security-critical records go to both archives again. From its next run, Tokyo's archive job back-fills: it writes
every range Osaka's job wrote alone to both regions, as the same objects, with the window's security-critical records
([audit-archive-single-region.md](audit-archive-single-region.md), #257). Step 10 proves it.

## 6. New generation, the outbox, Tokyo's workers (10 min)

The recovery job in Tokyo (`python -m sft.workers.recovery`, which reads Tokyo's archive), with
`RECOVERY_STEPS=generation,partitions,replay` and both times at step 3's hold. Tokyo's archive doesn't hold the
failover's generation yet: what Osaka's alone holds reaches it with the back-fill once the archive job resumes (step
10). So the generation step finds the cursor already past Tokyo's highest and keeps it, which is right after a
switchover, since no transaction ID is reused; the report shows `generation` one above `highest_in_archive`. The replay
reads what Tokyo's API wrote since step 5 and should find every record present; a re-applied record here means the
switchover lost something, which fails the drill. The records Osaka wrote alone between the hold and the fence aren't
read here: the switchover kept them in the database, and step 10 checks their archive copies. Then
`RECOVERY_STEPS=outbox` from the hold, for the messages that sat in Osaka's queues, and release Tokyo's workers:

```bash
ops/failover-values.sh release-tokyo --env prod --write
git commit -m "ops: start prod Tokyo's workers after the failback" deploy/environments/prod
```

## 7. DNS back to Tokyo (5 min)

Apply `infra/environments/prod/ap-northeast-1/edge` without `TF_VAR_api_alias_target`. The API's name points at
Tokyo again, and a record a real failover set by hand is back under Terraform.

## 8. Osaka back to its pilot light (10 min)

Inputs only, every one back to its default: Osaka's cluster root without `TF_VAR_system_node_count` (one node); its
data root without `TF_VAR_malware_protection_enabled` and `TF_VAR_replicate_to_tokyo` (the plan and the `to-tokyo`
rule go); its alarms root without `TF_VAR_heartbeat_enabled`, `TF_VAR_pilot_light` and `TF_VAR_database_role` (which
also removes Osaka's us-east-1 forwarding rule), and Tokyo's alarms root without `TF_VAR_database_role`. The pilot
light's cost is back to capacity 5.1's.

## 9. Verify (5 min)

The synthetic probe passes from Tokyo; a member without SSO signs in with their original Tokyo credentials ([AUTH]
2.6); a file uploaded during the failover downloads from Tokyo.

## 10. Prove the archive back-fill (10 min)

#257's drill step: every object Osaka's archive gained since the failover is in Tokyo's, under the same key, once.
Once Tokyo's workers run (step 6), `max(audit_archive_single_region_ranges)` is 0 and the archive job's last report
shows `backfilled`. Then, with the environment's `ReadOnly` profile, list both regions' archive under the failover's
generation and compare:

```bash
aws s3api list-objects-v2 --bucket sft-prod-apne3-audit-archive-<account> --prefix g<n>/ \
  --query 'Contents[].[Key,Size]' --output text | sort > osaka.txt
aws s3api list-objects-v2 --bucket sft-prod-apne1-audit-archive-<account> --prefix g<n>/ \
  --query 'Contents[].[Key,Size]' --output text | sort > tokyo.txt
diff osaka.txt tokyo.txt
```

The diff must be empty: no gap, no duplicate. For two keys, `aws s3api head-object --checksum-mode ENABLED` in each
region gives the same `ChecksumSHA256`. Then list `security-critical/v1/<the synthetic tenant>/<the failover's days>/`
in both: Tokyo holds every record Osaka does but the `download.grant_intent` ones (never in the database, data model
2.3). Record the counts in the drill log. A missing object fails the drill; so does one written twice under different
keys.

[AUTH]: ../security/authn-authz.md
