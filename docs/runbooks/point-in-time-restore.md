# Runbook: point-in-time restore

Restoring the database after data corruption or a bad migration (architecture 6; NFR-11: any point in the last 14
days, accurate to 5 minutes, service back within 2 hours). Migrations are expand-only, so a bad one is fixed forward
or by this restore, never by a down-migration (ADR-0005). Changes after the restore point are lost, except the
security-critical changes and the audit records, which the recovery job brings back from the archive (NFR-10,
NFR-15). `ops/point-in-time-restore.sh` runs, times and logs the steps. Decisions:
[disaster-recovery.md](../operations/disaster-recovery.md) (section 4, #42 gap 2b).

> [!IMPORTANT]
> **Pending the AWS run.** The re-import and re-apply run against a real database in CI
> (`tests/test_recovery_replay.py`); the AWS steps have not run yet. The first staging drill corrects them.

## When to use it

Only when the damage can't be fixed forward: rows changed or deleted across tenants by a bug or a migration, or a
schema the code can no longer use. A wrong change to a few rows is fixed forward through the API or a migration; a
bad deploy is rolled back (NFR-18). A restore costs every non-critical change since the restore point, for every
tenant.

```bash
ops/point-in-time-restore.sh --env prod --profile sft-prod-admin --restore-to 2026-12-01T02:55:00Z       # dry run
ops/point-in-time-restore.sh --env prod --profile sft-prod-admin --account-id <account> --execute \
  --restore-to 2026-12-01T02:55:00Z
```

| # | Step | Budget |
|---|---|---|
| 1 | Decide the restore point; hold the workers | 15 min |
| 2 | Restore to a new cluster | 50 min |
| 3 | Protect it in Osaka until it has a secondary | 15 min |
| 4 | Move the service onto it | 10 min |
| 5 | New archive generation; re-import and re-apply | 10 min |
| 6 | Re-publish the outbox; start the workers | 5 min |
| 7 | Verify | 5 min |
| | **Total, the RTO** | **110 min** (NFR-11: 2 h) |
| 8 | A new Osaka secondary (after the RTO) | hours |

## 1. Decide the restore point; hold the workers (15 min)

The restore point is the last good moment: just before the bad migration's PreSync job (Argo CD's sync history), or
before the errors began (the dashboards, the audit log). Aurora restores to the second; NFR-11's 5 minutes is the
margin for choosing it.

```bash
ops/failover-values.sh hold-tokyo --env prod --write
git commit -m "ops: hold prod Tokyo's workers for a point-in-time restore" deploy/environments/prod
```

The workers stop acting on the damaged database; the API keeps serving on it until step 4, and what it writes there
in the meantime is lost with the rest, except the security-critical records.

## 2. Restore to a new cluster (50 min)

```bash
aws rds restore-db-cluster-to-point-in-time --region ap-northeast-1 \
  --source-db-cluster-identifier sft-prod-apne1-aurora --db-cluster-identifier sft-prod-apne1-aurora-r<stamp> \
  --restore-to-time <restore point> --db-subnet-group-name sft-prod-apne1-aurora \
  --kms-key-id alias/sft/prod/database --enable-iam-database-authentication --deletion-protection
aws rds create-db-instance --region ap-northeast-1 --db-cluster-identifier sft-prod-apne1-aurora-r<stamp> \
  --db-instance-identifier sft-prod-apne1-aurora-r<stamp>-1 --engine aurora-postgresql --db-instance-class db.r8g.large
```

Give it the source's security group and cluster parameter group if the restore didn't. A restore of a global
database's primary is a standalone cluster (ADR-0011). The roles, their IAM authentication and the schema come with
it.

## 3. Protect it in Osaka (15 min, staging and prod)

Until a new Osaka secondary catches up, the restored cluster has no copy outside Tokyo (#42 gap 2b): take one cluster
snapshot and copy it to Osaka under Osaka's database key. Delete the copy in step 8.

## 4. Move the service onto it (10 min)

Swap the clusters' names, so the cluster endpoint the pods already use names the restored cluster; no Git or
Terraform change is needed to move the service:

```bash
aws rds modify-db-cluster --db-cluster-identifier sft-prod-apne1-aurora --new-db-cluster-identifier sft-prod-apne1-aurora-old<stamp> --apply-immediately
aws rds modify-db-cluster --db-cluster-identifier sft-prod-apne1-aurora-r<stamp> --new-db-cluster-identifier sft-prod-apne1-aurora --apply-immediately
```

Then reboot the old cluster's instances, so every pooled connection opens again on the endpoint. Endpoints follow the
identifier, with a short DNS TTL.

## 5. New archive generation; re-import and re-apply (10 min)

The recovery job (disaster-recovery.md section 4) with `RECOVERY_STEPS=generation,partitions,replay` and both
`RECOVERY_SINCE` and `RECOVERY_REWIND_TO` at the restore point:

- the generation becomes one more than the highest in the archive, because the restore gives out transaction IDs
  again (data model 2.5), and the cursor goes back to the restore point;
- every archived event after the restore point is re-imported with its own ID and time, and every security-critical
  change after it is made again: revocations, lockouts, deactivations, demotions, sign-outs, sign-in resets, key
  revocations, download counts.

Copy its counts into the log, and tell tenant admins of the unlocks it left out (their members unlock again) and the
sign-in resets whose invitation must be sent again.

The job is `python -m sft.workers.recovery` (#258), as `sft_recovery`, reading Tokyo's archive under both layouts; the
grants are revisions 0034 and 0035 (disaster-recovery.md section 4). Copy its report line into the log: `newest`
against the restore point shows how much the archive held beyond it. Ranges a regional loss left for the back-fill
(`audit_archive_single_region`, #257) come back with the restored database and are written again by the archive job;
that rewrites nothing that exists.

## 6. Re-publish the outbox; start the workers (5 min)

`RECOVERY_STEPS=outbox` with `RECOVERY_SINCE` 24 hours before the restore point: work whose results the restore took
back (a scan, an email) is done again, and consumers skip what the restored database shows done. Then:

```bash
ops/failover-values.sh release-tokyo --env prod --write
git commit -m "ops: start prod Tokyo's workers after the restore" deploy/environments/prod
```

Reconciliation's next run marks restored rows whose files were deleted since the restore point as deleted (NFR-11).

## 7. Verify (5 min)

The synthetic probe passes. In a drill: a transfer created after the restore point is gone, and a revocation made
after it still stands, re-applied by step 5. The RTO is the time from step 1 to here. The RPO is the restore point
against the newest event the restored cluster had before step 5.

## 8. A new Osaka secondary (after the RTO)

The restored cluster is outside the global database. Bring Terraform in line and give it a secondary:

1. `terraform state rm` the old cluster and its instances from Tokyo's data root, and `terraform import` the restored
   ones at the same addresses (they now carry the canonical names).
2. Make the global database from the restored cluster, and apply Osaka's data root, which removes the old secondary
   and creates a new one. It catches up in hours at 150 GB; the drill measures it.
3. When `AuroraGlobalDBReplicationLag` is under a second, delete the snapshot copy in Osaka. After 7 days, delete
   the old cluster, keeping its final snapshot 30 days.

In dev there is no Osaka: steps 3 and 8 are skipped, and step 8's first part still applies.
