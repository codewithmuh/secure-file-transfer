# Runbook: FileDeletionOverdue, FileDeletionLagging, UnarchivedGrants, LifecycleJobNotRunning

The alerts of the lifecycle jobs (#181; NFR-8, NFR-15; [data model](../design/data-model.md) 6), defined in
[`deploy/alerts/lifecycle.rules.yaml`](../../deploy/alerts/lifecycle.rules.yaml). Severity: `FileDeletionOverdue`
pages; the others are tickets. The audit archive job and the purge have their own runbooks
([audit-archive-lag.md](audit-archive-lag.md), [metadata-purge.md](metadata-purge.md)), and the partition job its
own ([audit-partitions.md](audit-partitions.md)).

## Symptoms

The jobs are CronJobs in `sft` (`deploy/charts/sft/values.yaml`, `lifecycleJobs`) that push their metrics to the
Pushgateway after each run, so every value is the one the last run left ([metrics](../operations/metrics.md) 7).

- `FileDeletionOverdue`: `lifecycle_overdue_deletions` is above 0 for 15 minutes. Files whose deletion was triggered
  (expiry, revocation, a deleted file) more than 7 days ago still have an object in a region: NFR-8 is missed.
- `FileDeletionLagging`: `lifecycle_deletion_lag_seconds`, the age of the oldest due deletion, is past 6 days. NFR-8's
  deadline is a day away.
- `UnarchivedGrants`: `lifecycle_unarchived_grants` is above 0 for 15 minutes. Download grants over a minute old
  whose committed audit record isn't confirmed; reconciliation retries each run and the cleanup keeps them.
- `LifecycleJobNotRunning{job, condition}`: a job hasn't finished a run for 30 minutes (`expiry`, `deletion`,
  `reconciliation`, every 5 minutes) or 26 hours (`storage-audit`, `cleanup`, daily). Its other gauges are stale.

## Impact

- Overdue or lagging deletion: a file's contents outlive what the PRD promises (NFR-8). Nobody can download them (the
  transfer has ended, and every link checks it), so it is a retention breach, not an exposure.
- Unarchived grants: the record of a download that happened is not yet in the audit log (NFR-15). The download itself
  was served only after the intent was written, so nothing is lost while the grant is kept.
- A job not running: `expiry` stopping leaves ended transfers marked active (the API still refuses them past
  `expires_at`); `deletion` stopping starts the NFR-8 clock running out; `reconciliation` stopping leaves completions,
  scans and grants unswept; `storage-audit` and `cleanup` stopping let orphans and expired codes pile up.

## Confirm

```bash
kubectl -n sft get cronjobs
kubectl -n sft get jobs -l app.kubernetes.io/component=<job> --sort-by=.metadata.creationTimestamp | tail -3
kubectl -n sft logs job/<latest job of that CronJob> | tail -20   # its one-line report: counts and errors only
```

In Grafana, the lifecycle jobs dashboard (`sft-lifecycle-jobs`): each job's last success, its items by result, the
deletion lag and the unarchived grants. A CronJob that is `SUSPEND True` outside the pilot light means a failover's
hold (`failover.holdWorkers`) is still on.

## Mitigate

1. **A job fails every run:** its log names the error. A database error points at its role's grants (data model 4.2)
   or the connection; an S3 `AccessDenied` at the jobs' role (`infra/modules/eks-cluster/workload-roles.tf`) or a
   bucket policy. `DeadlineExceeded` means the run is too long for `activeDeadlineSeconds`: look at its counts.
2. **A job doesn't start:** `kubectl -n sft describe cronjob <job>` (suspended, a missed schedule, an image pull or a
   network policy refusing it). After a failover, `ops/failover-values.sh release-workers` releases the hold.
3. **Deletion overdue:** the deletion job skips a file in `scanning` or `completing`, which the scan sweep or
   reconciliation should have ended: find the stuck files (IDs and states only) and fix the cause there. A file whose
   Osaka copy failed is retried every run; `file-replication.md` covers replication. Never set `deleted_at` by hand
   while an object may remain.
4. **Unarchived grants:** the archive write fails, which `AuditArchiveWriteFailing` says too
   ([audit-archive-writes.md](audit-archive-writes.md)); once writes work, the next reconciliation clears them.
5. Run a job once by hand: `kubectl -n sft create job --from=cronjob/<job> <job>-manual-<date>`.

## Escalate

`FileDeletionOverdue` that a run doesn't clear within the hour: escalate to the owner in
[CODEOWNERS](../../.github/CODEOWNERS), and record which files (by ID) and how late, for the NFR-8 report.

## Afterwards

Note the cause and, for an overdue deletion, how many files and how many days past the deadline.
