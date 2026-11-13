# Runbook: AuditArchiveLagging, AuditArchiveJobNotRunning

The alerts of NFR-15's archive ([data model](../design/data-model.md) 2.5; [architecture](../architecture.md) 5.2, 6;
threat model T-45, T-46), defined in [`deploy/alerts/lifecycle.rules.yaml`](../../deploy/alerts/lifecycle.rules.yaml).
Severity: page.

## Symptoms

- `AuditArchiveLagging`: `audit_archive_lag_seconds`, the age of the oldest committed audit event not yet in both
  regions' archive, has been above 120 s for 2 minutes. The job runs every minute, so normally it stays under about 70.
- `AuditArchiveJobNotRunning`: `lifecycle_job_last_success_timestamp_seconds{job="audit-archive"}` is more than 5
  minutes old. Every run fails, or none starts, and the lag gauge is stale.

The job is the `audit-archive` CronJob (`python -m sft.workers.audit_archive`, as `sft_archive`, #183). Each run
claims a range of committed transactions, writes it to both regions' archive bucket as gzipped JSON lines, and moves
the cursor (`audit_archive_cursor`) only once both regions hold every object.

## Impact

No event is lost: every event is in PostgreSQL, in the transaction of the change it records, and the job catches up
from its cursor. What grows is the window NFR-15 bounds: events written since the lag began exist only in the
database and its replica, so a regional failover in that window could lose them (R-05). Security-critical records
don't depend on this job; the API writes them to both regions itself (architecture 5.2). Audit search reads
PostgreSQL and is unaffected.

## Confirm

```bash
# Recent runs, and why the last ones failed: one JSON line per run, with its report; no event's contents are logged.
kubectl -n sft get jobs -l app.kubernetes.io/component=audit-archive --sort-by=.metadata.creationTimestamp | tail -5
kubectl -n sft logs job/<latest audit-archive job> | tail -20
# Which region refuses writes, and since when (Prometheus, port-forwarded as observability.md says):
#   increase(audit_archive_write_failures_total{job="audit-archive"}[15m])
#   increase(audit_archive_events_total[15m])        # by region: one region at 0 while the other moves
# Where the cursor is, and whether a run left a claim (read-only, as the master user under break-glass, or the
# recovery role in recovery scope):
#   SELECT generation, archived_up_to_tx, claimed_up_to_tx, archived_at FROM audit_archive_cursor;
#   SELECT pg_snapshot_xmin(pg_current_snapshot());   -- the oldest running transaction holds the cursor back
#   SELECT pid, now() - xact_start AS open_for, state, usename FROM pg_stat_activity
#    WHERE backend_xid IS NOT NULL OR backend_xmin IS NOT NULL ORDER BY xact_start LIMIT 5;
```

Locally: `make audit-archive`, then `docker compose logs`; the S3 stand-in holds both archive buckets.

## Mitigate

1. **A region refuses writes** (`audit_archive_write_failures_total{region}` rising, the logs' `code`): the claim
   stays, and every run writes the same objects again until that region takes them; the other region keeps its
   copies once. Check S3 in that region and, for Osaka, the cross-region S3 endpoint (ADR-0021): the security-critical
   writes of the API fail the same way (architecture 6, "Osaka archive unreachable"). `AccessDenied` after a change to
   the bucket policy or the `sft-<env>-archive` role means the archive job lost its `s3:PutObject` there; restore it
   through Terraform (modules/audit-archive, modules/eks-cluster). Nothing to do in the database.
2. **A long transaction holds the cursor** (the lag grows, runs succeed, `audit_archive_events_total` flat): the job
   can't pass the oldest running transaction (`pg_snapshot_xmin`), by design (T-44). Every workload role ends a
   transaction after 30 seconds (data model 2.5), so look for a session of the master user or `sft_migrate`: a
   migration, or someone's open `psql`. Let a migration finish; end anything else with
   `SELECT pg_cancel_backend(<pid>)`, then `pg_terminate_backend` if it stays.
3. **The job doesn't start or is killed**: `kubectl -n sft describe cronjob audit-archive` (suspended? the pilot light
   suspends it in Osaka), the pods' events (image pull, Pod Identity, `activeDeadlineSeconds` of 300 reached on a large
   backlog). A run that hits its deadline loses only its last range, which the next run writes again. After a long
   outage it catches up about 5,000 events a range, as many ranges as fit in 4 minutes a run.
4. **The database refuses it** (`permission denied`, login failures): check the `sft_archive` role and its IAM
   authentication (encryption and keys 6.3), and that migration 0034 ran (`audit_archive_cursor` exists).
5. **After a point-in-time restore or a regional failover** the runbooks set the generation to one more than the
   highest in the archive, as `sft_recovery`, before the service writes again (data model 2.5). If that step was
   missed the job writes under the old generation's prefix again, which the conditional write refuses for keys
   already there: set the generation, then the next run continues under the new one.

6. **A region is lost for good, not refusing for a while** (a regional failover): the failover runbook sets
   `auditArchive.survivingRegionOnly` to the region left, and the job writes it alone and keeps up; the API's
   security-critical records go there alone too ([audit-archive-single-region.md](audit-archive-single-region.md),
   #257). Never set it for an outage of Osaka's S3 alone while Tokyo serves: there the grants' `503` is the decision
   of #42 gap 5, and the archive catches up when Osaka answers.

Don't move the cursor by hand to make the alert stop: events behind it would never be archived.

## Escalate

If the lag passes 15 minutes, or a region has refused writes for 15 minutes, escalate to the owner in
[CODEOWNERS](../../.github/CODEOWNERS): the window of events that a regional failover could lose keeps growing.

## Afterwards

Write a blameless postmortem when the lag passed 15 minutes: timeline, how far behind it got, root cause, action
items. Note in the drill log whether the lag window overlapped a failover or restore.
