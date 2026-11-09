# Runbook: AuditPartitions

The audit partition alert of data model 6 (NFR-15), defined in
[`deploy/alerts/audit.rules.yaml`](../../deploy/alerts/audit.rules.yaml). Severity: ticket. Its `condition` label says
which:

- `default_rows`: audit events are in the default partition `audit_events_default`, because their month had no
  partition (`sft_audit_default_partition_rows > 0`);
- `next_month_missing`: next month has no partition and this month ends within 7 days
  (`sft_audit_partition_months_covered < 2`);
- `stale`: the partition step hasn't succeeded for 26 hours
  (`sft_audit_partition_last_success_timestamp_seconds`);
- `never_reported`: the step has never pushed its gauges in 26 hours, so `stale` can't fire.

## Symptoms

`audit_events` is partitioned by month on `occurred_at`, in UTC months named `audit_events_yYYYYmMM`. The lifecycle
job's step (`sft.service.audit_partitions`) calls `audit_create_partitions(3)` to keep three months ahead, and
measures with `audit_partition_status()`. The alert means a month has no partition yet, or rows already sit in the
default partition, or the step isn't running.

## Impact

The default partition catches any row whose month is missing, so audit writes, and every fail-closed action behind
them, never fail (data model 6). Nothing is lost. The harm is that a month whose rows sit in the default partition is
**blocked**: the function won't create its partition until an operator moves the rows, and its alert stays on until
then.

## Confirm

The job's log, one line per month with its status (`exists`, `created`, `blocked`, `failed`):

```bash
kubectl -n sft get cronjobs                        # is the job that runs the step there, and not suspended?
kubectl -n sft logs job/<its last run>
```

The step is part of the lifecycle jobs; the `sft.workers.audit_partitions` CronJob in the chart has no module yet, so
until it exists (the APP track) these gauges aren't reported and `never_reported` is the alert that shows it.

## Mitigate

1. **`stale`, `never_reported` or `next_month_missing`, nothing blocked:** the job isn't running or keeps failing (a `failed` month is
   often a 2-second lock timeout on a busy default partition; the next run tries again). Fix the job; one run with
   every month `created` or `exists` clears both.
2. **`default_rows`: move the rows**, pending the AWS run for the access path. It runs as the table owner
   (`sft_owner`, which the migration role `sft_migrate` becomes with `SET ROLE`, authn-authz 7.3), because no
   workload role may delete audit rows. In one transaction, for each blocked month:

   ```sql
   BEGIN;
   SET LOCAL lock_timeout = '5s';
   LOCK TABLE audit_events_default IN ACCESS EXCLUSIVE MODE;
   CREATE TABLE audit_events_y2027m01 (LIKE audit_events INCLUDING DEFAULTS INCLUDING CONSTRAINTS);
   INSERT INTO audit_events_y2027m01
     SELECT * FROM audit_events_default
      WHERE occurred_at >= '2027-01-01T00:00:00Z' AND occurred_at < '2027-02-01T00:00:00Z';
   DELETE FROM audit_events_default
    WHERE occurred_at >= '2027-01-01T00:00:00Z' AND occurred_at < '2027-02-01T00:00:00Z';
   ALTER TABLE audit_events ATTACH PARTITION audit_events_y2027m01
     FOR VALUES FROM ('2027-01-01T00:00:00Z') TO ('2027-02-01T00:00:00Z');
   COMMIT;
   ```

   The rows keep their `id`, `tx_id` and `occurred_at`, so the archive's cursor and every archived copy stay valid.
   Check the counts match before the `COMMIT`. Inserts into that month wait on the lock for the moment it takes. Then
   run the job once more; the month reports `exists` and the gauge returns to 0.
3. **After a restore or failover**, re-imported events with old `occurred_at` belong in past months: the runbook runs
   `audit_create_partitions(3, <first day of the oldest month>)` as `sft_recovery` before re-importing (data model 6).

## Escalate

Moving rows is a change to the audit trail: do it with the owner in [CODEOWNERS](../../.github/CODEOWNERS), and
record it.

## Afterwards

Record which months were blocked, why the job missed them, and the row counts moved.
