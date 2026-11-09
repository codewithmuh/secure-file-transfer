# Runbook: MetadataPurgeBlocked, MetadataPurgeBehind, MetadataPurgeNotRunning

The alerts of the 365-day metadata purge (#224; NFR-9; [data model](../design/data-model.md) 6), defined in
[`deploy/alerts/lifecycle.rules.yaml`](../../deploy/alerts/lifecycle.rules.yaml). Severity: ticket.

## Symptoms

- `MetadataPurgeBlocked`: `metadata_purge_blocked{kind}` is above 0. A transfer or upload request is past its
  `purge_after` (372 days after its end, or after its last received file's retention), but one of its files has no
  `deleted_at`, so the purge skipped it rather than leave the file's object with nothing pointing at it.
- `MetadataPurgeBehind`: `metadata_purge_lag_seconds` is above a day: after the last run, purgeable metadata is still
  there more than a day past due.
- `MetadataPurgeNotRunning`: `lifecycle_job_last_success_timestamp_seconds{job="purge"}` is more than 26 hours old:
  the daily run failed or didn't start, and the other two alerts' gauges are a day old.

The job is the `purge` CronJob (`python -m sft.workers.purge`, as `sft_jobs`, daily at 03:53 UTC). It deletes due
transfers and upload requests in each tenant's scope, at most 100 a transaction, with their child rows through the
foreign keys' cascade, and writes one `retention.rows_deleted` per transaction. Audit events are never touched.

## Impact

Nothing breaks for users. Metadata the PRD says to delete after 365 days (NFR-9) stays longer: names (sealed),
recipients' addresses, DLP decisions and findings' counts of ended transfers. That is a retention commitment missed,
not a security hole, and the audit records still describe what happened. A blocked parent also means a file whose
deletion never finished, which is NFR-8's concern: its contents may still be in S3.

## Confirm

```bash
# The runs, and what the last one reported (counts only): transfers_purged, upload_requests_purged, blocked_*.
kubectl -n sft get jobs -l app.kubernetes.io/component=purge --sort-by=.metadata.creationTimestamp | tail -3
kubectl -n sft logs job/<latest purge job> | tail -20
# Blocked parents and their undeleted files (as the master user under break-glass; IDs and states only):
#   SELECT t.tenant_id, t.id, t.ended_at, f.id AS file_id, f.state, f.delete_after
#     FROM transfers t JOIN files f ON f.tenant_id = t.tenant_id AND f.transfer_id = t.id
#    WHERE t.ended_at <= now() - interval '372 days' AND f.deleted_at IS NULL;
#   (the same for upload_requests through files.upload_request_id)
```

Locally: `make jobs JOB=purge`. The clock's test hook stops at 366 days, short of the purge's 372, so tests move the
jobs' clock directly (tests/test_purge.py).

## Mitigate

1. **Blocked**: the file was never deleted. Check `lifecycle_deletion_lag_seconds` and the
   [deletion job](../design/data-model.md) (section 6): a file stuck in `scanning` or `completing`, which deletion
   skips, means the scan sweep or reconciliation failed for it (data model 3.1), a bug to fix there. Once the deletion
   job has deleted every copy and set `deleted_at`, the next purge takes the parent. Never set `deleted_at` by hand
   while an object may remain.
2. **Behind**: the run stopped part way. Look for its error in the log, or `DeadlineExceeded` (its
   `activeDeadlineSeconds` is 3600). A first run after a long gap can have a large backlog; run it again by hand,
   `kubectl -n sft create job --from=cronjob/purge purge-manual-<n>`, as often as it takes. Each transaction stands on
   its own, so a cut run loses nothing.
3. **Not running**: `kubectl -n sft describe cronjob purge` (suspended? the pilot light suspends it in Osaka), the
   pods' events, and the `sft_jobs` login (IAM authentication, encryption and keys 6.3). A `permission denied` on
   `transfers` or `upload_requests` means migration 0034 didn't run.
4. **An audit trigger refuses the commit** (`a change to … has no audit event in its transaction`): a child table
   gained the trigger for deletes and the purge's event isn't in that transaction; a bug, fix it in
   `sft.service.lifecycle`.

## Escalate

None needed outside working hours. If metadata is more than 30 days overdue, raise it with the owner in
[CODEOWNERS](../../.github/CODEOWNERS): NFR-9 is a stated retention.

## Afterwards

For a blocked parent, record the file and why its deletion stalled in the issue that fixes the cause.
