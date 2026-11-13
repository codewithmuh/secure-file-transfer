# Runbook: AuditArchiveSingleRegion

The surviving-region mode of the audit archive for a regional loss (#257; [architecture](../architecture.md) 5.2, 7;
[data model](../design/data-model.md) 2.5), and its alert, defined in
[`deploy/alerts/lifecycle.rules.yaml`](../../deploy/alerts/lifecycle.rules.yaml). Severity: ticket.

## The mode

Every security-critical record (revocations, lockouts, download grants…) and every archive job batch goes to both
regions' Object Lock archive, and "archived" means both hold it. With one region lost, that would stop new download
grants in the other and hold the archive job's cursor still. So the chart has one toggle, which the failover runbook
sets in the cluster taking over ([regional-failover.md](regional-failover.md)):

```yaml
auditArchive:
  survivingRegionOnly: ap-northeast-3   # the region left; "" (the default) is both
```

It reaches the API, the operator API, the lifecycle jobs that write the archive (reconciliation) and the archive job as
`AUDIT_ARCHIVE_SURVIVING_REGION`. Then:

- **The API** writes each security-critical record to the surviving region alone, and `2xx` means it holds it
  (`sft.service.audit_archive.SurvivingRegion`). Grants work in Osaka with Tokyo gone. So does the operator API's
  `recoverTenantAdmin` (#239).
- **The archive job** writes each range to the surviving region alone and moves its cursor on, so the lag stays low.
  In the same transaction it records the range in `audit_archive_single_region` (revision 0039), and marks the window
  open on the cursor (`single_region_since`).
- **The audit partition job** never drops a month with a row in a recorded range (#255): it isn't in both regions yet.

**At failback** the runbook sets the toggle back to `""` ([regional-failback.md](regional-failback.md)). From the next
run the archive job **back-fills** before anything else: for each recorded range it reads the same events again, makes
the same objects (same keys, same bytes) and writes them to every region, which keeps what it already holds; then it
deletes the row. The lost region ends with exactly the objects the surviving one has: no gap, no duplicate. It also
writes the security-critical records of those events, and, for 15 minutes after it first writes both regions again,
of every new range's events, because the API's pods leave the mode a little after the job does. Then the window
closes. A grant's intent record (`download.grant_intent`) is never in the database and isn't back-filled: it gave no
access by itself, its committed record supersedes it, and every reader ignores intents (data model 2.3).

Dev has Tokyo alone; the chart refuses the toggle there. It is never for an outage of Osaka's S3 alone while Tokyo
serves: that is #42 gap 5's decision, no degraded mode ([audit-archive-writes.md](audit-archive-writes.md)).

## Symptoms

`audit_archive_single_region_ranges`, the ranges waiting for the back-fill, has been above 0 for 30 minutes.

- **While the failover runs on one region:** expected. The ticket records that the archive is in one region only.
- **After failback** (the toggle is `""`): the back-fill isn't progressing.

## Impact

While ranges wait, the events in them are in one region's archive only, so losing that region too would leave them in
the database and its backups alone (NFR-10). Nothing is lost while the back-fill runs, and the cursor keeps moving.

## Confirm

```bash
kubectl -n sft get cronjob audit-archive -o yaml | yq '.spec.jobTemplate.spec.template.spec.containers[0].env'
kubectl -n sft logs job/<latest audit-archive job> | tail -5   # "backfilled", "single_region" in the report
```

```promql
max(audit_archive_single_region_ranges)                    # going down after failback
increase(audit_archive_write_failures_total{job="audit-archive"}[15m])   # by region
```

## Mitigate

1. **During the failover:** nothing; fail back when the lost region is healthy.
2. **After failback, nothing moves:** check that every cluster's values have `survivingRegionOnly: ""` and Argo CD
   synced them, so the job runs in both-region mode. A job that fails each run on the lost region
   (`audit_archive_write_failures_total` there) means that region's archive still refuses writes:
   [audit-archive-lag.md](audit-archive-lag.md), step 1. The ranges wait, safely, and the back-fill resumes when it
   answers.
3. **The drill's proof:** after failback, every key under the failover's generation (`g<n>/`) in the surviving region's
   archive is in the other region's, with the same size and checksum, and `audit_archive_single_region_ranges` is 0.

Never delete rows of `audit_archive_single_region` by hand: the ranges would stay in one region, and their months could
be dropped from the database.

## Escalate

Ranges still waiting 2 hours after failback: escalate to the owner in [CODEOWNERS](../../.github/CODEOWNERS).

## Afterwards

Record in the drill log or the incident: when the mode was on and off, how many ranges were back-filled, and the
check of step 3.
