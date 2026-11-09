# Runbook: ScanFailed

The alert of FR-19 ([abuse and rate limits](../security/abuse-and-rate-limits.md) 8.2), defined in
[`deploy/alerts/scanning.rules.yaml`](../../deploy/alerts/scanning.rules.yaml). Severity: page.

## Symptoms

- A file ended `scan_failed` for an engine error (`scan_results_total{state="scan_failed", reason="engine_error"}`) or
  because its scan deadline passed (`reason="deadline_passed"`, recorded by the scan sweep), or
- a message sits in `sft-<env>-<region>-scan-small-dlq`, `-scan-large-dlq` or `-guardduty-results-dlq`.

Files over 2,000,000,000 bytes are GuardDuty's (#234): `engine_error` when GuardDuty answered `FAILED` or
`ACCESS_DENIED`, `deadline_passed` when no result arrived within two hours of completion. Every reason pages; the
`large_file_scanning_unavailable` of files completed before #234 no longer occurs.

## Impact

The file is blocked, and its transfer is `held` with `hold_reason = file_blocked`; the member gets the held notice and
sees the file's state and `scan_detail` (UC-1). Nothing unscanned is ever shared (FR-16). One file is a nuisance; many
in a few minutes mean no file is being scanned, which breaks NFR-5 for every tenant.

## Confirm

```bash
# Which pool, and why: the worker logs one line per attempt and per result (no file names, no values).
kubectl -n sft logs deploy/scan-worker-small --since=30m | grep -E 'clamd attempt failed|scan recorded|inspection attempt failed'
kubectl -n sft logs deploy/scan-worker-large --since=30m | grep -E 'clamd attempt failed|scan recorded'
# Is clamd beside each worker ready? A pod still loading signatures refuses connections.
kubectl -n sft get pods -l app.kubernetes.io/component=clamd -o wide
kubectl -n sft logs deploy/clamd-small --since=30m | tail -50
# The dead-letter queues
aws sqs get-queue-attributes --queue-url <dlq url> --attribute-names ApproximateNumberOfMessages
```

Locally: `docker compose logs scan-worker-small clamd`.

## Mitigate

1. **clamd down or restarting** (out of memory during a signature reload, a bad signature database from the mirror):
   restart it, or roll the mirror back to the last database it tested (capacity 3.3). The workers retry on their own.
2. **Every attempt times out on large files**: check the scan nodes' disk throughput and clamd's scratch; the worker's
   timeout grows with the size (`sft.service.scan_timing`), and staging measures it (NFR-5).
3. **A worker died without a result** (out of memory on a zip bomb): the sweep fails the file at its deadline, which
   is correct; check that clamd's limits (`MaxRecursion`, `MaxFiles`, `MaxScanSize`) are the chart's.
4. **Messages in a dead-letter queue**: once the cause is fixed, move them back with `StartMessageMoveTask`. Each is a
   prompt only: the worker re-reads the file, skips one that has a result, and scans one still `scanning`.
5. **GuardDuty, for files over 2 GB** (#234): `guardduty_results_total{outcome}` shows what the large pool's
   workers did with each result. `too_early` that keeps rising means results come before completion commits or
   before GuardDuty's tag; after 5 receives they land in `-guardduty-results-dlq`, and a redrive once the file is
   `scanning` records them. `tag_mismatch` means an event disagreed with GuardDuty's tag on the object and was
   ignored (T-50): look for who sent it. No results at all: check the plan's status
   (`aws guardduty list-malware-protection-plans`, its EventBridge rule and the events delivery role) and the
   GuardDuty service health in the Region.
6. **A file that failed for a transient reason** stays `scan_failed`: the member removes it and uploads it again
   (`deleteFile` on the held transfer sends the rest). No operator action rescans a file.

## Escalate

If no file can be scanned for 30 minutes, escalate to the owner in [CODEOWNERS](../../.github/CODEOWNERS): transfers
are held for every tenant.

## Afterwards

Write a blameless postmortem when the alert was more than one file: timeline, impact, root cause, action items.
