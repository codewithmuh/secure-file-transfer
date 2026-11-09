# Runbook: dead-letter queue (`sft-<env>-<rs>-<queue>-dlq`)

CloudWatch alarms on the dead-letter queues of `notify`, `signin-events`, `ses-events` and `ses-tenant-status`
([ADR-0013](../adr/0013-queues-sqs-outbox.md)), defined in
[`infra/modules/alarms/queues.tf`](../../infra/modules/alarms/queues.tf). Severity: page. The scan and GuardDuty
dead-letter queues page through `ScanFailed` instead ([scan-failed.md](scan-failed.md)).

## Symptoms

A message is in `sft-<env>-<rs>-<queue>-dlq`: its consumer received it 5 times and never deleted it.

## Impact

| Queue | What waits |
|---|---|
| `notify` | Emails: verification codes, links, notices. A recipient may be waiting for a code (NFR-7) |
| `signin-events` | Sign-in attempts for the audit log (NFR-15: within 60 s) and the lockout counts |
| `ses-events` | Bounces and complaints: the suppression list and a tenant's reputation are behind |
| `ses-tenant-status` | SES's pause of a tenant; no consumer exists yet (abuse 7.3), so any message here is unexpected |

Each message is a prompt, not the data itself: the worker re-reads state from the database, and a message it already
processed is skipped (`processed_messages`), so redriving is safe.

## Confirm

Commands are for the live run; the alarms are pending the AWS run.

```bash
aws sqs get-queue-attributes --region <region> --queue-url <dlq url> --attribute-names ApproximateNumberOfMessages
# Why: the consumer logs one line per failed attempt with the message ID, never its contents
kubectl -n sft logs deploy/notifier --since=1h | grep -E '"outcome": ?"(failed|invalid)"'
```

`worker_messages_total{consumer, outcome}` on the worker dashboard shows which outcome rose. `invalid` means a message
the worker can't parse, which should never happen: keep it for the postmortem rather than redrive it.

## Mitigate

1. Find and fix the cause first: a bad deploy (roll back), SES refusing sends (see [ses-reputation.md](ses-reputation.md)),
   the database or the counter store unavailable.
2. Then move the messages back with SQS's redrive:

   ```bash
   aws sqs start-message-move-task --region <region> --source-arn <dlq arn>
   ```

3. A message that fails again after the fix goes back to the dead-letter queue: leave it there (14 days, architecture
   5.6) and escalate.

## Escalate

If `notify` or `signin-events` can't be drained within 30 minutes, escalate to the owner in
[CODEOWNERS](../../.github/CODEOWNERS): codes aren't arriving, or failed sign-ins are missing from the audit log.

## Afterwards

A blameless postmortem when more than a few messages were affected: timeline, impact, root cause, action items.
