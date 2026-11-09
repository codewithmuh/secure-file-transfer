# Runbook: queue backlog (`sft-<env>-<rs>-<queue>-age`)

CloudWatch alarms on the age of the oldest message in each work and intake queue
([ADR-0013](../adr/0013-queues-sqs-outbox.md)), defined in
[`infra/modules/alarms/queues.tf`](../../infra/modules/alarms/queues.tf).

| Queue | Fires when | Severity | Target it protects |
|---|---|---|---|
| `signin-events` | Older than 30 s for 3 minutes | Page | Authentication 2.4; NFR-15's 60 s to the audit log |
| `notify` | Older than 60 s for 5 minutes | Page | NFR-7: emails handed to SES within 10 s at p95 |
| `scan-small` | Older than 5 minutes for 10 minutes | Page | NFR-5: shareable within 2 minutes up to 100 MB |
| `scan-large` | Older than 15 minutes for 15 minutes | Ticket | NFR-5: 15 minutes up to 20 GB |
| `ses-events`, `guardduty-results` | Older than 10 minutes for 15 minutes | Ticket | Bounce handling; large-file results |

## Symptoms

Messages wait longer than the table allows; the consumer is down, too slow or failing every message.

## Impact

Work is delayed, not lost: messages stay up to 4 days (architecture 5.6). Users see late codes, files stuck in
`scanning`, or sign-in events late in the audit log.

## Confirm

```bash
kubectl -n sft get deploy notifier relay scan-worker-small scan-worker-large    # replicas ready?
kubectl -n sft logs deploy/<consumer> --since=30m | tail -100                   # failing every message?
```

On the worker dashboard: `worker_messages_total{consumer}` by outcome, and the queue depth beside the age. A rising age
with no `processed` outcomes means the consumer isn't consuming; `failed` outcomes mean it is failing (the messages
will reach the dead-letter queue, see [dead-letter-queue.md](dead-letter-queue.md)). The sign-in events are consumed by
the notification worker.

## Mitigate

1. **Consumer down or crash-looping**: [service-unavailable.md](service-unavailable.md); a recent deploy is rolled
   back first.
2. **Consumer too slow** (a burst of uploads, a load test): scale the Deployment through its values file, or let
   Karpenter add scan nodes; check the scan pool's tenant cap isn't holding one tenant's burst back on purpose
   (abuse 6.4).
3. **A dependency is slow**: clamd or the DLP inspector ([scan-failed.md](scan-failed.md),
   [dlp-inspector.md](dlp-inspector.md)), SES ([ses-reputation.md](ses-reputation.md)), the database
   ([database-capacity.md](database-capacity.md)).
4. **Osaka**: its queues are idle in the pilot light; an alarm there after a failover is the same as in Tokyo.

## Escalate

If the `notify` or `signin-events` page doesn't clear within 30 minutes, escalate to the owner in
[CODEOWNERS](../../.github/CODEOWNERS).

## Afterwards

Note the cause; when it was capacity, update the capacity estimate (capacity 3).
