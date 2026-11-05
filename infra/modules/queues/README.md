# queues module

Every SQS queue of [ADR-0013](../../../docs/adr/0013-queues-sqs-outbox.md) for one Region, each with its dead-letter
queue. Written by [#101](https://github.com/codewithmuh/secure-file-transfer/issues/101). Nothing here has been
applied (infra/README.md). The same queues exist locally in `local/elasticmq/elasticmq.conf`; keep the two in step.

| Queue | Sender (the only one, T-50) | Consumer | Visibility |
|---|---|---|---|
| `scan-small` | Outbox relay, `sft-<env>-relay` | Scan worker | 60 s |
| `scan-large` | Outbox relay | Scan worker, which extends it as a heartbeat | 180 s |
| `notify` | Outbox relay | Notification worker | 30 s |
| `signin-events` | Sign-in triggers, `sft-<env>-signin-trigger` | Notification worker | 30 s |
| `ses-events` | SNS topic `sft-<env>-<region-short>-ses-events` | Notification worker | 30 s |
| `guardduty-results` | EventBridge delivery role, `sft-<env>-events-delivery` | Scan worker | 30 s |
| `ses-tenant-status` | EventBridge delivery role | Notification worker | 30 s |

Names are `sft-<env>-<region-short>-<queue>` and `...-<queue>-dlq`, so the application's `SQS_QUEUE_PREFIX` is
`sft-<env>-<region-short>-`.

| | |
|---|---|
| Type | Standard queues. The scan queues are fair queues because the relay sends the tenant ID as `MessageGroupId`; no queue setting is needed |
| Retention | 4 days; 14 days in a dead-letter queue (architecture 5.6) |
| Polling | 20-second long polling |
| Retries | 5 receives, then the dead-letter queue; each dead-letter queue accepts messages from its own queue only |
| Encryption | SSE-KMS with the Region's platform key, data key reused for 5 minutes (encryption 3.1) |
| Policy | Denies every request without TLS. Denies `SendMessage` to every principal but the queue's sender: roles by exact `aws:PrincipalArn`, so roles that don't exist yet are no error; the topic by `aws:SourceArn`. Dead-letter queues deny `SendMessage` to everyone |

Redriving a dead-letter queue back to its source queue needs `SendMessage` on the source queue, which only its sender
has. For the work queues the runbook re-publishes through the outbox instead, which keeps the relay their only sender.
For the intake queues the dead-letter runbook (phase 6) decides how messages go back.
