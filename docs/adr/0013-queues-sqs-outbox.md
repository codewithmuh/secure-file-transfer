# 0013. Use SQS standard queues with dead-letter queues, fed by the transactional outbox

- Status: accepted
- Date: 2026-11-03
- Issue: [#32](https://github.com/codewithmuh/secure-file-transfer/issues/32)

## Context

The API hands work to the scan and notification workers. Every message is written to an outbox table in the same
transaction as the change that causes it, and the outbox relay publishes it ([architecture](../architecture.md),
section 5.3). Delivery is at least once, messages carry IDs and never tokens or codes
([threat model](../threat-model.md), T-49), and after a regional failover every outbox message of the last 24 hours
without a processed-message record is published again.

- **Load.** About 100,000 messages a day, each under 1 KB ([capacity](../design/capacity-and-cost.md) 3.1).
- **Latency.** Time to shareable p95 ≤ 2 minutes for files up to 100 MB (NFR-5); emails handed over within 10 s
  (NFR-7).
- **Long work.** A 2 GB scan takes about 2 minutes, and a scan that keeps failing must end in `scan_failed`, never stuck
  in `scanning` (FR-19).
- **Fairness.** One tenant's burst must not starve the others: scans are capped per tenant, and a scan over its
  tenant's cap is deferred and re-sent ([abuse and rate limits](../security/abuse-and-rate-limits.md), 6.4).
- **AWS events** also arrive by queue: SES sending events through SNS, GuardDuty scan results and SES tenant status
  through EventBridge, and Cognito sign-in events from the sign-in triggers
  ([encryption and keys](../security/encryption-and-keys.md) 4.4, [authentication](../security/authn-authz.md) 2.4).

## Decision

Use **SQS standard queues**, each with a **dead-letter queue**.

- **Work queues**, one per kind of work: small-file scans, large-file scans and notifications. The scan queues are
  **fair queues** with the tenant ID as message group. Only the outbox relay's role may send to them (queue policy),
  and the relay claims rows with `FOR UPDATE SKIP LOCKED`, sends, then sets `published_at`.
- **Intake queues** for the AWS events above. Each queue policy names its one sender: the SES events topic or the
  EventBridge delivery role, pinned by `aws:SourceArn`, or the sign-in triggers' role. Consumers treat these events as
  prompts and re-read the state they act on (T-50).
- **Idempotent consumers.** Each consumer records `(consumer, message_id)` in `processed_messages` once its work is
  done (in the same transaction for a database change, after the send for an email, whose retry rebuilds the same link,
  [data model](../design/data-model.md) 2.2) and skips duplicates. For work queues `message_id` is the **outbox row
  ID** carried in the message, not the SQS message ID, so relay retries and post-failover re-publishes are recognised;
  intake queues use the source's event ID.
- **Deferred work is a new message.** A worker that must wait writes a new outbox row with a delay; the relay sends it
  with `DelaySeconds` (at most 15 minutes), and the worker deletes the message it received once that commits. Nobody
  defers by changing visibility, because every receive raises the receive count and would push healthy work into the
  dead-letter queue. A long scan extends its visibility timeout while it runs, as a heartbeat.
- **Retries** use the redrive policy: a small maximum receive count (starting at 5), and the last attempt records the
  terminal state, such as `scan_failed`, before the message moves to the dead-letter queue.
- **Settings.** Retention 4 days on work queues and 14 days on dead-letter queues (architecture 5.6), 20-second long
  polling, SSE-KMS with the platform key. Osaka has the same queues, idle until a failover (architecture 3.2).

## Options considered

| Option | Pros | Cons |
|---|---|---|
| **SQS standard queues, fed by the outbox** (chosen) | Managed, with throughput far beyond our load. Per-message delay, visibility timeouts, dead-letter redrive and redrive back are built in. Fair queues limit how long one tenant's backlog delays the others. IAM queue policies, KMS and a VPC endpoint. About 10 M requests a month at design load, a few dollars. Queue age and depth drive worker autoscaling. | At-least-once with occasional duplicates and no ordering, so every consumer must be idempotent and re-read state. Pending work lives in two places, the outbox and the queue, and the relay is one more process to run and alert on. Queues are regional: messages in Tokyo are lost with the region and come back only through the 24-hour re-publish, so consumers must tolerate replays up to a day old. Delays stop at 15 minutes. |
| **SQS FIFO queues** | Ordering per message group; duplicates removed within a 5-minute window. | The 5-minute window doesn't cover relay retries after an outage or failover re-publishes, so consumers must be idempotent anyway. No per-message delay, only per queue, which breaks deferred scans. A slow or failing message blocks its whole group, which defeats per-tenant fairness. Lower throughput limits. Workers re-read state, so they don't need ordering. |
| **EventBridge** | Content-based routing, archive and replay, many target types. Already the source of the GuardDuty and SES status events. | It pushes to targets and doesn't buffer for pull consumers, so workers would still need SQS queues as targets: one more hop, not a replacement. No per-message delay. Each message has exactly one consumer, so its fan-out isn't needed. |
| **A queue in PostgreSQL** (workers claim rows with `SKIP LOCKED`) | One system, no relay; work fails over with the database, so nothing is lost with a region's queues. Easy to inspect with SQL. | Polling and job-state updates load the writer and replicate to Osaka, the argument the abuse design makes against counters (4.3). A minutes-long scan can't hold a row lock under the 30-second transaction limit (data model 2.5), so leases, visibility, delays, retries and a dead-letter state are ours to build. A backlog under attack lands on the system of record. |

## Consequences

- **Alerts.** The oldest unpublished outbox row over 2 minutes; queue age per queue; any message in a dead-letter
  queue, with a runbook to inspect, fix and redrive. A queued sign-in event older than 30 seconds (authentication 2.4).
- **Failover.** Workers stay at zero in Osaka until security-critical changes are re-applied; then the re-publish runs
  and workers start (architecture section 7). `processed_messages` replicates with the database, so replays are cheap.
- **Message contract.** Topic, outbox ID, tenant ID, the IDs of the rows to act on and the trace context, nothing more.
  A canary test checks that no secret ever reaches a message (threat model section 6).
- **The threat model's T-50** names the relay and EventBridge as the only senders; it should also name the SES events
  topic and the sign-in triggers for their intake queues.

## When to revisit

If an event needs more than one consumer (put SNS or EventBridge in front of the queues), if ordering becomes a
requirement, if relay lag threatens NFR-5 at 2× design load, or if a failover drill shows the 24-hour re-publish window
is too short or too long.
