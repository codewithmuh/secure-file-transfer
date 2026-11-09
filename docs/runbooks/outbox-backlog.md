# Runbook: OutboxBacklog

The outbox alert of architecture 6 ("Outbox relay stopped"; ADR-0013, architecture 5.3), defined in
[`deploy/alerts/pipeline.rules.yaml`](../../deploy/alerts/pipeline.rules.yaml). Severity: page. Its `condition` label
says which:

- `backlog`: the oldest unsent outbox row is over 2 minutes old for 5 minutes
  (`outbox_oldest_unpublished_age_seconds > 120`);
- `relay_missing`: no relay has reported that age for 10 minutes, so the first condition can't fire.

## Symptoms

Files stay `scanning`, link emails and verification codes don't go out, and nothing new reaches the SQS work queues.
The queues' own age alarms stay quiet, because nothing is being added to them.

## Impact

Nothing is lost: the rows wait in PostgreSQL and the relay sends them when it runs again (architecture 6). Every tenant
waits, though: NFR-5 (time to shareable) and NFR-7 (emails within 10 s) are missed for as long as it lasts.

## Confirm

```bash
kubectl -n sft get deploy relay                       # 2 replicas ready? (the values file's relay.replicas)
kubectl -n sft logs deploy/relay --since=30m | tail -100
```

What the relay logs (`sft.workers.relay`), never message bodies:

- `SQS refused outbox rows; they are tried again later`, with the queue and the error codes: SQS or the relay's IAM
  role or the platform key is refusing (`AccessDenied`, `KMS.*`).
- `SQS didn't answer within the send budget`: SQS, or the VPC endpoint to it, is slow.
- `outbox row that breaks the message contract left unpublished` or `with an unknown topic`: a bad row from a deploy;
  it is skipped, and the others still go, so it alone doesn't hold the age up for long.
- `outbox age not measured`: the relay can't read the database; the gauge goes stale.

In Grafana: `outbox_publish_failures_total` by `queue`, `outbox_messages_published_total`, and
`outbox_relay_batch_duration_seconds`.

## Mitigate

1. **Relay down or crash-looping** (`relay_missing`): [service-unavailable.md](service-unavailable.md). A recent deploy
   is rolled back first (revert the version change; NFR-18).
2. **The database is slow or unreachable**: the relay claims rows `FOR UPDATE SKIP LOCKED` in short transactions; see
   [database-capacity.md](database-capacity.md).
3. **SQS refuses**: `AccessDenied` or a KMS error means the relay's role (`sft-<env>-relay`), the queue policy or the
   platform key policy changed; compare with `infra/modules/queues` and `infra/modules/kms-keys`, and revert the change
   through Terraform. Throttling clears on its own; the rows back off from 2 s up to 5 minutes.
4. **Too much work for two replicas** (a load test, a burst): raise `relay.replicas` in the cluster's values file; the
   replicas never take each other's rows.
5. **Not scraped, but running** (`relay_missing` with healthy pods and moving queues): the observability stack's scrape
   of the `relay` pods' `/metrics` on port 8001 broke; fix the scrape config in Git.

## Escalate

If rows aren't moving within 30 minutes, escalate to the owner in [CODEOWNERS](../../.github/CODEOWNERS).

## Afterwards

Write a blameless postmortem: timeline, how long NFR-5 and NFR-7 were missed, root cause, action items.
