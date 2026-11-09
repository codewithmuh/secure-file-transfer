# Runbook: EmailDeliveryFailing

The email alert of architecture 6 ("Email provider failing or throttling"; NFR-7, ADR-0015), defined in
[`deploy/alerts/pipeline.rules.yaml`](../../deploy/alerts/pipeline.rules.yaml). Severity: page.

## Symptoms

More than 5 % of the notification worker's messages fail for 10 minutes
(`worker_messages_total{consumer="notify", outcome="failed"}`). Recipients don't get their verification codes or link
emails; members don't get notices.

NFR-7's own measure, emails handed to SES within 10 s at p95, has no latency metric yet (docs/operations/slos.md lists
it as pending). Until it has, this failure rate and the `notify` queue's age alarm
([queue-backlog.md](queue-backlog.md)) stand in for it.

## Impact

A failed message is retried with backoff, and after 5 receives lands in `sft-<env>-<rs>-notify-dlq`
([dead-letter-queue.md](dead-letter-queue.md)). A recipient waiting for a code can't download; the web app offers to
send a new one (architecture 6). Sends are at least once, so a retry after a timeout can send an email twice.

## Confirm

```bash
kubectl -n sft get deploy notifier
kubectl -n sft logs deploy/notifier --since=30m | grep -E 'message failed|invalid message' | tail -50
```

The SES errors map to what the worker does (`sft.data.mail.ses`):

| Kind | SES errors | Meaning |
|---|---|---|
| Throttled | `TooManyRequestsException`, `LimitExceededException`, `Throttling` | Over the account's sending rate or quota |
| Paused | `SendingPausedException`, `AccountSuspendedException` | SES stopped our sending: reputation ([ses-reputation.md](ses-reputation.md)) |
| Rejected | `MessageRejected`, `BadRequestException` | Something about the one message |
| Misconfigured | `MailFromDomainNotVerifiedException`, `NotFoundException`, `AccessDenied*`, `ExpiredToken*`, signature errors | Every send fails until our setup is fixed |

With the environment's `ReadOnly` profile (pending the AWS run):

```bash
aws sesv2 get-account --region <region>      # SendingEnabled, EnforcementStatus, SendQuota
aws sesv2 get-configuration-set --configuration-set-name sft-<env> --region <region>
```

## Mitigate

1. **Misconfigured** after a deploy or a Terraform change: revert it. After a failover to Osaka, check that Osaka's
   identity, MAIL FROM domain and configuration set `sft-<env>` exist (the `identity` layer, `infra/modules/ses`).
2. **Throttled:** a burst (a load test, a large invitation backlog) passes; the retries catch up. If the quota is too
   small for the design load, request a higher one in the SES console (capacity 3).
3. **Paused:** follow [ses-reputation.md](ses-reputation.md). Nothing sends until AWS lifts the pause.
4. **Rejected, many:** look for the template or the address shape a recent change broke; fix forward or roll back.
5. **The worker can't reach SES:** the SES API goes through its VPC endpoint (architecture 3.1); check the endpoint and
   the notifier's network policy. Cognito invitations go through its proxy listener
   ([egress-proxy.md](egress-proxy.md)).
6. Once fixed, redrive the dead-letter queue ([dead-letter-queue.md](dead-letter-queue.md)).

## Escalate

If codes can't be sent for 30 minutes, escalate to the owner in [CODEOWNERS](../../.github/CODEOWNERS); with SES
paused, open an AWS support case as well.

## Afterwards

Write a blameless postmortem: timeline, emails delayed or lost, root cause, action items.
