# Runbook: region health (`sft-<env>-apne1-region-health`, `sft-<env>-apne3-region-health`)

CloudWatch alarms on each Region's Route 53 health check, in us-east-1 where Route 53 publishes them (architecture 6,
NFR-21), defined in [`infra/modules/alarms/region-health.tf`](../../infra/modules/alarms/region-health.tf) and made by
Tokyo's `alarms` stack. Severity: page for Tokyo, ticket for Osaka.

## Symptoms

The Region's health check has failed for 3 minutes. It requests `/edge-health` over HTTPS on the Region's own API name,
which the load balancer answers itself with `sft-edge-ok`, so it fails only when the load balancer, its certificate, its
DNS record or the Region's network can't answer, never because of the application. That is why Osaka's passes during
the pilot light.

## Impact

- **Tokyo**: possibly the whole service. Nothing moves traffic on its own: failover is always an operator's decision
  (architecture 7, T-78).
- **Osaka**: the service is fine, but the standby Region can't take a failover until it recovers (NFR-11).

## Confirm

1. Is it the Region or the check? Look at the [AWS Health Dashboard](https://health.aws.amazon.com/health/status) and
   your account's AWS Health events for the Region.
2. The other signals: do the API's burn-rate alerts, the synthetic probe and the load balancer alarms agree? A failing
   check with a healthy probe points at the check, its DNS record or its certificate.
3. From outside AWS:

   ```bash
   curl -sS https://<region's API name>/edge-health      # expect sft-edge-ok
   ```

## Mitigate

- **Tokyo, and AWS confirms a regional event**: this is the "confirm the regional failure and decide to fail over"
  step of the disaster-recovery outline (architecture 7, 10 minutes). Decide, then follow
  [regional-failover.md](regional-failover.md).
- **Tokyo, and only our edge is failing** (an expired certificate, a changed record, a deleted listener): fix the
  `edge` stack with an apply; no failover.
- **Osaka**: re-apply Osaka's `edge` stack if it drifted; if AWS reports an Osaka event, note that a failover isn't
  possible until it ends and watch Tokyo closely.

## Escalate

Tokyo: page the owner in [CODEOWNERS](../../.github/CODEOWNERS) at once; the failover decision has a 10-minute budget.
Osaka: within the working day.

## Afterwards

For Tokyo, the failover's drill report or a postmortem; for Osaka, a note in the operating log.
