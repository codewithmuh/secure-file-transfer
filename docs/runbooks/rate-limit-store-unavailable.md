# Runbook: RateLimitStoreUnavailable

The counter store alert of abuse and rate limits 4.5 and 8.2 (NFR-14, ADR-0014; architecture 6, "Rate-limit counters
unavailable"), defined in [`deploy/alerts/abuse.rules.yaml`](../../deploy/alerts/abuse.rules.yaml). Severity: page.
Abuse 8.2 calls this runbook `rate-limit-store-unavailable`; this file is it. Its `condition` label says which:

- `errors`: more than 1 % of calls to the store fail for 2 minutes
  (`rate_limit_store_errors_total` against `rate_limit_store_latency_seconds_count`);
- `fallback`: a pod has been on its per-pod fallback limiter for 2 minutes (`rate_limit_fallback_active == 1`).

## Symptoms

Link steps and member sign-in answer `503`; the pods' logs show errors from Valkey.

## Impact

What each group does without the store (abuse 4.5):

| Group | Behaviour |
|---|---|
| A, link steps | `503 service_unavailable`, `Retry-After: 5`: recipients and uploaders can't verify |
| B, sign-in | `503` from the sign-in routes, and the pre-authentication trigger denies sign-in |
| C to J | A per-pod limiter at each limit divided by 3, the minimum pod count |
| D and E, download counts and grants | Unchanged: they are in PostgreSQL |

Existing sessions keep working. Scan leases and the notification worker's per-address caps use the store too, so scans
and emails may slow.

## Confirm

In Grafana: `rate(rate_limit_store_errors_total[5m])` by pod, `rate_limit_store_latency_seconds` p99, and
`rate_limit_fallback_active`. Then:

```bash
kubectl -n sft logs deploy/api --since=15m | grep -i valkey | tail -30
```

With the environment's `ReadOnly` profile (pending the AWS run): the cache `sft-<env>-<rs>-valkey`
(`infra/modules/valkey`) in the ElastiCache console or
`aws elasticache describe-serverless-caches --serverless-cache-name sft-<env>-<rs>-valkey`, and its CloudWatch metrics:
`ThrottledCmds`, `ElastiCacheProcessingUnits` against the 30,000 ECPU ceiling, `BytesUsedForCache` against 1 GB, and
`CurrConnections`.

## Mitigate

1. **Throttled at the ECPU ceiling** (an attack, or a load test): the ceiling is deliberate, to cap what an attack
   costs (valkey module README). Find the source in the WAF logs and the rejections
   (`rate_limit_rejections_total` by `group`), add it to the WAF block list `sft-<env>-<rs>-block-list` (abuse 8.3),
   and turn on `attack-mode-links` in the edge root if it is on the link steps. Raise the ceiling only by a reviewed
   Terraform change.
2. **Authentication fails** (`WRONGPASS`, `NOAUTH`): each pod signs an IAM token for its Valkey user
   (`VALKEY_IAM_CACHE`, encryption 6.3). Check the workload role and the Valkey user of the same name, and recent
   changes to `infra/modules/valkey` or the cluster layer's roles; revert a bad one.
3. **Unreachable**: the security group admits 6379 from the main and scan node groups only. A change to the node
   groups or the network policies (`deploy/charts/sft/templates/networkpolicies.yaml`) can cut it off; revert.
4. **ElastiCache itself is impaired** in the Region: check the AWS Health Dashboard. The service degrades as the
   table says until it returns; a Region-wide outage is the failover decision ([region-health.md](region-health.md)).
5. Nothing to clean up afterwards: counters have a TTL of at most 25 hours, and windows simply restart.

## Escalate

If verification and sign-in stay down for 30 minutes, escalate to the owner in
[CODEOWNERS](../../.github/CODEOWNERS), and open an AWS support case if ElastiCache is at fault.

## Afterwards

Write a blameless postmortem: how long link steps and sign-in were refused, root cause, action items.
