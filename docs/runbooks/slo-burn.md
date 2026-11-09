# Runbook: ErrorBudgetBurn

The burn-rate alerts of the service level objectives (NFR-1, NFR-2, NFR-5, NFR-23), defined in
[`deploy/alerts/slo.rules.yaml`](../../deploy/alerts/slo.rules.yaml). Severity: page for a fast burn, ticket for a
slow one. The `slo` label names the objective; [the SLO document](../operations/slos.md) explains each one, its
indicator and its budget.

## Symptoms

- **Page:** at this pace the 28-day budget is gone within 2 days (14.4 times the allowed rate over 1 hour and the
  last 5 minutes) or 5 days (6 times over 6 hours and the last 30 minutes).
- **Ticket:** at this pace it is gone before the 28 days are (3 times over a day and the last 2 hours, or once over
  3 days and the last 6 hours). While the page fires, Alertmanager holds the ticket back.

Each alert needs at least 10 events in its long window, so a quiet hour doesn't page on one slow file.

## Impact

| `slo` | What users feel | Objective |
|---|---|---|
| `availability` | API calls and downloads fail with 5xx | NFR-1: 99.9 % succeed |
| `latency-p95`, `latency-p99` | The web app is slow; byte-moving routes don't count | NFR-2: p95 ≤ 300 ms, p99 ≤ 1 s |
| `time-to-shareable-small` | Transfers up to 100 MB take over 2 minutes to reach recipients | NFR-5 |
| `time-to-shareable-large` | Larger transfers take over 15 minutes | NFR-5 |
| `scan-pass-small-p95`, `scan-pass-small-p99` | Small files wait over 60 s (3 minutes at p99) in `scanning` | NFR-23 |
| `scan-pass-large-p95` | Files up to 2 GB wait over 10 minutes in `scanning` | NFR-23 |

## Confirm

In Grafana (port-forward to the `grafana` namespace, ADR-0009), the SLO dashboard, or Explore:

```promql
slo:sli_error:ratio_rate1h{slo="<slo>"} / on(slo) slo:error_budget   # the burn rate over the last hour
slo:sli_error:ratio_rate5m{slo="<slo>"}                              # is it still burning now?
slo:error_budget_remaining:ratio_28d                                 # what is left of each budget
```

Then find where:

- **availability:** `sum by (route, status) (rate(http_requests_total{status=~"5.."}[5m]))`; then the API's
  `request` log lines with a 5xx `status` in Loki, for their `request_id` and `trace_id`, and the error spans in Tempo.
- **latency:** `histogram_quantile(0.95, sum by (route, le) (rate(http_request_duration_seconds_bucket[5m])))`, then
  the slow route's traces in Tempo.
- **time to shareable and scan pass:** the queue backlog alarms ([queue-backlog.md](queue-backlog.md)), the outbox
  ([outbox-backlog.md](outbox-backlog.md)), and the scan workers ([scan-failed.md](scan-failed.md),
  [dlp-inspector.md](dlp-inspector.md)).

## Mitigate

1. **A deploy in the last hour?** Roll back first: revert the version change in the deploy config, and Argo CD syncs
   the previous version (architecture 6, "Bad deploy"; NFR-18: within 10 minutes). Investigate afterwards.
2. **availability:** a dependency that fails readiness or every call (the database, Valkey, S3, KMS):
   [service-unavailable.md](service-unavailable.md), [rate-limit-store-unavailable.md](rate-limit-store-unavailable.md),
   [database-capacity.md](database-capacity.md), [kms-throttling.md](kms-throttling.md). A burst of `503` on the
   download grant route can be Osaka's archive ([audit-archive-writes.md](audit-archive-writes.md)).
3. **latency:** an expensive route under load: scale the API through `api.replicas` in the cluster's values file (a
   commit; never `kubectl scale`, which Argo CD reverts); check the database
   ([database-capacity.md](database-capacity.md)).
4. **time to shareable:** follow the file's path: outbox, `scan-small` or `scan-large` queue, scan worker, then the
   `notify` queue. The stage whose age grows is the one to fix. Time a transfer waits for its sender's confirmation or
   an approver isn't counted (NFR-5).
5. **scan pass:** clamd or the DLP inspector is slow, or the scan pool is short of nodes: scale `scanPools.<pool>` in
   the values file, or let Karpenter add scan nodes; check signature reloads ([scan-failed.md](scan-failed.md)).
6. **A drill** that takes prod down should have set its marker ([drill-in-progress.md](drill-in-progress.md)); if it
   didn't, the burn is still real budget spent, and is noted in the drill's report.

## Escalate

A page that doesn't stop burning within 30 minutes: escalate to the owner in
[CODEOWNERS](../../.github/CODEOWNERS).

## Afterwards

A blameless postmortem for every page: timeline, budget spent, root cause, action items. What an empty budget means
for releases is in [the SLO document](../operations/slos.md).
