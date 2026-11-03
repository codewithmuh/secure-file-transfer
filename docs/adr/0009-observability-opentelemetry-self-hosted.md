# 0009. Use OpenTelemetry with self-hosted Prometheus, Grafana, Loki and Tempo for observability

- Status: accepted
- Date: 2026-11-03
- Issue: [#31](https://github.com/codewithmuh/secure-file-transfer/issues/31)

## Context

- **What is required.** Every user journey is traced end to end, with structured logs and metrics; every alert links
  to a runbook; dashboards and alerts are code (NFR-17). Availability is 99.9 % over a rolling 28 days (NFR-1), and
  the SLO signals (scan latency, time to shareable, queue and outbox age, replication lag) are metrics with alerts
  ([architecture](../architecture.md) 5.5).
- **Already designed.** OpenTelemetry for traces, Prometheus-format metrics on `/metrics`, JSON logs with `request_id`,
  `trace_id` and `tenant_id`, and the trace context carried through the outbox and SQS (architecture 5.3, 5.5, 8).
- **Telemetry holds data.** Logs are customer data under NFR-21 and stay in Japan. Secrets and personal data must never
  reach logs, spans or messages, and a canary test proves it ([threat model](../threat-model.md) T-49, T-88).
- **Each environment stands alone.** Nothing is shared between environments, so each tears down by itself; dev and
  staging run a cut-down platform ([capacity](../design/capacity-and-cost.md) 4.3).
- **Numbers.** In prod, Prometheus (2 replicas), Alertmanager, Grafana, Loki, Tempo and the gateway collectors request
  4.3 vCPU and 12.8 GiB (capacity 4.3), about $230 a month of main-pool nodes, plus 300 GB of volumes at $29 (A28).
  Loki chunks and Tempo traces in S3 add a few dollars (A33). CloudWatch prices a custom metric at $0.30 a month and log
  ingestion at $0.76/GB in Tokyo (capacity 5.1).

## Decision

Instrument the API and workers with the **OpenTelemetry** SDKs and send telemetry through OpenTelemetry collectors in
each cluster: an agent on every node and a gateway. Keep metrics in **Prometheus** with **Alertmanager**, logs in
**Loki** and traces in **Tempo**, both stored in S3 in the cluster's region under the logs key, and dashboards in
**Grafana**. Argo CD installs the same stack from Git in every cluster, cut down in dev and staging. CloudWatch keeps
only the AWS-service alarms (A34), EKS control-plane logs (A19) and an out-of-cluster watchdog.

## Options considered

| Option | Pros | Cons |
|---|---|---|
| **Self-hosted Prometheus, Grafana, Loki and Tempo** (chosen) | Runs in the cluster's region and goes with it at teardown: nothing outside Japan, nothing left behind. The same stack in every environment, and in Osaka after a failover. PromQL rules and Grafana dashboards are files in Git, so "as code" and the runbook check are plain file checks. No charge per series, sample or GB; the cost is node capacity. | Six components to run, size and upgrade, the collectors included. It shares the cluster's fate: when the cluster is down, its alerts stop, so an outside watchdog is needed. Two Prometheus replicas with no global view or long-term store. During a failover, Tokyo's history isn't readable from Osaka. |
| **Amazon Managed Service for Prometheus and Amazon Managed Grafana** | No metrics store or Grafana to run; it survives a cluster outage; Grafana sign-in through IAM Identity Center, with no path into the cluster. | Priced per sample ingested, stored and queried, which the capacity model doesn't price yet. Both must be available in Osaka for the pilot light, which is unconfirmed. Logs and traces still need Loki and Tempo or CloudWatch. Workspaces are separate resources for each environment's teardown to remove. |
| **CloudWatch only** (Container Insights, CloudWatch Logs, X-Ray) | Nothing to run; in-region; survives a cluster outage; one console with the AWS-service alarms. | At $0.30 per metric a month, latency histograms by route and status run to thousands of series, at $300 a month for every thousand. Logs cost $0.76/GB to ingest. Burn-rate SLO alerts and dashboards as code are harder to write and test. Prometheus-format metrics don't map one-to-one. |

## Consequences

- **Telemetry contract.** One JSON log line per event, with `request_id`, `trace_id` and `tenant_id`. Never file
  names, message text, email addresses (an HMAC where one is needed), tokens, codes, cookies, `Authorization` headers
  or query strings (architecture 5.5, T-49, T-88). Span attributes come from an allowlist. The canary test fails a pull
  request that leaks one. Client IP addresses stay in the audit log and the edge logs.
- **Traces.** W3C trace context runs from the web app's API calls through the API, the outbox and SQS to the workers.
  The gateway's tail sampling keeps every error and slow trace and 10 % of the rest, for 14 days (A33).
- **Metrics.** Prometheus scrapes `/metrics` on a port outside the load balancer's target group (architecture 8).
  Recording rules compute the SLIs. Prod keeps **30 days**, not A28's 15, so NFR-1's 28-day window is computed from
  local data; its volumes grow from 2 × 100 GB to 2 × 200 GB, about $19 a month more. High-cardinality metrics carry no
  tenant label; per-tenant views come from logs.
- **Logs.** Loki keeps 90 days (PRD data lifecycle table). EKS control-plane and audit logs stay in CloudWatch Logs,
  where the exec and break-glass alerts read them ([authn-authz](../security/authn-authz.md) 8.3).
- **Alerts.** Prometheus rules live in Git, each with a `runbook_url`; a CI test fails an alert without a runbook
  (NFR-17). Alertmanager pages through SNS in its own region. The in-cluster stack publishes a heartbeat metric to
  CloudWatch every minute, and a CloudWatch alarm that treats missing data as breaching pages if it stops, so a dead
  cluster still pages. AWS-service alarms and the synthetic probe also run outside the cluster.
- **Dashboards.** Grafana is provisioned from Git and is read-only in its UI. It runs alone in its own namespace, on no
  load balancer (T-05), and `ReadOnly` and `Operator` reach it by port-forward to that namespace. authn-authz 8.1 and
  T-63 allow port-forward only in `sft-operator`, so they gain this one namespace, which holds no role that can read
  files.
- **Osaka.** Its stack starts with the cluster after a failover, with empty history; Tokyo's data stays in Tokyo's
  buckets until the failback.
- **Capacity model.** The 30-day retention adds about $19 a month in prod; dev and staging keep the 3 and 7 days of
  capacity 4.3.

When to revisit: if running the stack takes more of the maintainer's time than the slices it supports; if managed
Prometheus and Grafana are confirmed in Osaka and price below the self-hosted line; or if the operating period needs
metrics older than 30 days, which would add a long-term store.
