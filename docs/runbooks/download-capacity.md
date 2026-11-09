# Runbook: DownloadCapacity

The download stream alert of abuse and rate limits 8.2 (abuse 5.7, ADR-0018), defined in
[`deploy/alerts/abuse.rules.yaml`](../../deploy/alerts/abuse.rules.yaml). Severity: ticket. Its `condition` label
says which:

- `streams`: active download streams above 70 % of what the API pods serve for 10 minutes. Each pod serves
  `DOWNLOAD_STREAMS_PER_POD` streams (100, the setting's default) and answers the next with `503`;
- `refused`: a request to a content route answered `503` in the last 10 minutes, because its pod's stream slots were
  full.

## Symptoms

Downloads start slowly or fail with `503` and `Retry-After: 10`; the browser retries. `download_streams_active` per pod
is near 100.

## Impact

Downloads stream through the API pods (ADR-0018), so a full pod refuses new streams while existing ones continue. A
refused download isn't counted: the grant stays, and the retry resumes under it (abuse 5.4). Many slow clients (a 5 GB
file takes over an hour at 10 Mbit/s) or a burst of large downloads fill the slots; so can someone holding many slow
streams open on purpose (AB-10, AB-11).

## Confirm

In Grafana:

```promql
sum(download_streams_active)                     # streams now, against 100 per pod
count(download_streams_active)                   # API pods
sum by (reason) (rate(download_streams_ended_total[15m]))
sum(rate(download_bytes_total[5m]))              # bytes a second
sum by (status) (increase(http_requests_total{route=~".*/content"}[15m]))
```

`download_streams_ended_total{reason="slow"}` rising means the 2 KB/s floor is closing streams that hold slots without
moving bytes. The API's `request` log lines carry `tenant_id`, which shows whether one tenant's downloads dominate.

## Mitigate

1. **Real demand:** add API pods. Raise `api.replicas` in the cluster's values file
   (`deploy/environments/<env>/<region>/values.yaml`) in a pull request; Argo CD rolls it out. Never `kubectl scale`:
   Argo CD's self-heal puts the count back, and operators may not scale workloads (authn-authz 8.1). Karpenter adds
   main-pool nodes as needed. Abuse 5.7 designs autoscaling on active streams (50 per pod); the chart doesn't have it
   yet, so this is by hand.
2. **Slow streams held on purpose:** find the sources in the load balancer's access logs (long requests to
   `/content` routes by client IP) and block them in the WAF block list ([link-enumeration.md](link-enumeration.md)). The
   per-recipient daily bytes (25 GB) and the grant's own caps still bound what they can take.
3. **A deploy that cut streams** (`reason="shutdown"`): they resume on their own; nothing to do.
4. If 100 streams per pod is the wrong size for the pods' memory, change `DOWNLOAD_STREAMS_PER_POD` and the alert's
   100 together (abuse.rules.yaml says so).

## Escalate

If `503` answers continue after scaling out, escalate to the owner in [CODEOWNERS](../../.github/CODEOWNERS).

## Afterwards

Update the capacity estimate (capacity 4.1, abuse 5.7) with the streams and bytes seen.
