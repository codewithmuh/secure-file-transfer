# Runbook: Watchdog and heartbeat-missing

The out-of-cluster watchdog of ADR-0009 (#246): the always-firing `Watchdog` alert, defined in
[`deploy/alerts/watchdog.rules.yaml`](../../deploy/alerts/watchdog.rules.yaml), and the CloudWatch alarm
`sft-<env>-<rs>-heartbeat-missing`, defined in
[`infra/modules/alarms/heartbeat.tf`](../../infra/modules/alarms/heartbeat.tf).
The `Watchdog` alert's severity is `heartbeat`: it fires all the time and never pages. The alarm's severity is page.

## How the heartbeat works

1. Prometheus fires `Watchdog` (`vector(1)`) on every evaluation.
2. Alertmanager routes it, every minute, to the Region's heartbeat topic `sft-<env>-<rs>-heartbeat`
   (`deploy/alerts/alertmanager.yaml`), signing as its Pod Identity role `sft-<env>-alertmanager`, through the egress
   proxy's `platform` listener (SNS has no VPC endpoint here, ADR-0021).
3. SNS counts each message in `AWS/SNS NumberOfMessagesPublished`. Nobody subscribes to the topic.
4. The alarm pages through `sft-<env>-<rs>-alerts-page` when 5 minutes in a row pass with none. Missing data counts
   as breaching, so a cluster that no longer exists pages the same way.

## Symptoms

The heartbeat-missing alarm pages. In-cluster alerts may not be reaching anyone, so check the other signals yourself.

## Impact

Whatever stopped the heartbeat may also stop every in-cluster page. The service itself may be fine.

## Confirm

From outside the cluster first, with the environment's `ReadOnly` profile (pending the AWS run):

```bash
aws cloudwatch get-metric-statistics --region <region> --namespace AWS/SNS --metric-name NumberOfMessagesPublished \
  --dimensions Name=TopicName,Value=sft-<env>-<rs>-heartbeat --statistics Sum --period 60 \
  --start-time "$(date -u -v-30M +%FT%TZ)" --end-time "$(date -u +%FT%TZ)"
aws cloudwatch describe-alarms --region <region> --state-value ALARM     # what else is alarming?
aws eks describe-cluster --region <region> --name <cluster> --query cluster.status
```

A publish that SNS refused (permissions, the key) isn't counted anywhere in SNS's metrics: Alertmanager's log shows it.
(`date -v` is macOS's; on Linux use `date -u -d '-30 min'`.) Then inside, through the tunnel:

```bash
kubectl -n monitoring get pods                                      # Prometheus and Alertmanager running?
kubectl -n monitoring logs statefulset/<alertmanager> --since=15m | grep -i -E 'sns|notify'   # AccessDenied? timeout?
kubectl -n egress-proxy get pods                                    # the proxy (egress-proxy.md)
```

In Grafana, `ALERTS{alertname="Watchdog"}` shows whether Prometheus still evaluates rules.

## Mitigate

The cause decides it:

1. **The cluster or its nodes are down:** [service-unavailable.md](service-unavailable.md), and for a Region,
   [region-health.md](region-health.md).
2. **The egress proxy is down:** [egress-proxy.md](egress-proxy.md). Its own alert can't leave the cluster meanwhile.
3. **Prometheus or Alertmanager is down** (out of memory, a full volume, a bad config): the observability stack is
   Argo CD's, from Git (ADR-0009); fix and revert there, as in [argocd-sync.md](argocd-sync.md).
4. **Alertmanager can't publish** (`AccessDenied`, `KMS.*` in its log): its role needs `sns:Publish` on the three
   topics, and the platform key must let it use the key through SNS; the topics' policies admit only that role
   (`infra/modules/alarms/topics.tf`). A missing permission on a fresh build pages from the start, by design.
5. **Osaka:** the alarm exists in Osaka but its actions are off during the pilot light, where no observability stack
   runs (root variable `heartbeat_enabled`, false there). The failover runbook,
   [regional-failover.md](regional-failover.md), applies Osaka's `alarms` stack with `TF_VAR_heartbeat_enabled=true`;
   the failback runbook turns it off again. An Osaka heartbeat page outside a failover means someone turned it on.
6. **A drill** that stops the cluster on purpose still pages here: the drill's runbook says to expect it.

## Escalate

If in-cluster alerting can't be restored within 30 minutes, escalate to the owner in
[CODEOWNERS](../../.github/CODEOWNERS), and watch the CloudWatch alarms and the synthetic probe by hand meanwhile.

## Afterwards

Write a blameless postmortem: how long the cluster's alerts were blind, what else fired meanwhile, root cause.
