# Runbook: Availability Zone failure

Losing one of Tokyo's three AZs (NFR-10: RPO 0; NFR-11: automatic recovery within 5 minutes; architecture 6). It is
both what to do when AWS reports an AZ impairment and the drill that proves the service rides it out. Nothing in the
recovery is manual; the operator watches it and decides only whether to wait or, if it doesn't recover, escalate.

> [!IMPORTANT]
> **Pending the AWS run.** The drill has not run yet; the first staging drill measures the RTO and corrects this page.

## What happens on its own

- **Database.** Aurora's storage keeps six copies across three AZs. If the writer was in the lost AZ, Aurora promotes
  the reader in another AZ, typically within a minute; the cluster endpoint follows, and the pools replace dead
  connections (`pool_pre_ping`).
- **Pods.** The API (three replicas or more, spread across AZs) keeps serving from the other two AZs; the load
  balancer stops sending to targets in the lost AZ. Karpenter replaces the lost nodes in the other AZs and the
  scheduler moves the pods. Cut downloads resume under the same grant; uploads resume from their parts.
- **Files.** S3 keeps every object in at least three AZs.
- **Not affected:** the generation of the audit archive (an AZ failover loses nothing, data model 2.5).

## In a real impairment

1. Confirm it: the AWS Health Dashboard's event for ap-northeast-1 and the zone ID, the API's 5xx and latency on the
   SLO dashboard, nodes `NotReady` in one zone (`kubectl get nodes -L topology.k8s.aws/zone-id`).
2. Watch the recovery: the writer's AZ (`aws rds describe-db-clusters --db-cluster-identifier sft-prod-apne1-aurora`),
   the API's ready pods, the probe.
3. If the service isn't back within 5 minutes: check that Karpenter is launching in the other zones (its logs, the
   node pools' limits) and that the API's pods aren't pinned to the lost zone. If the zone stays lost for hours, its
   NAT gateway is gone too; the other zones have their own (ADR-0021).
4. When the zone returns, nothing is moved back by hand: Karpenter and the scheduler spread new pods again.

## The drill

```bash
ops/az-failure.sh --env staging --profile sft-staging-admin --az apne1-az1                      # dry run
ops/az-failure.sh --env staging --profile sft-staging-admin --account-id <account> --execute --az apne1-az1 \
  --fis-template <template id>
```

| # | Step | Budget |
|---|---|---|
| 1 | Baseline: the probe passes; note the writer's AZ | 5 min |
| 2 | Lose the zone: its subnets (AWS FIS) or its nodes, and fail the writer over | 1 min |
| 3 | Automatic recovery: writer, pods, probe | 5 min (NFR-11) |
| 4 | No data lost | 5 min |
| 5 | End the drill | 10 min |

- **The failure.** With `--fis-template`, an AWS FIS experiment that disrupts the zone's subnets' connectivity for
  10 minutes (`aws:network:disrupt-connectivity` on the subnets tagged with the zone, run with an FIS role allowed to
  change those subnets' network ACLs only); make it in the console for the drill, or in Terraform once it is kept.
  Without it, the script cordons and drains the zone's nodes, which loses the pods but not the network. Either way it
  fails the writer over with `aws rds failover-db-cluster`, as Aurora does when the writer's zone goes.
- **The RTO** is the time from the injection to the probe passing and the API's 5xx back to its baseline, read on the
  SLO dashboard (port-forward to Grafana).
- **The RPO** is 0: every transfer the probe and the drill writer made before the injection is there, with its files.
  Anything missing fails the drill.

Write the results in the log ([template](../operations/drill-log-template.md)).
