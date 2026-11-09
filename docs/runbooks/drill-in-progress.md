# Runbook: DrillInProgress

The drill marker alert (NFR-1, NFR-11), defined in
[`deploy/alerts/watchdog.rules.yaml`](../../deploy/alerts/watchdog.rules.yaml). Severity: ticket. The `drill` label
names the drill.

## Symptoms

`sft_drill_active{drill}` is 1: a drill has announced itself, and this alert fires for as long as it runs.

## What the marker does

- **Inhibits the alerts the drill sets off on purpose.** While `DrillInProgress` fires, Alertmanager holds back every
  page and ticket except those labelled `security: "true"` (break-glass, field-key isolation, operator records) and
  this alert itself (`deploy/alerts/alertmanager.yaml`). A drill is no cover for an insider.
- **Keeps the window out of the SLOs.** NFR-1's 28-day figure leaves out the minutes the marker was on
  (`slo:sli_error:ratio_28d`, [the SLO document](../operations/slos.md)); drill windows are logged and reported
  separately, as NFR-1 asks.
- **Doesn't silence the CloudWatch side.** The heartbeat keeps flowing while the cluster runs; a drill that stops the
  cluster still pages from `heartbeat-missing` ([watchdog.md](watchdog.md)), and the AWS-service alarms still notify.
  The drill's runbook says which of those to expect.

## Impact

A ticket, by design: a marker left on after a drill would hide real alerts, so its alert keeps reminding.

## Confirm

Is a drill actually running? Check the operating period's log ([operating-period.md](operating-period.md)) and the
drill runbooks ([regional-failover.md](regional-failover.md), [regional-failback.md](regional-failback.md),
[az-failure.md](az-failure.md), [point-in-time-restore.md](point-in-time-restore.md); the DR track writes them). In
Grafana: `sft_drill_active` and `ALERTS{alertstate="firing"}` for what is being held back.

## Setting and clearing the marker

The drill scripts in `ops/` push the marker to each region's Pushgateway when a drill starts and delete it when it
ends, with the drill's name as a grouping key (`drill_marker` in `ops/lib/common.sh`; a regional failover or a restore
only with `--mode drill` or `--drill`, never a real one). By hand, through a port-forward to the Pushgateway (pending
the AWS run):

```bash
kubectl -n monitoring port-forward svc/pushgateway 9091:9091 &
# start
echo 'sft_drill_active 1' | curl --fail --data-binary @- http://localhost:9091/metrics/job/drill/drill/<name>
# end
curl --fail -X DELETE http://localhost:9091/metrics/job/drill/drill/<name>
```

Who may run this is an open point: authn-authz 8.1 gives `ReadOnly` and `Operator` port-forwards only to Grafana and
the operator API, so the drill runbooks name the access they use.

## Mitigate

1. **A drill is running:** nothing to do; the alert clears when the drill deletes its marker.
2. **The drill has ended and the marker is still on:** delete it as above. Then look at what was inhibited
   meanwhile (`ALERTS`), because those alerts reach people only now.
3. **Nobody started a drill:** something pushed the marker. Delete it, and find out what: only something inside
   the cluster should be able to reach the Pushgateway (the observability stack's network policy).

## Escalate

A marker nobody can explain: escalate to the owner in [CODEOWNERS](../../.github/CODEOWNERS), as a possible attempt to
hide alerts.

## Afterwards

Record the drill's start and end, as the marker shows them, in the drill's report and the operating period's log.
