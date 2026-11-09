# Runbook: regional failover, Tokyo to Osaka

Losing the Tokyo region (NFR-10, NFR-11: service back in Osaka within an hour). It follows architecture 7 step by
step; each step's budget is the architecture's, and `ops/regional-failover.sh` runs, times and logs them. It is a
procedure, started by a person: no alert or health check moves traffic on its own (T-78). The decisions behind it are
in [disaster-recovery.md](../operations/disaster-recovery.md).

> [!IMPORTANT]
> **Pending the AWS run.** Nothing in AWS has been applied yet. This page is written from the Terraform, the chart
> and the design; the first staging drill measures each step and corrects it. Steps that wait for code still to land
> say so (disaster-recovery.md section 8).

## Before you start

- **Who:** the maintainer, with the `Admin` permission set for the environment's account (assigned for the hour by a
  `BreakGlassApprover`; it alerts), a named CLI profile for it, and kube contexts for both clusters through the
  Systems Manager tunnel (`SFT_KUBE_CONTEXT_TOKYO`, `SFT_KUBE_CONTEXT_OSAKA`, or the defaults
  `sft-<env>-apne1`/`-apne3`). Tools: aws CLI v2, kubectl, yq, terraform 1.17, and the apply inputs of the checklist
  of #247.
- **Rehearse first.** A dry run prints every command and operator step and changes nothing:

  ```bash
  ops/regional-failover.sh --env prod --profile sft-prod-admin --mode real
  ```

- **Run it:**

  ```bash
  ops/regional-failover.sh --env prod --profile sft-prod-admin --account-id <prod account> --execute \
    --mode real --failed-at 2026-12-01T03:00:00Z
  ```

  In a drill, `--mode drill` and no `--failed-at`: the failure is declared when the script starts.

The log goes to `docs/operations/drills/<date>-regional-failover-<env>.md`; fill in the rest from
[the template](../operations/drill-log-template.md).

## Steps

| # | Step | Budget |
|---|---|---|
| 1 | Confirm the failure and decide | 10 min |
| 2 | Fence Tokyo through Git; take Osaka out of pilot light | 2 min |
| 3 | Promote Osaka's database | 5 min |
| 4 | Scale Osaka | 20 min |
| 5 | New archive generation; re-import and re-apply | 5 min |
| 6 | Sign-in: enrol members without SSO in the standby pool | alongside 7 and 8 |
| 7 | Re-publish the outbox; scale the workers up | 5 min |
| 8 | Switch DNS and the CDN origin | 5 min |
| 9 | Verify | 5 min |
| | **Total** | **57 min** |

### 1. Confirm the failure and decide (10 min)

Confirm that Tokyo is lost, not one service in it: Route 53's health checks on Tokyo's load balancer failing, the AWS
Health Dashboard for ap-northeast-1, the watchdog's alarms, and whether the API answers at all. A Tokyo-only outage of
one service (Cognito, S3) has its own row in architecture 6 and is not a reason to fail over. Then decide: a failover
loses up to NFR-10's RPO and asks members without SSO to re-enrol, so it is for a regional loss that won't end soon.

In a drill: announce the window (it is reported apart from NFR-1), and run the synthetic probe every minute as the
drill writer, so there is a recent write to lose. The script marks the drill in Tokyo's Pushgateway
(`sft_drill_active`, [drill-in-progress.md](drill-in-progress.md)), and in Osaka's after step 4, so the alerts it sets
off on purpose are held back, security alerts never; a real failover pages as it should.

### 2. Fence Tokyo; take Osaka out of pilot light (2 min)

One commit, made by the script and committed by the maintainer:

```bash
ops/failover-values.sh fence --env prod --write
git commit -m "ops: fence Tokyo and take prod Osaka out of pilot light" deploy/environments/prod
```

Tokyo's file gets `pilotLight: true`: whenever Tokyo's cluster answers again, Argo CD scales it to zero, so it never
writes to a database that is no longer the primary. Osaka's gets `pilotLight: false` with `failover.holdWorkers:
true`: the API and the migration job may run, every worker stays at zero and every CronJob suspended. Nothing here
needs Tokyo to answer.

### 3. Promote Osaka's database (5 min)

```bash
aws rds failover-global-cluster --region ap-northeast-3 --global-cluster-identifier sft-prod-aurora \
  --target-db-cluster-identifier arn:aws:rds:ap-northeast-3:<account>:cluster:sft-prod-apne3-aurora --allow-data-loss
```

Managed failover with data loss allowed: Aurora fences Tokyo's writer if it can reach it, and snapshots Tokyo's
volume when it comes back (ADR-0011). If it is refused because Tokyo can't be reached at all, detach and promote:
`aws rds remove-from-global-cluster` with Osaka's cluster. Wait until Osaka's cluster is the writer, or standalone.

Read the RPO: the largest `AuroraGlobalDBRPOLag` in the minutes before (the database) and Tokyo's
`ReplicationLatency` on the `to-osaka` rule of both files buckets (the files); the script fetches both. In a real
failover Tokyo's metrics may not answer; then step 5's log gives the newest event Osaka has.

Check `BackupRetentionPeriod` is 14 on the promoted cluster (#42 gap 2a).

### 4. Scale Osaka (20 min)

- The `system` node group from one node to two (the script runs `aws eks update-nodegroup-config`); Karpenter adds
  the main and scan nodes as Argo CD deploys what Git now holds.
- GuardDuty Malware Protection for Osaka's large-files bucket: apply `infra/environments/prod/ap-northeast-3/data`
  with `TF_VAR_malware_protection_enabled=true` (ADR-0019). GuardDuty validates its access to the bucket then.
- The Osaka alarms, quiet in the pilot light: apply `infra/environments/<env>/ap-northeast-3/alarms` with
  `TF_VAR_heartbeat_enabled=true TF_VAR_pilot_light=false` (and `TF_VAR_probe_enabled=true` where the probe runs), so
  the heartbeat, the API's targets and the probe page from Osaka. The root's `database.role` (`secondary`) becomes
  `primary` in the same change, so the writer's CPU and memory alarms watch Osaka ([alarms](../../infra/modules/alarms/README.md)).
- **Osaka's observability stack starts with the fencing commit** (its Applications follow `pilotLight`) **with empty
  history**: Prometheus, Loki and Tempo hold nothing from before the failover, so the SLO dashboard's 28-day figures and
  the burn-rate alerts' long windows start from zero, and the failure's own evidence stays in Tokyo's volumes and
  buckets. Read the drill's or the incident's numbers from CloudWatch and the drill log, not Osaka's Grafana.
- Put the node count into Git as well, so the next apply doesn't undo it (pending the Terraform input,
  disaster-recovery.md section 8).

Wait for the API's and the operator API's rollouts. The migration job runs first as Argo CD's PreSync hook; Osaka's
image is the same digest as Tokyo's, so it only checks the schema.

### 5. New archive generation; re-import and re-apply (5 min)

The recovery job, in Osaka (disaster-recovery.md section 4), with the window an hour back from the failure:

```bash
kubectl -n sft create job --from=cronjob/recovery recovery-1 --dry-run=client -o yaml \
  | yq '(.spec.template.spec.containers[0].env[] | select(.name == "RECOVERY_STEPS")).value = "generation,partitions,replay"
        | (.spec.template.spec.containers[0].env[] | select(.name == "RECOVERY_SINCE")).value = "<failure - 1h>"
        | (.spec.template.spec.containers[0].env[] | select(.name == "RECOVERY_REWIND_TO")).value = "<failure - 1h>"' \
  | kubectl apply -f -
```

- **Generation.** One more than the highest in Osaka's archive, with the cursor rewound an hour, or further if step
  3's `ReplicationLatency` on the archive was longer (#42 gap 1).
- **Replay.** Every security-critical record of that hour that the promoted database lacks is re-applied before any
  worker starts, so no worker acts on a revocation the replica hadn't received.

Copy the job's counts into the log. Tell tenant admins, by ticket, of every lockout it re-applied and every unlock it
left out: their members unlock again, which sends the recipient a new link.

Pending: the `recovery` CronJob and its entry point (disaster-recovery.md section 8).

**The audit archive while Tokyo is lost.** The archive job, Osaka's now, writes each batch to both regions and moves
its cursor only once both hold it (#183, data model 2.5). With Tokyo's S3 gone, every run fails on Tokyo, the cursor
stays, and `AuditArchiveLagging` and `AuditArchiveJobNotRunning` page: expected, and nothing is lost, since the events
wait in the database and are archived once Tokyo's bucket answers. The API's security-critical records go to both
regions the same way (architecture 5.2), so while Tokyo's archive can't be written, new download grants answer `503`
and the other security-critical changes answer "done, not confirmed". An Osaka-only archive mode for a regional loss,
which writes the surviving region alone and back-fills Tokyo later, is a follow-up issue; until it exists, a failover
for a lasting Tokyo loss serves uploads, sending and existing streams, but not new downloads. Record it in the report.

### 6. Sign-in: the standby pool (alongside 7 and 8)

SSO members sign in through Osaka's standby pool as usual. Members without SSO re-enrol ([AUTH] 2.6): start the
standby enrolment job, after step 5 so it never enrols a member the replay deactivated:

```bash
kubectl -n sft create job --from=cronjob/standby-enrolment standby-enrolment-1
```

It creates each active member without SSO in the standby pool and records the identity; the invitations are outbox
messages that the notifier sends once the workers start (#42 gap 6). Tenant admins are told. Sign in once through the
standby pool with the synthetic tenant's SSO test member.

Pending: the `standby-enrolment` job (disaster-recovery.md section 8).

### 7. Re-publish the outbox; scale the workers up (5 min)

The recovery job's `outbox` step with `RECOVERY_SINCE` 24 hours before the failure: every message sent since then goes
back to the relay, and consumers skip what they already did (architecture 5.3). That recovers the work that sat in
Tokyo's queues, small files' scans among it (#42 gap 8). Then release the workers:

```bash
ops/failover-values.sh release-workers --env prod --write
git commit -m "ops: start prod Osaka's workers after the failover" deploy/environments/prod
```

Wait for the relay, notifier and scan workers. The lifecycle CronJobs resume too.

### 8. Switch DNS and the CDN origin (5 min)

- **The API's name.** In a drill, and whenever Tokyo's state bucket answers: apply
  `infra/environments/prod/ap-northeast-1/edge` with `TF_VAR_api_alias_target` set to Osaka's load balancer
  (`terraform -chdir=infra/environments/prod/ap-northeast-3/edge output -json load_balancer`).
- **If Tokyo's state can't be read** (#42 gap 9): point the record by hand in the shared zone, as `Admin` in the
  shared account or through `sft-shared-dns-prod-deploy`, and note it in the log:

  ```bash
  aws elbv2 describe-load-balancers --region ap-northeast-3 --names sft-prod-apne3-api \
    --query 'LoadBalancers[0].[DNSName,CanonicalHostedZoneId]'
  aws route53 change-resource-record-sets --hosted-zone-id <shared zone> --change-batch '{"Changes":[{"Action":"UPSERT",
    "ResourceRecordSet":{"Name":"api.sft.<domain>","Type":"A","AliasTarget":{"DNSName":"<dns name>",
    "HostedZoneId":"<lb zone>","EvaluateTargetHealth":false}}}]}'
  ```

- **The web app.** CloudFront's origin group falls back to Osaka's bundle bucket by itself; load one page.

### 9. Verify (5 min)

Run the synthetic probe in Osaka (`kubectl -n sft create job --from=cronjob/synthetic-probe probe-failover-1`): send, verify
with a real email from Osaka's SES, download. `ProbeSuccess` for the environment is 1. Sign in once through the
standby pool. The RTO is the time from step 1 to here.

## Afterwards

- Keep watching the failed scans of large files: those completed just before the failure end `scan_failed` at their
  deadline (#42 gaps 3 and 8); members upload them again.
- Files uploaded in the last minutes before the failure that never reached Osaka show as unavailable (NFR-10).
- **The probe's mail.** The probe domain's MX and SES receipt rule point at Tokyo's SES inbound, which Osaka may not
  have (SES receiving runs in a few regions only; to check in the AWS run). If it is gone, the probe fails at
  `link_email` in Osaka until the MX points at a region that receives: `SyntheticProbeFailing` and the `probe-failing`
  alarm fire for that reason alone, and step 9 checks the email by hand. Note it in the report.
- In a drill, the script deletes the marker in Osaka; Tokyo's went with its stack. If Tokyo's Pushgateway comes back
  with it, delete it there too ([drill-in-progress.md](drill-in-progress.md)).
- Write the drill or incident report from the template. Then plan the failback ([regional-failback.md](regional-failback.md)).

[AUTH]: ../security/authn-authz.md
