# Runbook: regional failover, Tokyo to Osaka

Losing the Tokyo region (NFR-10, NFR-11: service back in Osaka within an hour). It follows architecture 7 step by
step; each step's budget is the architecture's, and `ops/regional-failover.sh` runs, times and logs them. It is a
procedure, started by a person: no alert or health check moves traffic on its own (T-78). The decisions behind it are
in [disaster-recovery.md](../operations/disaster-recovery.md).

> [!IMPORTANT]
> **Pending the AWS run.** Nothing in AWS has been applied yet. This page is written from the Terraform, the chart
> and the design; the first staging drill measures each step and corrects it. Every Terraform change in it is an
> input of an apply, never an edit of the code (#261).

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
ops/failover-values.sh surviving-osaka --env prod --write
git commit -m "ops: fence Tokyo and take prod Osaka out of pilot light" deploy/environments/prod
```

Tokyo's file gets `pilotLight: true`: whenever Tokyo's cluster answers again, Argo CD scales it to zero, so it never
writes to a database that is no longer the primary. Osaka's gets `pilotLight: false` with `failover.holdWorkers:
true`: the API and the migration job may run, every worker stays at zero and every CronJob suspended. Nothing here needs
Tokyo to answer.

The same commit sets `auditArchive.survivingRegionOnly: "ap-northeast-3"` in Osaka's file (the chart's
`AUDIT_ARCHIVE_SURVIVING_REGION`, #257): Osaka's API, reconciliation and archive job write Osaka's archive alone, so
new download grants work and the archive keeps up while Tokyo is lost; each range the archive job writes is recorded
for the back-fill at failback ([audit-archive-single-region.md](audit-archive-single-region.md)). A drill sets it too,
so every drill proves the back-fill.

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

Inputs only, each an apply of one of Osaka's roots with the apply checklist's inputs (#247, #261):

- The `system` node group from one node to two: apply `infra/environments/prod/ap-northeast-3/cluster` with
  `TF_VAR_system_node_count=2`. Karpenter adds the main and scan nodes as Argo CD deploys what Git now holds.
- GuardDuty Malware Protection for Osaka's large-files bucket: apply `infra/environments/prod/ap-northeast-3/data`
  with `TF_VAR_malware_protection_enabled=true` (ADR-0019). GuardDuty validates its access to the bucket then.
- The Osaka alarms, quiet in the pilot light: apply `infra/environments/<env>/ap-northeast-3/alarms` with
  `TF_VAR_heartbeat_enabled=true TF_VAR_pilot_light=false TF_VAR_database_role=primary` (and
  `TF_VAR_probe_enabled=true` where the probe runs), so the heartbeat, the API's targets and the probe page from
  Osaka, and the writer's CPU and memory alarms watch Osaka ([alarms](../../infra/modules/alarms/README.md)). The
  same apply makes Osaka's us-east-1 rule that forwards root, emergency user and Identity Center sign-ins to Osaka's
  security alerts ([privileged-sign-in.md](privileged-sign-in.md)). In a drill, also apply Tokyo's alarms with
  `TF_VAR_database_role=secondary`.
- **Osaka's observability stack starts with the fencing commit** (its Applications follow `pilotLight`) **with empty
  history**: Prometheus, Loki and Tempo hold nothing from before the failover, so the SLO dashboard's 28-day figures and
  the burn-rate alerts' long windows start from zero, and the failure's own evidence stays in Tokyo's volumes and
  buckets. Read the drill's or the incident's numbers from CloudWatch and the drill log, not Osaka's Grafana.
- Keep these inputs in the apply checklist until the failback, so the next apply of those roots doesn't undo them.

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

The job is `python -m sft.workers.recovery` as `sft_recovery` (#258). It lists Osaka's archive under both layouts (the
API's `security-critical/v1/` records and the archive job's `g<n>/` batches, every generation, from `RECOVERY_SINCE`'s
day), takes the highest generation, and runs the steps in the order generation, partitions, replay, outbox whatever
order they are named in. Its last log line is the report: `generation`, `highest_in_archive`, `records`, `newest` (the
newest archived record: the RPO evidence when the replica's lag can't be read), `replayed` by action and outcome, and
`reapplied` (IDs). Copy it into the drill log. Running it again is safe.

**The audit archive while Tokyo is lost.** Normally the archive job writes each batch to both regions and moves its
cursor only once both hold it, and the API writes security-critical records to both (#183, architecture 5.2). With
`auditArchive.survivingRegionOnly: ap-northeast-3` (step 2), Osaka's archive job writes Osaka alone and its lag stays
low; `AuditArchiveSingleRegion` opens a ticket after 30 minutes, expected until failback. Security-critical records,
download grants included, go to Osaka alone and answer `2xx`. Grant intents written now stay in Osaka only (they are
never in the database); everything else is back-filled to Tokyo at failback, whose step 10 checks it
([regional-failback.md](regional-failback.md)).

### 6. Sign-in: the standby pool (alongside 7 and 8)

SSO members sign in through Osaka's standby pool as usual. Members without SSO re-enrol ([AUTH] 2.6): start the
standby enrolment job, after step 5 so it never enrols a member the replay deactivated:

```bash
kubectl -n sft create job --from=cronjob/standby-enrolment standby-enrolment-1
```

It runs `python -m sft.workers.standby_enrolment`, as the notification worker (#258): for each active member who
signed in with a password (an identity on Tokyo's pool), it creates the user in Osaka's pool with Cognito's email
suppressed, sends the `member_reenrolment` email with a temporary password itself, and records the identity with its
`email.sent` event in the member's tenant. SSO members are skipped. Its log line counts `enrolled`,
`already_enrolled`, `not_local`, `inactive` and `address_in_use`; running it again sends nothing to members already
enrolled. Members still `invited` (they never signed in) hold an invitation for Tokyo's pool: after step 7 run
`kubectl -n sft create job --from=cronjob/invite-backlog invite-backlog-osaka-1`, which invites them again through
Osaka's pool. Tenant admins are told. Sign in once through the standby pool with the synthetic tenant's SSO test
member.

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
standby pool. `max(audit_archive_lag_seconds)` is under 2 minutes in Osaka. The RTO is the time from step 1 to here.

## Afterwards

- Keep watching the failed scans of large files: those completed just before the failure end `scan_failed` at their
  deadline (#42 gaps 3 and 8); members upload them again.
- Files uploaded in the last minutes before the failure that never reached Osaka show as unavailable (NFR-10).
- **The probe's mail.** Tokyo and Osaka both receive email (AWS General Reference, SES email receiving endpoints). The
  probe domain's MX names Tokyo first and Osaka second, and each Region has its own receipt rule and mailbox bucket
  (modules/probe-mailbox, #259), so with Tokyo gone senders deliver to Osaka and the probe reads Osaka's mailbox. If a
  sender keeps retrying Tokyo first, `link_email` may be slow for a while: step 9 checks the email by hand.
- In a drill, the script deletes the marker in Osaka; Tokyo's went with its stack. If Tokyo's Pushgateway comes back
  with it, delete it there too ([drill-in-progress.md](drill-in-progress.md)).
- Write the drill or incident report from the template. Then plan the failback ([regional-failback.md](regional-failback.md)).

[AUTH]: ../security/authn-authz.md
