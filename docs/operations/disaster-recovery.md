# Disaster recovery

How the service recovers from losing an Availability Zone, the Tokyo region, or the integrity of its database, how
each recovery is drilled and timed, and how the environments are torn down. Architecture section 6 lists the
failures and section 7 the regional failover's budget; this page turns them into runbooks, scripts and drills, and
records the decisions that the phase 4 review left open in
[#42](https://github.com/codewithmuh/secure-file-transfer/issues/42).

> [!IMPORTANT]
> **Every drill is pending the AWS run.** Nothing in AWS has been applied yet (infra/README.md). The runbooks and
> scripts are written from the Terraform, the chart and the design, and checked statically; the recovery job's
> re-import and re-apply run against a real PostgreSQL in CI (`tests/test_recovery_replay.py`). The first drills in
> staging measure every number below and correct these pages.

## 1. Targets

| Failure | RTO | RPO | Requirement | Runbook | Script |
|---|---|---|---|---|---|
| One AZ in Tokyo | ≤ 5 min, automatic | 0 | NFR-10, NFR-11 | [az-failure.md](../runbooks/az-failure.md) | `ops/az-failure.sh` |
| The Tokyo region | ≤ 1 h, an operator's decision; 57 min budget (architecture 7) | ≤ 5 min of metadata; ≤ 15 min of uploads for 99.99 % of files; no security-critical change but a grant committed in the second before the loss | NFR-10, NFR-11 | [regional-failover.md](../runbooks/regional-failover.md) | `ops/regional-failover.sh` |
| Back to Tokyo afterwards | No target; a planned window | 0 (switchover) | — | [regional-failback.md](../runbooks/regional-failback.md) | `ops/regional-failback.sh` |
| Corrupted data or a bad migration | ≤ 2 h | The chosen point, accurate to ≤ 5 min; security-critical changes and audit records after it are kept | NFR-11 | [point-in-time-restore.md](../runbooks/point-in-time-restore.md) | `ops/point-in-time-restore.sh` |
| End of an environment | Prod destroyed in ≤ 1 h, only the retained stack left | — | NFR-19, NFR-20 | [teardown.md](../runbooks/teardown.md) | `ops/teardown.sh` |

The operating period that ends in the teardown has its own runbook, [operating-period.md](../runbooks/operating-period.md).

## 2. What protects what

| Data | Within Tokyo | In Osaka | After a restore |
|---|---|---|---|
| Database | Aurora's six copies in three AZs; the reader takes over in about a minute | The global database's secondary, normally under a second behind (`AuroraGlobalDBRPOLag`, alarm at 1 min) | A new cluster from the 14-day continuous backup |
| Files | S3, at least three AZs | Replication with RTC, 99.99 % within 15 min | Not restored: file contents are never in database backups; restored rows that point at deleted files are marked deleted by reconciliation (NFR-11) |
| Audit records | PostgreSQL, then the archive job every minute | The archive bucket's replica (no RTC) | Re-imported from the archive (section 4) |
| Security-critical records | Written to both regions' archives before the API answers (#177) | The same records | Re-applied from the archive (section 4) |
| Outbox work | PostgreSQL; SQS in the region | Re-published from the outbox after a failover | Re-published from the outbox after a restore |

## 3. The scripts

Each runbook has a script in [`ops/`](../../ops/) that runs its steps in order, times each against its budget and
writes the drill log ([drill-log-template.md](drill-log-template.md)). The same script runs a drill and a real
recovery. Their contract (`ops/lib/common.sh`):

- **Explicit environment and profile.** Without `--env` and `--profile` a script refuses to start; `--profile
  default` is refused too. Every AWS call names the profile, and the shell's own AWS credentials are cleared first, so
  the default identity is never used. Recoveries need the `Admin` permission set (infra/README.md), so the profile is
  the environment's `Admin` profile, assigned for the hour by a `BreakGlassApprover`.
- **A dry run by default.** Without `--execute` a script prints every command and every operator step and runs
  nothing; it writes its log to a temporary file. That is how a runbook is rehearsed, and how the teardown lists what
  it would destroy (`ops/teardown.sh --inventory` also reads each stack's state and the tag search, read-only).
- **With `--execute`** it checks that the profile signs in to `--account-id`, asks the operator to type the
  environment's name, and writes the log to `docs/operations/drills/<date>-<drill>-<env>.md`.
- **Git stays a person's.** The scripts change the deploy values with `ops/failover-values.sh` and stop; the
  maintainer commits and pushes, and Argo CD applies the change in both clusters (deploy/README.md). Terraform inputs
  that only the operator holds (the apply checklist of #247) are printed as operator steps.
- **Checks.** `ops/test.sh` runs each script's refusals and dry runs, and the values changes on a copy of the repo;
  shellcheck checks every script.

### The values a failover flips

Three keys in each cluster's values file, flipped by `ops/failover-values.sh` and committed by the maintainer:

| Key | Pilot light (Osaka) | Fenced | Running, workers held | Running |
|---|---|---|---|---|
| `pilotLight` | `true` | `true` | `false` | `false` |
| `failover.holdWorkers` | `true` | any | `true` | `false` |
| `auditArchive.survivingRegionOnly` | `""` | `ap-northeast-3` (Osaka) | `ap-northeast-3` | `ap-northeast-3` until failback, then `""` |

`failover.holdWorkers` keeps every worker Deployment at zero and every CronJob suspended while the API, the operator
API and the migration job run, so nothing acts on a revocation the replica hadn't received before the recovery job has
re-applied it (architecture 7). Osaka's files carry it from the start; the script adds it to Tokyo's when a failback
or a restore needs it. `auditArchive.survivingRegionOnly` writes the surviving region's archive alone during a
regional loss; failback's back-fill writes the other (#257, gap 12). The chart reads both (section 8).

## 4. The recovery job

`sft.service.recovery_replay`, run by `python -m sft.workers.recovery` (`sft.service.recovery`, #258) as the
`sft_recovery` database role (IAM role `sft-{env}-recovery`, which lists and reads this Region's audit archive) in
recovery scope, by a suspended `recovery` CronJob rendered with its steps, as the field-keys runbook renders its
job. One module serves the regional failover, the failback and the restore, in four steps:

1. **`generation`.** The archive cursor's generation becomes one more than the highest in the surviving region's
   archive, and the cursor goes back to the oldest event written since `RECOVERY_REWIND_TO`, so reused transaction
   IDs never overwrite an archived record (data model 2.5), and batches that never reached the surviving region are
   archived again (gap 1 below).
2. **`partitions`.** The audit partitions from the oldest re-imported month, so nothing lands in the default
   partition.
3. **`replay`.** Every archived record after `RECOVERY_SINCE`, oldest first, one transaction each: the event is
   inserted with its own ID and time, `ON CONFLICT DO NOTHING`; if it was missing, its change is made again. A record
   whose event the database already has is skipped, so running it twice changes nothing.
4. **`outbox`.** Every outbox message published since `RECOVERY_SINCE` (24 hours back) goes back to unsent; the relay
   publishes it once the workers scale up, and consumers skip what they already did (architecture 5.3).

**What it re-applies.** The changes that take access away: transfer and upload request revocations (with their link
sessions, and the transfer's files sent to the deletion job), recipient and uploader lockouts, API key revocations,
deactivations and demotions (with their member sessions), forced sign-outs, sign-in resets (sessions and pool
identities), and the count of every download grant whose committed record is in the archive but whose row the
database lost. Grant intents are ignored (data model 2.3).

**What it doesn't, on purpose** (decision of #253): **unlocks**, and the invitation of a sign-in reset. An unlock
gives access back and issues a new link by email, an outbox message the recovery role can't write; re-applied
without it, the recipient would be unlocked with no link. Left locked, the recipient is safe and the member unlocks
again, which sends the link. A sign-in reset's sessions and identities go, which is what removes access; the admin
resets again to send the invitation. The job logs both, and the runbooks tell the tenant admins.

### Grants the recovery job needs

Data model 4.2 lists what `sft_recovery` reads and updates. Revision 0034 gives it `audit_archive_cursor` (with the
archive job's #183) and revision 0035 the rest, each policy in recovery scope only; `tests/test_recovery_replay.py`
checks the revision's statements against the helpers that wrote them. Beyond 4.2's list, the job needs `files (delete_after)`, so a re-applied revocation
sends the files to deletion (NFR-8); `idp_connections (id, tenant_id)` read, to tell pool identities from SSO ones;
`audit_events (tx_id, occurred_at)` read, to rewind the cursor; and `outbox (published_at, attempts,
next_attempt_at, last_error)`, to re-publish.

| Table | Read | Update | Policy (`recovery_reapply`) |
|---|---|---|---|
| `transfers` | `id, tenant_id, state, ended_at, revoked_by` | `state, hold_reason, ended_at, revoked_by, updated_at` | recovery scope |
| `files` | `id, tenant_id, transfer_id, delete_after` | `delete_after` | recovery scope |
| `upload_requests` | `id, tenant_id, state, ended_at, revoked_by, locked_at, failed_attempts` | `state, ended_at, revoked_by, locked_at, failed_attempts, updated_at` | recovery scope |
| `transfer_recipients` | `id, tenant_id, transfer_id, locked_at, failed_attempts` | `locked_at, failed_attempts, updated_at` | recovery scope |
| `link_sessions` | `id, tenant_id, recipient_id, upload_request_id, revoked_at` | `revoked_at` | recovery scope |
| `users` | `id, tenant_id, role, status` | `role, status, sso_fallback, dlp_approver, invitation_token_hash, invitation_expires_at, updated_at` | recovery scope |
| `api_keys` | `id, tenant_id, revoked_at` | `revoked_at, revoked_reason` | recovery scope |
| `member_sessions` | `id, tenant_id, user_id, created_at, revoked_at` | `revoked_at, revoked_reason` | recovery scope |
| `user_identities` | `id, tenant_id, user_id, idp_connection_id, created_at` | `DELETE` | recovery scope |
| `idp_connections` | `id, tenant_id` | — | recovery scope, pool rows only (`tenant_id IS NULL`) |
| `download_grants` | `id` | — | recovery scope |
| `download_counters` | `tenant_id, recipient_id, file_id, count, first_downloaded_at, last_downloaded_at` | `count, first_downloaded_at, last_downloaded_at, updated_at` | recovery scope |
| `audit_events` | `tx_id, occurred_at` | — (inserts, revision 0002) | recovery scope (`audit_recovery_select`) |
| `audit_archive_cursor` | all | all, the generation included (revision 0034) | recovery scope (`recovery_cursor`) |
| `outbox` | `published_at` | `published_at, attempts, next_attempt_at, last_error` | recovery scope |

No grant on `display_name_ct`, `message_ct` or any other ciphertext column.

## 5. The disaster-recovery gaps (#42)

Each gap of the phase 4 review, with its decision and the drill step that proves it.

| # | Gap | Decision | Proved by |
|---|---|---|---|
| 1 | **The archive cursor against untimed archive replication.** The cursor travels with the database, so after a failover it can be past batches that never reached Osaka's archive. | **Rewind, not RTC.** The failover's recovery job starts the new generation with the cursor rewound to the oldest event written in the hour before the failure (`RECOVERY_REWIND_TO`), or further if Osaka's archive replication was further behind. Those rows are archived again under the new generation; readers drop duplicates by `id` (data model 2.5). RTC on the archive would bound 99.99 % of objects to 15 minutes, but a bound is not a guarantee, so the rewind would still be needed; it would add a fee and nothing else. | Failover drill, step 5: every event the drill writer made in its last 10 minutes in Tokyo is in Osaka's archive afterwards, under the old or the new generation. `test_a_new_generation_rewinds_the_cursor_once`. |
| 2a | **Backups in Osaka.** Do cross-region backup copies exist, and does the promoted Osaka cluster keep 14 days of point-in-time recovery? | **No cross-region copies; 14 days from promotion.** Osaka's secondary already has `backup_retention_days = 14` (its data root), so once promoted it keeps its own 14 days from that moment. Points before the failover are restorable again only from Tokyo's backups once Tokyo returns. Aurora doesn't copy automated backups across regions, and daily AWS Backup copies would add about $90 a month of transfer for a restore point no better than the secondary. Accepted: for 14 days after a failover, NFR-11's restore window is the time since the failover. | Failover drill, step 3: `describe-db-clusters` shows `BackupRetentionPeriod` 14 on the promoted cluster, and `LatestRestorableTime` moves. |
| 2b | **A restored cluster has no secondary** until a new one catches up, hours at 150 GB. | **A snapshot copy in Osaka covers the window.** Right after the restore, one cluster snapshot is copied to Osaka under Osaka's database key, and deleted when the new secondary is in sync. A regional loss in that window loses the changes since the snapshot, not the database; security-critical records are in both archives anyway. | Restore drill, steps 3 and 8: the copy's time and the new secondary's catch-up time. |
| 3 | **Intake-queue events lost with Tokyo**: GuardDuty results, SES events, Cognito sign-in events. | **GuardDuty results:** recovered by the scan deadline: a large file whose result was lost stays `scanning`, the sweep fails it `scan_failed` at its deadline, and the member uploads it again (scan-failed runbook); nothing unscanned is shared. **SES bounces and complaints:** accepted loss; at worst one more email to an address that just bounced, whose next bounce is recorded in Osaka. **Cognito sign-in events:** accepted loss of the failed and successful sign-ins still in the queue, normally under a minute's worth; the drill report states the queue's age at the failure as the audit gap (NFR-15 can't hold for events lost with the region; T-81). | Failover drill: a file over 2 GB completed just before the failover ends `scan_failed` at its deadline and is never downloadable; the sign-in queue's `ApproximateAgeOfOldestMessage` at the failure is written in the log. |
| 4 | **S3 failback**: replication runs one way, so Osaka's new objects never reach Tokyo. | **Reverse replication at failback, then Batch Replication.** The failback's apply of Osaka's data root with `TF_VAR_replicate_to_tokyo=true` adds the rule `to-tokyo` to both files buckets (with RTC), and an S3 Batch Replication job per bucket, run as `sft-<env>-s3-batch-replication`, copies every object created in Osaka since the failover, tags included; the rule goes when Osaka is back in pilot light. The replication role's permissions and the files key's policy cover both directions at all times, so the failback changes only Osaka's stack (modules/files-buckets, #262). | Failback drill, step 2: each job's succeeded count equals the objects Osaka's buckets gained since the failover; the probe downloads, from Tokyo, a file uploaded during the failover. |
| 5 | **Degraded mode for download grants during an Osaka-only outage**, and its effect on NFR-1. | **No degraded mode.** Grants fail closed with `503` and count nothing; streams under existing grants continue; the other security-critical changes commit and answer `503` "done, not confirmed" (architecture 6). A grant with its intent in one region only is exactly what NFR-10 rules out if Tokyo is then lost. The errors count against NFR-1's download path: 43 minutes of failed grants a month is the whole error budget, so an Osaka S3 outage longer than that breaches NFR-1, and is reported as such, not excluded. | Osaka archive outage drill (staging only, section 6): grants answer `503` with nothing counted, streams continue, the alert fires, and grants succeed again within a minute of Osaka returning. |
| 6 | **Who creates Cognito users during a failover** while the workers are at zero. | **The notifier's role, in a one-off job.** A suspended `standby-enrolment` CronJob, run by hand like `invite-backlog`, as the notifier's service account and IAM role (`sft-{env}-notify`), which already holds Cognito's admin API on its region's pool through its proxy listener: no new role. It creates every active member without SSO in the standby pool without sending Cognito's email, records each identity, and sends each re-enrolment invitation itself (an outbox message can't carry the temporary password), with its `email.sent` event in the member's tenant (`python -m sft.workers.standby_enrolment`, #258). It runs after the replay, so it never enrols a member the replay deactivates. | Failover drill, step 6: a local test member of the synthetic tenant gets the invitation when the job runs, re-enrols, and signs in through the standby pool; a member the drill deactivated just before the failover gets none. |
| 7 | **Grant byte counters lost within the replication lag.** | **Accepted, bounded by the lag.** A grant's `bytes_served` and `request_count` updates in the seconds before the failure can be lost, so that grant may serve those seconds' bytes again, still within its 24 hours and 3 × size budget. Its count isn't affected: counts are re-applied from committed records (section 4). | Failover drill, step 3: `AuroraGlobalDBRPOLag` at the promotion is the bound, written in the log. |
| 8 | **GuardDuty retries and files over 2 GB mid-scan at the failover.** | **No on-demand rescan.** A large file completed in Tokyo whose result never arrived ends `scan_failed` at its deadline (gap 3); the member uploads it again, to Osaka, whose plan exists from step 4. A rescan of the replica would mean copying it in place, a new version that the file's pinned version wouldn't match, and an operator rescan is something the scan-failed runbook already rules out. Small files mid-scan are scanned again in Osaka: the outbox re-publish resends their scan messages. | Failover drill: a small file and a large one in `scanning` at the failover: the small one is scanned in Osaka, the large one ends `scan_failed` at its deadline. |

Gaps the runbooks found while being written, decided the same way:

| # | Gap | Decision | Proved by |
|---|---|---|---|
| 9 | **DNS when Tokyo's state can't be read.** The API's record belongs to Tokyo's edge stack, whose state is in Tokyo. | In a real failover, if Tokyo's state bucket doesn't answer, the operator upserts the API's alias record to Osaka's load balancer through the environment's DNS role in the shared zone, by CLI; the failback's edge apply puts it back under Terraform. Drills use the Terraform path. | Failover drill, step 8 (Terraform path); the CLI path once, in staging, with Tokyo's state bucket denied to the operator. |
| 10 | **The old Tokyo database after an unplanned failover.** | Never a writer again (T-78). After a managed failover Aurora brings it back as Osaka's secondary and keeps a snapshot of its volume from before; after a detach it is deleted and a new secondary made, its final snapshot kept. Rows only it had are the RPO NFR-10 allows: security-critical ones are re-applied from the archive, the rest are not merged automatically in v1, and the snapshot is kept 30 days for support questions. | Failback drill, step 1. |
| 11 | **Prod's files buckets have no teardown rights** (modules/data-stack gives `teardown_allowed` only outside prod), so prod's `data` destroy fails on non-empty buckets. | **The teardown apply gives them.** modules/data-stack passes `teardown_allowed` to prod's files buckets from its `TF_VAR_teardown=true` apply on (#263): `force_destroy`, and deletes by the deploy role and `Admin`, which runs `ops/teardown.sh`, as in dev and staging always. Never while prod runs. Prod's `cluster`, `identity` and `edge` take the same input for their deletion protection. | Teardown rehearsal in staging; prod's timed teardown. |
| 12 | **A regional loss and the archive's two-region writes** (#257). | **Surviving-region mode, back-filled at failback.** The failover sets `auditArchive.survivingRegionOnly`; the API and the archive job write the surviving region alone, the job records each range, and at failback rewrites the same objects to the other region. Grant intents aren't back-filled (never in the database; superseded by their committed records). Never for an Osaka-only S3 outage while Tokyo serves (gap 5). | Failback drill, step 10: the two regions' `g<n>/` listings are equal and `audit_archive_single_region_ranges` is 0. |

## 6. Drills

| Drill | Where and how often | What it measures |
|---|---|---|
| AZ failure | Staging, then prod during the operating period; once each | RTO from the injection to the probe passing; RPO 0 |
| Regional failover, then failback | Staging first, then prod once during the operating period (ADR-0011's revisit point) | Each step of architecture 7 against its budget; RTO; database and files RPO; the replay's counts |
| Point-in-time restore | Staging, then prod once | RTO; the restore point's accuracy (the newest event before it against the chosen time) |
| Osaka archive outage | Staging only: the cross-region S3 endpoint's policy denies the archive for 10 minutes, through a Terraform change reverted afterwards | Gap 5's behaviour; the alert |
| Teardown and rebuild | Staging when idle (every teardown is a rehearsal); prod at the end of the operating period | NFR-19: rebuild ≤ 2 h, teardown ≤ 1 h; nothing billable left |

Planned drill windows that take prod down are logged and reported apart from NFR-1 (PRD NFR-1). Each drill's log
goes in `docs/operations/drills/`.

### Results

| Drill | Environment | Date | RTO | RPO | Log |
|---|---|---|---|---|---|
| AZ failure | staging | pending the AWS run | | | |
| Regional failover | staging | pending the AWS run | | | |
| Regional failback | staging | pending the AWS run | | | |
| Point-in-time restore | staging | pending the AWS run | | | |
| Teardown | staging | pending the AWS run | | | |
| Each of the above | prod | pending the AWS run | | | |

## 7. Teardown

Architecture 3.4 sets the order; `ops/teardown.sh` runs it and [teardown.md](../runbooks/teardown.md) explains each
step. In short: in prod, the retained stack's teardown apply first (`TF_VAR_teardown=true`: the key-admin role and the
environment's workload roles leave the audit key's and archive's policies, the key's rotation stops, the retained
trail logs management events, and the $7 budget is created); then the layers in reverse, Osaka before Tokyo in each,
each `data` stack (and in prod each `cluster`, `identity` and `edge`) after its own teardown apply; then, for a final
teardown, the bootstrap stacks, and with the last environment the shared account's registry; then the tag search, and
the next bill. dev and staging go the same way without the retained stack when idle, and keep their bootstrap stacks
to be built again (NFR-20).

## 8. What other parts of the repository still owe this page

What the drills need from elsewhere, and where each landed:

- **The chart and the application** (#257, #258): the chart reads `failover.holdWorkers` and
  `auditArchive.survivingRegionOnly` (`AUDIT_ARCHIVE_SURVIVING_REGION`) and runs the suspended `recovery` and
  `standby-enrolment` CronJobs; `ops/failover-values.sh` flips the toggles (`surviving-osaka` at the failover's fence,
  `both-regions` at the failback).
- **Terraform**: the recovery job's Pod Identity role `sft-{env}-recovery` (modules/eks-cluster, #258), and the inputs
  of #261, #262 and #263: every runbook step sets inputs only.

  | Input | Root | Set by |
  |---|---|---|
  | `TF_VAR_system_node_count=2` | Osaka's `cluster` | The failover, step 4; the failback, step 8, back to 1 |
  | `TF_VAR_database_role=primary` (Osaka), `secondary` (Tokyo) | `alarms` | The failover, step 4; the failback, step 8, back |
  | `TF_VAR_heartbeat_enabled`, `TF_VAR_pilot_light`, `TF_VAR_malware_protection_enabled` | Osaka's `alarms`, `data` | The failover; the failback, back (#246, ADR-0019) |
  | `TF_VAR_replicate_to_tokyo=true` | Osaka's `data` | The failback, step 2 to step 8 (gap 4) |
  | `TF_VAR_aurora_global_generation=2`, `TF_VAR_aurora_role=secondary` (Tokyo) | Both `data` roots | A failback after a detach, step 1, until the next rebuild |
  | `TF_VAR_teardown=true` | prod's `retained`, `data`, `cluster`, `identity`, `edge` | The teardown (gap 11) |

  The retained stack has its own state bucket, deploy role, trail and alerts, and its teardown apply takes the
  environment's roles out of the audit key's and archive's policies and turns the key's rotation off (encryption 8.4).
- **An alert on SCP changes** (encryption 8.4's table names it), which only the management account sees: the
  organization stack's own rule in us-east-1, into a topic the maintainer subscribes to
  (`infra/organization/scp-alerts.tf`, #277, [scp-change.md](../runbooks/scp-change.md)). Firing for real is pending
  the AWS run.
