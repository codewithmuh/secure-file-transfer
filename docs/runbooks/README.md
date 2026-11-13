# Runbooks

One page per alert or alarm. Every alert and every alarm links to its runbook (NFR-17), and
[`deploy/tests/test_runbooks.py`](../../deploy/tests/test_runbooks.py) fails if one doesn't, if the page is missing,
or if this index leaves it out. The Prometheus rules are in [`deploy/alerts/`](../../deploy/alerts/), routed by
[`alertmanager.yaml`](../../deploy/alerts/alertmanager.yaml); the CloudWatch alarms are in
[`infra/modules/alarms`](../../infra/modules/alarms/README.md). [SLOs](../operations/slos.md) explains the objectives,
the burn-rate alerts and the coverage of every alert the design promises.

Each runbook answers: **what is broken, how bad is it, how to confirm, how to mitigate, how to escalate.**

A **page** needs someone now; a **ticket** is for working hours. During a drill, Alertmanager inhibits every alert
except those marked `security="true"` ([drill-in-progress.md](drill-in-progress.md)).

## Prometheus alerts (in the cluster)

| Alert | Severity | Runbook |
|---|---|---|
| `ErrorBudgetBurn` (NFR-1, NFR-2, NFR-5, NFR-23) | Page or ticket | [slo-burn.md](slo-burn.md) |
| `SyntheticProbeFailing`, `SyntheticProbeStale` (NFR-1) | Page | [synthetic-probe.md](synthetic-probe.md) |
| Service unavailable, readiness failing | Page | [service-unavailable.md](service-unavailable.md) |
| `OutboxBacklog` | Page | [outbox-backlog.md](outbox-backlog.md) |
| `EmailDeliveryFailing`, `EmailSendSlow` (NFR-7) | Page | [email-delivery.md](email-delivery.md) |
| `ScanFailed` | Page | [scan-failed.md](scan-failed.md) |
| `DlpInspectorFailing` | Page | [dlp-inspector.md](dlp-inspector.md) |
| `ClamavSignaturesStale` (T-27) | Ticket | [clamav-signatures.md](clamav-signatures.md) |
| `DlpApprovalBacklog` | Ticket | [dlp-approvals.md](dlp-approvals.md) |
| `RateLimitStoreUnavailable` | Page | [rate-limit-store-unavailable.md](rate-limit-store-unavailable.md) |
| `LinkProbing` | Ticket | [link-enumeration.md](link-enumeration.md) |
| `VerificationGuessing` | Page | [verification-abuse.md](verification-abuse.md) |
| `EmailBombing` | Ticket | [email-abuse.md](email-abuse.md) |
| `DownloadCapacity` | Ticket | [download-capacity.md](download-capacity.md) |
| `ApiKeyMisuse` | Ticket | [api-key-compromise.md](api-key-compromise.md) |
| `EgressProxyDown` | Page | [egress-proxy.md](egress-proxy.md) |
| `ArgoCdApplicationUnhealthy` | Ticket | [argocd-sync.md](argocd-sync.md) |
| `KeyringRefreshFailing` | Ticket | [keyring-refresh.md](keyring-refresh.md) |
| `KeyringKeyTooOld` | Ticket | [keyring-rotation.md](keyring-rotation.md) |
| `FieldDecryptScopeMismatch` (security), `FieldKeysUnavailable` | Page | [field-keys.md](field-keys.md) |
| `BreakGlassActive`, `BreakGlassSelfApproved`, `BreakGlassSweepStalled`, `BreakGlassTenantRecordsMissed` (security), and the break-glass database role's EventBridge alert | Page | [break-glass.md](break-glass.md) |
| `OperatorAuditFailing` (security) | Page | [operator-audit.md](operator-audit.md) |
| `BreakGlassGrantUnrecorded`, `BreakGlassReconciliationStalled` (security; page), `BreakGlassRecordedByReconciliation` (security; ticket) | Page or ticket | [break-glass-records.md](break-glass-records.md) |
| `SsoProviderDrift` (security; page), `SsoProviderUnrecorded` (security; ticket), `SsoDriftCheckStalled` | Page or ticket | [sso-provider-drift.md](sso-provider-drift.md) |
| `AuditArchiveWriteFailing` | Page | [audit-archive-writes.md](audit-archive-writes.md) |
| `AuditArchiveLagging`, `AuditArchiveJobNotRunning` (NFR-15) | Page | [audit-archive-lag.md](audit-archive-lag.md) |
| `AuditArchiveSingleRegion` | Ticket | [audit-archive-single-region.md](audit-archive-single-region.md) |
| `MetadataPurgeBlocked`, `MetadataPurgeBehind`, `MetadataPurgeNotRunning` (NFR-9) | Ticket | [metadata-purge.md](metadata-purge.md) |
| `FileDeletionOverdue` (NFR-8; page), `FileDeletionLagging`, `UnarchivedGrants` (NFR-15), `LifecycleJobNotRunning` | Page or ticket | [lifecycle-jobs.md](lifecycle-jobs.md) |
| `AuditPartitions` (data model 6, NFR-9) | Ticket | [audit-partitions.md](audit-partitions.md) |
| `Watchdog` (never pages; feeds the heartbeat) | Heartbeat | [watchdog.md](watchdog.md) |
| `DrillInProgress` | Ticket | [drill-in-progress.md](drill-in-progress.md) |

## CloudWatch alarms (outside the cluster)

Named `sft-<env>-<rs>-<what>`, to the Region's `alerts-page` or `alerts-ticket` topic.

| Alarm | Severity | Runbook |
|---|---|---|
| `heartbeat-missing` (off in Osaka during the pilot light) | Page | [watchdog.md](watchdog.md) |
| `probe-failing` (once the environment's probe runs) | Page | [synthetic-probe.md](synthetic-probe.md) |
| `database-rpo-lag` (Osaka, staging and prod) | Page | [database-replication-lag.md](database-replication-lag.md) |
| `database-cpu`, `database-memory` | Ticket | [database-capacity.md](database-capacity.md) |
| `<queue>-dlq` for `notify`, `signin-events`, `ses-events`, `ses-tenant-status` | Page | [dead-letter-queue.md](dead-letter-queue.md) |
| `<queue>-age` | Page or ticket | [queue-backlog.md](queue-backlog.md) |
| `files-replication-*`, `large-files-replication-*` (Tokyo, staging and prod) | Page | [file-replication.md](file-replication.md) |
| `api-lb-5xx`, `api-no-healthy-targets` | Page | [service-unavailable.md](service-unavailable.md) |
| `nat-<id>-port-allocation`, `nat-<id>-packet-drops` | Ticket | [nat-gateway.md](nat-gateway.md) |
| `kms-quota` | Ticket | [kms-throttling.md](kms-throttling.md) |
| `ses-reputation` (`SesReputation`) | Page | [ses-reputation.md](ses-reputation.md) |
| `signin-trigger-errors`, `signin-trigger-throttles` | Page | [signin-trigger.md](signin-trigger.md) |
| `apne1-region-health` (page), `apne3-region-health` (ticket), in us-east-1 | Page or ticket | [region-health.md](region-health.md) |

## EventBridge alerts (security events)

Rules on CloudTrail's events, not metrics, so they page with no cluster and no metric, and a drill never holds them
back. The environment's are `sft-<env>-<rs>-<rule>` in each Region, to the Region's `alerts-page` topic
([`infra/modules/alarms/security-events.tf`](../../infra/modules/alarms/security-events.tf), #256); prod's retained
stack has its own, to its own topics ([`infra/environments/prod/retained/alerts.tf`](../../infra/environments/prod/retained/alerts.tf), #263).
Every rule's message names its runbook; the alarms module's `terraform test` fails if one doesn't exist.

| Rule (alert) | Severity | Runbook |
|---|---|---|
| `kms-key-changed` (`KmsKeyChanged`), `kms-key-destroyed` (`KmsKeyDisabledOrDeleted`, prod) | Page | [kms-key-change.md](kms-key-change.md) |
| `key-admin-used` (`KeyAdminRoleUsed`) | Page | [key-admin-role.md](key-admin-role.md) |
| `human-sign-in` (`PrivilegedSignIn`): root, the emergency user, `Admin`, `BreakGlass` | Page | [privileged-sign-in.md](privileged-sign-in.md) |
| `security-service-off`, `alerting-or-endpoint-changed` (`SecurityServiceChanged`): CloudTrail, GuardDuty, Config, these rules, a public cluster endpoint | Page | [security-service-off.md](security-service-off.md) |
| `break-glass-db-assumed` (`BreakGlassDatabaseRoleAssumed`) | Page | [break-glass.md](break-glass.md) |
| `retained-bucket-changed`, `retained-key-changed`, `retained-trail-changed` (prod's retained stack) | Page | [retained-stack-change.md](retained-stack-change.md) |
| `sft-management-scp-changed` (`ScpChanged`): any SCP change, in the management account's us-east-1, to its own topic ([`infra/organization/scp-alerts.tf`](../../infra/organization/scp-alerts.tf), #277) | Page | [scp-change.md](scp-change.md) |

## Procedures

Steps the maintainer runs on purpose, not in answer to an alert.

| Procedure | Runbook |
|---|---|
| Create the AWS organization, its guardrails and budgets, and bootstrap the accounts (M4) | [organization-and-bootstrap.md](organization-and-bootstrap.md) |
| Build staging and prod with the Osaka pilot light: inputs, order, checks (#247) | [apply-staging-and-prod.md](apply-staging-and-prod.md) |
| Backfill, rotate, re-wrap and purge the tenants' data keys (#236) | [field-keys.md](field-keys.md) |
| Request, approve, use and end break-glass access to tenant data (FR-35) | [break-glass.md](break-glass.md) |
| Purge metadata past its 365 days (#224) | [metadata-purge.md](metadata-purge.md) |
| Set up, run and read the synthetic probe and its synthetic tenant (#248) | [synthetic-probe.md](synthetic-probe.md) |
| Recover a tenant admin's sign-in through the recovery contact (`recoverTenantAdmin`, #239) | [tenant-admin-recovery.md](tenant-admin-recovery.md) |
| Run the load test, the NFR-23 benchmark and the NFR-3 upload test (#249 to #251) | [../operations/performance.md](../operations/performance.md) |
| Read and record a drill: the disaster-recovery decisions, targets and drill programme (#42) | [../operations/disaster-recovery.md](../operations/disaster-recovery.md) |
| Write one region's audit archive alone during a regional loss, and back-fill the other at failback (#257) | [audit-archive-single-region.md](audit-archive-single-region.md) |
| Fail over from Tokyo to Osaka (NFR-11, architecture 7, #252) | [regional-failover.md](regional-failover.md) |
| Fail back from Osaka to Tokyo (#252) | [regional-failback.md](regional-failback.md) |
| Lose an Availability Zone, and its drill (NFR-11) | [az-failure.md](az-failure.md) |
| Restore the database to a point in time (NFR-11, #253) | [point-in-time-restore.md](point-in-time-restore.md) |
| Run a drill without paging for it | [drill-in-progress.md](drill-in-progress.md) |
| Start, run and end prod's operating period (#254) | [operating-period.md](operating-period.md) |
| Bring an environment up or down with one command: `make aws-up`, `make aws-down`, `make aws-status` (NFR-19, NFR-20, #295) | [environment-up-down.md](environment-up-down.md) |
| Tear an environment down, prod's retained stack aside (NFR-19, #254) | [teardown.md](teardown.md) |
