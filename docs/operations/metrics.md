# Metrics catalogue

Every metric the service exposes, what it measures, where it comes from, and which SLO or alert reads it (#242;
[architecture](../architecture.md) 5.5, 6; [PRD](../prd.md) NFR-1, NFR-2, NFR-5, NFR-7, NFR-8, NFR-9, NFR-15, NFR-23).

- **Where they come from.** The API, the operator API and every worker serve `/metrics` on their internal port, which
  Prometheus scrapes (ADR-0009, architecture 8). The scheduled jobs exit after each run, so they push their registry
  to the Pushgateway instead (`METRICS_PUSHGATEWAY_URL`), with the grouping key `job="<job>"`: the same value as their
  `lifecycle_job_last_success_timestamp_seconds{job}` label. AWS's own metrics arrive through the CloudWatch exporter
  (section 9). The observability stack itself is [observability.md](observability.md).
- **Labels never hold tenant data** (NFR-26, architecture 5.5): no tenant ID, user, address, file name, message,
  token, code or detected value. A label is a route template, an HTTP status, a region, a job's name, or a code from a
  closed list in the code. tests/test_sli_metrics.py checks every label name against that list (section 11) and every
  value made at start.
- **Series exist at zero.** A labelled series an alert or SLO reads is made at zero when the process starts, so the
  first event shows as an increase and `absent()` means the process isn't running.
- **This page is the list.** tests/test_sli_metrics.py fails when the code defines a metric this page doesn't list,
  or this page lists one of ours (Source `sft.…`) that the code no longer defines. Add the row with the metric.

Counters are listed by the name Prometheus exposes, with `_total`; a histogram also exposes `_bucket`, `_sum` and
`_count`.

## 1. The SLIs

How each SLO's indicator is computed. The objectives, windows and burn-rate alerts are in [slos.md](slos.md).

| SLO | Indicator | From |
|---|---|---|
| NFR-1 availability, 99.9 % over 28 days | Good: API responses that aren't `5xx`, over all valid requests, from `http_requests_total{status}`; the load balancer's `5xx` (it answers for a pod that didn't) from the CloudWatch exporter; and the synthetic probe's journey, every 5 minutes | Sections 2, 9 |
| NFR-2 API latency, p95 at most 300 ms and p99 at most 1 s | `http_request_duration_seconds` by route, leaving out the routes that move file bytes (`route=~".*/content"`, which NFR-2 excludes; uploads go to S3 directly); the bucket edges at 0.3 s and 1 s make both exact | Section 2 |
| NFR-5 time to shareable, p95 at most 2 min up to 100 MB and 15 min up to 20 GB | `time_to_shareable_seconds{kind, size_class}`, with edges at 120 s and 900 s. The email hand-off after a transfer is sent is bounded by `outbox_oldest_unpublished_age_seconds` and the notification queue's age, and measured end to end by the probe | Sections 3, 4, 9 |
| NFR-7 email hand-off, p95 at most 10 s | `send_latency_seconds{type}` for `verification_code`, `transfer_link` and `upload_request`, the emails a person waits for: from the outbox message that asked for the email to SES accepting it; the edge at 10 s makes the p95 exact (`EmailSendSlow`) | Section 5 |
| NFR-8 deletion within 7 days | `lifecycle_deletion_lag_seconds` below 7 days, and `lifecycle_overdue_deletions` at 0 | Section 7 |
| NFR-15 audit integrity, every event archived within 60 s | `audit_archive_lag_seconds` below 120 s (the job runs every minute, data model 2.5), and the job's last success | Section 7 |
| NFR-23 inspection time, p95 at most 60 s and p99 at most 3 min up to 100 MB, p95 at most 10 min up to 2,000,000,000 bytes | `scan_pass_duration_seconds{pool}`, with edges at 60 s, 180 s and 600 s | Section 3 |

**What `time_to_shareable_seconds` measures** (`sft.service.sli`). `kind="transfer"`: from the later of the
transfer's submission and its counted files' last upload completion, to the transfer `sent` with every file
shareable and its recipient emails queued, observed only when the evaluation itself sends it. A transfer that waited
for its sender's confirmation or an approver restarts NFR-5's clock at that act; from there only the email hand-off
remains, NFR-5's 60-second leg, which the outbox age and the probe cover. `kind="request_file"`: from a received
file's upload completing to its scan result recorded `clean`. `size_class` is `small` when the largest counted file
is at most 100 MB, else `large`.

**What `send_latency_seconds` measures** (`sft.service.notifications`, #260): from the outbox message's ID, a UUIDv7
made in the transaction of the change that asked for the email (data model 1), to the provider accepting the email.
So it covers the relay, the `notify` queue and the worker. A link email starts at its `recipient.link_due` message,
which the worker writes when it fans out a sent transfer; the hop before it is measured by
`outbox_oldest_unpublished_age_seconds` and the probe. Every type is measured, for the dashboards; some wait on purpose (a link held by the cross-tenant cap,
an approver's digest, a notice window), so NFR-7's alert reads the three types above.

**What `scan_pass_duration_seconds` measures** (`sft.workers.scan`): from a scan attempt starting, after its tenant's
cap let it in, to its malware and inspection results committed. `pool="small"` serves files up to 100 MB and
`pool="large"` up to 2,000,000,000 bytes (ADR-0019), NFR-23's two classes. Larger files are GuardDuty's, with no
inspection, outside NFR-23.

## 2. The API and the operator API

| Name | Type | Labels | Source | Used by |
|---|---|---|---|---|
| `http_requests_total` | counter | `method`, `route`, `status` | `sft.api.observability` | NFR-1 availability SLO (`ErrorBudgetBurn`); `DownloadCapacity` |
| `http_request_duration_seconds` | histogram | `method`, `route`, `status` | `sft.api.observability` | NFR-2 latency SLO (`ErrorBudgetBurn`) |
| `sft_operator_platform_audit_failures_total` | counter | `action` | `sft.api.operator.app` | `OperatorAuditFailing` (operator change without its platform event) |
| `sft_break_glass_active_grants` | gauge | `self_approved` | `sft.api.operator.app` | `BreakGlassActive`, `BreakGlassSelfApproved` |
| `sft_break_glass_sweep_last_success_timestamp_seconds` | gauge | none | `sft.api.operator.app` | `BreakGlassSweepStalled` |
| `sft_break_glass_tenant_records_missed_total` | counter | none | `sft.api.operator.app` | `BreakGlassTenantRecordsMissed` |
| `sft_break_glass_unrecorded_assignments` | gauge | none | `sft.api.operator.jobs` (#239) | `BreakGlassGrantUnrecorded` |
| `sft_break_glass_records_reconciled_total` | counter | none | `sft.api.operator.jobs` (#239) | `BreakGlassRecordedByReconciliation` |
| `sft_break_glass_reconciliation_last_success_timestamp_seconds` | gauge | none | `sft.api.operator.jobs` (#239) | `BreakGlassReconciliationStalled` |
| `sft_sso_provider_drift` | gauge | `pool`, `problem` | `sft.api.operator.jobs` (#239) | `SsoProviderDrift`, `SsoProviderUnrecorded` |
| `sft_sso_drift_check_last_success_timestamp_seconds` | gauge | none | `sft.api.operator.jobs` (#239) | `SsoDriftCheckStalled` |
| `auth_failures_total` | counter | `scheme` | `sft.api.auth_failures` (#260): the API's and the operator API's authentication points, every scheme at 0 on start | `ApiKeyMisuse` (`scheme="api_key"`, more than 50 in 5 minutes); dashboards |

`route` is the route template (`/v1/transfers/{transfer_id}`), `unmatched` for a path no route serves, so IDs never
become labels; `method` is one of the seven HTTP methods or `other`; `status` is the response's status code.

## 3. Scanning, DLP and time to shareable

| Name | Type | Labels | Source | Used by |
|---|---|---|---|---|
| `time_to_shareable_seconds` | histogram | `kind`, `size_class` | `sft.service.sli` | NFR-5 SLO |
| `scan_pass_duration_seconds` | histogram | `pool` | `sft.workers.scan` | NFR-23 SLO |
| `scan_results_total` | counter | `state`, `reason` | `sft.workers.scan` | `ScanFailed` |
| `scan_deferrals_total` | counter | none | `sft.workers.scan` | Dashboards: tenants at their scan cap |
| `dlp_inspection_seconds` | histogram | none | `sft.workers.scan` | Dashboards: the inspector's own share of NFR-23 |
| `dlp_inspection_results_total` | counter | `state`, `reason` | `sft.workers.scan` | `DlpInspectorFailing` |
| `dlp_inspector_failures_total` | counter | `kind` | `sft.workers.scan` | `DlpInspectorFailing` |
| `guardduty_results_total` | counter | `outcome` | `sft.workers.scan` | The scan-failed runbook; dashboards |
| `clamav_signature_age_seconds` | gauge | none | `sft.workers.scan` | `ClamavSignaturesStale` (T-27: above a day). From clamd's `VERSION` every 5 minutes, computed at each scrape from the database's build time; NaN until clamd first answers |

## 4. The outbox, the queues and the workers

| Name | Type | Labels | Source | Used by |
|---|---|---|---|---|
| `outbox_oldest_unpublished_age_seconds` | gauge | none | `sft.workers.relay` | `OutboxBacklog`, above 120 s (ADR-0013); NFR-5's email leg |
| `outbox_messages_published_total` | counter | `queue` | `sft.workers.relay` | Dashboards |
| `outbox_publish_failures_total` | counter | `queue` | `sft.workers.relay` | Dashboards; `OutboxBacklog` when publishing stops |
| `outbox_relay_batch_duration_seconds` | histogram | none | `sft.workers.relay` | Dashboards |
| `worker_messages_total` | counter | `consumer`, `outcome` | `sft.workers.consumer` | `EmailDeliveryFailing`; dashboards |

Queue age is SQS's own (`ApproximateAgeOfOldestMessage`), which the application doesn't see; it comes through the
CloudWatch exporter (section 9).

## 5. Email, links and rate limits

| Name | Type | Labels | Source | Used by |
|---|---|---|---|---|
| `emails_sent_total` | counter | `type` | `sft.service.notifications` | Dashboards; NFR-7 |
| `email_caps_hit_total` | counter | `cap` | `sft.service.notifications` | Dashboards (abuse 7.2) |
| `send_latency_seconds` | histogram | `type` | `sft.service.notifications` | NFR-7 (`EmailSendSlow`); dashboards. Edges 1, 2.5, 5, 10, 20, 30, 60, 300 and 900 s |
| `link_lookups_total` | counter | `result` | `sft.service.links` | Dashboards (abuse 8.1) |
| `verification_attempts_total` | counter | `result` | `sft.service.links` | Dashboards (abuse 8.1) |
| `verification_codes_total` | counter | `result` | `sft.service.links` | Dashboards (abuse 8.1) |
| `recipient_lockouts_total` | counter | none | `sft.service.links` | Dashboards (NFR-14) |
| `uploader_lockouts_total` | counter | none | `sft.service.links` | Dashboards (NFR-14) |
| `rate_limit_store_errors_total` | counter | none | `sft.data.counters` | `RateLimitStoreUnavailable` |
| `rate_limit_store_latency_seconds` | histogram | none | `sft.data.counters` | Dashboards (ADR-0014: p99 5 ms) |
| `rate_limit_fallback_active` | gauge | none | `sft.data.counters` | `RateLimitStoreUnavailable` |
| `rate_limit_rejections_total` | counter | `group`, `key_type` | `sft.data.counters` | Dashboards (abuse 8.1) |

## 6. Downloads

| Name | Type | Labels | Source | Used by |
|---|---|---|---|---|
| `download_grants_total` | counter | `result` | `sft.service.downloads` | Dashboards; NFR-1's download path |
| `download_streams_active` | gauge | none | `sft.service.downloads` | Dashboards; capacity |
| `download_bytes_total` | counter | none | `sft.service.downloads` | Dashboards; egress |
| `download_streams_ended_total` | counter | `reason` | `sft.service.downloads` | Dashboards |

## 7. The scheduled jobs: lifecycle, purge, audit archive and partitions

Pushed to the Pushgateway by each run (grouping key `job`), so each value is the one the last run left.

| Name | Type | Labels | Source | Used by |
|---|---|---|---|---|
| `lifecycle_job_last_success_timestamp_seconds` | gauge | `job` | `sft.service.lifecycle` | `AuditArchiveJobNotRunning` (`job="audit-archive"`), `MetadataPurgeNotRunning` (`job="purge"`), `LifecycleJobNotRunning` (the others) |
| `lifecycle_items_total` | counter | `job`, `result` | `sft.service.lifecycle` | Dashboards |
| `lifecycle_deletion_lag_seconds` | gauge | none | `sft.service.lifecycle` | `FileDeletionLagging` (NFR-8) |
| `lifecycle_overdue_deletions` | gauge | none | `sft.service.lifecycle` | `FileDeletionOverdue` (NFR-8) |
| `lifecycle_unarchived_grants` | gauge | none | `sft.service.lifecycle` | `UnarchivedGrants` (NFR-15: grants whose committed record waits) |
| `metadata_purge_rows_total` | counter | `kind` | `sft.service.lifecycle` | Dashboards (NFR-9) |
| `metadata_purge_blocked` | gauge | `kind` | `sft.service.lifecycle` | `MetadataPurgeBlocked` |
| `metadata_purge_lag_seconds` | gauge | none | `sft.service.lifecycle` | `MetadataPurgeBehind` |
| `dlp_approval_oldest_pending_age_seconds` | gauge | none | `sft.service.lifecycle` | Dashboards; the `DlpApprovalBacklog` runbook (FR-43). The expiry job's |
| `dlp_approval_pending_timeout_used_ratio` | gauge | none | `sft.service.lifecycle` | `DlpApprovalBacklog` (`pending_half_timeout`, above 0.5; abuse 8.2). The largest share of its tenant's approval timeout a pending request has used |
| `audit_archive_lag_seconds` | gauge | none | `sft.service.archive_job` | `AuditArchiveLagging`, NFR-15 SLO |
| `audit_archive_events_total` | counter | `region` | `sft.service.archive_job` | Dashboards: both regions keep pace |
| `audit_archive_write_failures_total` | counter | `region` | `sft.service.audit_archive` | `AuditArchiveLagging` runbook; the API's security-critical writes too |
| `audit_archive_single_region_ranges` | gauge | none | `sft.service.archive_job` | `AuditArchiveSingleRegion` (#257): ranges written to one region alone during a regional loss, waiting for the back-fill |
| `sft_audit_default_partition_rows` | gauge | none | `sft.service.audit_partitions` | `AuditPartitions` (data model 6) |
| `sft_audit_partition_months_covered` | gauge | none | `sft.service.audit_partitions` | `AuditPartitions` (data model 6) |
| `sft_audit_partition_last_success_timestamp_seconds` | gauge | none | `sft.service.audit_partitions` | `AuditPartitions` |
| `sft_audit_expired_partitions` | gauge | none | `sft.service.audit_partitions` | `AuditPartitions` (`expired_present`; NFR-9, #255) |

`job` is the CronJob's name: `expiry`, `deletion`, `reconciliation`, `storage-audit`, `cleanup`, `purge`,
`audit-partitions` or `audit-archive`. `audit_archive_write_failures_total` counts the archive job's batch writes and
the API's security-critical records together, by region; the API's series are scraped and the job's pushed, so their
`job` label tells them apart.

## 8. Keys

| Name | Type | Labels | Source | Used by |
|---|---|---|---|---|
| `field_key_unwraps_total` | counter | `purpose`, `result` | `sft.service.fields` | `FieldKeysUnavailable` |
| `field_decrypt_scope_mismatch_total` | counter | `purpose` | `sft.service.fields` | `FieldDecryptScopeMismatch` |
| `field_plaintext_reads_total` | counter | `column` | `sft.service.fields` | Dashboards: the backfill's progress (#236) |
| `sft_keyring_refresh_failures_total` | counter | `keyring` | `sft.runtime.secrets` | `KeyringRefreshFailing` |
| `sft_keyring_refreshed_timestamp_seconds` | gauge | `keyring` | `sft.runtime.secrets` | Dashboards |
| `keyring_active_key_age_seconds` | gauge | `keyring` | `sft.runtime.secrets` (#260), where each process loads and reloads its keyrings: `CSRF`, `email`, `code`, `link` | `KeyringKeyTooOld` (encryption 6.5: its period plus 7 days) |

## 9. From outside the application

Not defined in our code, so the catalogue test doesn't look for them there. The CloudWatch exporter's names follow its
defaults, `aws_<namespace>_<metric>_<statistic>` in snake case, as deploy/alerts/scanning.rules.yaml already reads
them; the exporter's configuration ([observability.md](observability.md)) decides which it scrapes.

| Name | Type | Labels | Source | Used by |
|---|---|---|---|---|
| `aws_sqs_approximate_age_of_oldest_message_maximum` | gauge | `dimension_QueueName` | CloudWatch exporter (OBS, #243) | Dashboards; the `<queue>-age` alarms read CloudWatch directly; NFR-5 |
| `aws_sqs_approximate_number_of_messages_visible_maximum` | gauge | `dimension_QueueName` | CloudWatch exporter (OBS, #243) | `ScanFailed` (dead-letter queues); worker dead-letter alerts |
| `aws_applicationelb_httpcode_elb_5_xx_count_sum` | gauge | `dimension_LoadBalancer` | CloudWatch exporter (OBS, #243) | NFR-1: the load balancer's own `5xx` |
| `aws_applicationelb_request_count_sum` | gauge | `dimension_LoadBalancer` | CloudWatch exporter (OBS, #243) | NFR-1: requests the pods never saw |
| `aws_rds_aurora_global_dbreplication_lag_maximum` | gauge | `dimension_DBClusterIdentifier` | CloudWatch exporter (OBS, #243) | Dashboards; the `database-rpo-lag` alarm reads CloudWatch directly (NFR-10) |
| `aws_rds_cpuutilization_average`, `aws_rds_database_connections_average` | gauge | `dimension_DBClusterIdentifier` | CloudWatch exporter (OBS, #243) | Dashboards; the `database-cpu` alarm reads CloudWatch directly |
| `aws_applicationelb_httpcode_target_5_xx_count_sum` | gauge | `dimension_LoadBalancer` | CloudWatch exporter (OBS, #243) | Dashboards |
| `aws_s3_operations_pending_replication_maximum` | gauge | `dimension_SourceBucket`, `dimension_DestinationBucket`, `dimension_RuleId` | CloudWatch exporter (OBS, #243) | Dashboards |
| `aws_s3_replication_latency_maximum` | gauge | `dimension_SourceBucket`, `dimension_DestinationBucket`, `dimension_RuleId` | CloudWatch exporter (OBS, #243) | Dashboards; the `files-replication-*` alarms read CloudWatch directly (NFR-10) |
| `push_time_seconds` | gauge | `job` | The Pushgateway itself (OBS, #243) | When each job last pushed, whether it succeeded or not |

## 10. The synthetic probe

`sft.probe` (#248) runs as a CronJob every 5 minutes and pushes each run's result to the Pushgateway with
`pushadd`, under the grouping key `job="sft-synthetic-probe"`, so a failed run leaves the last success time as it was.
It also puts CloudWatch `SecureFileTransfer/Probe` `ProbeSuccess` (1 or 0) by `Environment`, and by `Environment` and
`ImageDigest`, which the `probe-failing` alarm and the promotion gate read (docs/runbooks/synthetic-probe.md).

| Name | Type | Labels | Source | Used by |
|---|---|---|---|---|
| `synthetic_probe_success` | gauge | none | `sft.probe.report` | `SyntheticProbeFailing`; the NFR-1 dashboard |
| `synthetic_probe_last_success_timestamp_seconds` | gauge | none | `sft.probe.report` | `SyntheticProbeStale` |
| `synthetic_probe_step_failures_total` | counter | `step` | `sft.probe.report` | The runbook: which step failed (1 on it, 0 on the others, each run) |
| `synthetic_probe_duration_seconds` | gauge | none | `sft.probe.report` | Dashboards: NFR-5 end to end, the email included |
| `synthetic_probe_step_duration_seconds` | gauge | `step` | `sft.probe.report` | Dashboards: where a run's time went |
| `synthetic_probe_download_first_byte_seconds` | gauge | none | `sft.probe.report` | Dashboards: NFR-4's synthetic measure |

`step` is one of the probe's steps (`sft.probe.journey.STEPS`): `edge`, `create`, `upload`, `send`, `shareable`,
`link_email`, `verify`, `download`, `revoke`.

## 11. Labels

The closed list of label names, which tests/test_sli_metrics.py holds the code to:

| Label | Values |
|---|---|
| `method` | `GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE`, `OPTIONS`, `other` |
| `route` | A route template of the API, or `unmatched` |
| `status` | An HTTP status code |
| `region` | `ap-northeast-1`, `ap-northeast-3` |
| `job` | A scheduled job's name (section 7) |
| `kind` | `transfer` or `request_file` (time to shareable); `transfer` or `upload_request` (the purge); a failure's kind (the inspector) |
| `size_class` | `small` (up to 100 MB), `large` |
| `pool` | `small`, `large` |
| `step` | A step of the synthetic probe (section 10) |
| `scheme` | `session`, `api_key`, `operator`, `link`: how a caller authenticated (`auth_failures_total`) |
| `state`, `reason`, `result`, `outcome`, `type`, `cap`, `group`, `key_type`, `queue`, `consumer`, `purpose`, `column`, `keyring`, `action`, `self_approved`, `problem` | Codes from enums or fixed lists in the module named in the Source column |

A detector ID may appear in a label (NFR-26 allows IDs and counts); no metric has one today.
