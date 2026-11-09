# Service level objectives and alerting

The objectives the operating period is measured against, how each is measured, and how the alerts that guard them
work (NFR-1, NFR-2, NFR-5, NFR-10, NFR-17, NFR-23; [ADR-0009](../adr/0009-observability-opentelemetry-self-hosted.md);
[#245](https://github.com/codewithmuh/secure-file-transfer/issues/245), [#246](https://github.com/codewithmuh/secure-file-transfer/issues/246)).
Every alert and alarm has a runbook, listed in the [runbook index](../runbooks/README.md).

> [!IMPORTANT]
> **Nothing here has run against real traffic.** The rules pass their promtool tests and the alarms pass Terraform's
> static checks; whether each fires in AWS, and how noisy it is, is pending the AWS run (staging first, then prod).

## 1. Objectives

Each objective is measured over a rolling **28 days** while prod runs (NFR-1), from Prometheus, which keeps 30 days in
prod (ADR-0009). Drill windows are left out (section 4). The error budget is the share of events allowed to be bad.

| Objective | Indicator (bad events / all events) | Target | Error budget | `slo` label |
|---|---|---|---|---|
| NFR-1 availability | API responses with a 5xx status / all API responses, the download path included (`http_requests_total`) | 99.9 % good | 0.1 % (about 40 minutes of full outage in 28 days) | `availability` |
| NFR-2 latency, p95 | API calls slower than 300 ms / all API calls, without the routes that move file bytes (the download stream, the audit export; uploads go straight to S3) (`http_request_duration_seconds`) | 95 % within 300 ms | 5 % | `latency-p95` |
| NFR-2 latency, p99 | The same calls slower than 1 s | 99 % within 1 s | 1 % | `latency-p99` |
| NFR-5 time to shareable, small | Transfers whose largest file is up to 100 MB, and such files of upload requests, shareable after more than 2 minutes / all of them (`time_to_shareable_seconds{size_class="small"}`) | 95 % within 2 minutes | 5 % | `time-to-shareable-small` |
| NFR-5 time to shareable, large | The rest, up to 20 GB, after more than 15 minutes (`size_class="large"`) | 95 % within 15 minutes | 5 % | `time-to-shareable-large` |
| NFR-23 scan and inspection, small, p95 | Files of the small pool (up to 100 MB) whose scan took more than 60 s from start to both results recorded (`scan_pass_duration_seconds{pool="small"}`) | 95 % within 60 s | 5 % | `scan-pass-small-p95` |
| NFR-23, small, p99 | The same files over 3 minutes | 99 % within 3 minutes | 1 % | `scan-pass-small-p99` |
| NFR-23, large, p95 | Files of the large pool, up to 2,000,000,000 bytes, over 10 minutes (`pool="large"`) | 95 % within 10 minutes | 5 % | `scan-pass-large-p95` |

Two indicators of NFR-1 aren't in Prometheus's figure: a timeout or an error the load balancer answers itself never
reaches the API's metrics, so the `api-lb-5xx` and `api-no-healthy-targets` alarms watch them; and the **synthetic
probe** (#248) runs the whole send → verify → download journey every 5 minutes and pages when it fails for 10 minutes
(`SyntheticProbeFailing`, and `SyntheticProbeStale` when it stops reporting). The probe's tenant is excluded from
product metrics (NFR-1), but its API calls count here, as any client's do.

**NFR-10 (recovery point)** isn't an error budget: it is a bound on how far Osaka may lag. CloudWatch alarms watch it
where the signals are: `database-rpo-lag` pages when Osaka's database replica is more than a minute behind for
5 minutes (NFR-10 allows 5), and the files buckets' `replication-latency` and `replication-failed` alarms page past
S3 Replication Time Control's 15 minutes or on any failed object. The drills measure it (NFR-10, NFR-11).

**Not yet measured as objectives**, each for want of a metric (section 6): NFR-5's 60 seconds from a confirmation or
approval to the recipient emails; NFR-7's 10 seconds to hand an email to SES (the `notify-age` alarm and
`EmailDeliveryFailing` stand in); NFR-4's 1 second to the first byte, which comes from the web app's timing and the
probe.

The histograms behind NFR-5 and NFR-23 come from the API and the scan worker (#242,
[metrics](metrics.md)). Their buckets must include each threshold above (120, 900, 60, 180 and 600 seconds),
because the rules count the events in the bucket at the threshold.

## 2. Recording rules

[`deploy/alerts/slo.rules.yaml`](../../deploy/alerts/slo.rules.yaml) records, for each `slo` and each window `<w>` of
5m, 30m, 1h, 2h, 6h, 1d and 3d:

| Series | Meaning |
|---|---|
| `slo:sli_error:ratio_rate<w>{slo}` | The share of bad events in the window |
| `slo:sli_events:rate<w>{slo}` | Events per second in the window |
| `slo:error_budget{slo}` | The budget, a constant per objective |
| `slo:sli_error:ratio_28d{slo}` | The share of bad events over 28 days, drill windows left out: the figure the operating period reports |
| `slo:error_budget_remaining:ratio_28d{slo}` | 1 for a full budget, 0 for an empty one, below 0 for a missed objective |

These names are the contract with the SLO dashboard (#244).

## 3. Burn-rate alerts

The **burn rate** is the share of bad events divided by the budget: at 1 the budget lasts exactly 28 days. One alert,
`ErrorBudgetBurn`, labelled with its `slo`, follows the multi-window, multi-burn-rate pattern of the Google SRE
workbook (chapter 5):

| Severity | Burn rate | Long window | Short window | Budget spent when it fires | `for` |
|---|---|---|---|---|---|
| Page | 14.4 | 1 h | 5 m | 2 % in an hour | 2 m |
| Page | 6 | 6 h | 30 m | 5 % in six hours | 2 m |
| Ticket | 3 | 1 d | 2 h | 10 % in a day | 15 m |
| Ticket | 1 | 3 d | 6 h | 10 % in three days | 15 m |

Both windows must be over the line, so an alert stops soon after the burn does. Each alert also needs 10 events in its
long window (6 hours for a page, 3 days for a ticket): one slow file in a quiet hour of staging is not a page. While a
page fires, Alertmanager holds back the ticket for the same `slo`.

The thresholds are a starting point. Staging's first weeks show how noisy they are; a change to a window, a burn rate
or a budget is a reviewed change to the rules and this table.

## 4. Drills

NFR-1 says planned drill windows that take prod down are logged and reported separately, not counted. A drill marks
its window itself: when it starts, it pushes `sft_drill_active{drill="<name>"} 1` to the cluster's Pushgateway, and
when it ends it deletes it (the drill scripts in `ops/`, [drill-in-progress.md](../runbooks/drill-in-progress.md)).
While the marker is there:

- `DrillInProgress` fires, as a ticket, so a marker left behind is noticed;
- Alertmanager inhibits every page and ticket except those labelled `security="true"` (break-glass, a tenant
  isolation breach, an operator's unrecorded action): a drill is no cover for an insider;
- the 28-day figures leave those 5-minute intervals out (`slo:sli_bad_outside_drills:rate5m`,
  `slo:sli_events_outside_drills:rate5m`);
- the CloudWatch alarms still notify: they can't see the marker. The drill's runbook says which to expect.

The Watchdog keeps flowing, so a drill that takes the whole cluster down still pages from CloudWatch, which is what
it should do. A real regional failure is not a drill and is expected to breach NFR-1; NFR-11 bounds the recovery.

## 5. Routing

| What | Where it goes |
|---|---|
| Prometheus alerts with `severity="page"` | Alertmanager → `sft-<env>-<rs>-alerts-page`, re-sent hourly while firing |
| Prometheus alerts with `severity="ticket"` | Alertmanager → `sft-<env>-<rs>-alerts-ticket`, re-sent daily |
| `Watchdog` (`severity="heartbeat"`) | Alertmanager → `sft-<env>-<rs>-heartbeat` every minute; CloudWatch's `heartbeat-missing` alarm pages after 5 minutes without one |
| CloudWatch alarms | The Region's page or ticket topic directly, never through the cluster |
| Route 53 health check alarms | `sft-<env>-apne1-region-health-page` and `-ticket` in us-east-1, where Route 53 publishes (NFR-21) |
| Break-glass EventBridge alerts | `sft-<env>-<rs>-break-glass-alerts` (infra/modules/break-glass-role) |

The operators' addresses (`TF_VAR_alert_emails`) subscribe to every topic but the heartbeat. A pager service, when
there is one, subscribes to the page topics. Routing is [`deploy/alerts/alertmanager.yaml`](../../deploy/alerts/alertmanager.yaml),
checked and route-tested by [`deploy/alerts/test.sh`](../../deploy/alerts/test.sh); the topics and alarms are
[`infra/modules/alarms`](../../infra/modules/alarms/README.md). Osaka's heartbeat alarm stays off during the pilot
light, when no stack runs there to send one; the failover turns it on (ADR-0009, architecture 7).

**Why the heartbeat is an SNS topic.** ADR-0009 asks for a heartbeat metric in CloudWatch every minute. Alertmanager
can't write a metric, but it can publish to SNS, and SNS counts what each topic receives as
`AWS/SNS NumberOfMessagesPublished`. So the Watchdog's repeat every minute is the heartbeat, with nothing new to run:
no exporter, no sidecar. Missing data counts as breaching, so a stack that is gone pages as surely as one that stops.

## 6. Coverage

Every alert the design promises, and where it stands. "Pending a metric" means the signal doesn't exist in the code
yet; each is listed for the APP track and later issues, and the alert follows its metric.

### Architecture 6, failure handling

| Failure | Alert or alarm |
|---|---|
| Scan engine down or slow | `ScanFailed`; `scan-small-age`, `scan-large-age`; `ErrorBudgetBurn` for `scan-pass-*` and `time-to-shareable-*` |
| DLP inspector down, slow or crashing | `DlpInspectorFailing`; `ErrorBudgetBurn` for `scan-pass-*` (NFR-23's p95, which abuse 8.2 lists under `DlpInspectorFailing`) |
| Approvals not decided | `DlpApprovalBacklog` (no eligible approver); the oldest pending request's age is pending a metric |
| Email provider failing or throttling | `EmailDeliveryFailing`, `notify-age`, `notify-dlq`, `ses-events-dlq`, `ses-reputation` |
| Outbox relay stopped | `OutboxBacklog` (age over 2 minutes, or no relay reporting) |
| API pod or node lost | `ErrorBudgetBurn` (`availability`), `api-no-healthy-targets`, `SyntheticProbeFailing` |
| One AZ lost | The same, with `database-*` alarms; AWS Health events aren't alerted on (below) |
| Tokyo region lost | `apne1-region-health`, `heartbeat-missing`, `api-lb-5xx` |
| Audit archive behind | `AuditArchiveLagging`, `AuditArchiveJobNotRunning` (`lifecycle.rules.yaml`, #183) |
| Osaka archive unreachable | `AuditArchiveWriteFailing` |
| Egress proxy down | `EgressProxyDown`; `heartbeat-missing` when Alertmanager can't reach SNS through it |
| Rate-limit counters unavailable | `RateLimitStoreUnavailable` |
| Cognito unavailable in Tokyo | `signin-trigger-errors`, `signin-trigger-throttles`, `signin-events-age`, `signin-events-dlq`; Cognito's own sign-in metrics are pending (below) |
| File replication lagging | `files-replication-latency`, `large-files-replication-latency`, `*-replication-failed` |
| Bad deploy | `ErrorBudgetBurn` (`availability`, `latency-*`), `ArgoCdApplicationUnhealthy` |
| Bad migration or data corruption | No alert of its own: errors burn the budget; the reconciliation report and the restore runbook take it from there |

### Abuse and rate limits 8.2

| Alert | Status |
|---|---|
| `RateLimitStoreUnavailable`, `LinkProbing`, `VerificationGuessing`, `EmailBombing`, `DownloadCapacity` | Prometheus rules, as specified. `EmailBombing` counts cap hits, not distinct addresses: no metric carries an address. |
| `ApiKeyMisuse` | The "held at its limit" half. Bearer authentication failures are pending a metric (`auth_failures_total{scheme}`). |
| `SesReputation` | CloudWatch alarm `ses-reputation` |
| `DlpApprovalBacklog` | The "no eligible approver" half; the age half is pending a metric (`dlp_oldest_pending_approval_seconds`) |
| `ScanFailed`, `DlpInspectorFailing` | Prometheus rules (#175, #176) |
| `TenantSendingPaused`, `TenantSendingSpike` | Pending: SES's tenant status rule and its consumer, and our worker's own pause, aren't built; a per-tenant rate needs the logs (Loki), as abuse 8.1 says |
| `CredentialStuffing`, `SignInWafBlocks` | Pending: Cognito's sign-in metrics and the sign-in web ACL's `rate-token-nat` blocks, as CloudWatch alarms with the `credential-stuffing` runbook |
| `HttpFlood` | Pending: WAF's blocked requests through the CloudWatch exporter, combined with a burn alert |
| `TenantQuota`, `ScanEvasion`, `DlpEvasion` | Pending a metric: each is per tenant (`tenant_quota_used_ratio`, `dlp_decisions_total`), which Prometheus can't carry without a tenant label; they need the logs |

### Other alerts the design promises

| Promise | Status |
|---|---|
| Break-glass, field keys, operator records ([authn-authz](../security/authn-authz.md) 8, [encryption](../security/encryption-and-keys.md) 3) | Prometheus rules (`break-glass`, `field-encryption`, `operator`), never inhibited; the break-glass role's EventBridge alert (#232) |
| Audit partitions (data model 6) | `AuditPartitions` |
| File deletion within 7 days (NFR-8), the lifecycle jobs running, grants awaiting their record (NFR-15) | `FileDeletionOverdue`, `FileDeletionLagging`, `LifecycleJobNotRunning`, `UnarchivedGrants` (`lifecycle.rules.yaml`) |
| Metadata purge (NFR-9) | `MetadataPurgeBlocked`, `MetadataPurgeBehind`, `MetadataPurgeNotRunning` |
| The synthetic probe (NFR-1) | `SyntheticProbeFailing`, `SyntheticProbeStale`; the `probe-failing` alarm once the probe runs |
| Keyring refresh (encryption 6.4) | `KeyringRefreshFailing`. "A keyring's active key older than its period plus 7 days" (encryption 6) is pending a metric. |
| KMS: key policy, disable, deletion and grant changes, the key-admin role, use of a key pending deletion (encryption 4.4, 8.3; T-61) | Pending: EventBridge rules on CloudTrail, like the break-glass role's |
| People: BreakGlass and Admin sign-ins, the emergency user, root sign-in, exec into application pods (authn-authz 8.3, 8.4; T-64, T-74) | Pending: EventBridge rules and an EKS audit log metric filter |
| Security services turned off (T-75), the cluster endpoint opened (ADR-0021) | Pending: EventBridge rules |
| CloudFront's 5xx rate, in us-east-1 (architecture 5.5) | Pending: an alarm beside the region-health ones |
| ClamAV signatures over 24 hours old (T-27) | Pending a metric |
| Valkey near its size limit ([valkey](../../infra/modules/valkey/README.md)) | Pending: an `ElastiCache BytesUsedForCache` alarm |
| Argo CD sync and health (architecture 6) | `ArgoCdApplicationUnhealthy` |
| Kyverno background report violations (ADR-0007) | Pending: Kyverno's policy report metric, once the observability stack scrapes it |
| The retained stack's EventBridge rules and NFR-19 budget (encryption 8.4) | The DR track (#254, `infra/environments/prod/retained`) |

The security EventBridge rules are the largest gap. They need no new metric, only rules, an alert topic per Region and
their runbooks, and they are the next issue after M7's alerting.

## 7. Checks

- `deploy/alerts/test.sh`: `promtool check rules` and `promtool test rules` on every rule file, with a test case that
  fires each rule; `amtool check-config` and route tests on `alertmanager.yaml`.
- `deploy/tests/test_runbooks.py`: every alert and every CloudWatch alarm names a runbook that exists, every alert has
  a page or ticket severity and a firing test, and the runbook index lists them; it plants an alert and an alarm
  without a runbook to show that it fails.
- `infra/scripts/check.sh`: fmt, validate, tflint, Trivy and the `alarms` module's tests.
- Pending the AWS run: each alarm's metric and dimensions against real resources, Alertmanager's SNS calls through the
  egress proxy, the heartbeat alarm's behaviour when the stack stops, the probe's metric in the promotion gate, and
  the thresholds' noise in staging.
