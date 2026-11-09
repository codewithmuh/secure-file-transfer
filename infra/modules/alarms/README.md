# alarms module

The AWS-side alarms of [ADR-0009](../../../docs/adr/0009-observability-opentelemetry-self-hosted.md) (A34): the
out-of-cluster watchdog, and what CloudWatch watches on the AWS services under the application, so that a dead
cluster, or a fault Prometheus can't see well, still pages. Written by
[#246](https://github.com/codewithmuh/secure-file-transfer/issues/246) and called once per Region by the `alarms`
layer (`infra/environments/<env>/<region>/alarms`), applied after every other layer of its Region. Nothing here has been
applied (infra/README.md); every alarm below is pending the AWS run.

Prometheus's rules in [`deploy/alerts`](../../../deploy/alerts/) watch the application: SLO burn rates, the outbox,
the scan pipeline, the egress proxy. This module watches the AWS services under it. One signal is alarmed in one place:
the scan dead-letter queues are the in-cluster `ScanFailed` alert's, so they aren't repeated here.

## Topics

| Topic | Region | Who publishes | Who subscribes |
|---|---|---|---|
| `sft-<env>-<rs>-alerts-page` | Each | CloudWatch alarms named `sft-<env>-*`; Alertmanager's role `sft-<env>-alertmanager` | `TF_VAR_alert_emails` |
| `sft-<env>-<rs>-alerts-ticket` | Each | The same | `TF_VAR_alert_emails` |
| `sft-<env>-<rs>-heartbeat` | Each | Alertmanager only, once a minute, for the always-firing `Watchdog` alert | Nobody: the heartbeat alarm counts its messages |
| `sft-<env>-<rs>-break-glass-alerts` | Each | Made by [`break-glass-role`](../break-glass-role/README.md) | `TF_VAR_alert_emails`, subscribed here |
| `sft-<env>-apne1-region-health-page` and `-ticket` | us-east-1, Tokyo's stack only | The Route 53 health check alarms | `TF_VAR_alert_emails` |

The Regions' topics use the platform key, whose policy already admits CloudWatch alarms named `sft-<env>-*`
([encryption](../../../docs/security/encryption-and-keys.md) 3.1, 4.4). The us-east-1 topics need a key there, and no
Japanese key may be replicated outside Osaka (rule 4), so Tokyo's stack makes one small key, `alias/sft/<env>/alarms`,
for those two topics only, with the common key policy of [`key-policy`](../key-policy/README.md) and one statement for
CloudWatch alarms; 7 days' deletion window in dev and staging, 30 in prod (encryption 8.3). Each topic denies
publishing to everyone but its publishers, and changes to everyone but the deploy role, as the break-glass topic does.
Every address confirms its subscription once, from the message SNS sends it.

## Alarms

Every alarm is `sft-<env>-<rs>-<what>`, which the keys' policies and SCP 3 match, and names its severity and its
runbook, as a literal URL, in its description; `deploy/tests/test_runbooks.py` fails if one doesn't or the runbook is
missing (NFR-17). Pages notify the page topic, tickets the ticket topic, and both notify again when the alarm clears.

| Alarm | Where | Fires when | Severity | Runbook |
|---|---|---|---|---|
| `heartbeat-missing` | Each Region; Osaka's doesn't notify in the pilot light | No message on the heartbeat topic for 5 minutes; missing data breaches | Page | [watchdog](../../../docs/runbooks/watchdog.md) |
| `database-rpo-lag` | Osaka (staging, prod) | `AuroraGlobalDBRPOLag` over 60 s for 5 minutes (ADR-0011, NFR-10) | Page | [database-replication-lag](../../../docs/runbooks/database-replication-lag.md) |
| `database-cpu`, `database-memory` | Tokyo (and dev's standalone cluster) | The writer's CPU over 80 %, or its freeable memory under about a tenth of the instance's, for 15 minutes | Ticket | [database-capacity](../../../docs/runbooks/database-capacity.md) |
| `<queue>-dlq` | Each Region | A message in the `notify`, `signin-events`, `ses-events` or `ses-tenant-status` dead-letter queue (ADR-0013) | Page | [dead-letter-queue](../../../docs/runbooks/dead-letter-queue.md) |
| `<queue>-age` | Each Region | The oldest message older than: `signin-events` 30 s for 3 min (authn-authz 2.4), `notify` 60 s for 5 min (NFR-7), `scan-small` 5 min for 10 min (NFR-5) as pages; `scan-large` 15 min, `ses-events` and `guardduty-results` 10 min, for 15 min, as tickets | Page or ticket | [queue-backlog](../../../docs/runbooks/queue-backlog.md) |
| `<files\|large-files>-replication-failed`, `-replication-latency` | Tokyo (staging, prod) | Any failed replication, or a replica more than 15 minutes late (RTC, NFR-10) | Page | [file-replication](../../../docs/runbooks/file-replication.md) |
| `api-lb-5xx` | Each Region | The load balancer answers more than 10 5xx of its own a minute for 5 minutes | Page | [service-unavailable](../../../docs/runbooks/service-unavailable.md) |
| `api-no-healthy-targets` | Each Region; Osaka's doesn't notify in the pilot light | No healthy API target for 3 minutes | Page | [service-unavailable](../../../docs/runbooks/service-unavailable.md) |
| `nat-<id>-port-allocation`, `nat-<id>-packet-drops` | Each NAT gateway | Any port allocation error, or more than 0.01 % of packets dropped for 15 minutes | Ticket | [nat-gateway](../../../docs/runbooks/nat-gateway.md) |
| `kms-quota` | Each Region | Symmetric KMS requests above 80 % of the account's quota for 5 minutes | Ticket | [kms-throttling](../../../docs/runbooks/kms-throttling.md) |
| `ses-reputation` | Each Region | `SesReputation` (abuse 8.2): bounce rate ≥ 2 % or complaint rate ≥ 0.05 % for 3 hours | Page | [ses-reputation](../../../docs/runbooks/ses-reputation.md) |
| `signin-trigger-errors`, `-throttles` | Each Region | The sign-in trigger fails more than 5 times in 5 minutes, or is throttled at all (T-89) | Page | [signin-trigger](../../../docs/runbooks/signin-trigger.md) |
| `<rs>-region-health` | us-east-1, made by Tokyo's stack | A Region's Route 53 health check fails for 3 minutes: Tokyo's pages, Osaka's raises a ticket | Page or ticket | [region-health](../../../docs/runbooks/region-health.md) |

Not here, and why:

- **The audit archive's replication**: it runs without RTC, so it has no replication metrics. Security-critical
  records go to both Regions directly (architecture 5.2), and the reconciliation job compares the archives.
- **The age of `ses-tenant-status`**: nothing consumes it yet (abuse 7.3), so its age would always breach. Its
  dead-letter queue is alarmed.
- **A KMS throttle count**: KMS publishes none; usage against the quota warns before throttling.
- **The egress proxy**: it runs in the cluster, so its health is a Prometheus alert; the NAT gateways under it are here.

## The pilot light and a failover

Osaka's stack makes every alarm, so a failover only switches them on. During the pilot light,
`TF_VAR_heartbeat_enabled` (default `false` in Osaka) keeps the heartbeat alarm from notifying, since no
observability stack runs there (ADR-0009), and `TF_VAR_pilot_light` (default `true` in Osaka) does the same for the API
target alarm, whose target group is empty by design. The failover runbook applies Osaka's `alarms` stack with
`TF_VAR_heartbeat_enabled=true TF_VAR_pilot_light=false`, and the failback applies it with the defaults again.
Osaka's database alarms follow its role: the writer's CPU and memory alarms need `database.role` to say it is no longer
the secondary.

**The synthetic probe's alarm** (`probe.tf`, #248): `probe-failing` pages when `SecureFileTransfer/Probe`
`ProbeSuccess` for the environment has no 1 for two 5-minute periods, missing data included. It exists only with
`TF_VAR_probe_enabled=true`, set once the environment's probe runs (`probe.enabled` in its values file); before that,
missing data would page for good. It doesn't notify in Osaka's pilot light.

## Inputs worth knowing

| Input | Notes |
|---|---|
| `alert_emails` | Who the alerts reach: `TF_VAR_alert_emails`, a JSON list, at apply time. Never committed; at least one address |
| `database` | The cluster's identifier and role from the `data` state, and the FreeableMemory floor in bytes |
| `replicated_buckets` | Tokyo's files buckets and their Osaka replicas; empty in dev and in Osaka |
| `region_health` | Tokyo's stack only: both Regions' health check IDs (from each `edge` state) and what the us-east-1 key needs |

The `alarms` roots read the `network`, `data` and `edge` states of their Region; Tokyo's in staging and prod also reads
Osaka's `edge` state for its health check, so Osaka's `edge` goes first. The NAT gateways come from the VPC by a data
source, so the network stack needs no new output.

## Count and cost

| Environment | Tokyo | Osaka | Total | Capacity A34 |
|---|---|---|---|---|
| prod | 31 | 24 | 55 | 60 |
| staging | 31 | 24 | 55 | 40 |
| dev | 22 | — | 22 | 10 |

The probe's alarm adds one per Region once it is on. Staging carries prod's alarms, since the drills run there first, and dev the same set on one Region, so both are above
A34's estimate. At $0.10 per alarm and per metric in a metric math alarm (the NAT drop alarms read three metrics, the SES
reputation alarm two), that is under $8 a month for prod, about $1.50 more than A34 for staging and $2 for dev: noise
against capacity 7.3's totals. The us-east-1 key adds $1 a month per environment.

## Requests outside this module

- **Alertmanager's role**, `sft-<env>-alertmanager` (the observability stack, #243, `modules/observability`):
  `sns:Publish` on the three topics of its Region, and the platform key statement `AlertmanagerPublishesToAlertTopics`
  in `modules/kms-keys` that lets it use the key through SNS. Both exist; until they are applied, the heartbeat alarm
  pages, which is the point.
