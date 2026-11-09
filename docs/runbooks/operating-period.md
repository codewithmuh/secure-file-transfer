# Runbook: the operating period

Prod runs for a bounded period, the end-to-end operating period of the PRD, then is destroyed (NFR-19). This page
says what runs during it, what it may cost, what the maintainer checks each day and week, and how it ends. Its
length is Rashid's call (PRD open question 7); every extra month costs about $5,290 and every extra day of prod about
$131 (capacity 7.3).

> [!IMPORTANT]
> **Pending the AWS run.** The operating period starts once prod is applied, after every milestone is coded.

## What runs

| What | Where | Notes |
|---|---|---|
| prod | Tokyo, with Osaka's pilot light (architecture 3.1, 3.2) | Scenario (a) of capacity section 1: fixed infrastructure, the synthetic probe and a few demo users, about $3,990 a month |
| The synthetic probe | prod, every 5 minutes | The NFR-1 SLI's journey, from the synthetic tenant |
| Load-test windows | prod, up to two a month | k6 at 1× and 2× design load (NFR-16), sampled bytes (capacity 7.3) |
| Drills | staging first, then prod, once each in the period | AZ failure, regional failover and failback, point-in-time restore ([disaster-recovery.md](../operations/disaster-recovery.md) section 6) |
| dev and staging | Up only when used | Torn down when idle ([teardown.md](teardown.md), NFR-20) |
| The retained stack | prod account | From prod's creation; it outlives the period |

## The monthly cap

AWS Budgets (infra/organization/budgets.tf, NFR-20): **$6,500 a month** in total, with per-account budgets of shared
$20, dev $500, staging $800 and prod $5,180, alarming at 50 % actual and 80 % and 100 % actual and forecast. The
planned month with both load-test windows and one drill is $5,292, 81 % of the cap and past its 80 % alarm, so
capacity 7.3 recommends raising the cap to $7,500 or cutting about $490 a month; until Rashid decides, the cap is
$6,500, and the 80 % alarm is expected in a month with both load-test windows.

When an alarm fires: the 50 % alarm before day 15 means spend is running ahead (look for an environment left up, or
a load test's nodes still running); the 80 % and 100 % alarms on actual spend mean stop the next load-test window,
tear down dev and staging, and check Cost Explorer by `environment` and `component` against capacity section 5.

## Daily checks (about 10 minutes)

1. **Alerts.** Anything that paged or ticketed since yesterday is answered or has an issue (every alert has a
   runbook, NFR-17).
2. **SLOs.** The SLO dashboard (port-forward to Grafana): NFR-1 availability over the rolling 28 days and its error
   budget left; NFR-2 latency; NFR-5 time to shareable. Drill windows are logged apart.
3. **The probe.** `ProbeSuccess` stayed 1, and the last success is under 10 minutes old.
4. **Recovery readiness.** `AuroraGlobalDBRPOLag` under a minute, S3 replication latency inside RTC's 15 minutes,
   the audit archive lag under 2 minutes, and Osaka's pilot light as Git holds it (one `system` node, every workload
   at zero).
5. **Lifecycle.** The expiry, deletion, reconciliation and audit jobs ran (`lifecycle_job_last_success_timestamp_seconds`
   for each); the reconciliation report has no leftovers older than 2 days (NFR-8).
6. **Spend.** Yesterday's cost in Cost Explorer by environment, against capacity section 5's daily line ($131 for
   prod at idle); dev and staging are down unless someone is using them.

## Weekly checks

- The month's spend against the cap's pace; the forecast alarm's state.
- Image and signature updates promoted through staging (NFR-18), and no known critical or high vulnerability in a
  running image (NFR-13).
- The drill and load-test plan for the rest of the period; each done one has its log in `docs/operations/drills/`.
- Break-glass and `Admin` assignments: none left standing.

## The end

1. Rashid sets the end date; tenants (the demo users) are told a week before, and new sends stop two days before, so
   transfers expire and the deletion job empties the files buckets before the teardown (NFR-8).
2. The final reports are written: NFR-1 over the period with the drill windows apart, the drills' RTO and RPO, the
   load tests, and the bill.
3. The prod teardown ([teardown.md](teardown.md)), timed against NFR-19's hour; then dev and staging for good, the
   last with `--last`, which takes the shared registry.
4. A month later, the bill shows only the retained stack, under $7 (NFR-19). Its budget alarms if not.
