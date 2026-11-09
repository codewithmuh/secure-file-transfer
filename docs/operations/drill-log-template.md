# Drill log template

Every drill and every real recovery leaves one log, the written report NFR-10 and NFR-11 ask for. The scripts in
[`ops/`](../../ops/) start it: with `--execute` they write `docs/operations/drills/<date>-<drill>-<env>.md` with the
header and one table row per step, timed, then the measures they read. The operator fills in the rest from this
template and commits it with the drill's follow-ups. A dry run writes its log to a temporary file instead, so
rehearsing a runbook leaves nothing in the repository.

Copy the sections below the line into the log the script started, under its table.

---

## Summary

| | |
|---|---|
| Drill | regional failover / regional failback / AZ failure / point-in-time restore / teardown / Osaka archive outage |
| Environment and region | staging or prod; the regions involved |
| Date, start and end (UTC) | |
| Operator, and who else was there | |
| Runbook and commit | the runbook's path and the commit of `main` the drill ran from |
| Drill window announced | where, and when it was logged as a planned window for NFR-1 |
| Result | passed / passed with findings / failed |

## Targets and what was measured

| Target | Requirement | Measured | Met |
|---|---|---|---|
| RTO | NFR-11: 1 h regional, 5 min AZ, 2 h restore; NFR-19: teardown 1 h | | |
| RPO, metadata | NFR-10: ≤ 5 min regional, 0 for an AZ; NFR-11: restore accurate to ≤ 5 min | | |
| RPO, files | NFR-10: ≤ 15 min for 99.99 % of files (S3 RTC) | | |
| Security-critical changes lost | NFR-10: none, but a grant committed in the second before the failure | | |
| Each step against its budget | architecture 7 for a failover; the script's budgets otherwise | see the table above | |

How each number was read: the CloudWatch metric and its window (`AuroraGlobalDBRPOLag`, `ReplicationLatency`,
`ProbeSuccess`), the recovery job's log lines, the probe's runs. Write the number and where it came from, so the next
drill can read it the same way.

## The recovery job's report

The counts the recovery job logged (`recovery replay done`): reimported, reapplied, not_reapplied, present, ignored;
the generation it started; the outbox messages it marked for publishing again. Tenant admins told of lockouts the
replay re-applied and of unlocks it left out, and when.

## Timeline

Anything that happened between the steps: waits, retries, alerts that fired (and should have), what the operator
looked at. UTC times.

## What went wrong

Blameless. For each finding: what happened, its effect on the targets, and the cause.

## What changes

Each finding's follow-up: a runbook or script change, an issue, or an ADR to revisit (ADR-0011 names the first
failover drill as its revisit point). Link the issue numbers.

## Evidence

Links or paths to the screenshots, CloudWatch graphs and job logs kept with this log. No secrets, tokens, codes,
email addresses or file names: IDs and counts only.
