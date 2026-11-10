# Runbook: break-glass records from Identity Center

The service keeps a record of every Identity Center `BreakGlass` grant (FR-35, [authn-authz](../security/authn-authz.md)
8.3, #239), so each tenant it names sees it in its audit log (UC-4). The break-glass tool records a grant with
`recordBreakGlassGrant` after the assignment; every 15 minutes the operator API's reconciliation job reads the
`BreakGlass` assignments of the last day from CloudTrail and records any the tool didn't (`recorded_by:
reconciliation`). The authoritative record is still the Identity Center assignment plus CloudTrail. This page is the
runbook of three alerts in [`deploy/alerts/break-glass-records.rules.yaml`](../../deploy/alerts/break-glass-records.rules.yaml),
all labelled `security: "true"`, so Alertmanager never inhibits them during a drill.

> [!IMPORTANT]
> **The AWS steps are pending the AWS run.** The reconciliation reads the management account's CloudTrail through a
> read-only role there (`BREAK_GLASS_TRAIL_ROLE_ARN`: `sft-<env>-break-glass-trail`, infra/organization, not applied
> yet). It stays off until the environment sets that role, the `BreakGlass` permission set and the identity store
> (`operatorApi.env`) and the operator API has a way out to CloudTrail and the identity store (an egress proxy
> listener, a follow-up). The break-glass tool isn't built.
> The first drill checks these steps and corrects this page.

## How a grant is recorded

- **By the tool.** After the `BreakGlassApprover` assigns `BreakGlass`, the tool creates the one-time removal schedule
  `sft-break-glass-<incident ID>`, whose description is JSON with `assignment_request_id`, `reason` and `tenant_ids`,
  and calls `recordBreakGlassGrant` with the same facts. A retry with the same `assignment_request_id` answers `200`
  with the first record.
- **By the job.** It matches CloudTrail's `CreateAccountAssignment` events for the `BreakGlass` permission set and
  this account with the removal schedules' `CreateSchedule` events, by the assignment request ID. A schedule it can't
  read leaves the record with the incident `unknown` and a placeholder reason, never without the record. Tenant IDs
  that don't exist are dropped and counted in the record's audit event (`tenants_dropped`).
- A recorded grant is `active` until its end (at most an hour), so `BreakGlassActive` pages for it too, and the sweep
  records its expiry in the tenants' logs. It never lets anyone in as `sft_breakglass`: that role works only with grants
  the service made ([break-glass.md](break-glass.md)).

## BreakGlassGrantUnrecorded

A `BreakGlass` assignment started an hour or more ago and the job couldn't record it
(`sft_break_glass_unrecorded_assignments > 0`). The tenants it names can't see that their data may have been read.

- **Confirm:** `kubectl -n sft-operator logs deploy/operator-api --since=2h | grep "couldn't be recorded"` names the
  assignment request ID and the error. In the management account, CloudTrail's `CreateAccountAssignment` event with
  that request ID shows who assigned `BreakGlass` to whom.
- **Mitigate:** usually the database (fix it, and the next run records the grant) or a malformed assignment (an
  empty user name). If the job can never record it, record it by hand with `recordBreakGlassGrant` from the facts in
  CloudTrail and the removal schedule, then tell the named tenants' admins directly.
- **Unexpected assignment** (no incident, an approver who didn't approve): treat it as a security incident first:
  remove the assignment, and follow [break-glass.md](break-glass.md)'s "Unexpected" steps.

## BreakGlassReconciliationStalled

The job hasn't run to the end for 45 minutes, so a grant made now could go unrecorded for over an hour unseen.

- **Confirm:** `kubectl -n sft-operator logs deploy/operator-api --since=1h | grep break_glass_reconciliation` for
  the failure: often the role assumption (`AccessDenied` from STS), CloudTrail's `LookupEvents` throttling, or the
  database.
- **Mitigate:** fix the cause; the next run reads the whole last day again, so nothing is lost while it catches up. If
  the operator API is down, [service-unavailable.md](service-unavailable.md) applies first.

## BreakGlassRecordedByReconciliation

The job recorded a grant that the tool should have recorded (`sft_break_glass_records_reconciled_total` rose). The
record is there now; this is a ticket to find out why the tool's call failed.

- **Confirm:** the grant (`listBreakGlassRequests` with `state=active` or `expired`, `recorded_by: reconciliation`) and
  the tool's own output for that assignment.
- **Mitigate:** fix the tool or its path to the operator API. Check that the grant was expected, as for any
  break-glass use, and note it in the after-action review.

## Escalate

To the owner in [CODEOWNERS](../../.github/CODEOWNERS) for anything unexpected above.
