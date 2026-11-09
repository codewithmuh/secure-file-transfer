# Runbook: OperatorAuditFailing

The operator records alert (FR-34, authn-authz 8.2, T-64), defined in
[`deploy/alerts/operator.rules.yaml`](../../deploy/alerts/operator.rules.yaml). Severity: page. It carries
`security: "true"`, so Alertmanager never inhibits it, not even during a drill.

## Symptoms

An operator call committed its change but its platform audit event wasn't written
(`sft_operator_platform_audit_failures_total{action}`). Today only tenant creation counts it
(`action="tenant.created"`):
`createTenant` answers `201` even when the second write fails, because a retry would make a second tenant.
`suspendTenant` answers `503` instead, and its retry writes the event (`sft.service.operator_tenants`).

## Impact

Nothing is unrecorded: the change commits with its event in the tenant's own audit log, which the database requires
(`audit_required`). But the platform's view of what operators did has a hole, and an operator action without its
platform record is what an insider would want (T-64). It should never happen, so every one is looked at.

## Confirm

```bash
kubectl -n sft-operator logs deploy/operator-api --since=30m | tail -100   # the failed platform write and its error
```

The operator API's log names the operator session and the tenant, never tenant data. With the operator token, the
tenant is visible through `getTenant`. Ask the operator who made the call (the log's operator user name) to confirm it
was theirs and intended.

## Mitigate

1. **The write failed for an ordinary reason** (the database was unavailable for a moment, a lock timeout): the
   change is real and recorded in the tenant's log. Write down the tenant, the time, the operator and the action, so
   the platform record's gap is explained. The operator API has no operation that writes a missing platform event
   afterwards, so the incident note is the record.
2. **It keeps failing:** the platform scope's insert (the `sft_operator` role's grants on `audit_events`, migration
   0002 and later) or the database is broken; [service-unavailable.md](service-unavailable.md) for the operator API.
   Stop creating tenants until it is fixed.
3. **The operator didn't make the call, or can't explain it:** treat it as a security incident. Remove that
   operator's Identity Center assignments, and escalate.

## Escalate

Always tell the owner in [CODEOWNERS](../../.github/CODEOWNERS) the same day; at once if the call wasn't expected.

## Afterwards

Every occurrence goes in the operating period's log with its explanation.
