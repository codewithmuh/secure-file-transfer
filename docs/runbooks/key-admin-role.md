# Runbook: key-admin role used (`KeyAdminRoleUsed`)

An EventBridge alert on every assumption of `sft-<env>-keyadmin`, granted or refused, and on every call the role makes,
reads included ([encryption](../security/encryption-and-keys.md) 4.4 rules 6 and 7), defined in
[`infra/modules/alarms/security-events.tf`](../../infra/modules/alarms/security-events.tf) as
`sft-<env>-<rs>-key-admin-used` (#256). Severity: page. Never held back by a drill.

The key-admin role exists for one thing: putting a broken key policy back when the deploy role can't. Only the
`BreakGlass` permission set may assume it, under `/sft-bootstrap/`, which only `Admin` may change (SCP 4).

> [!IMPORTANT]
> **Pending the AWS run**, like every EventBridge alert: checked statically, fired for real in staging's first drill.

## The message

Time, Region, account, event source and name (`AssumeRole` for an assumption), the caller (the `BreakGlass` session
that assumed it, or the role's own session), the source IP, any error code and the CloudTrail event ID. Assumptions
through STS's global endpoint are recorded in us-east-1; the alarms layer forwards them to Tokyo's bus (and Osaka's
after a failover), so they page here too.

## Impact

None by itself if it was planned: someone with an approved `BreakGlass` assignment is repairing a key policy. Unplanned,
it is someone able to rewrite any key policy in the account (T-61).

## Confirm

```bash
aws cloudtrail lookup-events --region <region> --profile <env>-readonly \
  --lookup-attributes AttributeKey=EventId,AttributeValue=<cloudtrail_event_id>
aws cloudtrail lookup-events --region <region> --profile <env>-readonly \
  --lookup-attributes AttributeKey=Username,AttributeValue=<role session name> --max-results 50
```

Match the session to a break-glass assignment and its incident ([break-glass.md](break-glass.md)). List what the role
did: `GetKeyPolicy` and `PutKeyPolicy` on the key the incident names, nothing else.

## Mitigate

1. **Planned:** acknowledge the page in the incident. When the repair is done, apply the stack that owns the key, so
   Terraform's policy is the one in force again, and end the `BreakGlass` assignment.
2. **Unplanned:** remove the `BreakGlass` assignment in Identity Center (a `BreakGlassApprover` can), check every key's
   policy against Terraform's (`terraform plan` of each data stack and of prod's retained stack shows the drift), and
   follow [kms-key-change.md](kms-key-change.md) for each changed key.

## Escalate

Unplanned use is an incident: page the owner in [CODEOWNERS](../../.github/CODEOWNERS) at once.
