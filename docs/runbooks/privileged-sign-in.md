# Runbook: privileged sign-in (`PrivilegedSignIn`)

An EventBridge alert on people with the most access signing in or acting in an environment's account
([authn-authz](../security/authn-authz.md) 8.3, 8.4; threat model T-64, T-74), defined in
[`infra/modules/alarms/security-events.tf`](../../infra/modules/alarms/security-events.tf) as
`sft-<env>-<rs>-human-sign-in` (#256). Severity: page. Never held back by a drill.

It fires on:

- a console sign-in, or any call, by the **root user** (centralized root access means member accounts have no root
  credentials; an `AssumeRoot` session from the management account counts too);
- a console sign-in, or any call, by the account's **emergency user** `sft-<env>-emergency` (authn-authz 8.4);
- a console sign-in, or an `AssumeRoleWithSAML`, with the **`Admin`** or **`BreakGlass`** permission set.

Root and IAM user sign-ins and calls through STS's global endpoint are recorded in us-east-1. The alarms layer's rule
`sft-<env>-apne1-global-events` there forwards them to Tokyo's default event bus, where this rule sees them; after a
failover Osaka's stack makes its own (`TF_VAR_pilot_light=false`), so they keep paging. In Osaka's pilot light its rule
looks at Osaka's own events only, so nothing pages twice.

> [!IMPORTANT]
> **Pending the AWS run.** Checked statically. Which event names Identity Center records in the member account for a
> permission set sign-in (`AssumeRoleWithSAML` in the member account; `Federate` stays in the management account) is
> confirmed in staging's first break-glass drill.

## The message

Time, Region, account, event source and name, the caller's ARN and type (`Root`, `IAMUser`, `AssumedRole`, `SAMLUser`),
the source IP, any error code and the CloudTrail event ID. A refused sign-in carries its error code: the attempt is the
signal.

## Impact

`Admin` and `BreakGlass` can do almost anything the SCPs allow; the emergency user is `AdministratorAccess` for when
Identity Center is down; root is the account itself. Planned, each is a person doing an approved task. Unplanned, it is
an account takeover in progress (T-74).

## Confirm

```bash
aws cloudtrail lookup-events --region <region from the message> --profile <env>-readonly \
  --lookup-attributes AttributeKey=EventId,AttributeValue=<cloudtrail_event_id>
```

- **`Admin` or `BreakGlass`:** an assignment a `BreakGlassApprover` made for the hour (infra/README.md, permission
  sets): find it in Identity Center's assignments and the approval's incident or ticket ([break-glass.md](break-glass.md)).
  A drill, a bootstrap apply and a recovery script run as `Admin`; their logs name the time.
- **The emergency user:** used only when Identity Center can't be reached (authn-authz 8.4). Confirm with the maintainer
  that Identity Center was down and that they signed in.
- **Root:** nobody signs in as root. An `AssumeRoot` session from the management account is a privileged root task
  (infra/README.md); confirm it with the maintainer.

## Mitigate

1. **Planned:** acknowledge it in the incident or the drill log. Nothing else.
2. **Not planned, `Admin` or `BreakGlass`:** remove the assignment in Identity Center (a `BreakGlassApprover` can), and
   revoke the role's sessions (IAM console, the role, "Revoke active sessions").
3. **Not planned, the emergency user:** deactivate its console password and security key as `Admin`, and rotate the
   offline password.
4. **Not planned, root:** in the management account, check centralized root access for the account and any root
   credentials; delete them (`aws iam delete-login-profile` through `AssumeRoot`). Then follow the incident process.
5. In each case, list what the session did (CloudTrail by the session's access key or user name) and undo it with
   Terraform applies; the other security alerts ([kms-key-change.md](kms-key-change.md),
   [security-service-off.md](security-service-off.md)) show the worst of it.

## Escalate

Unplanned use of any of these is an incident: page the owner in [CODEOWNERS](../../.github/CODEOWNERS) at once.
