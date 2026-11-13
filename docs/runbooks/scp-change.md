# Runbook: SCP changed (`ScpChanged`)

An EventBridge alert on any change to a service control policy or to where one applies (encryption 8.4,
[ADR-0006](../adr/0006-aws-account-per-environment.md)), defined in
[`infra/organization/scp-alerts.tf`](../../infra/organization/scp-alerts.tf) as `sft-management-scp-changed` (#277).
Severity: page. Never held back by a drill.

The SCPs bind every role in the member accounts, the deploy roles and `BreakGlass` included: the region guard, the
guards on the state buckets, keys, trails and the audit archive, and who may change IAM (infra/README.md, "Organization
and guardrails"). Organizations records its calls only in the management account, in us-east-1, where no environment's
rule can see them, so this rule lives there and emails the addresses in the organization stack's `alert_emails` through
the topic `sft-management-scp-alerts`.

It fires on `AttachPolicy`, `DetachPolicy`, `UpdatePolicy`, `DeletePolicy`, `EnablePolicyType` and
`DisablePolicyType`, by anyone, whether the call succeeded or was refused: **the maintainer's own applies of the
organization stack page too**. Organizations has no other policy type in use here, so every such call is about an SCP.

> [!IMPORTANT]
> **Pending the AWS run**, like every EventBridge alert: checked statically, fired for real by the first organization
> apply after the shared stack's organization trail exists (the rule sees nothing before that trail logs).

## The message

Time, account, event name, the caller's ARN and type, the source IP, any error code and the CloudTrail event ID. Not
the request, which holds the whole policy for `UpdatePolicy`: look the event up by its ID.

## Impact

A detached or loosened SCP lifts a guardrail from every role it bound, in every account under that root or OU, until
it is put back. A refused attempt is someone trying, from inside the management account.

## Confirm

As `sft-management-admin`:

```bash
aws cloudtrail lookup-events --region us-east-1 \
  --lookup-attributes AttributeKey=EventId,AttributeValue=<cloudtrail_event_id>
cd infra/organization && terraform plan    # with the inputs of the runbook's step 5; nothing to change if planned
```

- **Planned:** you applied the organization stack just now, and the event's caller is your `Admin` session: compare
  with the plan you approved. `terraform plan` shows no changes.
- **Unplanned:** any other caller, any refused attempt, or a plan that wants to put something back.

## Mitigate

1. **Put the SCPs back with Terraform:** apply `infra/organization` as in
   [organization-and-bootstrap.md](organization-and-bootstrap.md), which re-creates and re-attaches every SCP as the
   code says. SCPs never bind the management account, so the apply works whatever was detached.
2. **An unknown caller or a refused attempt:** remove that principal's assignments and end its sessions in Identity
   Center (a `BreakGlassApprover` can), as in [privileged-sign-in.md](privileged-sign-in.md), and check who holds
   `Admin` in the management account.
3. **Look at what happened meanwhile:** each member account's management events are in the organization trail's log
   archive under Object Lock (ADR-0006); search them for the window the guardrail was off, for the actions it denies.

## Escalate

Every unplanned change is an incident: page the owner in [CODEOWNERS](../../.github/CODEOWNERS) at once.
