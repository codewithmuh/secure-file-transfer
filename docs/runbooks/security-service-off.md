# Runbook: security service changed (`SecurityServiceChanged`)

An EventBridge alert on the services that record and watch the account being changed or turned off (threat model T-75),
and on the cluster's API endpoint made public (ADR-0021), defined in
[`infra/modules/alarms/security-events.tf`](../../infra/modules/alarms/security-events.tf) as
`sft-<env>-<rs>-security-service-off` and, for the alert rules and the endpoint, `sft-<env>-<rs>-alerting-or-endpoint-changed`
(#256; two rules because one pattern holds at most 4,096 characters). Severity: page. Never held back by a drill.

It fires on, by anyone but a Terraform deploy role, and on any refused attempt by anyone:

| Service | Calls |
|---|---|
| CloudTrail | `StopLogging`, `DeleteTrail`, `UpdateTrail`, `PutEventSelectors`, `PutInsightSelectors` |
| GuardDuty | `DeleteDetector`, `UpdateDetector`, `DisassociateFromAdministratorAccount`, `DisassociateFromMasterAccount`, `DeleteMalwareProtectionPlan`, `UpdateMalwareProtectionPlan` |
| Config | `StopConfigurationRecorder`, `DeleteConfigurationRecorder`, `PutConfigurationRecorder`, `DeleteDeliveryChannel`, `DeleteConfigRule` |
| EventBridge | `DeleteRule`, `DisableRule` and `RemoveTargets` on a `sft-<env>-*` rule: these alerts themselves |

and, by anyone, `UpdateClusterConfig` that turns on the EKS cluster's public endpoint, which the deploy role can't do
(`eks:endpointPublicAccess`).

SCP 3 already denies these to everyone but the apply roles, so a success by anyone else means the SCP was changed or
bypassed, and a refused attempt is someone trying.

> [!IMPORTANT]
> **Pending the AWS run**, like every EventBridge alert: checked statically, fired for real in staging's first drill.

## The message

Time, Region, account, event source and name, the caller's ARN and type, the source IP, any error code and the
CloudTrail event ID. Not the request: look the event up by its ID.

## Impact

Turning off the trail, GuardDuty, Config or these rules is how an attacker hides what comes next (T-75). While it lasts,
other alerts may be blind. A public cluster endpoint exposes the Kubernetes API to the internet.

## Confirm

```bash
aws cloudtrail lookup-events --region <region> --profile <env>-readonly \
  --lookup-attributes AttributeKey=EventId,AttributeValue=<cloudtrail_event_id>
aws guardduty list-detectors --region <region>
aws configservice describe-configuration-recorder-status --region <region>
aws events describe-rule --region <region> --name <rule>
aws eks describe-cluster --region <region> --name sft-<env>-<rs>-eks --query cluster.resourcesVpcConfig
```

## Mitigate

1. **Put it back with Terraform:** apply the stack that owns the resource (the data stack for GuardDuty's plans, the
   alarms stack for these rules, the cluster stack for the endpoint; the shared stack for the organization trail). A
   public endpoint first: apply the cluster stack, which sets it private.
2. **A refused attempt or an unknown caller:** end that principal's sessions and assignments, as in
   [privileged-sign-in.md](privileged-sign-in.md), and check the SCPs in the management account
   ([organization-and-bootstrap.md](organization-and-bootstrap.md)).
3. Look for what happened while it was off: the organization trail's log archive keeps every event under Object Lock
   (ADR-0006).

## Escalate

Every unplanned change is an incident: page the owner in [CODEOWNERS](../../.github/CODEOWNERS) at once.
