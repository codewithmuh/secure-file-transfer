# Runbook: KMS key changed (`KmsKeyChanged`, `KmsKeyDisabledOrDeleted`)

EventBridge alerts on CloudTrail's KMS events ([encryption](../security/encryption-and-keys.md) 4.4 rule 7, 8.3;
threat model T-61), defined in [`infra/modules/alarms/security-events.tf`](../../infra/modules/alarms/security-events.tf)
(#256), one rule of each per Region, to the Region's `alerts-page` topic. Severity: page. Never held back by a drill.

| Rule | Fires on |
|---|---|
| `sft-<env>-<rs>-kms-key-changed` (`KmsKeyChanged`) | `PutKeyPolicy`, `DisableKey`, `DisableKeyRotation`, `ScheduleKeyDeletion`, `CancelKeyDeletion`, `RevokeGrant`, `ReplicateKey`, `ImportKeyMaterial`, `DeleteImportedKeyMaterial` or `UpdatePrimaryRegion` by anyone but a Terraform deploy role (the environment's, and in prod the retained stack's), and any refused attempt at one of them, by anyone |
| `sft-<env>-<rs>-kms-key-destroyed` (`KmsKeyDisabledOrDeleted`), prod only | `DisableKey`, `DisableKeyRotation` or `ScheduleKeyDeletion` by a deploy role, which succeeded |

> [!IMPORTANT]
> **Pending the AWS run.** The rules are written and checked statically (`infra/scripts/check.sh test`); whether each
> fires on a real event, and what the message looks like, is checked in staging's first break-glass drill.

## The message

The alert email holds the event's time, Region, account, event source and name, the caller's ARN and type, the source
IP, the error code (empty when it succeeded) and the CloudTrail event ID. Never the request's parameters: a key policy
can be in them. Look the event up by its ID for the rest.

## Impact

A key that is disabled, scheduled for deletion or has a broken policy makes the files, the audit archive or the
database unreadable (T-61). A changed policy can also give someone a use of the key that the design never allowed.
A refused attempt is a person or a role trying something the SCPs and key policies stop: the attempt is the signal.

## Confirm

```bash
aws cloudtrail lookup-events --region <region> --profile <env>-readonly \
  --lookup-attributes AttributeKey=EventId,AttributeValue=<cloudtrail_event_id>
aws kms describe-key --region <region> --key-id <key id from the event's resources>
aws kms get-key-rotation-status --region <region> --key-id <key id>
```

- **Who was it?** An `AWSReservedSSO_BreakGlass_*` or `AWSReservedSSO_Admin_*` session is a person with an approved
  assignment; check the break-glass record ([break-glass.md](break-glass.md)) and the incident it names.
  `sft-<env>-keyadmin` also pages through [key-admin-role.md](key-admin-role.md).
- **Was it planned?** In prod, `KmsKeyDisabledOrDeleted` fires on purpose in two places only: the teardown's
  retained-stack apply turning the audit key's rotation off, and the destroys of a final teardown
  ([teardown.md](teardown.md)). Both are acknowledged in the teardown's log.

## Mitigate

1. **A pending deletion nobody planned:** cancel it now, as `BreakGlass` (the only role besides the deploy role that
   may): `aws kms cancel-key-deletion --key-id <key>`, then `aws kms enable-key --key-id <key>`. Prod's 30-day wait
   leaves time; dev's and staging's 7 days less.
2. **A disabled key:** `aws kms enable-key` as `BreakGlass`; the service recovers as its calls start succeeding.
3. **A changed policy:** put the policy Terraform holds back by applying the stack that owns the key (the data stack,
   or prod's retained stack for the audit key). If the policy now locks the deploy role out, the key-admin role puts
   it back ([key-admin-role.md](key-admin-role.md), encryption 4.4 rule 6).
4. **Rotation turned off:** turn it on again by applying the owning stack (`enable_key_rotation`).
5. **A refused attempt:** find the principal and why it tried; if its credentials may be someone else's, treat it as
   a compromise: end its sessions (`aws iam put-role-policy` with a deny on `aws:TokenIssueTime`, or remove the
   Identity Center assignment) and follow the incident process.

## Escalate

Any change nobody can explain within 15 minutes is an incident: page the owner in [CODEOWNERS](../../.github/CODEOWNERS),
and record the key's state and the event in the incident. Keep the CloudTrail record; it is in the organization trail's
Object Lock bucket (ADR-0006).
