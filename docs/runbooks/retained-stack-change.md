# Runbook: retained stack changed (`RetainedBucketChanged`, `RetainedKeyChanged`, `RetainedTrailChanged`)

EventBridge alerts of prod's retained stack ([encryption](../security/encryption-and-keys.md) 8.4, #263), defined in
[`infra/environments/prod/retained/alerts.tf`](../../infra/environments/prod/retained/alerts.tf), to the stack's own
topics `sft-prod-<rs>-retained-alerts` under the audit key, through its own delivery role. They outlive prod: after the
teardown nothing else watches the audit archive. Severity: page.

| Rule | Fires on |
|---|---|
| `sft-prod-<rs>-retained-bucket-changed` | A guard of the audit archive bucket, or of the retained stack's state or trail bucket, changed (policy, lifecycle, Object Lock, replication, versioning, encryption, public access, ownership, deletion) by anyone but `sft-prod-retained-terraform-deploy`, or any refused attempt |
| `sft-prod-<rs>-retained-key-changed` | The audit key's policy, state, rotation, grants or replicas changed by anyone but that role, any refused attempt, and the key disabled or scheduled for deletion by anyone |
| `sft-prod-apne1-retained-trail-changed` | The retained trail stopped, deleted or changed, or one of these rules changed, by anyone but that role, or any refused attempt |

While prod runs, EventBridge sees these calls through the organization trail; from the teardown apply on, through the
retained trail's management events. While prod runs, a change to the audit key also pages through the environment's
`kms-key-changed` rule ([kms-key-change.md](kms-key-change.md)): two pages for one event.

> [!IMPORTANT]
> **Pending the AWS run.** Checked statically. Fired for real once in prod's operating period: change a tag on the
> trail bucket as `Admin`, and see the page.

## Planned pages

- The teardown's retained-stack apply turns the audit key's rotation off: `retained-key-changed` fires once
  (`DisableKeyRotation`). Acknowledge it in the teardown log ([teardown.md](teardown.md)).
- When the archive's retention ends, the retained stack's deploy role schedules the key's deletion: it fires again,
  as it should.

## Impact

The archive is the record NFR-15 and NFR-19 promise to keep. A changed guard can let records be deleted early (a
lifecycle rule, a shorter lock), read by someone new (a policy), or made unreadable (the key). A stopped trail hides
what comes next.

## Confirm and mitigate

```bash
aws cloudtrail lookup-events --region <region> --profile sft-prod-admin \
  --lookup-attributes AttributeKey=EventId,AttributeValue=<cloudtrail_event_id>
cd infra/environments/prod/retained && terraform plan   # shows the drift, with the retained stack's inputs
```

1. **Put it back:** apply the retained stack (as its deploy role from the `prod-retained` environment, or as `Admin`
   with `TF_VAR_teardown` as it stands). Object Lock in compliance mode still protects every record already written,
   whatever the bucket policy says.
2. **The key scheduled for deletion:** cancel it as `BreakGlass` or `Admin` (`aws kms cancel-key-deletion`, then
   `enable-key`), in Tokyo and Osaka; the 30-day wait leaves time.
3. **The trail stopped:** apply the stack, which starts it again (`StartLogging`).
4. **An unknown caller:** end its sessions and assignments ([privileged-sign-in.md](privileged-sign-in.md)).

## Escalate

Any unplanned change is an incident: page the owner in [CODEOWNERS](../../.github/CODEOWNERS) at once.
