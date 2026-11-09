# break-glass-role module

The IAM side of the service's break-glass grants (FR-35, [authn-authz](../../../docs/security/authn-authz.md) 8.3).
Written by [#232](https://github.com/codewithmuh/secure-file-transfer/issues/232) and called by
[`data-stack`](../data-stack/README.md) in every `data` root, because it names the Region's Aurora cluster. Nothing here
has been applied (infra/README.md); everything below is pending the AWS run.

An operator requests a grant in the operator API (`requestBreakGlass`), a second operator approves it, and for at most
60 minutes the requester may read the named tenants' rows as the PostgreSQL login role `sft_breakglass`. This module
makes the IAM role they sign in to that login role with, and the alert on every use. The runbook is
[docs/runbooks/break-glass.md](../../../docs/runbooks/break-glass.md).

| | |
|---|---|
| Role | `sft-<env>-break-glass-db`, at path `/`. Created by Tokyo's data stack (`create_role`), IAM being global; 1-hour sessions |
| Trust | The account's `BreakGlass` permission set role only (`aws:PrincipalArn` like `*AWSReservedSSO_BreakGlass_*`, modules/conventions), as for the key-admin role. `sts:AssumeRole` and `sts:TagSession` together, and only with the session tag `sft-break-glass-grant` set to a grant ID (shape `8-4-4-4-12`) and no other tag key, so an untagged assumption is refused. Only through STS in the environment's Regions (`aws:RequestedRegion`), where the alert rule is |
| Permission | One inline policy per Region, `connect-<region-short>`: `rds-db:connect` as `sft_breakglass` on that Region's cluster (`dbuser:<cluster resource ID>/sft_breakglass`), only while the session carries the grant tag. Each Region's data stack adds its own, so the role works on Osaka's cluster after a failover |
| What it reads | Nothing by itself. Row-level security on `sft_breakglass` admits the tenants of the grant named in `app.break_glass_grant`, only while that grant is active and before it ends (`break_glass_tenants()`). An expired grant reads nothing, whatever IAM says |
| Alert | In each Region: the EventBridge rule `sft-<env>-<rs>-break-glass-db-assumed` on CloudTrail's `AssumeRole` for the role, granted or refused, into the topic `sft-<env>-<rs>-break-glass-alerts` through `sft-<env>-events-delivery`. The message carries the caller, source IP, request (with the grant tag), time and CloudTrail event ID, never the response's credentials |
| Topic | Under the Region's platform key. Only the delivery role may publish; only the deploy role may change or delete it, because SCP 4 guards `sft-*` rules but not topics. Subscriptions (the pager, every operator) come with M7's alerting as code (ADR-0009) |

## Why a role of its own, not BreakGlass itself

`BreakGlass` can already read anything (authn-authz 8.3, "Allows"), the master user included. This role is narrower:
it reaches one login role that reads a few tenant tables of named tenants, with ciphertext for file names and
messages, and its every use is tied to a grant in the service and its audit records. The Identity Center `BreakGlass`
path stays the way in when the API or the database is down.

## Inputs worth knowing

- `cluster_resource_id`: the Region's `module.aurora.cluster_resource_id`.
- `regions`: dev Tokyo; staging and prod Tokyo and Osaka.
- `deploy_role_arn`: the bootstrap stack's deploy role, the only principal that may change the topic.

The deploy role's permissions are in `modules/terraform-oidc-roles/permissions-break-glass.tf`. A deploy role that
may rewrite this role's trust could assume it; it can already read the master password at apply, and every assumption
pages, so that adds no reach.

## Pending the AWS run

- That `aws:RequestedRegion` is present in the trust evaluation of `AssumeRole` through a regional STS endpoint. If it
  isn't, every assumption is refused (it fails closed); drop the condition and rely on the CLI's regional endpoint.
- That CloudTrail management events from the organization trail reach the account's EventBridge in both Regions, and
  how long they take.
- The database side: the bootstrap job creates `sft_breakglass` with `rds_iam`; the migration creates its policies.
