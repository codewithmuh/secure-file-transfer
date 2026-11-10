# Runbook: SSO provider drift

Once a day the operator API compares each tenant's recorded SSO configuration (`configureTenantSso`) with the
providers in both user pools (FR-26, [authn-authz](../security/authn-authz.md) 2.5 and 2.6, #239). Each provider is
created in both pools by the operator CLI, `python -m sft.runtime.sso_providers`, named after the tenant ID without
dashes. This page is the runbook of the three alerts in [`deploy/alerts/sso.rules.yaml`](../../deploy/alerts/sso.rules.yaml).

> [!IMPORTANT]
> **Pending the AWS run.** The check reads Cognito with the operator API's role, which holds
> `cognito-idp:ListIdentityProviders`, `DescribeIdentityProvider` and `DescribeUserPoolClient` on both pools
> (modules/eks-cluster). It stays off until the environment sets `SSO_DRIFT_POOLS` (`operatorApi.env`) and the operator
> API has a way out to Cognito (an egress proxy listener, a follow-up). The local stack has no check.

## What the check reports

Per pool (its Region: `ap-northeast-1` Tokyo, `ap-northeast-3` Osaka) and problem:

| Problem | Means |
|---|---|
| `missing` | An active connection's provider isn't in the pool. In the active pool, the tenant's SSO sign-in fails now; in the standby pool, at a failover. |
| `changed` | The provider is there but its type, its OIDC issuer, its attribute mapping (only email, subject and groups), or its identifiers (none) differ, or the app client doesn't offer it. |
| `unrecorded` | The pool has a provider no tenant records: left after a connection changed, or made by hand. |

An inactive connection isn't checked. Each finding is a platform audit event, `sso_provider.drift_found`, with the
pool, the problem, the tenant, what changed and the connection as its target; each run writes
`sso_provider.drift_checked`.

## SsoProviderDrift

A provider is `missing` or `changed` in a pool. Security-labelled: a change nobody made through the CLI could map the
wrong attributes into a sign-in.

- **Confirm:** the platform audit log's latest `sso_provider.drift_found` events name the tenant and what differs.
  Compare with the pool: `aws cognito-idp describe-identity-provider --user-pool-id <pool> --provider-name <tenant ID
  without dashes>`, with the `Operator` permission set. CloudTrail's `UpdateIdentityProvider` or
  `DeleteIdentityProvider` events say who changed it.
- **Mitigate:** if the change wasn't planned, treat it as a security incident first (who has `Operator`, what the
  change did). Then put the provider back as recorded with the CLI, for both pools, with the tenant's issuer and
  client from the tenant's onboarding record; the CLI creates or updates it and offers it on the app client. The alert
  clears at the next check (the next day), or sooner if the operator API restarts, since the check runs at start.
- If the recorded configuration is what is wrong (the tenant moved to a new provider), record the new one with
  `configureTenantSso` instead.

## SsoProviderUnrecorded

A pool has a provider no tenant records. A ticket: it signs nobody in, because sign-in finds the connection from our
records, never from the pool.

- **Confirm:** the `sso_provider.drift_found` event names the provider (a tenant's ID, if it is one).
- **Mitigate:** if it belongs to a tenant whose connection changed, delete it from the pool
  (`aws cognito-idp delete-identity-provider`), and take it off the app client's providers. If you don't know where
  it came from, find out from CloudTrail before deleting it.

## SsoDriftCheckStalled

The check hasn't run to the end for 26 hours, so drift goes unseen.

- **Confirm:** `kubectl -n sft-operator logs deploy/operator-api --since=26h | grep sso_drift_check` for the error:
  usually Cognito refusing the role (`AccessDenied`), throttling, or the database.
- **Mitigate:** fix the cause and restart the operator API (`kubectl -n sft-operator rollout restart` is not an
  `Operator` action: ask through a Git change or the on-call admin), or wait for the next day's run.

## Escalate

To the owner in [CODEOWNERS](../../.github/CODEOWNERS) for anything unexpected above.
