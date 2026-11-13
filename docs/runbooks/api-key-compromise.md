# Runbook: ApiKeyMisuse

The API key abuse alert of abuse and rate limits 8.2 (AB-9, authn-authz 5), defined in
[`deploy/alerts/abuse.rules.yaml`](../../deploy/alerts/abuse.rules.yaml). Severity: ticket. Abuse 8.2 calls this
runbook `api-key-compromise`; this file is it.

## Symptoms

Its `condition` label says which half of abuse 8.2's alert fired:

- `auth_failures` (#260): more than 50 bearer authentications failed in 5 minutes
  (`auth_failures_total{scheme="api_key"}`): someone presents keys that don't exist, are revoked or expired.
- `held_at_limit`: requests on API keys have been refused by their rate limits for 10 minutes on end
  (`rate_limit_rejections_total{key_type="api_key"}`).

## Impact

Failing authentications are someone guessing or replaying keys, or a tenant's automation still using a key that was
revoked or has expired. Guessing is hopeless (a key is 256 random bits, authn-authz 5.1); the per-IP limits and the
WAF's rate rules slow it further. A key held at its limit is either a tenant's automation that is misbehaving (a retry loop), or a leaked key being used.
A key can never read file contents, unlock anyone or decide on DLP (authn-authz 5.3), and every call it makes is in its
tenant's audit log, so the worst a leaked key does is create or read transfers and upload requests within its scopes,
and export at most 100,000 audit events an hour.

## Confirm

For `auth_failures`: `sum by (scheme) (increase(auth_failures_total[5m]))`, and the API's logs for the `401` answers on
bearer requests, which carry the client IP but never the key. Many IPs and no tenant point at guessing; one IP and
one tenant's integration at a revoked key still in use.

For `held_at_limit`, in Grafana: `rate(rate_limit_rejections_total{key_type="api_key"}[5m])` by `group` (I is the audit export, J key
creation; abuse 2.2). The API's logs for the `429` answers carry `tenant_id`; the edge logs carry the client IPs. The
tenant's audit log names the key (`api_key.used` events, actor type `api_key`); its admins can read it, operators
can't (FR-28).

## Mitigate

1. **Tell the tenant's admins**, with the time window and what the limits refused. They know whether it is their
   automation.
2. **Their automation:** they fix it, or create a new key with narrower scopes and revoke the old one.
3. **A leaked key:** any admin of the tenant revokes it (`revokeApiKey`), which applies to the next request because
   lookups aren't cached (authn-authz 5.2), and reviews what it did in the audit log. Deactivating or demoting the key's
   owner revokes all of their keys at once.
4. **Abuse from a few IPs while the tenant can't be reached:** block them in the WAF block list
   ([link-enumeration.md](link-enumeration.md)). In an emergency, abuse 8.3 lets an operator revoke a key; the operator API has
   no operation for it yet, so that needs the owner (escalate).

## Escalate

A key that keeps being used after the tenant was told, or a tenant that can't be reached: escalate to the owner in
[CODEOWNERS](../../.github/CODEOWNERS).

## Afterwards

Note the key's prefix (never the key), the tenant, the cause and what was done.
