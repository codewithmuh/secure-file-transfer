# Runbook: EmailBombing

The email abuse alert of abuse and rate limits 8.2 (AB-3, abuse 7.2), defined in
[`deploy/alerts/abuse.rules.yaml`](../../deploy/alerts/abuse.rules.yaml). Severity: ticket. Abuse 8.2 calls this
runbook `email-abuse`; this file is it.

## Symptoms

Within an hour, the per-address link-email cap was hit more than 20 times
(`email_caps_hit_total{cap="address_link_emails_all"}`), or more than 100 code requests were refused by their limits
(`verification_codes_total{result="rate_limited"}`). Metrics carry no address, so the first counts hits, not distinct
addresses (abuse 8.1).

## Impact

The caps did their job: each address gets at most 5 codes an hour and 50 a day, and at most 20 link emails per tenant
and 100 across tenants a day (AB-3). What remains is someone using the service to send mail to people who didn't ask,
which costs our SES reputation ([ses-reputation.md](ses-reputation.md)).

## Confirm

In Grafana: `email_caps_hit_total` by `cap`, `verification_codes_total` by `result`, `emails_sent_total` by `type`.
Then find the source:

- **Codes:** a leaked link is being used to request codes. The API's logs for `requestVerificationCode` with
  `rate_limited` carry `tenant_id` and the request ID; the edge logs carry the client IP.
- **Link emails:** a member or an API key is sending transfers or upload requests to a victim. The notifier's logs carry
  the `tenant_id`; the tenant's audit log names the actor, which its admins can read and operators can't.

## Mitigate

1. **Codes from a few IPs:** block them in the WAF block list ([link-enumeration.md](link-enumeration.md)).
2. **A tenant's member or key:** tell the tenant's admins. They revoke the transfer or request, deactivate the member or
   revoke the key (authn-authz 5.2), and can add the victim's address to the suppression list (abuse 7.4).
3. **The tenant itself is the abuser:** the operator can suspend it (`suspendTenant`, through the operator API), which
   refuses every call and stops its links (abuse 8.3). A suspension is a decision with the owner.

## Escalate

If complaints or bounces rise with it, or a tenant must be suspended, escalate to the owner in
[CODEOWNERS](../../.github/CODEOWNERS).

## Afterwards

Note the source and what was done. Check the SES reputation metrics for the next three days.
