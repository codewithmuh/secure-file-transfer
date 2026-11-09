# Runbook: VerificationGuessing

The verification abuse alert of abuse and rate limits 8.2 (AB-2, NFR-14), defined in
[`deploy/alerts/abuse.rules.yaml`](../../deploy/alerts/abuse.rules.yaml). Severity: page. Abuse 8.2 calls this
runbook `verification-abuse`; this file is it. Its `condition` label says which:

- `mismatches`: wrong verification codes at more than 5 times their 7-day rate, and at least 20 in 15 minutes, for
  15 minutes (`verification_attempts_total{result="mismatch"}`);
- `lockouts`: more than 10 recipients or uploaders locked out within an hour (`recipient_lockouts_total`,
  `uploader_lockouts_total`).

## Symptoms

Many wrong codes, or many lockouts. Members and tenant admins get a lockout email for each one (authn-authz 4.4).

## Impact

A guesser can't win: codes have 6 digits, 5 attempts each, and 20 failed attempts lock the recipient (at most a
2 × 10^-5 chance, AB-2). The harm is to the real recipients: whoever holds a leaked link can lock them out, and they
can't download until their member unlocks them (PRD risk table).

## Confirm

In Grafana: `rate(verification_attempts_total[5m])` by `result`, `increase(recipient_lockouts_total[1h])`, and
`rate_limit_rejections_total{group="A"}` (each IP gets at most 30 failed attempts an hour across all links). The
sources are in the edge logs, as in [link-enumeration.md](link-enumeration.md): `/v1/links/` requests by client IP and ASN.
The API's logs carry `tenant_id`, which shows whether one tenant's links are targeted.

## Mitigate

1. **A few sources:** block them in the WAF block list `sft-<env>-<rs>-block-list`
   ([link-enumeration.md](link-enumeration.md) has the commands).
2. **Anonymous or hosting networks:** turn on `attack_mode_links` in the edge root, as in
   [link-enumeration.md](link-enumeration.md).
3. **One tenant targeted:** tell its admins. The member, or a tenant admin, unlocks each real recipient
   (`unlockRecipient`, `unlockUploader`): unlocking always issues a new link and the old one stops working, so the
   holder of a leaked link is cut off (authn-authz 4.4). Or they revoke the transfer and send it again. Operators can't
   unlock, and API keys can't either: a person decides.
4. **Lower a limit** only through the deploy config, for every tenant at once (NFR-14, abuse 8.3).

## Escalate

If lockouts keep rising for an hour after blocking, escalate to the owner in [CODEOWNERS](../../.github/CODEOWNERS).

## Afterwards

Note the sources and the tenants affected. Remove the blocks once quiet for a day.
