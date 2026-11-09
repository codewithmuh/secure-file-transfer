# Runbook: SesReputation (`sft-<env>-<rs>-ses-reputation`)

The `SesReputation` alert of [abuse and rate limits](../security/abuse-and-rate-limits.md) 7.3 and 8.2
([ADR-0015](../adr/0015-email-ses.md)), a CloudWatch alarm defined in
[`infra/modules/alarms/email.tf`](../../infra/modules/alarms/email.tf). Severity: page.

## Symptoms

The account's `Reputation.BounceRate` has been at least 2 %, or its `Reputation.ComplaintRate` at least 0.05 %, for 3
hours in the Region.

## Impact

None yet, but SES reviews an account at 5 % bounces or 0.1 % complaints and may pause it at 10 % or 0.5 %. A paused
account sends nothing: no verification codes, no links, for every tenant (NFR-7).

## Confirm

Commands are for the live run; the alarm is pending the AWS run.

```bash
aws sesv2 get-account --region <region>          # EnforcementStatus, SendingEnabled
aws sesv2 list-suppressed-destinations --region <region> --start-date "$(date -u -v-1d +%FT%TZ)"
```

Which tenant: the notification worker's bounce and complaint records per tenant (the operator API's tenant view), and
`emails_sent_total{type}` on the email dashboard for a type that spiked.

## Mitigate

1. **One tenant**: SES's tenant pause or our own automatic pause (abuse 7.3) should already hold it; if not, suspend the
   tenant's sending through the operator API and contact its admins (abuse 8.2's `tenant-abuse` runbook).
2. **Bounces from a bad list** (a tenant importing stale addresses): the suppression list stops repeats; the rate falls
   as volume grows.
3. **Complaints on one email type**: check the template for something that reads as spam; pause that notice type if
   needed.
4. Never disable the alarm or the suppression list to "get mail flowing".

## Escalate

If the rate keeps rising after the tenant is held, escalate to the owner in [CODEOWNERS](../../.github/CODEOWNERS) and
open an AWS support case before SES pauses the account.

## Afterwards

Postmortem: which tenant and why, and whether our own pause thresholds should be lower.
