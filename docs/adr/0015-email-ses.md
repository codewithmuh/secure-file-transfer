# 0015. Use Amazon SES in Tokyo and Osaka for all service email

- Status: accepted
- Date: 2026-11-03
- Issue: [#32](https://github.com/codewithmuh/secure-file-transfer/issues/32)

## Context

Every link, code and notice goes by email, so the email provider is on the critical path: a recipient who can't get a
code can't download ([architecture](../architecture.md), section 1). The [PRD](../prd.md) asks for emails handed to
the provider within 10 s at p95 (NFR-7), names deliverability as a risk, and notes that SES starts in a sandbox, needs
production access and SPF, DKIM and DMARC, and is set up per region, so the failover drill must send from Osaka
(section 10). Customer data, email addresses included, stays in Japan (NFR-21).

- **Volume.** About 46,600 emails a day, 1.42 M a month, peaking near 5 a second
  ([capacity](../design/capacity-and-cost.md) 3.2).
- **Abuse.** A tenant or a compromised member could send spam or phishing through us, and one tenant's bounces or
  complaints could get the whole account paused, which would stop verification for everyone
  ([abuse and rate limits](../security/abuse-and-rate-limits.md) AB-3, AB-4, section 7;
  [threat model](../threat-model.md) T-56 to T-59).
- **Domain.** The service domain is still open (PRD open question 5).

## Decision

Send every service email through **Amazon SES (API v2) in Tokyo**, with an identical, **production-approved setup in
Osaka** for failover.

- **Production access and quotas** in both regions, at least 100,000 emails a day and 20 a second, before the first load
  test (capacity 3.2). The failover drill sends real email from Osaka.
- **A dedicated sending subdomain** of the service domain, for example `mail.<domain>`, verified as a domain identity in
  each region with Easy DKIM, each region's DKIM records managed in Route 53 by Terraform. **One custom MAIL FROM
  subdomain per region**, because SES requires exactly one MX record on it and that record points at one region's
  feedback endpoint. SPF on each MAIL FROM subdomain, and **DMARC at `p=reject`** on the sending subdomain, with
  aggregate reports to a mailbox we read.
- **One configuration set per region**: TLS required to receiving servers, reputation metrics on, and bounce, complaint,
  delivery, reject and delivery-delay events, tagged with tenant and email type, published through SNS to the
  notification worker's queue (ADR-0013).
- **One SES tenant per tenant** in each region, created by `createTenant`, on the Standard reputation policy, so SES
  pauses only the tenant with high-severity findings. Status changes reach the notification worker through
  EventBridge; it holds that tenant's email and pages an operator.
- **Per-tenant controls of our own** (abuse design 7.2, 7.3): sending caps applied by the notification worker, which
  holds over-cap email with the recipient shown as `queued`, and an automatic pause at 5 % hard bounces (at least 50)
  or 0.3 % complaints (at least 3) over the tenant's last 1,000 emails.
- **Suppression.** Our `email_suppressions` table decides: a hard bounce suppresses an address everywhere, a complaint
  only for the tenant that sent the email (abuse design 7.4). SES's account-level suppression list covers bounces as a
  backstop. Complaints use SES's tenant-level suppression lists, not the account list, which would block a complaining
  address for every tenant.
- **Content.** Fixed, localized templates with no file names or message text; `From` on our subdomain, `Reply-To` the
  sender; only links to our web app (abuse design 7.5). Shared sending IPs; no dedicated IPs in v1.

## Options considered

| Option | Pros | Cons |
|---|---|---|
| **Amazon SES in Tokyo and Osaka** (chosen) | Runs in both our regions, so addresses, links and codes stay in AWS in Japan, and the Osaka setup is part of the same failover. IAM roles instead of an API key. Tenant-level reputation and pauses. Configuration-set events land in our own queues. About $142 a month for 1.42 M emails, plus about $10 for tenant management; a mailbox simulator for load tests. | Everything is per region: identities, DKIM and MAIL FROM records, configuration sets, SES tenants, quotas and production access, set up and kept in step twice. Production access is a manual AWS review per region, a lead-time risk before load tests and drills. Shared IPs tie part of our deliverability to other senders. The account's reputation still sums every tenant (R-07). Osaka sends almost nothing until a failover, then the full volume at once. Tenant management's availability in both regions isn't confirmed yet. |
| **A third-party email API** | Sends from anywhere, so failover needs no second setup. Mature deliverability tooling, dedicated IP pools, inbound handling and template editors; sub-accounts per customer are common. | Every recipient address, link and code passes through a party outside our AWS accounts and usually outside Japan (NFR-21). One more API key to store and rotate, one more party in the threat model and the supply chain. The provider's outage isn't covered by our Osaka failover. Delivery events arrive by webhook, a new public endpoint. Usually costs more per email at this volume, and its contract outlives teardown (NFR-19). |
| **Our own mail servers** (an open-source MTA such as Postfix on EC2) | Full control; no per-email fee. | IP reputation starts from zero and needs warming. Outbound port 25 on EC2 is restricted until AWS lifts it. DKIM signing, bounce handling, feedback loops and blocklist monitoring are ours, on another stateful fleet for one maintainer. |

## Consequences

- **Infrastructure.** Terraform manages identities, DNS records, configuration sets, event destinations and the
  tenant-pause rules in both regions. A daily check verifies SPF, DKIM and DMARC for both regions (threat model
  section 6).
- **Before load tests.** Production access and quotas confirmed in both regions. The first staging build confirms SES
  tenant management and tenant-level suppression in Tokyo and Osaka (the SES guide lists no regional restriction). If
  either is missing in a region, that region relies on our own per-tenant pause and suppression table, and this ADR is
  revisited.
- **Monitoring.** Account bounce and complaint rates alarm at 2 % and 0.05 % held for 3 hours (abuse design 7.3);
  NFR-7 is measured from outbox write to SES acceptance; the notification worker backs off when throttled.
- **TLS required.** A receiving server without TLS gets no email; staging measures how often that happens (threat model
  open point 8).
- **Failover.** Suppressions and our own pauses live in PostgreSQL and fail over with it. SES tenant pauses are per
  region, so the failover runbook applies Tokyo's open pauses in Osaka before workers start.
- **Cognito's own emails** (sign-in and MFA) are configured with member sign-in, in the security ADRs (#33).

## When to revisit

If tenant management or tenant-level suppression is unavailable in Tokyo or Osaka, if drills or the load test show
NFR-7 or inbox placement failing, if volume grows enough to justify dedicated IPs, or once the domain (open question 5)
is chosen and the subdomain names are fixed.
