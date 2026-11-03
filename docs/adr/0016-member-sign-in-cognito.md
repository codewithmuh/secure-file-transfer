# 0016. Use Amazon Cognito with mandatory MFA and federated tenant SSO for member sign-in

- Status: accepted
- Date: 2026-11-03
- Issue: [#33](https://github.com/codewithmuh/secure-file-transfer/issues/33)

## Context

PRD open question 1 asks how members and tenant admins sign in. The [PRD](../prd.md) requires multi-factor
authentication for every member (FR-25, Must) and single sign-on through the tenant's own OIDC or SAML identity provider
(FR-26, Should), with no self-service sign-up (FR-34). Sign-in has to meet OWASP ASVS 5.0 Level 2 (NFR-13), allow at
most 10 failed sign-ins per account per 15 minutes (NFR-14), put every attempt in the audit log within 60 seconds
(FR-27, NFR-15), be back in Osaka within an hour of losing Tokyo (NFR-11), and keep customer data in Japan (NFR-21).
One maintainer builds and runs it, and the synthetic probe tenant (NFR-1) has no identity provider of its own.

The design is argued in [authentication and authorization](../security/authn-authz.md), sections 2 and 3, and its
threats in the [threat model](../threat-model.md) (T-07 to T-11, residual risks R-01 and R-10). This ADR records it.

## Decision

Use **Amazon Cognito for sign-in only**, and keep sessions and authorization in our own service:

- **One user pool per environment in Tokyo**, shared by every tenant, on the **Plus** plan with threat protection in
  enforce mode and admin-only sign-up. **MFA is required:** TOTP, or a passkey with user verification. SMS and email
  codes are off.
- **Tenant SSO is federated through the pool:** one SAML or OIDC provider per tenant, each an `idp_connections` row.
  Identities are keyed by `(idp_connection_id, subject)` and bound only through a one-time invitation, never by an
  email claim. Our sign-in page names the provider; Cognito's routing by email domain is not configured.
- **Our own session.** The API runs the authorization code flow with PKCE (S256) and a confidential client, validates
  the ID token once, revokes the refresh token, and creates a server-side session in PostgreSQL behind the
  `__Host-sft_session` cookie. No Cognito token reaches the browser.
- **An Osaka standby pool** in staging and prod, from the same Terraform and with no users. Every tenant's SSO provider
  exists in both pools, so SSO members sign in through Osaka unchanged. Members without SSO re-enrol by email after a
  declared failover. Cognito's multi-Region replication isn't used: it doesn't offer Osaka as a replica Region and
  doesn't support TOTP on a replica.
- **The admin passkey rule sits behind a launch switch.** A local admin's session holds the admin role only when the
  ID token's `amr` claim shows a passkey; otherwise it acts as a member and admin operations return
  `403 passkey_required` (revocations excepted). The switch goes on in staging and prod once a staging test shows that
  both pools issue `amr`.
- **Cognito's own email goes through our SES identity.** Each pool uses Cognito's developer email sending
  (`EmailSendingAccount` `DEVELOPER`) with the SES domain identity on our sending subdomain, `mail.<domain>`, in the
  pool's own Region. The few emails Cognito sends itself, such as managed login's password-reset codes, carry the same
  DKIM, SPF and DMARC as every other service email and use that Region's configuration set
  ([ADR-0015](0015-email-ses.md)). Cognito's default sender, an Amazon address limited to 50 emails a day, isn't used.

## Options considered

| Option | Pros | Cons |
|---|---|---|
| **Cognito Plus for local members, tenant SSO federated through it, our own session** (chosen) | AWS stores passwords, TOTP secrets and passkeys. Mandatory MFA, passkeys, the breached-password check and lockout are settings, not code (ASVS chapter V6). AWS parses SAML and OIDC responses, so our service never parses SAML or sees a password. A managed service, not another service of ours. Cognito is used only at sign-in, so replacing it later changes sign-in, not sessions or authorization. | Credentials can't be exported: lock-in, and after a regional failover local members re-enrol, during which control of the mailbox is enough to take over their account (R-10). An email alias is unique in a pool, so an address can hold a local sign-in for one tenant only. Cognito's MFA doesn't apply to federated users, and SAML gives no proof that the tenant's provider used MFA. The `amr` claim the passkey rule reads is still being rolled out. Plus has no free tier: $0.02 per monthly active user, about $500 a month at design load ([capacity](../design/capacity-and-cost.md), A36). Its built-in lockout alone allows more failures than NFR-14, so a trigger of ours counts them. |
| Cognito with its multi-Region replication add-on | Passwords and passkeys replicate, so passkey members wouldn't re-enrol after a failover | Osaka isn't a supported replica Region, and any other Region breaks NFR-21. TOTP doesn't work on a replica. A replica can't create users or reset sign-ins, so invitations and recovery wait for Tokyo. Needs a multi-Region KMS key and costs about $150 a month more at design load. |
| Build our own: passwords and TOTP or passkeys (WebAuthn), plus SAML and OIDC | No per-user fee. Credentials live in PostgreSQL and replicate to Osaka with everything else: the best failover. | Weeks of security-critical code for one maintainer: password hashing and breach checks, TOTP replay protection, WebAuthn ceremonies, recovery, and SAML signature validation, a long-standing source of critical bugs. Most of ASVS chapters V6 and V10 become ours to meet and test. |
| SSO only: every tenant signs in through its own identity provider | No credentials stored at all | FR-25 is only as strong as each tenant's identity provider. Tenants without one, and the synthetic probe tenant, can't sign in. |

## Consequences

What we build and run:

- **Sign-in endpoints** with single-use pre-auth state (state, PKCE verifier, nonce) in the Valkey store for 10
  minutes, failing closed when the store is down; ID token checks (signature, issuer, audience, `token_use`, expiry,
  nonce); identity resolution from how the sign-in arrived, never from an issuer string; and `prompt=login` on every
  sign-in, so Cognito's own one-hour cookie can't undo our 30-minute idle timeout.
- **Two Lambda triggers.** The pre-authentication trigger counts failures and refuses the 11th in 15 minutes
  ([abuse and rate limits](../security/abuse-and-rate-limits.md), 2.3). Both triggers send attempts and successes
  through SQS to the audit log, and deny sign-in when they can't.
- **Invitations and resets.** The notification worker creates local members' Cognito users and records their
  identities; SSO identities bind through a one-time invitation link. A sign-in reset ends the member's sessions and
  removes their identities in both pools at once. Only the notification worker's IAM role may call Cognito's admin
  operations; the API and operator API roles have no Cognito permissions.
- **SSO onboarding** is an operator runbook: DNS TXT proof of each email domain, the provider created in both pools,
  the tenant admin's audited confirmation that their provider enforces MFA, and a test sign-in through each pool. A
  daily job compares each tenant's recorded configuration with both pools.
- **Failover.** The runbook re-creates every active local member in the Osaka pool and emails a re-enrolment
  invitation; tenant admins are told and every re-enrolment is audited. Signed-in members keep their sessions, which
  replicate with PostgreSQL. Recipients, uploaders and API keys don't depend on Cognito, so the synthetic probe keeps
  measuring them. Which role creates those users while Osaka's workers are still scaled to zero, given that only the
  notification worker may call Cognito's admin operations, isn't decided yet; it is a disaster-recovery gap tracked in
  [#42](https://github.com/codewithmuh/secure-file-transfer/issues/42).
- **Email.** Each pool names its own Region's SES identity, so the Osaka standby pool sends through Osaka's after a
  failover. An identity policy on each SES identity lets Cognito send as it for that Region's pool only.
- One pool serves every tenant, because a pool per tenant would need a custom domain each and Cognito allows four per
  Region. Isolation between tenants in the pool comes from our identity mapping, which the isolation suite tests.
- Until the passkey switch is on, local admins on TOTP can be phished in real time like members (R-01). If the pools
  don't issue `amr` by launch, an ADR records running without the rule.
- The sign-in operations are in the [API contract](../api/openapi.yaml), and `member_sessions` and the per-pool
  `user_identities` in the [data model](../design/data-model.md), section 2.

When to revisit: if the first regional failover drill shows that local-member re-enrolment can't meet NFR-11, or most
tenants turn out to need local accounts, write a superseding ADR for our own passkey sign-in, keeping Cognito for
federation or replacing it. Revisit too when Cognito's replication supports Osaka, so members with passkeys could fail
over without re-enrolling, and if people who work for several tenants under one address become common.
