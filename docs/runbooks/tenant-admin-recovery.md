# Runbook: recover a tenant admin's sign-in

Operator-assisted recovery ([authn-authz](../security/authn-authz.md) 2.5, #239): a tenant whose last admin has lost
their factor, or an SSO tenant whose identity provider is down with no fallback admin available. It is a procedure,
not the answer to an alert. The operator API's `recoverTenantAdmin` does the work; this page is how an operator decides
to call it and checks what it did.

> [!IMPORTANT]
> **The AWS steps are pending the AWS run.** The operator API's archive buckets (`AUDIT_ARCHIVE_TOKYO_BUCKET`,
> `AUDIT_ARCHIVE_OSAKA_BUCKET`) and the Cognito pools have not been applied yet (infra/README.md). Locally the call
> works against PostgreSQL and the S3Mock archive; the first drill in dev checks this page and corrects it.

## When to use it

Only when the tenant can't help itself:

- every admin of the tenant has lost their factor, so no admin can run `resetUserSignIn` for another; or
- the tenant uses SSO, its identity provider is down, and it has no fallback admin who can sign in locally.

Not for a member: their admin resets them. Not for an admin who still has a colleague admin: that colleague resets them.

## 1. Confirm the request through the recovery contact

The request arrives by email or phone. Never act on that channel alone: it may be an attacker who controls the admin's
mailbox.

1. Read the tenant's recovery contact, the second contact besides the first admin given at `createTenant`, with a
   fresh operator token (#274):

   ```
   GET /v1/operator/tenants/{tenant_id}/recovery-contact
   ```

   The read is recorded as `tenant.recovery_contact_read` in the tenant's audit log, where its admins see it, and in
   the platform log, so read it only for a request you are acting on. `503`: the platform record wasn't written and
   nothing was returned; retry. `recovery_contact: null` means a tenant made before contacts were recorded: use the
   onboarding record kept with the tenant's agreement instead.
2. Call or write to that contact, from our own records, never from a number or address in the request. Confirm that
   the tenant asks for the recovery, and which admin it is for.
3. Write down how you confirmed it, in one or two sentences: who you reached, how, and when. That text becomes
   `confirmed_via`, kept in the recovery's row, never in an audit event.

If the contact can't be reached or doesn't confirm, stop. Tell the requester that you couldn't confirm it.

## 2. Call `recoverTenantAdmin`

With a fresh operator token (`createOperatorToken`) and a new `Idempotency-Key` for this recovery:

```
POST /v1/operator/tenants/{tenant_id}/admin-recovery
Idempotency-Key: <a new key for this recovery>
{"user_id": "<the admin's ID>", "confirmed_via": "<how you confirmed it>"}
```

- `202` with `kind: sign_in_reset`: a local admin. Their sessions ended, their old sign-in is gone, and the
  notification worker emails them a new invitation with a temporary password.
- `202` with `kind: temporary_local_sign_in`: an admin of a tenant with an active SSO connection. They get the same
  invitation, and a local sign-in that works for 72 hours (`temporary_sign_in_expires_at`), even if the tenant requires
  SSO. Ask them to name a fallback admin while they are in, so the next outage needs no operator.
- `409 invalid_state`: the user isn't an active admin. Check the ID with the tenant.
- `404 not_found`: no such tenant, or the user isn't in it.
- `503`: the recovery took effect, but its record didn't reach both regions' archive. Retry with the **same**
  `Idempotency-Key`: the retry archives the record and answers `202`, without a second reset. Don't use a new key.

## 3. Check

- The tenant's audit log has a security-critical `user.sign_in_reset` by the operator, naming the recovery and its
  kind; the platform log has `tenant.admin_recovered`.
- The notification worker sent the invitation (`email.sent`, `member_invitation`). If it didn't within a few minutes,
  see [dead-letter-queue.md](dead-letter-queue.md).
- Every active admin of the tenant, the recovered one included, was emailed `tenant_admin_recovered` (#273): in the
  tenant's log, `email.sent` events on the recovery with that type, one per admin. If not within a few minutes, see
  [dead-letter-queue.md](dead-letter-queue.md).

## 4. After 72 hours (temporary sign-in only)

Nothing to do. Sign-in refuses the temporary identity from its `expires_at`, and the daily `cleanup` job deletes it
and records `user.temporary_sign_in_ended`. Its message then has the notification worker delete the admin's Cognito
user in the active pool (#273), unless a newer reset has made the admin a new one since. A user left in the other pool
after a failover maps to nothing in our database and can't sign in to the service; delete it by hand with the
operator's AWS credentials if the tenant asks.

## Escalate

A request you can't confirm, or one the tenant says it never made: treat it as an account takeover attempt, tell the
tenant through its recovery contact, and record it in the incident log.
