# Runbook: break-glass access to tenant data

Break-glass in the service (FR-35, [authn-authz](../security/authn-authz.md) 8.3, #232): an operator reads named
tenants' rows for at most 60 minutes, as the PostgreSQL login role `sft_breakglass`, under a grant that a second
operator approved. It is both a procedure and the runbook of three alerts, defined in
[`deploy/alerts/break-glass.rules.yaml`](../../deploy/alerts/break-glass.rules.yaml), and of the EventBridge alert on
the IAM role (`infra/modules/break-glass-role`). Severity: page, all of them.

> [!IMPORTANT]
> **The AWS steps are pending the AWS run.** Nothing in AWS has been applied yet (infra/README.md). The steps below
> are written from the Terraform, the chart and the contract; the first drill in dev checks them and corrects this page.

## When to use it

Only for an incident or a support case that needs rows of a tenant's data and that nothing else answers: the operator
API, the dashboards, logs and the tenant's own audit log come first. Examples: a transfer stuck in a state no job
moves it out of; a tenant reporting a wrong recipient list that its admins can't see.

It is **not** for reading file contents, file names or messages: `sft_breakglass` can't read objects, and names and
messages are ciphertext to it. It isn't for repairs either: it reads, it never writes.

When the operator API or the database is down, this path is down too. Use the Identity Center `BreakGlass` path of
authn-authz 8.3 instead (assignment by a `BreakGlassApprover`, then the master user or the cluster), which works
without the service, and record the grant afterwards with `recordBreakGlassGrant`. When Identity Center itself is
unreachable, authn-authz 8.4 (the emergency user) applies.

## What it can read

`SELECT` only, on these tables, and only the rows of the tenants the grant names:

| Table | Notes |
|---|---|
| `tenants` | The named tenants' own rows |
| `users` | Members of the named tenants |
| `transfers`, `transfer_recipients` | Messages are ciphertext (field encryption, data model 4.2) |
| `files` | Metadata; names are ciphertext. No access to the objects in S3 |
| `upload_requests` | Messages are ciphertext |
| `audit_events` | The named tenants' records |

Row-level security admits a row only when its `tenant_id` is in `break_glass_tenants()`, which returns the grant's
tenants while the grant named by `app.break_glass_grant` is active and before its `ends_at`. So reads stop at the
grant's end, on the next statement, whether or not anyone acts. Every sign-in is in the cluster's connection log, and
the database bootstrap job sets `pgaudit.log` on `sft_breakglass` so that every statement is logged too, as it does
for the master user (pending the AWS run).

## 1. Request

Through the operator API, as any operator (`Operator` permission set). Port-forward to it and get an operator token
(`createOperatorToken`, authn-authz 8.2), then:

```bash
kubectl -n sft-operator port-forward deploy/operator-api 8443:8000
# In another shell, with OPERATOR_TOKEN from createOperatorToken:
curl -sk -X POST https://127.0.0.1:8443/v1/operator/break-glass-requests \
  -H "Authorization: Bearer $OPERATOR_TOKEN" -H 'Content-Type: application/json' \
  -d '{"incident_id": "<incident or ticket>", "reason": "<why rows are needed>",
       "tenant_ids": ["<tenant id>"], "duration_minutes": 30}'
```

Name the fewest tenants and the shortest time that will do; 60 minutes is the most. The answer is the request, in
`requested`; its `id` is the grant ID used below. A request that nobody approves within an hour lapses.

## 2. Approve (a second operator)

Another operator checks the incident and the scope, then approves:

```bash
curl -sk -X POST https://127.0.0.1:8443/v1/operator/break-glass-requests/<id>/approve \
  -H "Authorization: Bearer $OPERATOR_TOKEN"
```

The grant is `active` from now until `ends_at` (`duration_minutes` later). The approval writes a security-critical
platform audit record and one in each named tenant's audit log, where its admins see it (UC-4).
`BreakGlassActive` pages from now until the grant ends.

**Self-approval** answers `403 self_approval_forbidden`, except where the cluster's values set
`BREAK_GLASS_SELF_APPROVAL=true` on the operator API. Only dev sets it today. The reference run has a single
maintainer, so a second approver isn't possible: self-approval is then allowed, marked `self_approved`, pages on its
own (`BreakGlassSelfApproved`) and is recorded in the after-action review. That is accepted risk R-08 (threat model,
authn-authz 9.1). Turning it on in staging or prod is a reviewed commit to that cluster's values file, and it is turned
off again as soon as a second operator exists.

## 3. Connect as `sft_breakglass`

Pending the AWS run. The requester needs the `BreakGlass` permission set, assigned for one hour by a
`BreakGlassApprover` as in authn-authz 8.3 (that assignment pages too). From that session:

```bash
export AWS_PROFILE=<the BreakGlass profile of the environment's account> AWS_REGION=ap-northeast-1
GRANT=<the grant id>
# The session tag must be the grant ID: the role refuses an assumption without it, or with any other tag.
# A regional STS endpoint (the CLI's default) in Tokyo or Osaka; the role refuses any other Region.
creds=$(aws sts assume-role \
  --role-arn "arn:aws:iam::<account id>:role/sft-<env>-break-glass-db" \
  --role-session-name "<your Identity Center user name>" \
  --tags "Key=sft-break-glass-grant,Value=$GRANT" \
  --duration-seconds 3600 --query Credentials --output json)
export AWS_ACCESS_KEY_ID=$(jq -r .AccessKeyId <<<"$creds") \
       AWS_SECRET_ACCESS_KEY=$(jq -r .SecretAccessKey <<<"$creds") \
       AWS_SESSION_TOKEN=$(jq -r .SessionToken <<<"$creds")
unset AWS_PROFILE
# The writer endpoint: the data stack's aurora_endpoint output (in Osaka after a failover, Osaka's).
PGPASSWORD=$(aws rds generate-db-auth-token --hostname "<writer endpoint>" --port 5432 \
  --username sft_breakglass --region "$AWS_REGION")
export PGPASSWORD
psql "host=127.0.0.1 port=<local port> dbname=sft user=sft_breakglass sslmode=verify-full \
      sslrootcert=<rds-ca-ecc384-g1 bundle>"
```

Every assumption, granted or refused, pages through the EventBridge rule `sft-<env>-<rs>-break-glass-db-assumed`,
naming the caller and the grant. The token from `generate-db-auth-token` is valid for 15 minutes for new connections;
make another one if you reconnect later.

**Reaching the endpoint.** Aurora is in isolated subnets and its security group admits only the main and scan node
groups. No reviewed path from an operator's machine to port 5432 exists yet; the master-user path of authn-authz 8.3
has the same gap. The AWS run decides it (for example a Systems Manager port-forwarding session through a node that
the database admits) and replaces `127.0.0.1:<local port>` above with it. With `sslmode=verify-full` the host name
must match the certificate, so a tunnel needs `hostaddr=127.0.0.1` and `host=<writer endpoint>`.

Then, in psql, name the grant before any query:

```sql
SET app.break_glass_grant = '<grant id>';
SELECT id FROM tenants;        -- only the grant's tenants
```

A query without the setting, or after `ends_at`, returns no rows. Keep the session to what the request named; the
after-action review compares the pgaudit log with the scope.

## 4. End

End it as soon as you are done, rather than waiting for `ends_at`:

```bash
curl -sk -X POST https://127.0.0.1:8443/v1/operator/break-glass-requests/<id>/end \
  -H "Authorization: Bearer $OPERATOR_TOKEN"
```

Access ends with that transaction. Any operator may end a grant; ending one already ended changes nothing. Then quit
psql, drop the assumed role's variables, and ask the `BreakGlassApprover` to remove the `BreakGlass` assignment if it
is still there.

**Automatic expiry.** If nobody ends it, the grant stops reaching its tenants at `ends_at` on its own, in the
database. Within a minute the operator API's sweep (every 30 s) marks it `expired`, with an audit record, and
`BreakGlassActive` clears. A request never approved is marked `lapsed` an hour after it was made.

## The alerts

### BreakGlassActive

A grant is active (`sft_break_glass_active_grants > 0`). It pages for as long as one is.

- **Confirm:** `listBreakGlassRequests` with `state=active`: who asked, who approved, the incident, the tenants and
  `ends_at`.
- **Expected** (a grant you know about, with an incident): acknowledge, and check that it ends.
- **Unexpected** (no incident, an approver who didn't approve, tenants outside the incident): end it at once
  (`endBreakGlass`), then treat it as a security incident: who holds `Operator`, whose token approved it (the platform
  audit log names both), and whether the IAM role was assumed (the EventBridge alert, CloudTrail).

### BreakGlassSelfApproved

A grant that its requester approved alone is active. In the single-maintainer reference run that is expected and
accepted (R-08): note it for the after-action review. Anywhere `BREAK_GLASS_SELF_APPROVAL` should be off, it means
someone turned it on: end the grant, find the commit that set it, and revert it.

### BreakGlassSweepStalled

The sweep hasn't completed for 5 minutes. Database access still ends at `ends_at`, because the database checks the
time itself, but grants stay `active` in the service, their expiry records are missing, and `BreakGlassActive` may be
wrong.

- **Confirm:** `kubectl -n sft-operator logs deploy/operator-api --since=15m` for the sweep's errors (often the
  database or the audit write). `kubectl -n sft-operator get pods`: a pod that restarts loses no state; the next sweep
  catches up.
- **Mitigate:** fix the cause (the database, the operator API's role); the next sweep records every grant that ended
  meanwhile, with its real end time. If the operator API is down, service-unavailable's runbook applies first.

### The EventBridge alert on `sft-<env>-break-glass-db`

Someone assumed, or tried to assume, the break-glass database role. Its message names the caller, the source IP, the
grant ID from the session tag and the CloudTrail event ID. Check that the grant ID is an active grant whose requester
is the caller. A refused attempt (an `errorCode` in the CloudTrail event), a grant ID that isn't active, or a caller
who isn't the requester is a security incident: remove the `BreakGlass` assignment and end the grant. Until M7 wires
the topic to the pager (ADR-0009), nothing is subscribed: pending the AWS run and M7.

## Afterwards

An after-action review within 2 business days, for every grant, self-approved or not (authn-authz 8.3): the incident,
what was read (the pgaudit log of `sft_breakglass` and the tenants' audit records) against the approved scope, whether
the access was needed, and an issue to make it unnecessary next time. Self-approval is recorded in it (R-08). Uses are
counted; the target is zero.

## Escalate

If a grant can't be ended (the operator API is down while one is active), it still ends at `ends_at` in the database.
Escalate to the owner in [CODEOWNERS](../../.github/CODEOWNERS) for anything unexpected in the alerts above.
