# API contract

| | |
|---|---|
| Contract | [openapi.yaml](openapi.yaml), OpenAPI 3.1 |
| Requirements | [PRD](../prd.md), especially FR-31 and NFR-14 |
| Design | [Architecture](../architecture.md), [data model](../design/data-model.md), [ADR-0002](../adr/0002-api-framework.md), [ADR-0018](../adr/0018-stream-downloads-through-api.md) (downloads) |
| Security design | [Authentication and authorization](../security/authn-authz.md), [abuse prevention, rate limits and downloads](../security/abuse-and-rate-limits.md), [encryption and keys](../security/encryption-and-keys.md), [threat model](../threat-model.md) |
| Tracking | [#14](https://github.com/codewithmuh/secure-file-transfer/issues/14), part of phase 2 ([#16](https://github.com/codewithmuh/secure-file-transfer/issues/16)); aligned with phase 3 in [#26](https://github.com/codewithmuh/secure-file-transfer/issues/26) and with the phase 4 reviews in [#41](https://github.com/codewithmuh/secure-file-transfer/issues/41) |

Everything the web app does goes through this API (FR-31), and tenant automation uses the same API with API keys
(FR-32). The contract is **design-first**: phase 2 writes it before any code. Once code exists, the document generated
from the code is committed here and CI fails if the two differ; a breaking-change check fails the pull request unless
it is marked as breaking (ADR-0002). Until then, CI lints this file (section 11).

The phase 3 security design settled the two parts that phase 2 left provisional. Members sign in through Amazon
Cognito managed login or their tenant's own identity provider, and the API issues its own session (PRD open question
1, [authn-authz](../security/authn-authz.md) section 2). Downloads stream through the API under a download grant (open
question 8, [abuse-and-rate-limits](../security/abuse-and-rate-limits.md) section 5).

## 1. Base URL and versioning

- Every path is relative to `/v1` on the API origin, a subdomain of a domain the maintainer owns (PRD open question
  5); the name is set before the first deploy.
- The operator paths (`/operator/...`) are served by the operator API, a separate workload with its own `servers`
  entry in the spec. No load balancer or ingress routes to it; operators reach it with `kubectl port-forward` into the
  `sft-operator` namespace (authn-authz 8.2).
- The major version is in the path. Within `/v1` only backwards-compatible changes are made: new operations, new
  optional request fields, new response fields and new error codes. Clients ignore response fields they don't know,
  and treat an unknown error `code` by its HTTP status.
- A breaking change ships only in a new version (`/v2`), which runs next to `/v1` until `/v1` is retired.
- A deprecated operation is marked `deprecated: true` in the spec, and its responses carry a `Deprecation` header
  (RFC 9745) and a `Sunset` header (RFC 8594) with the retirement date. The notice period is at least 6 months. The web
  app moves to the new version in the same release; the notice period is for API-key automation.
- `info.version` is the version of this document. It stays `1.0.0-draft` until the API service's first release.

## 2. Callers and authentication

| Caller | Security scheme | Sent as | Used by |
|---|---|---|---|
| Member or admin, signing in | None: `security: []` | Browser navigation; a `__Host-sft_auth` cookie holds the sign-in state for 10 minutes | `startSignIn`, `completeSignIn`, `startInvitationSignIn` |
| Member or admin, web app | `memberSession`, plus `csrfToken` on POST, PATCH and DELETE | `__Host-sft_session` cookie; `X-CSRF-Token` header with the token from `getCurrentMember` | Most operations |
| Tenant automation | `tenantApiKey`, with scopes | `Authorization: Bearer` header, never a query string or body | Transfers, upload requests, audit |
| Recipient or uploader, before verification | None: `security: []` | Link token in the request body | `resolveLink`, `requestVerificationCode`, `createLinkSession` |
| Recipient or uploader, after verification | `linkSession`, plus `csrfToken` on unsafe methods | `__Host-sft_link` cookie; `X-Link-Session` header naming the session; `X-CSRF-Token` with that session's token. The content download sends only the cookie. | `/session` operations |
| Platform operator | `operatorToken`, from `createOperatorToken` | `Authorization: Bearer` header, through a port-forward to the operator API | `createTenant`, `configureTenantSso`, `recoverTenantAdmin`, `recordBreakGlassGrant` |

- Every operation declares its `security` explicitly. The only public operations are the three link steps, the three
  sign-in steps and `createOperatorToken`, whose signed AWS request is itself the credential. There is no public
  `/v1/health`. The load balancer checks `GET /readyz` on a target port its public listener doesn't route, Route 53's
  health checks probe a fixed response that each load balancer answers itself, and metrics are scraped inside the
  cluster (architecture section 8, ADR-0021). None of these is an API operation.
- Every operation also declares `x-permission`: the permission the service layer checks, or `public` (ADR-0002). A lint
  rule fails if one is missing. The [permission table](../security/authn-authz.md#63-permission-table) lists every
  value with who may use it.
- **One credential per request.** A request with a session cookie and an `Authorization` header together gets
  `401 credentials_invalid`.
- `memberSession: [admin]` means the session must act with the admin role. For an API key, the requirement lists the
  scope it needs, such as `transfers:write`. A key acts as the tenant admin who created it, limited to its scopes. It
  never downloads file contents, unlocks a recipient or uploader, or manages users, roles, policy, SSO or keys
  (authn-authz 5.3). Deactivating that admin, or demoting them to `member`, revokes every key they own in the same
  transaction.
- **Admin rights need a passkey.** A local admin acts with the admin role only in a session signed in with a passkey;
  an SSO admin, with their identity provider's assurance. Otherwise the session acts as a member, and an operation that
  needs the admin role answers `403 passkey_required`, including a tenant-wide read such as `scope=tenant` or another
  member's transfer. Revocations (`revokeTransfer`, `revokeUploadRequest`, `revokeApiKey`) are exempt, because a
  stolen session can use them only to stop sharing (authn-authz 3.3). `getCurrentMember` returns the session's
  `effective_role` and `auth_method`, so the web app can offer a passkey sign-in first.
- **Step-up.** `inviteUser`, `updateUser`, `deactivateUser`, `updateTenantPolicy`, `createApiKey`, `resetUserSignIn`
  and `exportAuditEvents` need a sign-in within the last 15 minutes, otherwise `401 reauthentication_required`. The
  web app runs `startSignIn` again the same way in, which forces a fresh sign-in at Cognito and at the tenant's
  identity provider, then retries. An API key may call only `exportAuditEvents` of these, within its own limits.
- **A file's API key scope follows its owner.** `getFile` and `deleteFile` list both `transfers:*` and
  `upload_requests:*` because OpenAPI can't make the choice depend on the file. The service checks the scope that
  matches the file: `transfers:*` for a file of a transfer, `upload_requests:*` for a received file. A key with only
  the other scope gets `404`.

**Sign-in.** The web app's sign-in page asks for the work address and offers two ways in: "Continue with SSO" calls
`startSignIn` with `method=sso` and only the address's domain, and "Sign in with a password or passkey" with
`method=local`. Our page, not Cognito, picks the identity provider. Cognito redirects back to `completeSignIn`, which
exchanges the code with PKCE and the client secret, finds the identity by `(idp_connection_id, subject)`, never by an
email claim, and sets a new `__Host-sft_session`. No Cognito token reaches the browser, and the API keeps none. A
refused sign-in returns to the web app with `error=sign_in_failed`, which names no reason; the reason is audited. A
member of an SSO tenant first signs in from their invitation link through `startInvitationSignIn`, which binds their
identity provider's subject to the invited user (authn-authz 2.4, 2.5). `signOut` ends the session and returns the
user pool's logout URL.

**Sessions.** A member session lasts at most 12 hours and 30 minutes idle; a member has at most 10. The role is read on
every request. A role change, a sign-in reset, a deactivation or a forced sign-out (`signOutUser`) ends every session
of that user (authn-authz 3.3).

**Who sees what.** A member sees and acts on their own transfers and upload requests. A tenant admin, and an API key
with the matching scope (it acts as its admin owner), also sees every transfer and upload request in the tenant, as
metadata with its files' states and its recipients' status, and can revoke it. An admin can also unlock its recipient
or uploader; an API key can't (UC-3, FR-20). The other actions on another member's item (send, cancel, extend, upload,
delete a file, download a received file) belong to its owner, and an admin gets `403 permission_denied`. An item in
another tenant, or another member's item for a member who isn't an admin, returns `404`, never `403`, so its existence
is never revealed (NFR-12).

**CSRF and cookie sessions.** Each member session and each link session has its own CSRF token, derived from the
session token and never stored: `key_id + "." + base64url(HMAC-SHA-256(K_csrf, session token))` (authn-authz 3.4). It
is returned in the response body, always with `Cache-Control: no-store`: `csrf_token` in `getCurrentMember`, and in
`createLinkSession` and `getLinkSession`. Because it is derived, the same token comes back after every page load until
the session changes. The web app keeps it in memory and sends it in `X-CSRF-Token`; there is no readable CSRF cookie,
because the web app and the API are separate origins. The service checks the token of the session the request uses, so
starting a link session never breaks a member's token. Both session cookies are `HttpOnly`, `Secure`,
`SameSite=Strict` and host-only, so a cross-site request carries no session at all. The service also checks `Origin`
and `Sec-Fetch-Site` on every unsafe request, and unsafe methods accept only `application/json` bodies (anything else
gets `400 malformed_request`). The sign-in state cookie `__Host-sft_auth` is `SameSite=Lax`, because Cognito's
redirect to the callback is cross-site.

**Several link sessions per browser.** A browser can hold up to 10 link sessions at once, one per transfer recipient or
upload request, under its `__Host-sft_link` cookie, so verifying a second link never ends the first; an 11th ends the
oldest. Every `/session` call names its session in the `X-Link-Session` header (the `id` from `createLinkSession`, or
`link_session_id` from `resolveLink`) and sees only that session's transfer or request. The ID isn't a credential: it
works only with the cookie of the browser that verified it. The one exception is `getSessionDownloadContent`, which a
navigation starts and so can't send a header: the grant ID in its path names the session, and the cookie must hold it.

**Operators.** The operator CLI signs an STS `GetCallerIdentity` request with the operator's IAM Identity Center
credentials and exchanges it at `createOperatorToken` for a 15-minute operator token. Only this environment's
`Operator` permission set role is accepted; `BreakGlass` and other environments' roles are refused (authn-authz 8.2).
The operator API never returns file names, messages or contents.

## 3. Errors

Every error is an RFC 9457 problem (`application/problem+json`) with these fields:

| Field | Meaning |
|---|---|
| `type` | Stable URI per problem, `https://secure-file-transfer.example/problems/{code}`. The host changes to the service's domain once its name is set, before the first deploy (open question 5). |
| `title`, `detail` | For people. They may change; never branch on them. |
| `status` | The HTTP status. |
| `code` | Stable, machine-readable code. Clients branch on this. |
| `request_id` | Also in logs and traces; quote it when reporting a problem. |
| `errors` | For `validation_failed` and `recipient_undeliverable`, one entry per problem with a JSON Pointer. |
| `attempts_remaining`, `current_state` | For `code_invalid` and for state conflicts. |

| Status | Codes |
|---|---|
| 400 | `malformed_request`, `invalid_cursor` |
| 401 | `authentication_required`, `session_expired`, `credentials_invalid`, `reauthentication_required` |
| 403 | `permission_denied`, `passkey_required`, `csrf_failed`, `recipient_locked`, `download_limit_reached`, `download_grant_exhausted` |
| 404 | `not_found`, `link_not_found` |
| 409 | `idempotency_conflict`, `idempotency_in_progress`, `invalid_state`, `transfer_revoked`, `transfer_expired`, `upload_request_revoked`, `upload_request_expired`, `transfer_empty`, `upload_incomplete`, `file_not_shareable`, `user_exists`, `last_admin` |
| 410 | `link_revoked`, `link_expired` |
| 413 | `file_too_large`, `total_too_large`, `storage_quota_exceeded`, `request_too_large` |
| 416 | `range_not_satisfiable` |
| 422 | `validation_failed`, `expiry_out_of_range`, `recipient_domain_not_allowed`, `recipient_undeliverable`, `too_many_files`, `upload_size_mismatch`, `code_invalid`, `code_expired`, `code_attempts_exhausted`, `export_too_large` |
| 429 | `rate_limited` |
| 503 | `service_unavailable`: a call couldn't reach the audit archive, the rate-limit counters or the sign-in state store, or an API pod is full of download streams. A download grant, a verification or a sign-in changed nothing; a security-critical change took effect and a retry completes its record (section 5). |

Members see `transfer_revoked` or `transfer_expired` (409) when they act on a transfer that was revoked or has expired;
recipients see `link_revoked` or `link_expired` (410). Operations that apply only to drafts, such as adding
and uploading files, answer `409 invalid_state` with `current_state` instead, because a draft is never revoked or
expired: it is cancelled. Each operation's description lists the codes it can return.

`completeSignIn` is a browser navigation from Cognito, so it never answers with a problem document for a refused
sign-in: it redirects to the web app's sign-in page with `error=sign_in_failed`, and the audit log records why.

## 4. Pagination

List operations that can grow take `cursor` and `limit` (1–100, default 25) and return `items` and `next_cursor`.
`next_cursor` is `null` on the last page. Cursors are opaque: pass them back unchanged. An invalid or expired cursor
returns `400 invalid_cursor`. Lists bounded by the PRD (at most 50 files or recipients, at most 1,000 upload parts) are
returned whole. Audit search takes `cursor` and `limit` in its request body (section 7).

## 5. Idempotency

Every `POST` that creates something accepts an `Idempotency-Key` header (architecture 5.4): `createTransfer`,
`addTransferFile`, `createUploadRequest`, `addSessionUploadFile`, `inviteUser`, `createTenant` and
`recoverTenantAdmin`; so does `extendTransferExpiry`. The key is scoped to the caller and kept for 24 hours with a
fingerprint of the **method, the path with its resource IDs filled in, and the body**. The service keeps the response
status and the ID of what was created, never the response body. A retry with the same key, method, path and body gets
the same status, with the response rebuilt from the resource as it is now. The same key with any of them different
gets `409 idempotency_conflict`, so a key reused with the same body on another transfer is refused, not answered with
the first transfer.

These take no `Idempotency-Key`:

- **Calls that grant access** (`createSessionDownload`, `createReceivedFileDownload`, `requestVerificationCode`,
  `createLinkSession`, the sign-in steps and `createOperatorToken`). They are checked and audited every time and never
  replay a response.
- **`createApiKey`**, because the secret is never stored, so a retry couldn't return it. If the response is lost,
  revoke the key by its prefix and create another.

State changes are safe to retry by design: `sendTransfer`, `cancelTransfer`, `revokeTransfer`, `revokeUploadRequest`,
`extendTransferExpiry` (to the same time), `completeUpload`, `unlockRecipient`, `unlockUploader`, `deactivateUser`,
`signOutUser`, `revokeApiKey`, `configureTenantSso` (the same configuration) and `recordBreakGlassGrant` (the same
`assignment_request_id`) return success with the current state when the change has already happened.

**Security-critical changes** (NFR-10, data model 2.5) are committed first, so they take effect at once, and then
written to the audit archive in both regions before the `2xx`:

| Change | Operations |
|---|---|
| Revocations of transfers and upload requests | `revokeTransfer`, `revokeUploadRequest` |
| API key revocations | `revokeApiKey`, and the keys a deactivation or demotion revokes |
| Deactivations and demotions | `deactivateUser`, `updateUser` (to `member`) |
| Forced sign-outs | `signOutUser` |
| Unlocks (and the lockouts that `createLinkSession` records) | `unlockRecipient`, `unlockUploader` |
| Sign-in resets | `resetUserSignIn`, `recoverTenantAdmin` |

If the archive write fails, the change stands and the call returns `503`. A retry finds the change already made, writes
the archive record if it is still missing, and returns success; the archive job also copies the record within a
minute (architecture 5.2). The web app must not tell the member such a change failed: it shows it as done and retries
in the background. After a failover or restore, the runbooks re-apply these records before any worker starts.

A **download grant** (`createSessionDownload`, `createReceivedFileDownload`) is the opposite: its ID is generated and
an intent record goes to both archives first, then the download is counted, so a `503` means nothing was counted. A
committed record follows in the background, and only committed records, or grants the database still holds, are
re-applied after a failover or restore, so a refused grant never counts (data model 2.3).
`recordBreakGlassGrant` is best effort: the Identity Center assignment and CloudTrail are the record, and a
reconciliation job fills any gap (authn-authz 8.3).

## 6. Rate limiting

A request over a limit gets `429 rate_limited` with a `Retry-After` header in whole seconds: when the limiting key next
admits a request, the largest if several limits are hit. The `detail` never names the key, another tenant or another
address. Every operation declares `429`, and a lint rule fails if one doesn't. The limits come from NFR-14 and the
abuse design ([abuse-and-rate-limits](../security/abuse-and-rate-limits.md) section 2.2, which lists every key).

| NFR-14 limit | Where it applies |
|---|---|
| ≤ 1,000 API requests per tenant per minute | Every tenant operation, members and API keys together. Revocations, deactivations and unlocks never count against it. |
| ≤ 60 link-page requests per IP address per minute | `resolveLink`, `requestVerificationCode`, `createLinkSession` |
| ≤ 5 verification codes per email address per hour | `requestVerificationCode`, across all tenants |
| A code is valid ≤ 10 minutes and allows ≤ 5 attempts | `createLinkSession`: `422 code_expired`, `422 code_attempts_exhausted` (not 429) |
| Lockout after 20 failed attempts until the member unlocks | `403 recipient_locked`; `unlockRecipient`, `unlockUploader`, which issue a new link |
| A verified session lasts ≤ 24 hours | `linkSession` cookie; then `401 session_expired` |
| ≤ 10 failed sign-ins per account per 15 minutes | Enforced at Cognito by a pre-authentication trigger, not by this API; `startSignIn` and `completeSignIn` take 60 a minute per IP address |

Starting limits from the abuse design:

| Group | Operations | Main limits |
|---|---|---|
| Link steps | `resolveLink`, `requestVerificationCode`, `createLinkSession` | Codes: 1 every 30 s and 20 a day per link; 50 a day per address; 1,000 an hour per tenant. 20 `link_not_found` and 30 failed codes an hour per IP. Fail closed: `503`. |
| Sign-in | `startSignIn`, `completeSignIn`, `startInvitationSignIn` | 60 a minute per IP each. Fail closed: `503` when the counters or the sign-in state store are unavailable. |
| Download grants | `createSessionDownload`, `createReceivedFileDownload` | 100 an hour per recipient, resumes included; 300 an hour per member and per IP; 2,000 an hour per tenant. Granted bytes: 25 GB a day per recipient, 500 GB a day per tenant. |
| Download content | `getSessionDownloadContent`, `getReceivedFileDownloadContent` | A grant: 3 × file size, 20 requests, 24 hours, one stream (`403 download_grant_exhausted`). Concurrent streams: 6 per session, 20 per IP, 200 per tenant. A full pod answers `503`, `Retry-After: 10`. |
| Uploads | `addTransferFile`, `addSessionUploadFile` and the part, list and complete operations | 600 a minute per caller, 1,200 per IP. 200 GB declared a day per tenant; 2 TB stored (`413 storage_quota_exceeded`); 100 file declarations per upload request. |
| Email | `sendTransfer`, `createUploadRequest`, `inviteUser` | 200 recipient emails an hour per member or key, 2,000 per tenant; 20 link emails a day to one address per tenant. A cap across tenants delays the email (`queued`) instead of refusing it. Invitations: 100 an hour per tenant, 3 a day per address. |
| Audit | `searchAuditEvents`, `exportAuditEvents` | 60 searches a minute per tenant; 10 exports an hour, 1 at a time. An API key: 1 export an hour, at most 100,000 events (`422 export_too_large`). |
| Keys and tenants | `createApiKey`, `createTenant` | 20 new keys a day and at most 25 active per tenant; 30 new tenants an hour per operator. |
| Other tenant calls | Everything else for members and API keys | 300 a minute per member and per key; 100 failed authentications in 5 minutes block an IP for 15 minutes. |

**The WAF** also limits by IP address before a request reaches the API: 100 link-step requests a minute and 6,000
requests in 5 minutes for the whole API. Its `429` has a fixed `Retry-After` (60 or 300) and the same problem fields,
but as `application/json`, because WAF custom responses can't use `application/problem+json`; so clients branch on the
status. It carries CORS headers (`Access-Control-Allow-Origin` with the web app's origin,
`Access-Control-Allow-Credentials: true`, `Access-Control-Expose-Headers: Retry-After`), so the web app can read it. A
blocked CORS preflight can't be read at all, so the web app treats a failed fetch as retryable after 60 seconds.

If the rate-limit counters are unavailable, the link steps and the sign-in steps fail closed with `503`; other calls
carry on under a per-pod limiter (abuse-and-rate-limits 4.5).

## 7. Why tokens never appear in URLs

URLs end up in load balancer, CDN and WAF logs, in browser history and in `Referer` headers. So:

- The emailed link carries its token in the URL fragment (`/t#token`), which browsers never send to a server, and so
  does an SSO invitation link (`/invite#token`). The web app removes the fragment from the address bar before
  anything else runs, and posts the token in a request body (architecture 4.2, authn-authz 4.1). No path or query
  parameter carries a token.
- Verification codes travel in the request body; sessions in `HttpOnly` cookies; CSRF tokens in response bodies and
  the `X-CSRF-Token` header; API keys and operator tokens in the `Authorization` header. `X-Link-Session` carries only
  a session ID, and a content URL only a grant ID, neither of which is a secret.
- Audit search and export are `POST` with filters in the body, because a filter can hold an email or IP address.
- The one URL that carries a credential is a pre-signed upload URL for one part of one file: it allows a single `PUT`
  of exactly that part's size, for at most 15 minutes, and never allows reading.
- **The one exception** to "no token in a query string" is Cognito's authorization code on `completeSignIn`, because
  OAuth's redirect puts it there. It is valid for 5 minutes, single use, and useless without the PKCE verifier and the
  client secret, which never leave the server. Application logs drop that route's query string.
- `DownloadAccess.url` carries no credential. It works only with the cookie of the session that created the grant, so
  a forwarded URL grants nothing (FR-14).

## 8. Uploads, downloads and audit exports

**Upload**, for a member (`/files`) or an uploader (`/session/files`):

1. `addTransferFile` or `addSessionUploadFile` declares the name and size, reserves the size in the tenant's storage
   quota, and returns the upload plan (`part_size`, `part_count`).
2. `requestUploadPartUrls` or `requestSessionUploadPartUrls` returns up to 100 pre-signed part URLs per call; the
   browser `PUT`s the parts in parallel.
3. After an interruption, `listUploadedParts` or `listSessionUploadedParts` shows which parts arrived, so only the
   missing ones are sent (NFR-3).
4. `completeUpload` or `completeSessionUpload` runs in three phases, and no lock is held across the object-storage
   calls (data model 3.1). First, in a short transaction, it locks the transfer or request, re-checks it and counts
   the files and the total again, so a cancellation or revocation that landed first wins and no part is assembled
   (NFR-6), and parallel uploads can't pass 50 files or 20 GB (`422 too_many_files`, `413 total_too_large`); the file
   becomes `completing`. Then, with no transaction open, it assembles the parts and reads the real size. Last, in a
   second short transaction, it re-checks the transfer or request: the file moves to `scanning`, goes back to
   `uploading` if parts were missing (`409 upload_incomplete`), or is `rejected` on a size mismatch or a cancellation
   or revocation that landed meanwhile. A rejected file's object is removed by the deletion job, because the API never
   deletes objects.

A member uploads only to a `draft`. A draft is never revoked or expired, so the race to handle is a cancellation, by
the member or by the 7-day job: the upload's next call gets `409 invalid_state` with `current_state: cancelled`.

**Download** is two steps, streamed through the API (open question 8, abuse-and-rate-limits section 5):

1. `createSessionDownload` (a recipient) or `createReceivedFileDownload` (a member) returns a `DownloadAccess` grant.
   The grant's ID is generated first and an intent record written to both regions' audit archive (NFR-10); then one
   transaction counts the download, creates the grant and commits its audit record (FR-4, NFR-15), and a committed
   record follows in the background (section 5). So a `503` always means nothing was counted.
2. The web app navigates to the grant's `url`, `getSessionDownloadContent` or `getReceivedFileDownloadContent`, so the
   browser's own download manager saves and resumes the file. That `GET` is authorised by the grant ID in the path
   plus the cookie of the session that created the grant, with no `X-Link-Session` and no CSRF header: without the
   cookie the answer is `401`, with another session's cookie `404`.

A grant belongs to one session and one file, lasts 24 hours, and allows 3 × the file size in bytes, 20 requests and one
stream at a time. Range requests (one range each, `206`; otherwise `416`) and `If-Range` with the strong `ETag` resume
under the same grant, uncounted. A range is `bytes=<start>-`, `bytes=<start>-<end>` or `bytes=-<suffix>` (pattern
`^bytes=(\d+-\d*|-\d+)$`); anything else, or a range that doesn't fit the file, gets `416 range_not_satisfiable`. After
a reload, `resume_grant_id` gets the grant back, in the same session, while it has time, bytes and requests left (FR-6);
after that, `403 download_grant_exhausted`. Every content request re-checks revocation, and a running stream re-checks
at least every 30 seconds, so a running download stops within 60 seconds of a revocation (NFR-6). Each re-check also
counts as activity for the session, a link session or a member session, so a long download doesn't end it for idleness.
Content is always `application/octet-stream` with `Content-Disposition: attachment`, `nosniff`, a sandbox CSP and
`Cache-Control: no-store`; the bytes served are the object version that was scanned. There is no `HEAD`.

**Audit export** (`exportAuditEvents`) as CSV neutralises formulas, because fields such as `actor_email`, `user_agent`
and `details` hold text an outsider chose (CWE-1236). Every cell is quoted (RFC 4180), and a cell that starts with `=`,
`+`, `-`, `@`, a tab or a carriage return is prefixed with a single quote (`'`), so a spreadsheet shows it as text. JSON
exports are unchanged. An admin's export needs a recent sign-in and stops at 1,000,000 events; an API key may export
once an hour, at most 100,000 events, and the tenant's admins are emailed the first time each key exports.

## 9. Requirements coverage

Every Must requirement with a user action, and the operations that serve it. This is the acceptance criterion of #14.

| PRD | Requirement | Operations |
|---|---|---|
| FR-1 | Create a transfer with files, recipients, expiry and message | `createTransfer`, `addTransferFile`, `sendTransfer`, `listTransfers`, `getTransfer` |
| FR-2 | Files up to 5 GB, 20 GB per transfer, resumable uploads | `addTransferFile`, `requestUploadPartUrls`, `listUploadedParts`, `completeUpload` |
| FR-3 | Expiry from 1 hour to 30 days, capped by policy | `createTransfer`, `sendTransfer`, `createUploadRequest`, `getTenantPolicy` |
| FR-4 | Download limit per recipient per file | `createTransfer`, `createSessionDownload`, `getSessionDownloadContent` |
| FR-5 | Notify only when every file is shareable, otherwise held | `sendTransfer`, `getTransfer`, `deleteFile`, `cancelTransfer` |
| FR-6 | Download files one by one; resume without using up the limit | `listSessionFiles`, `createSessionDownload` (`resume_grant_id`), `getSessionDownloadContent` (Range) |
| FR-7 | Per-recipient status | `listTransferRecipients` (`delivery_state`, `notified_at`, verification and downloads); `getUploadRequest` for the uploader; `clearEmailSuppression` lets a tenant admin email a `suppressed` address again |
| FR-10 | Create an upload request | `createUploadRequest`, `listUploadRequests`, `getUploadRequest` |
| FR-11 | Uploader uploads up to 50 files, resumable | `getLinkSession`, `addSessionUploadFile`, `requestSessionUploadPartUrls`, `listSessionUploadedParts`, `completeSessionUpload` |
| FR-12 | Shareable files reach the member; blocked files reported to both sides | `listUploadRequestFiles`, `getFile`, `createReceivedFileDownload`, `getReceivedFileDownloadContent`, `listSessionFiles` |
| FR-13 | Member deletes received files early | `deleteFile` |
| FR-14 | Verify the email address before anything is shown | `resolveLink`, `requestVerificationCode`, `createLinkSession`; content URLs work only with the grant's session |
| FR-15 | Verification bound to a browser session and one item | `createLinkSession`, `getLinkSession`, `endLinkSession` |
| FR-16 | Visible file state; only shareable files download | `getFile`, `getTransfer`, `listSessionFiles` |
| FR-17 | Infected files never download | `createSessionDownload`, `createReceivedFileDownload` (`409 file_not_shareable`) |
| FR-18 | Unscannable files blocked by default; warning when allowed | `updateTenantPolicy`; `warning` in `DownloadAccess` and `SessionFile` |
| FR-20 | Revoke transfers and upload requests | `revokeTransfer`, `revokeUploadRequest` |
| FR-22 | Invite, deactivate and assign roles | `inviteUser`, `listUsers`, `getUser`, `updateUser`, `deactivateUser`, `signOutUser`, `resetUserSignIn`, `getCurrentMember` |
| FR-23 | Tenant policy | `getTenantPolicy`, `updateTenantPolicy` |
| FR-25 | Sign in with MFA | `startSignIn`, `completeSignIn`, `signOut`, `getCurrentMember`; `resetUserSignIn` for a lost factor; `recoverTenantAdmin` for a tenant's last admin |
| FR-28 | Search the audit log | `searchAuditEvents` |
| FR-33 | English and Japanese recipient and uploader pages and emails, in v1 | `locale` on recipients and upload requests; `default_locale` in the tenant policy |
| FR-34 | Provision a tenant and its first admin | `createTenant`; the operator API's `createOperatorToken` |
| FR-35 | Operators can't read contents; break-glass time-limited, audited and alerted | `recordBreakGlassGrant` (best effort; the record is Identity Center plus CloudTrail); no operator operation returns file names, messages or contents |
| NFR-14 | Member unlocks a locked-out recipient or uploader | `unlockRecipient`, `unlockUploader` |

Should requirements:

| PRD | Operations |
|---|---|
| FR-8 First-download email | `notify_on_first_download` in `createTransfer` |
| FR-9 Extend expiry | `extendTransferExpiry` |
| FR-24 Allowed and blocked domains | `updateTenantPolicy`; checked by `createTransfer` and `createUploadRequest` |
| FR-26 Tenant single sign-on | `startSignIn` (`method=sso`), `startInvitationSignIn`, `configureTenantSso`; `sso_fallback` in `updateUser` |
| FR-29 Export the audit log | `exportAuditEvents` |
| FR-32 Tenant API keys | `createApiKey`, `listApiKeys`, `revokeApiKey`; the `tenantApiKey` scheme |

Requirements with no user action of their own: FR-19 (scan retries; the state shows in `getFile`), FR-21 (expiry; the
`link_expired` and `transfer_expired` errors), FR-27 (every operation is audited, including searches, exports, every
API key call and every sign-in attempt), and FR-30 and FR-31 (this contract).

## 10. Open points for review

Decided by phase 3 and now in the contract: member sign-in (open question 1), the download mechanism (open question 8),
derived CSRF tokens, the operator token exchange, and that API keys can't unlock.

| Point | Current choice |
|---|---|
| Problem `type` host (open question 5) | `secure-file-transfer.example` until the subdomain's name is set, before the first deploy |
| A refused sign-in | `completeSignIn` redirects to the web app with `error=sign_in_failed` and no reason; the audit log has the reason. It is a redirect value, not a problem `code`. |
| Who owns what an API key creates | The admin who created the key; the audit log names the key as the actor. Deactivating or demoting that admin revokes their keys. |
| Expiry (FR-3) and its extension (FR-9) | A draft holds a duration (`expires_in`); `expires_at` is set when it is submitted. Extensions are capped over the **whole lifetime**: `expires_at` is never more than 30 days, or the tenant's `max_expiry` if shorter, after `submitted_at`, so repeated extensions can't keep a transfer alive. Extending to the current expiry is a no-op, so a retry is safe. |
| Lengths the PRD doesn't set | Message ≤ 2,000 characters; file name ≤ 255; API keys expire after 90 days by default, at most 365 |
| Action paths | Verbs such as `/send`, `/revoke`, `/unlock`, `/sign-out`, `/reset-sign-in`. The architecture's illustrative `/revocation` becomes `/revoke`. |
| Audit export | Streamed in the response, at most 1,000,000 events for an admin and 100,000 for an API key; an asynchronous export job only if that proves too small. CSV cells are formula-neutralised (section 8). |
| Download grant budget | 3 × file size, 20 requests, 24 hours, one session and one stream (ADR-0018) |
| Operator API address | `http://127.0.0.1:{local_port}/v1`, the local end of the port-forward; the port is the operator's choice |
| Deprecation notice | At least 6 months |

Later, not in v1 (each needs its own issue; none is required by the security design):

- Operator operations to suspend and resume a tenant. Until then a suspension is a runbook step, and the contract only
  shows its effect (`Tenant.status`, every session of the tenant ends).
- Per-tenant overrides of rate limits and quotas, set by an operator. In v1 they change only through deploy
  configuration, for every tenant at once (PRD NFR-14).
- A public operation behind a "report this email" link in emails, which would suppress the address for that tenant.
- Source address ranges on an API key, and a cap on expiry extensions (for example 90 days after sending).
- Tenant-admin self-service for SSO (requiring SSO, confirming MFA), SCIM deprovisioning and SAML single logout.

## 11. Checking the contract

CI lints the spec in the `repo-checks` job, with the linter image pinned in `ci.yml`: the linter's recommended rules
plus the rules in [`redocly.yaml`](../../redocly.yaml), which fail the build if an operation lacks `x-permission` or a
`429` response. To run the same check locally:

```bash
docker run --rm -v "$PWD:/spec" redocly/cli:2.64.1 lint docs/api/openapi.yaml
```

Once the API service exists, CI also compares the document generated from the code with this file, and a
breaking-change check runs on every pull request (ADR-0002). A CI test also checks every `x-permission` value against
the service's permission registry and the [permission table](../security/authn-authz.md#63-permission-table)
(authn-authz 6.5).
