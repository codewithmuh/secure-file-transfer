# API contract

| | |
|---|---|
| Contract | [openapi.yaml](openapi.yaml), OpenAPI 3.1 |
| Requirements | [PRD](../prd.md), especially FR-31 and NFR-14 |
| Design | [Architecture](../architecture.md), [ADR-0002](../adr/0002-api-framework.md) |
| Tracking | [#14](https://github.com/codewithmuh/secure-file-transfer/issues/14), part of phase 2 ([#16](https://github.com/codewithmuh/secure-file-transfer/issues/16)) |

Everything the web app does goes through this API (FR-31), and tenant automation uses the same API with API keys
(FR-32). The contract is **design-first**: phase 2 writes it before any code. Once code exists, the document generated
from the code is committed here and CI fails if the two differ; a breaking-change check fails the pull request unless
it is marked as breaking (ADR-0002). Until then, CI lints this file (section 11).

Parts marked **provisional** in the spec wait for a phase 3 decision: member sign-in (PRD open question 1) and the
download mechanism (open question 8).

## 1. Base URL and versioning

- Every path is relative to `/v1` on the API origin. The domain waits for PRD open question 5.
- The major version is in the path. Within `/v1` only backwards-compatible changes are made: new operations, new
  optional request fields, new response fields and new error codes. Clients ignore response fields they don't know,
  and treat an unknown error `code` by its HTTP status.
- A breaking change ships only in a new version (`/v2`), which runs next to `/v1` until `/v1` is retired.
- A deprecated operation is marked `deprecated: true` in the spec, and its responses carry a `Deprecation` header
  (RFC 9745) and a `Sunset` header (RFC 8594) with the retirement date. The notice period is at least 6 months. The web
  app moves to the new version in the same release; the notice period is for API-key automation.
- `info.version` is the version of this document. It stays `1.0.0-draft` until the phase 3 decisions are in.

## 2. Callers and authentication

| Caller | Security scheme | Sent as | Used by |
|---|---|---|---|
| Member or admin, web app | `memberSession`, plus `csrfToken` on POST, PATCH and DELETE | `__Host-sft_session` cookie; `X-CSRF-Token` header with the token from `getCurrentMember` | Most operations |
| Tenant automation | `tenantApiKey`, with scopes | `Authorization: Bearer` header | Transfers, upload requests, audit |
| Recipient or uploader, before verification | None: `security: []` | Link token in the request body | `resolveLink`, `requestVerificationCode`, `createLinkSession` |
| Recipient or uploader, after verification | `linkSession`, plus `csrfToken` on unsafe methods | `__Host-sft_link` cookie; `X-Link-Session` header naming the session; `X-CSRF-Token` with that session's token | `/session` operations |
| Platform operator | `operatorToken` | `Authorization: Bearer` header | `createTenant` |

- Every operation declares its `security` explicitly. The three link steps above are the only public operations.
  Health checks and metrics are not part of this API (architecture section 8).
- Every operation also declares `x-permission`: the permission the service layer checks, or `public` (ADR-0002). A lint
  rule fails if one is missing.
- `memberSession: [admin]` means the member needs the admin role. For an API key, the requirement lists the scope it
  needs, such as `transfers:write`. A key acts as the tenant admin who created it, limited to its scopes, and can never
  download file contents. Deactivating that admin, or demoting them to `member`, revokes every key they own in the same
  transaction.
- **A file's API key scope follows its owner.** `getFile` and `deleteFile` list both `transfers:*` and
  `upload_requests:*` because OpenAPI can't make the choice depend on the file. The service checks the scope that
  matches the file: `transfers:*` for a file of a transfer, `upload_requests:*` for a received file. A key with only
  the other scope gets `404`.
- Signing in and out are not in this version: how members sign in with MFA waits for open question 1 (FR-25, FR-26).

**Who sees what.** A member sees and acts on their own transfers and upload requests. A tenant admin, and an API key
with the matching scope (it acts as its admin owner), also sees every transfer and upload request in the tenant, as
metadata with its files' states and its recipients' status, and can revoke it and unlock its recipient or uploader
(UC-3, FR-20). The other
actions on another member's item (send, cancel, extend, upload, delete a file, download a received file) belong to its
owner, and an admin gets `403 permission_denied`. An item in another tenant, or another member's item for a member who
isn't an admin, returns `404`, never `403`, so its existence is never revealed (NFR-12).

**CSRF and cookie sessions.** Each member session and each link session has its own CSRF token, returned in the
response body: `csrf_token` in `getCurrentMember`, and in `createLinkSession` and `getLinkSession`. The web app keeps it
in memory and sends it in `X-CSRF-Token`; there is no readable CSRF cookie, because the web app and the API are separate
origins. The service checks the token of the session the request uses, so starting a link session never breaks a
member's token. Both session cookies are `HttpOnly`, `Secure`, `SameSite=Strict` and host-only, and the service also
checks `Origin` on every unsafe request.

**Several link sessions per browser.** A browser can hold several link sessions at once, one per transfer recipient or
upload request, under its `__Host-sft_link` cookie, so verifying a second link never ends the first. Every `/session`
call names its session in the `X-Link-Session` header (the `id` from `createLinkSession`, or `link_session_id` from
`resolveLink`) and sees only that session's transfer or request. The ID isn't a credential: it works only with the
cookie of the browser that verified it.

## 3. Errors

Every error is an RFC 9457 problem (`application/problem+json`) with these fields:

| Field | Meaning |
|---|---|
| `type` | Stable URI per problem, `https://secure-file-transfer.example/problems/{code}`. The host changes to the real domain before v1 (open question 5). |
| `title`, `detail` | For people. They may change; never branch on them. |
| `status` | The HTTP status. |
| `code` | Stable, machine-readable code. Clients branch on this. |
| `request_id` | Also in logs and traces; quote it when reporting a problem. |
| `errors` | For `validation_failed`, one entry per problem with a JSON Pointer. |
| `attempts_remaining`, `current_state` | For `code_invalid` and for state conflicts. |

| Status | Codes |
|---|---|
| 400 | `malformed_request`, `invalid_cursor` |
| 401 | `authentication_required`, `session_expired`, `credentials_invalid` |
| 403 | `permission_denied`, `csrf_failed`, `recipient_locked`, `download_limit_reached` |
| 404 | `not_found`, `link_not_found` |
| 409 | `idempotency_conflict`, `idempotency_in_progress`, `invalid_state`, `transfer_revoked`, `transfer_expired`, `upload_request_revoked`, `upload_request_expired`, `transfer_empty`, `upload_incomplete`, `file_not_shareable`, `user_exists`, `last_admin` |
| 410 | `link_revoked`, `link_expired` |
| 413 | `file_too_large`, `total_too_large`, `request_too_large` |
| 422 | `validation_failed`, `expiry_out_of_range`, `recipient_domain_not_allowed`, `too_many_files`, `upload_size_mismatch`, `code_invalid`, `code_expired`, `code_attempts_exhausted`, `export_too_large` |
| 429 | `rate_limited` |
| 503 | `service_unavailable`: a call couldn't reach the audit archive or the rate-limit counters. A download grant or a verification changed nothing; a security-critical change took effect and a retry completes its record (section 5). |

Members see `transfer_revoked` or `transfer_expired` (409) when they act on a transfer that was revoked or has expired;
recipients see `link_revoked` or `link_expired` (410). Operations that apply only to drafts, such as adding
and uploading files, answer `409 invalid_state` with `current_state` instead, because a draft is never revoked or
expired: it is cancelled. Each operation's description lists the codes it can return.

## 4. Pagination

List operations that can grow take `cursor` and `limit` (1–100, default 25) and return `items` and `next_cursor`.
`next_cursor` is `null` on the last page. Cursors are opaque: pass them back unchanged. An invalid or expired cursor
returns `400 invalid_cursor`. Lists bounded by the PRD (at most 50 files or recipients, at most 1,000 upload parts) are
returned whole. Audit search takes `cursor` and `limit` in its request body (section 7).

## 5. Idempotency

Every `POST` that creates something accepts an `Idempotency-Key` header (architecture 5.4): `createTransfer`,
`addTransferFile`, `createUploadRequest`, `addSessionUploadFile`, `inviteUser` and `createTenant`; so does
`extendTransferExpiry`. The key is scoped to the caller and kept for 24 hours with a fingerprint of the **method, the
path with its resource IDs filled in, and the body**. A retry with the same key, method, path and body gets the stored
response. The same key with any of them different gets `409 idempotency_conflict`, so a key reused with the same body
on another transfer is refused, not answered with the first transfer's response.

These take no `Idempotency-Key`:

- **Calls that grant access** (`createSessionDownload`, `createReceivedFileDownload`, `requestVerificationCode`,
  `createLinkSession`). They are checked and audited every time and never replay a stored response.
- **`createApiKey`**, because the stored response would hold the key in plain text. If the response is lost, revoke the
  key by its prefix and create another.

State changes are safe to retry by design: `sendTransfer`, `cancelTransfer`, `revokeTransfer`, `revokeUploadRequest`,
`extendTransferExpiry` (to the same time), `completeUpload`, `unlockRecipient`, `deactivateUser` and `revokeApiKey`
return success with the current state when the change has already happened.

**Security-critical changes** (revocations, deactivations, and demotions with the API keys they revoke; NFR-10) are
committed first, so they take effect at once, and then written to the audit archive in both regions before the `200`.
If that write fails, the change stands and the call returns `503`. A retry finds the change already made, writes the
archive record if it is still missing, and returns `200`; the archive job also copies the record within a minute
(architecture 5.2). A download grant is the opposite: its record goes to the archive first and the download is counted
after, so a `503` from `createSessionDownload` means nothing was counted.

## 6. Rate limiting

A request over a limit gets `429 rate_limited` with a `Retry-After` header in seconds. Every operation declares `429`,
and a lint rule fails if one doesn't. The starting limits come from NFR-14; phase 3 may tighten them.

| NFR-14 limit | Where it applies |
|---|---|
| ≤ 1,000 API requests per tenant per minute | Every tenant operation, members and API keys together |
| ≤ 60 link-page requests per IP address per minute | `resolveLink`, `requestVerificationCode`, `createLinkSession` |
| ≤ 5 verification codes per email address per hour | `requestVerificationCode` |
| A code is valid ≤ 10 minutes and allows ≤ 5 attempts | `createLinkSession`: `422 code_expired`, `422 code_attempts_exhausted` (not 429) |
| Lockout after 20 failed attempts until the member unlocks | `403 recipient_locked`; `unlockRecipient`, `unlockUploader` |
| A verified session lasts ≤ 24 hours | `linkSession` cookie; then `401 session_expired` |
| ≤ 10 failed sign-ins per account per 15 minutes | Sign-in operations, added with open question 1 |
| Per IP, account and tenant limits on uploads and downloads | Upload and download operations; numbers set in phase 3 |

If the rate-limit counters are unavailable, verification fails closed with `503` (architecture section 6).

## 7. Why tokens never appear in URLs

URLs end up in load balancer, CDN and WAF logs, in browser history and in `Referer` headers. So:

- The emailed link carries its token in the URL fragment (`/t#token`), which browsers never send to a server. The web
  app posts it in the request body (architecture 4.2). No path or query parameter carries a token.
- Verification codes travel in the request body; sessions in `HttpOnly` cookies; CSRF tokens in response bodies and
  the `X-CSRF-Token` header; API keys in the `Authorization` header. `X-Link-Session` carries only a session ID, which
  is not a secret.
- Audit search and export are `POST` with filters in the body, because a filter can hold an email or IP address.
- The one URL that carries a credential is a pre-signed upload URL for one part of one file: it allows a single `PUT`
  of exactly that part's size, for at most 15 minutes, and never allows reading.
- `DownloadAccess.url` carries no credential. It works only together with the verified session or the cookies set on
  that response, so a forwarded URL grants nothing (FR-14).

## 8. Uploads, downloads and audit exports

**Upload**, for a member (`/files`) or an uploader (`/session/files`):

1. `addTransferFile` or `addSessionUploadFile` declares the name and size and returns the upload plan (`part_size`,
   `part_count`).
2. `requestUploadPartUrls` returns up to 100 pre-signed part URLs per call; the browser `PUT`s the parts in parallel.
3. After an interruption, `listUploadedParts` shows which parts arrived, so only the missing ones are sent (NFR-3).
4. `completeUpload` assembles the parts, checks the real size and re-checks the transfer or request under a lock, so a
   cancellation of the draft, or a revocation of the upload request, that lands meanwhile wins (NFR-6). Under the same
   lock it counts the files and the total again, so parallel uploads can't pass 50 files or 20 GB
   (`422 too_many_files`, `413 total_too_large`). The file moves to `scanning`.

A member uploads only to a `draft`. A draft is never revoked or expired, so the race to handle is a cancellation, by
the member or by the 7-day job: the upload's next call gets `409 invalid_state` with `current_state: cancelled`.

**Download** (`createSessionDownload`, `createReceivedFileDownload`) returns a `DownloadAccess` grant. For a recipient,
the grant's ID is generated first and its record written to both regions' audit archive (NFR-10); then one transaction
counts the download, creates the grant and commits its audit record (FR-4, NFR-15). So a `503` always means nothing was
counted. Its `method` is `stream` or `signed_cookie`, the two candidates for open question 8 (architecture 4.2). Phase
3 picks one and the other is removed before v1. Resuming passes `resume_grant_id` so it isn't counted again (FR-6); how
a grant is bounded is part of that decision. If phase 3 chooses streaming, a content operation for the bytes is added
then; since a browser navigation can't send `X-Link-Session`, it finds the session from the grant's recipient.

**Audit export** (`exportAuditEvents`) as CSV neutralises formulas, because fields such as `actor_email`, `user_agent`
and `details` hold text an outsider chose (CWE-1236). Every cell is quoted (RFC 4180), and a cell that starts with `=`,
`+`, `-`, `@`, a tab or a carriage return is prefixed with a single quote (`'`), so a spreadsheet shows it as text. JSON
exports are unchanged.

## 9. Requirements coverage

Every Must requirement with a user action, and the operations that serve it. This is the acceptance criterion of #14.

| PRD | Requirement | Operations |
|---|---|---|
| FR-1 | Create a transfer with files, recipients, expiry and message | `createTransfer`, `addTransferFile`, `sendTransfer`, `listTransfers`, `getTransfer` |
| FR-2 | Files up to 5 GB, 20 GB per transfer, resumable uploads | `addTransferFile`, `requestUploadPartUrls`, `listUploadedParts`, `completeUpload` |
| FR-3 | Expiry from 1 hour to 30 days, capped by policy | `createTransfer`, `sendTransfer`, `createUploadRequest`, `getTenantPolicy` |
| FR-4 | Download limit per recipient per file | `createTransfer`, `createSessionDownload` |
| FR-5 | Notify only when every file is shareable, otherwise held | `sendTransfer`, `getTransfer`, `deleteFile`, `cancelTransfer` |
| FR-6 | Download files one by one; resume without using up the limit | `listSessionFiles`, `createSessionDownload` (provisional) |
| FR-7 | Per-recipient status | `listTransferRecipients` |
| FR-10 | Create an upload request | `createUploadRequest`, `listUploadRequests`, `getUploadRequest` |
| FR-11 | Uploader uploads up to 50 files, resumable | `getLinkSession`, `addSessionUploadFile`, `requestSessionUploadPartUrls`, `listSessionUploadedParts`, `completeSessionUpload` |
| FR-12 | Shareable files reach the member; blocked files reported to both sides | `listUploadRequestFiles`, `getFile`, `createReceivedFileDownload`, `listSessionFiles` |
| FR-13 | Member deletes received files early | `deleteFile` |
| FR-14 | Verify the email address before anything is shown | `resolveLink`, `requestVerificationCode`, `createLinkSession` |
| FR-15 | Verification bound to a browser session and one item | `createLinkSession`, `getLinkSession`, `endLinkSession` |
| FR-16 | Visible file state; only shareable files download | `getFile`, `getTransfer`, `listSessionFiles` |
| FR-17 | Infected files never download | `createSessionDownload`, `createReceivedFileDownload` (`409 file_not_shareable`) |
| FR-18 | Unscannable files blocked by default; warning when allowed | `updateTenantPolicy`; `warning` in `DownloadAccess` and `SessionFile` |
| FR-20 | Revoke transfers and upload requests | `revokeTransfer`, `revokeUploadRequest` |
| FR-22 | Invite, deactivate and assign roles | `inviteUser`, `listUsers`, `getUser`, `updateUser`, `deactivateUser`, `getCurrentMember` |
| FR-23 | Tenant policy | `getTenantPolicy`, `updateTenantPolicy` |
| FR-25 | Sign in with MFA | **Gap:** waits for open question 1 |
| FR-28 | Search the audit log | `searchAuditEvents` |
| FR-34 | Provision a tenant and its first admin | `createTenant` |
| NFR-14 | Member unlocks a locked-out recipient or uploader | `unlockRecipient`, `unlockUploader` |

Should requirements:

| PRD | Operations |
|---|---|
| FR-8 First-download email | `notify_on_first_download` in `createTransfer` |
| FR-9 Extend expiry | `extendTransferExpiry` |
| FR-24 Allowed and blocked domains | `updateTenantPolicy`; checked by `createTransfer` and `createUploadRequest` |
| FR-26 Tenant single sign-on | **Gap:** waits for open question 1 |
| FR-29 Export the audit log | `exportAuditEvents` |
| FR-32 Tenant API keys | `createApiKey`, `listApiKeys`, `revokeApiKey`; the `tenantApiKey` scheme |
| FR-33 English and Japanese | `locale` on recipients and upload requests; `default_locale` in the tenant policy |

Requirements with no user action of their own: FR-19 (scan retries; the state shows in `getFile`), FR-21 (expiry; the
`link_expired` and `transfer_expired` errors), FR-27 (every operation is audited, including searches and exports),
FR-30 and FR-31 (this contract), and FR-35 (break-glass access, designed in phase 3; `createTenant` gives no access to
file contents).

## 10. Open points for review

| Point | Current choice |
|---|---|
| Member sign-in and sign-out (open question 1) | Not in the contract; `memberSession` is provisional |
| Download mechanism (open question 8) | `DownloadAccess` lists both candidates; phase 3 removes one |
| Problem `type` host (open question 5) | `secure-file-transfer.example` until the domain is chosen, before v1 |
| Who owns what an API key creates | The admin who created the key; the audit log names the key as the actor. The data model confirms. Deactivating or demoting that admin revokes their keys. |
| Expiry (FR-3) and its extension (FR-9) | A draft holds a duration (`expires_in`); `expires_at` is set when it is submitted. Extensions are capped over the **whole lifetime**: `expires_at` is never more than 30 days, or the tenant's `max_expiry` if shorter, after `submitted_at`, so repeated extensions can't keep a transfer alive. Extending to the current expiry is a no-op, so a retry is safe. |
| Lengths the PRD doesn't set | Message ≤ 2,000 characters; file name ≤ 255; API keys expire after 90 days by default, at most 365 |
| Action paths | Verbs such as `/send`, `/revoke`, `/unlock`. The architecture's illustrative `/revocation` becomes `/revoke`. |
| Audit export | Streamed in the response, at most 1,000,000 events; an asynchronous export job only if that proves too small. CSV cells are formula-neutralised (section 8). |
| Link sessions per browser | Several at once under one cookie, picked by `X-Link-Session`, at most 10; verifying an 11th ends the oldest |
| Deprecation notice | At least 6 months |

## 11. Checking the contract

CI lints the spec in the `repo-checks` job, with the linter image pinned in `ci.yml`: the linter's recommended rules
plus the rules in [`redocly.yaml`](../../redocly.yaml), which fail the build if an operation lacks `x-permission` or a
`429` response. To run the same check locally:

```bash
docker run --rm -v "$PWD:/spec" redocly/cli:2.64.1 lint docs/api/openapi.yaml
```

Once the API service exists, CI also compares the document generated from the code with this file, and a
breaking-change check runs on every pull request (ADR-0002).
