# 0018. Stream downloads through the API service under session-bound grants

- Status: accepted
- Date: 2026-11-03
- Issue: [#33](https://github.com/codewithmuh/secure-file-transfer/issues/33)

## Context

PRD open question 8 asks which download mechanism meets FR-6, FR-14 and NFR-6 together. The [PRD](../prd.md) asks
that a download is counted against the per-recipient limit (FR-4); that an interrupted download resumes without using
up the limit and that resuming can't get around it (FR-6); that neither a forwarded link nor a forwarded download
address grants anything without verification (FR-14, FR-15); and that no new download can start more than 5 seconds
after a revocation, and one in progress stops within 60 seconds (NFR-6). The first byte must arrive within 1 second
at p95 (NFR-4), the audit record must be written before any download is served (NFR-15), file contents are never
stored outside Japan (NFR-21), and the pages work in the latest two versions of four browsers (NFR-22).

The simplest mechanism, a short-lived pre-signed S3 URL, is a bearer token, and the PRD refuses to accept it as a
residual risk (section 11). The options are compared in [abuse and rate limits](../security/abuse-and-rate-limits.md),
section 5, and the threats are in the [threat model](../threat-model.md) (T-22 to T-26). This ADR records the choice.

## Decision

**Stream file bytes from S3 through the API service, under a download grant bound to the session that created it.**

- **Grant.** `createSessionDownload` (or `createReceivedFileDownload` for a member's received file) generates the grant
  ID and writes a grant **intent** record (`download.grant_intent`) to the audit archive in both Regions. Only then
  does one transaction count the download, create the grant and write `download.granted`. After the commit the API
  writes a **committed** record (`download.grant_committed`) to both archives, in the background and retried until both
  confirm. A `503` means nothing was counted. The count is one conditional update, so parallel requests can't exceed
  the limit.
- **Content by navigation.** The browser navigates to the content URL, so its own download manager saves and resumes
  the file. A navigation can't send `X-Link-Session`, so the content request is authorised by the grant ID in the path
  plus the `__Host-sft_link` cookie, which must hold the grant's session (for a member, their session cookie):
  without the cookie `401`, with another session `404`. The URL itself is no credential.
- **Bounds.** One file and one session; 24 hours, never past the session, the transfer's expiry or a revocation;
  3 × the file size in bytes; 20 content requests; one active stream, where a new request takes over. Range requests
  and `resume_grant_id` resume under the same grant without counting again.
- **Streams.** Each content request takes the grant's stream lease (`active_stream_id`), which the stream renews at
  every 30-second re-check. Bytes sent are added to `bytes_served` by grant ID alone, whichever stream sent them; only
  the lease columns depend on `active_stream_id`, so a takeover never loses bytes already sent. A running stream counts
  as activity for its session, a link session or a member session alike, so a long download doesn't end its session
  for idleness; the session's absolute lifetime still applies.
- **Revocation.** Grant and content requests read the state from the PostgreSQL writer, so they fail at once with
  `410 link_revoked`. A running stream re-checks every 30 seconds, so a running download stops within 60 seconds of a
  revocation (NFR-6).
- **Bytes served** are the S3 version recorded at completion and scanned, as an attachment with
  `application/octet-stream`, `nosniff`, `Content-Security-Policy: sandbox` and `no-store`. The API never issues
  pre-signed `GET` URLs for file objects.

## Options considered

| Option | Pros | Cons |
|---|---|---|
| **Stream through the API under session-bound grants** (chosen) | The only option that meets FR-4, FR-6, FR-14 and NFR-6 together: every request is checked against the session and PostgreSQL, and the server sees every byte it sends. The browser's own download manager saves and resumes, in every browser NFR-22 names. No new component. First byte in about 0.3 s. Bytes leave only from Tokyo or Osaka. | The API pods carry file bytes: about 0.35 vCPU in the peak hour and 0.7 at bursts, stream caps per pod, and scaling on active streams. About $243 a month more load balancer capacity at design load ([capacity](../design/capacity-and-cost.md), 5.6). A deploy cuts streams after a 120-second drain; they can be resumed, but the user may notice. A slow client holds a stream for hours (5 GB at 10 Mbit/s takes over an hour). An API outage is also a download outage. The content routes need an async S3 client, because boto3 is synchronous. |
| CloudFront signed cookies bound to the session | Bytes stay off the pods; a few dollars a month of requests | The cookies are bearer tokens while they live, and need a `Domain` shared with the CDN host, so they can't be `__Host-` cookies. The server sees cookie refreshes, not bytes. NFR-6 needs cookies of ≤ 5 s and downloads in chunks of ≤ 60 s, so the web app needs a chunked-download engine: two of NFR-22's four browsers don't offer the File System Access API for saving files, and service-worker workarounds are fragile for files of several GB. Adds a second distribution, a key group to rotate, a files key policy that lets CloudFront decrypt, origin failover to Osaka, and a cache policy that must guarantee nothing is stored at edges outside Japan. |
| Pre-signed S3 `GET` URL | The simplest and fastest; no extra cost | A bearer URL: a forwarded URL works without verification (FR-14), its reuse is invisible (FR-4), resumes are unbounded (FR-6), and it outlives a revocation (NFR-6). The PRD doesn't accept it. |
| A per-request session check at the CDN edge (Lambda@Edge) | Keeps bytes off the pods while checking the session | Still checks only when a request starts, runs outside Japan with session data, and adds a component |

## Consequences

- **Pod sizing.** A pod accepts at most 100 streams with 1 MiB buffers (about 200 MiB of its 1.5 GiB), and pods scale
  on active streams (50 per pod) as well as request rate and CPU. Caps of 6 concurrent streams per session or
  account, 20 per IP address and 200 per tenant; a stream slower than 2 KB/s over 2 minutes is closed, and the load
  balancer's 60-second idle timeout closes a silent one.
- **Deploys.** Ordinary requests keep the 20-second drain of the runtime contract
  ([architecture](../architecture.md), section 8); streams get up to 120 seconds, then close. The pod's grace period is
  150 seconds and the target group's deregistration delay exceeds the stream drain. With `maxUnavailable: 0` and
  `maxSurge: 25%`, new pods serve at once and rollback stays within NFR-18's 10 minutes. A cut stream resumes under the
  same grant, uncounted, and `download_streams_ended_total{reason="shutdown"}` measures how often it happens.
- **A new `download_grants` table**, a security-critical record like the download count
  ([data model](../design/data-model.md), section 2.3).
- **Recovery re-applies only grants that happened.** A failover or restore re-applies a grant, and its count, only if
  it has a committed record in the archive or a row in the database; an intent with neither was refused or rolled
  back, so it never gave access and is ignored. One window remains: a grant committed in Tokyo whose committed record
  hasn't reached the archive and whose row hasn't reached the Osaka replica is lost if Tokyo is lost at that moment.
  Both normally land within a second of the commit; a grant lost this way lets that recipient download the file once
  more than the limit allows, and its intent record shows which grant it was. Byte counts lost within the replication
  lag are a disaster-recovery gap tracked in [#42](https://github.com/codewithmuh/secure-file-transfer/issues/42).
- **Grants need both Regions' archive,** so an Osaka-only outage stops new downloads in Tokyo until Osaka returns
  (threat model R-11). Whether a degraded mode should serve grants during such an outage, and its effect on NFR-1, is
  open in [#42](https://github.com/codewithmuh/secure-file-transfer/issues/42).
- **Resuming depends on the browser sending the `SameSite=Strict` cookie.** A resume that starts from the browser's
  download manager may arrive without `__Host-sft_link` or the member's cookie in some browsers; it then gets `401`,
  and the user starts the download again from the page, which reuses the grant through `resume_grant_id`, uncounted,
  within its byte budget. The staging browser matrix records the result for each browser of NFR-22
  ([abuse and rate limits](../security/abuse-and-rate-limits.md), 9.1 and 9.2).
- **Cost.** Internet egress is the same for every option, about $2,962 a month at design load; streaming adds the
  load balancer's $243 and almost nothing at idle.
- **Limits bound fetches, not copies.** A recipient who keeps a file can share it; revocation stops further downloads.
- **Contract and design.** In the [API contract](../api/openapi.yaml), `DownloadMethod` has only `stream`, and the
  content operations are `getSessionDownloadContent` and `getReceivedFileDownloadContent`; the
  [architecture](../architecture.md) records the download decision and the 120-second stream drain.
- **Tests** ([abuse and rate limits](../security/abuse-and-rate-limits.md), 5.5): 50 parallel grant requests at a
  limit of 1 give one grant; a failed intent write gives `503` and no count; a download interrupted at 50 % resumes
  without a new count; a takeover keeps the bytes the old stream sent; the fourth copy and the 21st request are
  refused; revoking during a 1 GB stream stops it within 60 seconds.

When to revisit: if `download_streams_ended_total{reason="shutdown"}` shows that deploys cut a noticeable share of long
downloads, or streams on the API pods push ordinary calls past NFR-2 in the first load test, move the content routes
to a separate deployment of the same image with longer drains. Compare the CDN option again if every browser NFR-22
names gains a reliable way to save chunked downloads to disk.
