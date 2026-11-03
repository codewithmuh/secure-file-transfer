# Product requirements: secure-file-transfer v1

| | |
|---|---|
| Status | Accepted as the v1 baseline ([#2](https://github.com/codewithmuh/secure-file-transfer/issues/2)); changes go through pull requests |
| Owner | Muhammad Rashid |
| Last updated | 2026-11-03 |
| Next step | Decisions (planning phase 4, [#34](https://github.com/codewithmuh/secure-file-transfer/issues/34)) |
| Aligned with | Architecture, data model, API contract and the phase 3 security design ([#26](https://github.com/codewithmuh/secure-file-transfer/issues/26)) |

## 1. Summary

Companies often need to exchange confidential files with people outside the company: contracts with a customer,
payroll with an accountant, drawings with a supplier. Email attachments are capped in size, can't be recalled once
sent, and leave no record of who opened what.

secure-file-transfer lets a company send files through a link that expires, or ask someone outside the company to
deliver files through an upload link. Recipients prove they control their email address before they can download.
Every file is scanned for malware before anyone can download it, every action is recorded in an audit log, and the
company can revoke access at any time.

This is a reference service: built and operated to the standard of a real B2B SaaS team, but with no customers. Success
therefore means the engineering targets in this document are met and measured (section 9), not revenue or adoption.

## 2. Goals

1. Sending and requesting confidential files with outsiders is as easy as email, without email's risks.
2. The company stays in control after sending: expiry, download limits, revocation and a complete audit trail.
3. No file reaches a recipient before it has passed a malware scan.
4. Each tenant's data is isolated, encrypted and kept in Japan, and recovery from losing a whole AWS region is proven in
   drills.
5. The service is run the way a large company runs production: SLOs, alerts with runbooks, dev → staging → prod
   promotion, and measured RTO/RPO.

## 3. Users and roles

A **tenant** is one customer company. Members and admins belong to exactly one tenant. External people have no account;
they get access to one transfer or one upload request at a time.

| Role | Who | Can |
|---|---|---|
| Tenant admin | IT or security staff at the customer | Manage members and tenant policy; see and revoke every transfer and upload request in the tenant; search and export the audit log. Sees metadata only, not file contents. |
| Member | Any employee of the customer | Send transfers; create upload requests; see and revoke their own; download files delivered to their own upload requests. |
| Recipient | External person a transfer is sent to | After verifying their email address: see and download the files of that transfer while it is valid. |
| Uploader | External person an upload request is sent to | After verifying their email address: upload files to that request while it is valid. |
| Platform operator | The team running the service | Provision tenants and operate the platform. No access to file contents; emergency (break-glass) access is audited and raises an alert. |

## 4. Use cases

### UC-1 Send files to external recipients

1. A member creates a transfer: chooses files, adds recipient email addresses, sets an expiry, and optionally adds a
   message and a download limit.
2. The files upload from the browser. An interrupted upload resumes where it stopped.
3. Each file is scanned for malware. When every file is shareable (FR-16), each recipient gets an email with a link.
4. A recipient opens the link, proves they control the invited address, and downloads the files one by one.
5. The member sees, for each recipient, whether they were notified, verified and downloaded, and which files.

If any file isn't shareable (it is infected, its scan keeps failing, or it can't be scanned and tenant policy blocks
unscannable files), the transfer is **held**: no recipient is notified, and the member sees which file failed and why. The member
can remove that file and send the rest, or cancel the transfer.

### UC-2 Request files from someone outside the company

1. A member creates an upload request for one external email address, with an expiry and an optional message.
2. The uploader gets an email, opens the link, verifies their address and uploads files (same limits as UC-1).
3. Each file is scanned. Shareable files (FR-16) become available to the member, who is notified. Other files are
   blocked, and both the member and the uploader are told.

### UC-3 Revoke access

A member revokes one of their own transfers or upload requests, or a tenant admin revokes any in the tenant. From that
moment no new download or upload can start, and recipients see that the link was revoked. Revoking an upload request
stops further uploads; files already received stay available to the member until their retention ends (FR-13).

### UC-4 Review activity

A tenant admin searches the audit log by person, email address, transfer, action or time range, for example to answer
"who downloaded the contract we sent on Monday, and from which IP address?". They can export the results.

### UC-5 Administer a tenant

A tenant admin invites and deactivates members, assigns roles, and sets tenant policy: the longest allowed expiry,
recipient domains that are allowed or blocked, what happens to files that can't be scanned, and how long files received
through upload requests are kept.

### UC-6 Operate the platform

A platform operator provisions a new tenant and its first admin, watches SLO dashboards, responds to alerts by following
runbooks, and runs backup-restore and regional-failover drills.

## 5. Functional requirements

Priority: **Must** means v1 does not ship without it. **Should** means it is in v1 unless it threatens the schedule.
**Could** means later.

### Transfers (sending)

| ID | Requirement | Priority |
|---|---|---|
| FR-1 | A member creates a transfer with 1–50 files, 1–50 recipient email addresses, an expiry, and an optional message. | Must |
| FR-2 | Files are up to 5 GB each and 20 GB per transfer. Uploads are resumable: after an interruption, completed parts are not sent again. | Must |
| FR-3 | Expiry is between 1 hour and 30 days, capped by tenant policy. The default is 7 days, or the tenant's maximum if that is shorter. | Must |
| FR-4 | An optional download limit per recipient per file (1–100). | Must |
| FR-5 | Recipients are notified only after every file in the transfer is shareable (FR-16). Otherwise the transfer is held (UC-1). | Must |
| FR-6 | Recipients download each file individually. There is no server-side zip of several files. An interrupted download of a large file can be resumed without using up the download limit (FR-4), and resuming can't be used to get around that limit. Downloads stream through the service under a download grant bound to the verified session ([ABUSE] 5, open question 8). | Must |
| FR-7 | The member sees per-recipient status: notified, verified, and downloaded (which files, when). | Must |
| FR-8 | The member can choose to be emailed on the first download of a transfer. | Should |
| FR-9 | The member can extend the expiry of an active transfer, within tenant policy. | Should |

### Upload requests (receiving)

| ID | Requirement | Priority |
|---|---|---|
| FR-10 | A member creates an upload request for one external email address, with an expiry (same range as FR-3) and an optional message. | Must |
| FR-11 | The uploader can upload up to 50 files, up to 5 GB each and 20 GB in total, with resumable uploads. | Must |
| FR-12 | Shareable files (FR-16) become available to the requesting member, who is notified. Blocked files are reported to both sides. | Must |
| FR-13 | Files received through an upload request are kept for the tenant's retention period, counted from each file's upload (default 30 days, 1–90 days), then deleted. The request expiring or being revoked stops new uploads but doesn't shorten this. The member can delete received files earlier. | Must |

### Verification of external people

| ID | Requirement | Priority |
|---|---|---|
| FR-14 | Before any file name, message or content is shown, a recipient or uploader must prove they control the invited email address at that moment. A forwarded or leaked link alone grants nothing, and neither does a forwarded download address: downloads work only within the verified session (FR-15, [ABUSE] 5). The proof is a one-time code emailed to that address ([AUTH] 4). | Must |
| FR-15 | A successful verification is bound to that browser session and that transfer or request, and it expires (NFR-14). | Must |

### Malware scanning

| ID | Requirement | Priority |
|---|---|---|
| FR-16 | Every uploaded file is scanned before it can be downloaded. Each file has a visible state: uploading, scanning, clean, infected, unscannable or scan-failed. A file is **shareable** when it is clean, or unscannable and allowed by tenant policy (FR-18); only shareable files can be downloaded. | Must |
| FR-17 | Infected files are quarantined and can never be downloaded by anyone, including the sender, tenant admins and platform operators. | Must |
| FR-18 | Files the scanner can't inspect, such as password-protected archives, are blocked by default. Tenant policy can allow them, in which case anyone downloading them (recipient or member) sees a warning. | Must |
| FR-19 | A scan that fails because of an engine error is retried. If it keeps failing, the file stays blocked and an operator alert fires. The tenant policy for unscannable files never applies to scan failures. | Must |

### Control and lifecycle

| ID | Requirement | Priority |
|---|---|---|
| FR-20 | A member revokes their own transfers and upload requests. A tenant admin revokes any in the tenant. | Must |
| FR-21 | Transfers and upload requests expire automatically, and expired or revoked ones can't be used. Their data is deleted on the schedule below. | Must |

#### Data lifecycle

This table is the single source for when data is deleted. File contents are gone from every copy (primary region, DR
region and backups) within 7 days of the trigger (NFR-8). Database records leave the live database at the trigger and
age out of database backups within the 14-day restore window (NFR-11).

| Data | Deletion is triggered when |
|---|---|
| Files of a transfer, including quarantined ones | The transfer expires or is revoked |
| Files removed from a held transfer, or of a cancelled transfer | The file is removed, or the transfer is cancelled by the member or after 7 days as an unsent draft |
| Files received through an upload request | Their retention period ends (FR-13), or the member deletes them |
| Parts of an upload that never completed | 24 hours after the last part arrived, or when the transfer or request is revoked |
| Stored objects that no transfer or request refers to (for example parts sent after a revocation) | 24 hours after they appear; the reconciliation job (NFR-8) finds them |
| Metadata of transfers and upload requests | When no audit record refers to it any more, so audit records stay readable (at most 365 days after the item's last event) |
| Audit records | 365 days after they were written (NFR-9) |
| Verification codes and sessions | When they expire (NFR-14) |
| Application, load balancer, CDN and WAF logs | 90 days after they were written |

### Tenant administration and sign-in

| ID | Requirement | Priority |
|---|---|---|
| FR-22 | A tenant admin invites members, deactivates them and assigns the admin or member role. An email address can hold a sign-in without SSO for one tenant only ([AUTH] 2.5). | Must |
| FR-23 | Tenant policy: longest expiry, handling of unscannable files, and retention of received files. | Must |
| FR-24 | Tenant policy: allowed and blocked recipient email domains. | Should |
| FR-25 | Members and admins sign in with multi-factor authentication. | Must |
| FR-26 | Tenant single sign-on through the customer's own identity provider (OIDC or SAML). | Should |

### Audit

| ID | Requirement | Priority |
|---|---|---|
| FR-27 | Every security-relevant action is recorded: sign-in, transfer and request creation, each upload, scan results, emails sent, each verification attempt (success or failure), each download, revocation, expiry and expiry extensions, deletion, member and policy changes, API key creation, use and revocation, audit log searches and exports, and operator break-glass access. Each record holds the actor, tenant, target, time, source IP and user agent. | Must |
| FR-28 | A tenant admin searches and filters the audit log in the web app. | Must |
| FR-29 | A tenant admin exports audit log results as CSV or JSON, from the web app and the API. | Should |

### Web app and API

| ID | Requirement | Priority |
|---|---|---|
| FR-30 | A React + TypeScript web app for members and admins, and for the recipient and uploader pages. | Must |
| FR-31 | Everything the web app does goes through a public, versioned REST API described in OpenAPI 3.1. | Must |
| FR-32 | Tenant-scoped API keys for automation, such as creating transfers or exporting the audit log. | Should |
| FR-33 | Recipient and uploader pages and all emails are available in English and Japanese, in v1 (open question 6). | Must |

### Platform

| ID | Requirement | Priority |
|---|---|---|
| FR-34 | A platform operator provisions a tenant and its first admin through an operator API or CLI. There is no self-service sign-up. | Must |
| FR-35 | Platform operators can't read file contents during normal operation. Any break-glass access is time-limited, audited (FR-27) and raises an alert. | Must |

## 6. Non-functional requirements

Each target is checked by the method in the last column. "Design load" means the load in section 6.1. Tools named in
the last column are the ones the phase 4 ADRs chose.

| ID | Quality | Target | How it is measured |
|---|---|---|---|
| NFR-1 | Availability | 99.9 % of valid requests to the API and the download path succeed, over a rolling 28 days while prod runs. | SLI from load-balancer and service metrics (5xx and timeouts count as failures), plus a synthetic probe every 5 minutes that runs the full send → verify → download journey from a dedicated synthetic tenant to the probe's own mailbox on our domain. That tenant is excluded from product metrics. Only the probe mailbox's addresses are exempt from the per-address limits (NFR-14): the verification-code caps and the link-email caps, and only on the synthetic tenant's links ([ABUSE] 2.2). Planned drill windows that take prod down are logged and reported separately, not counted. A real regional failure is expected to breach this target; NFR-11 bounds the recovery. |
| NFR-2 | API latency | p95 ≤ 300 ms and p99 ≤ 1 s for API calls at design load, excluding the time spent moving file bytes. | Server-side latency histograms; k6 load test. |
| NFR-3 | Upload speed and resume | A 5 GB file uploads over a 100 Mbit/s link in ≤ 8 minutes (line rate plus ≤ 10 % overhead). After the connection drops, the upload resumes without re-sending completed parts. | Automated browser test on a throttled network, with a forced disconnect halfway through. |
| NFR-4 | Download start | p95 ≤ 1 s from a verified recipient's click to the first byte. | Real-user timing in the web app; synthetic probe. |
| NFR-5 | Time to shareable | For a transfer, from the last upload completing to every file shareable and the recipient emails handed to the email provider: p95 ≤ 2 minutes when the largest file is up to 100 MB; p95 ≤ 15 minutes for any transfer up to the 20 GB limit. For an upload request, the same targets apply to each file, from its upload completing to it being available to the member. | Timestamps on file state changes; traces. |
| NFR-6 | Revocation | No new download or upload can start ≤ 5 s after revocation, and a download already in progress stops ≤ 60 s after revocation. Upload parts sent after revocation are never assembled into a file. An upload only completes through a server-side call that checks the current state, so a revoked transfer or request never accepts a new file. | Automated test that revokes during an active download and an active upload, then retries both. |
| NFR-7 | Email | Verification and notification emails are handed to the email provider within p95 ≤ 10 s. | Service metrics; email provider delivery events. |
| NFR-8 | Data deletion | A file's contents are deleted from every copy (primary region, DR region and backups) ≤ 7 days after its deletion trigger in the data lifecycle table (section 5). Audit records are kept. | A daily reconciliation job that compares metadata with storage in both regions and reports any leftovers. |
| NFR-9 | Retention | Audit records are kept for 365 days and then deleted. Everything else follows the data lifecycle table (section 5). | Lifecycle rules plus the reconciliation job. |
| NFR-10 | Durability and RPO | No acknowledged upload is lost short of losing the whole Tokyo region. Losing one Availability Zone loses no data (RPO 0). Losing the Tokyo region loses ≤ 5 minutes of metadata, and at most the last 15 minutes of uploads for 99.99 % of files (the commitment of S3 replication with Replication Time Control). After a failover, files that hadn't reached Osaka are shown as unavailable, not as broken links. Security-critical changes (revocations of transfers, upload requests and API keys; deactivations, demotions and forced sign-outs; lockouts and unlocks; sign-in resets; download grants, [ARCH] 5.2) are not lost in a failover or restore: they reach the audit archive in both regions before the API confirms them, and the failover and restore runbooks re-apply them before any worker starts ([ARCH] 4.4, 7). The one stated exception is a download grant committed in the second before Tokyo is lost ([ARCH] 4.2). The disaster-recovery gaps still open are tracked in [#42](https://github.com/codewithmuh/secure-file-transfer/issues/42), and the drills of phase 6 prove this target. | Measured in AZ-failure and regional-failover drills, with a written report per drill. |
| NFR-11 | Recovery (RTO) | AZ failure: automatic recovery, RTO ≤ 5 minutes. Tokyo region failure: service restored in Osaka, RTO ≤ 1 hour. Member sign-in moves to a standby user pool in Osaka: SSO members sign in as usual, and members without SSO re-enrol in that pool by email (a new password and MFA factor) as a step of the failover runbook; after failback they use their original sign-in again. Existing sessions, recipients, uploaders and API keys don't depend on the user pool ([AUTH] 2.6). Restore after data corruption (for example a bad migration), to any chosen point in the last 14 days, accurate to ≤ 5 minutes: RTO ≤ 2 hours. Changes after that point are lost, except the security-critical changes and audit records that NFR-10 and NFR-15 protect. File contents deleted under NFR-8 can't be recovered, by design; restored metadata that points to them is marked deleted. | Timed drills in staging and prod; each drill report records the measured RTO and RPO. |
| NFR-12 | Tenant isolation | No API call, link or token gives access to another tenant's data. | An isolation test suite runs in CI on every pull request and against staging, trying every endpoint with another tenant's IDs and tokens. |
| NFR-13 | Security baseline | Meets OWASP ASVS 5.0 Level 2 for the web app and API. TLS 1.2+ for all traffic. Files, database, backups and logs encrypted at rest with KMS keys, with one exception: load balancer access logs support only SSE-S3. They hold IP addresses, user agents and paths with opaque IDs, never link tokens ([KEYS] 3.1). No known critical or high vulnerabilities in a released image. Secrets only in AWS Secrets Manager, never in git. | ASVS checklist in the security design; Trivy and gitleaks in CI; AWS Config rules. |
| NFR-14 | Abuse resistance | Rate limits per IP address, per account and per tenant on sign-in, verification, link access, uploads and downloads. Starting limits: ≤ 10 failed sign-ins per account per 15 minutes, enforced by a pre-authentication trigger on the user pool (Cognito's own lockout alone allows up to 14); verification codes ≤ 5 per email address per hour and ≤ 50 a day, and ≤ 20 per link a day; ≤ 60 link-page requests per IP per minute; ≤ 1,000 API requests per tenant per minute; downloads ≤ 500 GB granted per tenant a day and ≤ 25 GB per recipient a day; uploads ≤ 200 GB declared per tenant a day and ≤ 2 TB stored per tenant; an API key exports the audit log at most once an hour, ≤ 100,000 events per export. A verification proof is valid ≤ 10 minutes and allows ≤ 5 attempts; codes have at least 6 digits. After 20 failed attempts in total for one recipient on one transfer or request, that recipient is locked out until the member unlocks them; the member and tenant admins are told. A verified session lasts ≤ 24 hours. Link tokens carry ≥ 128 bits of randomness. [ABUSE] 2 lists every limit with its key and where it is enforced. Limits change only through deploy config, for every tenant at once; per-tenant overrides are not in v1. | Automated tests for each limit; WAF and service metrics on rejected requests. |
| NFR-15 | Audit integrity | Every action in FR-27 is recorded ≤ 60 s after it happens, failed sign-ins included (through the user pool's sign-in triggers, [AUTH] 2.4). A download is only served if its audit record has been written (fail closed). In prod, archived audit records can't be changed or deleted before their retention ends, and no restore or failover removes them; dev and staging use a short, removable lock so they can be torn down. Records written within the database replication lag (normally seconds) can be lost in a regional failover before they reach the archive. Security-critical records can't, because they are written to both regions' archive before the API confirms them (NFR-10, [THREAT] R-05). | Tests that make the audit write fail; a daily job that matches storage access logs against audit records; S3 Object Lock on archived records. |
| NFR-16 | Scalability | Handles the design load (6.1) at the latency targets with no manual action, and scales out automatically beyond it. | k6 load test at 1× and 2× design load. |
| NFR-17 | Observability | Every user journey is traced end to end, with structured logs and metrics. Every alert links to a runbook. Dashboards and alerts are defined as code. | Review in phase 6; a test that fails if an alert has no runbook. |
| NFR-18 | Deployability | Zero-downtime deploys. The same build artifacts (container image digests and the versioned web app bundle) are promoted dev → staging → prod. Rollback ≤ 10 minutes. Releases several times a week are routine. | Deployment metrics from Argo CD and the web app release pipeline; a timed rollback drill for both. |
| NFR-19 | Rebuild and teardown | The whole prod environment can be built from Terraform and Argo CD in ≤ 2 hours, and destroyed in ≤ 1 hour, leaving nothing that still bills except the retained stack: the prod audit archive, the KMS key that encrypts it, and the stack's own Terraform state, trail and alert topic that guard them. They outlive the environment until the archive's retention ends (NFR-9, NFR-15), in the prod AWS account, which stays open, for ≤ $7 a month: about $2.20 planned and about $6.00 in the worst case ([KEYS] 8.4). The cap was $5 until the retained stack needed its own state, trail and alerting; holding $5 would have meant dropping the audit key's yearly rotation. One more exception: the shared account's log archive is under a 90-day Object Lock, so it keeps billing a few cents for up to 90 days after the final teardown, inside the cap. | Timed rebuild and teardown, with the AWS bill checked afterwards. |
| NFR-20 | Cost control | AWS Budgets alarms at 50 %, 80 % and 100 % of the monthly budget (open question 7). dev and staging are torn down when idle. | Budget configuration in Terraform; the monthly bill. |
| NFR-21 | Data residency | All customer data (files, metadata, backups and logs) stays in Tokyo (ap-northeast-1) and Osaka (ap-northeast-3). Global AWS services (CloudFront with its certificate and WAF, IAM, Route 53, Budgets) are exempt from the region guard; their logs are delivered to storage in Tokyo. The region guard also allows these resources in us-east-1 only, none of which holds file contents: CloudFront, its WAF and its ACM certificate; CloudWatch metrics and alarms, which AWS publishes there for CloudFront and for Route 53 health checks, and the SNS topic those alarms notify; the CloudWatch Logs delivery configuration for the CloudFront WAF, which writes its logs to Tokyo; and the KMS key that signs the DNS zone (DNSSEC). Traffic may pass through CDN edges outside Japan for users abroad, but file contents are never cached or stored there. | AWS Config, plus an SCP or IAM condition that denies other regions except those global services; review of S3 replication, backup, log delivery and CDN cache settings. |
| NFR-22 | Web app quality | Recipient and uploader pages meet WCAG 2.2 AA. They support the latest two versions of Chrome, Edge, Firefox and Safari. | Automated accessibility checks (axe) in CI plus a manual pass; a browser test matrix. |

### 6.1 Design load

These are the targets the system is designed and load-tested for. The [capacity estimate][CAP] refines them.

| Measure | Target |
|---|---|
| Tenants | 500 |
| Members | 25,000 |
| Transfers and upload requests | 10,000 per day; the peak hour carries 3× the average hour |
| Files per transfer | 3 on average, 50 at most |
| File size | median 5 MB, p95 200 MB, maximum 5 GB |
| New data | about 1 TB per day |
| Stored data at steady state | about 15 TB in Tokyo, replicated to Osaka (assumes 80 % of new data arrives through transfers kept 7 days and 20 % through upload requests kept 30 days, plus up to 7 days until deletion completes) |
| File downloads | about 40,000 per day |
| API requests | about 50 per second on average, 150 per second in the peak hour, bursts to 300 per second |

The load test runs the API at full design load but moves file bytes at a sampled rate, because data transfer out of AWS
at 1 TB a day would cost more than the test is worth. The sampling rate and its cost are part of the phase 6 test plan.

## 7. Environments and topology

| Environment | Purpose | Shape | Running |
|---|---|---|---|
| dev | Day-to-day integration | One region (Tokyo), smallest sizes, single-AZ where possible | Torn down when idle |
| staging | Release rehearsal and drills | Prod's shape at smaller sizes, including the Osaka pilot light | Up for release testing and drills, torn down when idle |
| prod | The real service | Tokyo across 3 Availability Zones. Osaka pilot light: files and database replicate continuously; compute starts only on failover. | Up for the end-to-end operating period, then destroyed (NFR-19) |

Each environment has its own AWS account under AWS Organizations, and a shared account holds logs and the container
registry (open question 4). The same build artifacts are promoted from dev to staging to prod (NFR-18). The React app
is static files served through a CDN, not another service, so the backend stays one API service plus workers with one
system of record.

## 8. Non-goals for v1

- **End-to-end encryption** where the service can't read file contents. It would make malware scanning impossible,
  and FR-16 takes priority. Files are encrypted in transit and at rest with keys the service controls through KMS.
- **Content inspection beyond malware** (DLP classification, keyword or personal-data detection).
- **Email gateway integration** that turns attachments into links automatically.
- **Desktop, mobile or Outlook add-in clients.** The web app and the API are the only clients.
- **Collaboration features:** folders, sync, previews, comments, file versions.
- **Server-side zip downloads** of several files (FR-6).
- **Anonymous public links.** Every recipient verifies an email address.
- **Self-service sign-up, billing and plans.** Platform operators provision tenants (FR-34).
- **Active-active multi-region.** Osaka is a pilot light for disaster recovery, not a second live region.
- **Compliance certification** (SOC 2, ISO 27001, ISMAP). The design follows those controls where cheap, but nothing is
  audited or certified.

## 9. Success metrics

### Engineering targets: what "done" means for v1

- Every Must requirement in section 5 works end to end in prod.
- Every NFR in section 6 is measured, with the result published in `docs/` (dashboards, load-test report, drill
  reports).
- A regional failover drill to Osaka meets RTO ≤ 1 hour and the RPO in NFR-10 (≤ 5 minutes of metadata, ≤ 15 minutes
  of files), measured, not estimated.
- The tenant isolation suite (NFR-12) has run on every pull request since the first data-access code, with zero
  failures on `main`.
- A timed full teardown and rebuild meets NFR-19.

### Product metrics: instrumented, with no targets

If this were a real product, these would drive decisions. They are collected so the dashboards are realistic: weekly
active senders, transfers created, the share of transfers downloaded at least once, time from send to first download,
verification failure rate, infected-file rate, and revocations per 1,000 transfers.

## 10. Assumptions and constraints

- AWS work uses only the personal AWS profile Rashid provides. Until then, infrastructure code is written and checked
  statically; nothing is applied.
- Amazon SES starts in sandbox mode, which can only send to verified addresses. Production sending needs an approved
  SES production-access request and a domain with SPF, DKIM and DMARC records. SES identities and production access
  are per region, so Tokyo and Osaka each need them, and the regional failover drill must send email from Osaka.
  SES is available in Osaka (architecture 3.2).
- One maintainer builds the service in thin vertical slices (phase 5), so Should items may move to a later release.
- Prod runs for a bounded operating period, so availability (NFR-1) is measured over that window, not over a calendar
  year.

## 11. Risks

| Risk | Impact | Mitigation |
|---|---|---|
| Some scan engines can't handle files near 5 GB, or are too slow for NFR-5. | Large files stay blocked or miss the time target. | ClamAV can't scan files over 2 GB, so scanning is a hybrid: ClamAV up to 2 GB, GuardDuty Malware Protection for S3 above ([ABUSE] 6.4, open question 2). GuardDuty publishes no time to result, so staging measures it on 5 GB files before the design is fixed; the scan step stays behind an interface. |
| Data transfer and cross-region replication costs grow with the 1 TB/day design load. | Bills higher than planned during load tests and drills. | Sampled byte load (6.1), budget alarms (NFR-20), teardown after each test window. |
| Email deliverability: verification emails land in spam or are delayed. | Recipients can't verify, so files can't be downloaded. | SPF, DKIM and DMARC; SES reputation metrics on a dashboard; NFR-7 alerting. |
| The simplest download mechanism, a short-lived pre-signed URL, is a bearer token. | It would break FR-14 (a forwarded URL works without verification), make FR-4 limits and FR-6 resumes hard to enforce, and briefly outlive a revocation. | Closed: downloads stream through the API under a grant bound to the verified session, so no bearer URL is issued ([ABUSE] 5, open question 8). The PRD does not accept a bearer URL as a residual risk. |
| File replication to Osaka lags during heavy uploads. | Files uploaded in the last ≤ 15 minutes before a regional failure are lost (NFR-10). | Replication with a time guarantee and an alarm on lag; files not yet replicated are marked unavailable after failover. |
| Email isn't ready in Osaka when Tokyo fails. | Recipients can't verify, so the service is down for them even though the API is up. | SES set up and approved in both regions (section 10); the failover drill sends real verification emails from Osaka. |
| An outage of S3 in Osaka, or of the cross-region endpoint to it, while Tokyo is healthy ([THREAT] T-81, R-11). | Security-critical records must reach both regions' archive, so new downloads in Tokyo fail closed: the API answers 503 and counts nothing. The other security-critical changes take effect in Tokyo at once and stand; their 503 only means the archive record isn't confirmed yet. Streams under existing grants, sign-in, sending and uploads carry on. | Alarms on the cross-region write; retries complete the records when Osaka returns; the runbook covers an Osaka-only outage. A degraded mode for grants is a disaster-recovery gap tracked in [#42](https://github.com/codewithmuh/secure-file-transfer/issues/42), with the phase 6 runbooks. |
| After a Tokyo failover, members without SSO re-enrol by email (NFR-11, [THREAT] R-10). | Until they do they can't sign in, and during that window control of a member's mailbox is enough to take over the account. | Re-enrolment emails go out only when an operator declares a failover; each invitation is single use and needs a new MFA factor; tenant admins are told and every re-enrolment is audited ([AUTH] 2.6). |
| A leaked link lets someone lock the real recipient out (NFR-14). | The recipient can't download until the member acts. | The member and tenant admins are told; the member can unlock the recipient, which always issues a new link, or revoke and re-send the transfer ([AUTH] 4.4). |
| Scope: a React app, multi-region DR and three environments for one maintainer. | Schedule slips. | Must/Should split; thin slices; the Osaka pilot light comes after the single-region slice works. |

## 12. Open questions

All eight are decided (owner: Rashid). The numbers stay, because other documents refer to them. Questions 1, 2, 3 and 8
are argued in the phase 3 security design and recorded in phase 4 ADRs; questions 4 to 7 are the maintainer's decisions
of 2026-11-03.

| # | Question | Decision | Argued in |
|---|---|---|---|
| 1 | Member sign-in for v1: a managed identity provider with mandatory MFA, tenant SSO, or both (FR-25, FR-26)? | Both, through Amazon Cognito (Plus plan): one user pool per environment for members without SSO, with mandatory MFA (TOTP, or a passkey with user verification), and each tenant's SSO provider federated through it. The API issues its own server-side session after the code exchange. | [AUTH] 2 |
| 2 | Which malware scan engine handles 5 GB files within NFR-5? | A hybrid: ClamAV in the scan workers for files up to 2 GB, GuardDuty Malware Protection for S3 for larger files. Staging measures GuardDuty's time to result on 5 GB files. | [ABUSE] 6.4, [CAP] 3.3 and 5.5 |
| 3 | One KMS key per tenant, or shared keys with per-tenant encryption context? | Shared keys, one per data class, plus per-tenant data keys that encrypt file names and messages, bound to the caller's tenant. A dedicated key per tenant is a later opt-in for tenants that require one. | [KEYS] 5 |
| 4 | One AWS account per environment (AWS Organizations), or one account for all three? | One account per environment (dev, staging, prod) under AWS Organizations, with Rashid's personal account as the management account and a shared account for logs and the container registry. People sign in through IAM Identity Center with MFA. | Maintainer; the accounts ADR records it |
| 5 | Which domain name does the service use (web app, links, email sender)? | A subdomain of a domain Rashid owns, delegated to Route 53. The name is given before the first deploy. | Maintainer |
| 6 | Is Japanese localization (FR-33) in v1 or the first release after? | In v1, for the recipient and uploader pages and all emails, so FR-33 is a Must. | Maintainer |
| 7 | Monthly AWS budget for the prod operating period, and how long that period is. | A cap of $6,500 a month during the operating period, with alarms at $3,250, $5,200 and $6,500 (NFR-20); about $800 a month for dev and staging during the build. The length of the operating period is still open: each extra month costs about $4,770. **To revisit:** with the phase 4 network design (ADR-0021), Osaka's always-on `system` nodes and Kyverno on the `system` group, the planned month is now about $4,770, 80 % of the cap and about $30 under its 80 % alarm, and dev and staging cost about $950 a month during the build. The capacity estimate recommends raising the cap to $6,500 or cutting about $480 ([CAP] 7.3). | Maintainer; [CAP] 7.3 |
| 8 | Which download mechanism meets FR-6, FR-14 and NFR-6 together: streaming through the service, CDN signed cookies bound to the verified session, or something else? | Stream through the API. A download is counted once, when its grant is created; the grant belongs to the verified session, and the browser resumes with Range requests under the same grant. The stream re-checks state every 30 s, so a revocation stops it within 60 s. | [ABUSE] 5 |

## 13. Glossary

| Term | Meaning |
|---|---|
| Transfer | One send: a set of files shared with one or more external recipients through expiring links. |
| Upload request | One request for an external person to deliver files to a member. |
| Tenant | One customer company and everything that belongs to it. |
| Verification | Proof that an external person controls the invited email address at the moment of access. |
| Held transfer | A transfer that can't be sent because one of its files isn't shareable. |
| Shareable | A file that is clean, or unscannable and allowed by tenant policy (FR-16). |
| Download grant | The right to download one file, created and counted once per download and bound to the verified session that asked for it. Resuming uses the same grant, within a byte, request and time budget ([ABUSE] 5.4). |
| Pilot light | A disaster recovery setup where data is replicated to a second region continuously, but compute there starts only during a failover. |
| RPO / RTO | Recovery point objective (how much recent data can be lost) and recovery time objective (how long until service is back). |
| SLI / SLO | Service level indicator (what is measured) and service level objective (the target for it). |

[ABUSE]: security/abuse-and-rate-limits.md
[ARCH]: architecture.md
[AUTH]: security/authn-authz.md
[KEYS]: security/encryption-and-keys.md
[THREAT]: threat-model.md
[CAP]: design/capacity-and-cost.md
