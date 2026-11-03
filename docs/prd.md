# Product requirements: secure-file-transfer v1

| | |
|---|---|
| Status | Draft, in review ([#2](https://github.com/codewithmuh/secure-file-transfer/issues/2)) |
| Owner | Muhammad Rashid |
| Last updated | 2026-11-03 |
| Next step | Architecture and system design (planning phase 2) |

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
3. Each file is scanned for malware. When every file is clean, each recipient gets an email with a link.
4. A recipient opens the link, proves they control the invited address, and downloads the files one by one.
5. The member sees, for each recipient, whether they were notified, verified and downloaded, and which files.

If a file is infected, its scan keeps failing, or it can't be scanned and tenant policy blocks unscannable files
(FR-18), the transfer is **held**: no recipient is notified, and the member sees which file failed and why. The member
can remove that file and send the rest, or cancel the transfer.

### UC-2 Request files from someone outside the company

1. A member creates an upload request for one external email address, with an expiry and an optional message.
2. The uploader gets an email, opens the link, verifies their address and uploads files (same limits as UC-1).
3. Each file is scanned. Clean files, and unscannable files if tenant policy allows them (FR-18), become available to
   the member, who is notified. Other files are blocked, and both the member and the uploader are told.

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
| FR-5 | Recipients are notified only after every file in the transfer is clean, or unscannable and allowed by tenant policy (FR-18). A transfer with a blocked file is held (UC-1). | Must |
| FR-6 | Recipients download each file individually. There is no server-side zip of several files. An interrupted download resumes where it stopped, and resuming within the same verified session doesn't count as a new download (FR-4). | Must |
| FR-7 | The member sees per-recipient status: notified, verified, and downloaded (which files, when). | Must |
| FR-8 | The member can choose to be emailed on the first download of a transfer. | Should |
| FR-9 | The member can extend the expiry of an active transfer, within tenant policy. | Should |

### Upload requests (receiving)

| ID | Requirement | Priority |
|---|---|---|
| FR-10 | A member creates an upload request for one external email address, with an expiry (same range as FR-3) and an optional message. | Must |
| FR-11 | The uploader can upload up to 50 files, up to 5 GB each and 20 GB in total, with resumable uploads. | Must |
| FR-12 | Clean files become available to the requesting member, who is notified. Blocked files are reported to both sides. | Must |
| FR-13 | Files received through an upload request are kept for the tenant's retention period, counted from each file's upload (default 30 days, 1–90 days), then deleted. The request expiring or being revoked stops new uploads but doesn't shorten this. The member can delete received files earlier. | Must |

### Verification of external people

| ID | Requirement | Priority |
|---|---|---|
| FR-14 | Before any file name, message or content is shown, a recipient or uploader must prove they control the invited email address at that moment. A forwarded or leaked link alone grants nothing. The leading mechanism is a one-time code emailed to that address; security design (phase 3) confirms it. | Must |
| FR-15 | A successful verification is bound to that browser session and that transfer or request, and it expires (NFR-14). | Must |

### Malware scanning

| ID | Requirement | Priority |
|---|---|---|
| FR-16 | Every uploaded file is scanned before it can be downloaded. Each file has a visible state: uploading, scanning, clean, infected, unscannable or scan-failed. | Must |
| FR-17 | Infected files are quarantined and can never be downloaded by anyone, including the sender, tenant admins and platform operators. | Must |
| FR-18 | Files the scanner can't inspect, such as password-protected archives, are blocked by default. Tenant policy can allow them, in which case recipients see a warning. | Must |
| FR-19 | A scan that fails because of an engine error is retried. If it keeps failing, the file stays blocked and an operator alert fires. The tenant policy for unscannable files never applies to scan failures. | Must |

### Control and lifecycle

| ID | Requirement | Priority |
|---|---|---|
| FR-20 | A member revokes their own transfers and upload requests. A tenant admin revokes any in the tenant. | Must |
| FR-21 | Transfers and upload requests expire automatically, and expired or revoked ones can't be used. Their data is deleted on the schedule below. | Must |

#### Data lifecycle

This table is the single source for when data is deleted. Deletion is complete in every copy (primary region, DR region
and backups) within 7 days of the trigger (NFR-8).

| Data | Deletion is triggered when |
|---|---|
| Files of a transfer, including quarantined ones | The transfer expires, is revoked or is deleted by the member |
| Files received through an upload request | Their retention period ends (FR-13), or the member deletes them |
| Parts of an upload that never completed | 24 hours after the last part arrived, or when the transfer or request is revoked |
| Metadata of transfers and upload requests | 365 days after the transfer or request ended, so audit records stay readable |
| Audit records | 365 days after they were written (NFR-9) |

### Tenant administration and sign-in

| ID | Requirement | Priority |
|---|---|---|
| FR-22 | A tenant admin invites members, deactivates them and assigns the admin or member role. | Must |
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
| FR-33 | Recipient and uploader pages and all emails are available in English and Japanese. | Should |

### Platform

| ID | Requirement | Priority |
|---|---|---|
| FR-34 | A platform operator provisions a tenant and its first admin through an operator API or CLI. There is no self-service sign-up. | Must |
| FR-35 | Platform operators can't read file contents during normal operation. Any break-glass access is time-limited, audited (FR-27) and raises an alert. | Must |

## 6. Non-functional requirements

Each target is checked by the method in the last column. "Design load" means the load in section 6.1. Tools named in
the last column are current candidates; the phase 4 ADRs confirm or replace them.

| ID | Quality | Target | How it is measured |
|---|---|---|---|
| NFR-1 | Availability | 99.9 % of valid requests to the API and the download path succeed, over a rolling 28 days while prod runs. | SLI from load-balancer and service metrics (5xx and timeouts count as failures), plus a synthetic probe every 5 minutes that runs the full send → verify → download journey from a dedicated synthetic tenant. That tenant is excluded from product metrics and exempt from the per-address verification limits only (NFR-14). Planned failover drill windows are logged and reported separately, not counted. |
| NFR-2 | API latency | p95 ≤ 300 ms and p99 ≤ 1 s for API calls at design load, excluding the time spent moving file bytes. | Server-side latency histograms; k6 load test. |
| NFR-3 | Upload speed and resume | A 5 GB file uploads over a 100 Mbit/s link in ≤ 8 minutes (line rate plus ≤ 10 % overhead). After the connection drops, the upload resumes without re-sending completed parts. | Automated browser test on a throttled network, with a forced disconnect halfway through. |
| NFR-4 | Download start | p95 ≤ 1 s from a verified recipient's click to the first byte. | Real-user timing in the web app; synthetic probe. |
| NFR-5 | Time to shareable | From the last upload completing to every file clean and the recipient emails handed to the email provider (for an upload request: the files available to the member): p95 ≤ 2 minutes when the largest file is up to 100 MB; p95 ≤ 15 minutes for any transfer or request up to the 20 GB limit. | Timestamps on file state changes; traces. |
| NFR-6 | Revocation | No new download or upload can start ≤ 5 s after revocation. A download URL stops working ≤ 60 s after it was issued, and an upload-part URL ≤ 15 minutes after. An upload only completes through a server-side call that checks the current state, so a revoked transfer or request never accepts a new file. | Automated test that revokes during an active download and an active upload, then retries both. |
| NFR-7 | Email | Verification and notification emails are handed to the email provider within p95 ≤ 10 s. | Service metrics; email provider delivery events. |
| NFR-8 | Data deletion | A file's contents are deleted from every copy (primary region, DR region and backups) ≤ 7 days after its deletion trigger in the data lifecycle table (section 5). Audit records are kept. | A daily reconciliation job that compares metadata with storage in both regions and reports any leftovers. |
| NFR-9 | Retention | Audit records are kept for 365 days and then deleted. Received files follow FR-13. Metadata of expired transfers is kept for 365 days so audit records stay readable. | Lifecycle rules plus the reconciliation job. |
| NFR-10 | Durability and RPO | No acknowledged upload is lost short of losing the whole Tokyo region. Losing one Availability Zone loses no data (RPO 0). Losing the Tokyo region loses ≤ 5 minutes of metadata and ≤ 15 minutes of uploaded files (the cross-region replication guarantee for files). After a failover, files that hadn't reached Osaka are shown as unavailable, not as broken links. | Measured in AZ-failure and regional-failover drills, with a written report per drill. |
| NFR-11 | Recovery (RTO) | AZ failure: automatic recovery, RTO ≤ 5 minutes. Tokyo region failure: service restored in Osaka, RTO ≤ 1 hour. Restore after data corruption (for example a bad migration), to any point in the last 14 days: RTO ≤ 2 hours, RPO ≤ 5 minutes. File contents deleted under NFR-8 can't be recovered, by design; restored metadata that points to them is marked deleted. | Timed drills in staging and prod; each drill report records the measured RTO and RPO. |
| NFR-12 | Tenant isolation | No API call, link or token gives access to another tenant's data. | An isolation test suite runs in CI on every pull request and against staging, trying every endpoint with another tenant's IDs and tokens. |
| NFR-13 | Security baseline | Meets OWASP ASVS 5.0 Level 2 for the web app and API. TLS 1.2+ for all traffic. Files, database, backups and logs encrypted at rest with KMS keys. No known critical or high vulnerabilities in a released image. Secrets only in AWS Secrets Manager, never in git. | ASVS checklist in the security design; Trivy and gitleaks in CI; AWS Config rules. |
| NFR-14 | Abuse resistance | Rate limits per IP address, per account and per tenant on sign-in, verification, link access, uploads and downloads. Starting limits: ≤ 10 failed sign-ins per account per 15 minutes; ≤ 5 verification codes per email address per hour; ≤ 60 link-page requests per IP per minute; ≤ 1,000 API requests per tenant per minute. A verification proof is valid ≤ 10 minutes and allows ≤ 5 attempts; codes have at least 6 digits. After 20 failed attempts in total for one recipient on one transfer or request, that recipient is locked out and the member is told. A verified session lasts ≤ 24 hours. Link tokens carry ≥ 128 bits of randomness. Phase 3 may tighten these numbers. | Automated tests for each limit; WAF and service metrics on rejected requests. |
| NFR-15 | Audit integrity | Every action in FR-27 is recorded ≤ 60 s after it happens. A download is only served if its audit record has been written (fail closed). In prod, stored audit records can't be changed or deleted before their retention ends; dev and staging use a short, removable lock so they can be torn down. | Tests that make the audit write fail; a daily job that matches storage access logs against audit records; S3 Object Lock on archived records. |
| NFR-16 | Scalability | Handles the design load (6.1) at the latency targets with no manual action, and scales out automatically beyond it. | k6 load test at 1× and 2× design load. |
| NFR-17 | Observability | Every user journey is traced end to end, with structured logs and metrics. Every alert links to a runbook. Dashboards and alerts are defined as code. | Review in phase 6; a test that fails if an alert has no runbook. |
| NFR-18 | Deployability | Zero-downtime deploys. The same build artifacts (container image digests and the versioned web app bundle) are promoted dev → staging → prod. Rollback ≤ 10 minutes. Releases several times a week are routine. | Deployment metrics from Argo CD; a timed rollback drill. |
| NFR-19 | Rebuild and teardown | The whole prod environment can be built from Terraform and Argo CD in ≤ 2 hours, and destroyed in ≤ 1 hour, leaving nothing that still bills except the prod audit archive, which outlives the environment until its retention ends (NFR-9, NFR-15) and should cost well under $1 a month. | Timed rebuild and teardown, with the AWS bill checked afterwards. |
| NFR-20 | Cost control | AWS Budgets alarms at 50 %, 80 % and 100 % of the monthly budget. dev and staging are torn down when idle. | Budget configuration in Terraform; the monthly bill. |
| NFR-21 | Data residency | All customer data (files, metadata, backups and logs) stays in Tokyo (ap-northeast-1) and Osaka (ap-northeast-3). Global AWS services that hold no customer data (CloudFront with its certificate and WAF, IAM, Route 53, Budgets) are exempt. File downloads are never cached at CDN edges. | AWS Config, plus an SCP or IAM condition that denies other regions except those global services; review of S3 replication, backup and CDN cache settings. |
| NFR-22 | Web app quality | Recipient and uploader pages meet WCAG 2.2 AA. They support the latest two versions of Chrome, Edge, Firefox and Safari. | Automated accessibility checks (axe) in CI plus a manual pass; a browser test matrix. |

### 6.1 Design load

These are the targets the system is designed and load-tested for. The capacity estimate in phase 2 refines them.

| Measure | Target |
|---|---|
| Tenants | 500 |
| Members | 25,000 |
| Transfers and upload requests | 10,000 per day; the peak hour carries 3× the average hour |
| Files per transfer | 3 on average, 50 at most |
| File size | median 5 MB, p95 200 MB, maximum 5 GB |
| New data | about 1 TB per day |
| Stored data at steady state | about 15 TB in Tokyo (7-day transfers, 30-day retention of received files, and up to 7 days until deletion completes), replicated to Osaka |
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

The same build artifacts are promoted from dev to staging to prod (NFR-18). The React app is static files served
through a CDN, not another service, so the backend stays one API service plus workers with one system of record.

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
  Phase 2 confirms that SES is available in Osaka.
- One maintainer builds the service in thin vertical slices (phase 5), so Should items may move to a later release.
- Prod runs for a bounded operating period, so availability (NFR-1) is measured over that window, not over a calendar
  year.

## 11. Risks

| Risk | Impact | Mitigation |
|---|---|---|
| Some scan engines can't handle files near 5 GB, or are too slow for NFR-5. | Large files stay blocked or miss the time target. | Phase 4 ADR compares engines on 5 GB files before the design is fixed; keep the scan step behind an interface. |
| Data transfer and cross-region replication costs grow with the 1 TB/day design load. | Bills higher than planned during load tests and drills. | Sampled byte load (6.1), budget alarms (NFR-20), teardown after each test window. |
| Email deliverability: verification emails land in spam or are delayed. | Recipients can't verify, so files can't be downloaded. | SPF, DKIM and DMARC; SES reputation metrics on a dashboard; NFR-7 alerting. |
| A download URL works for anyone who holds it during its short lifetime. | A URL forwarded within 60 s works for someone who never verified; repeated use could slip past the download limit; a download started just before revocation may finish. | URLs live ≤ 60 s (NFR-6); every URL issue is checked against current state, counted and audited; phase 3 decides whether downloads must be single-use or bound to the client (open question 8). |
| File replication to Osaka lags during heavy uploads. | Files uploaded in the last ≤ 15 minutes before a regional failure are lost (NFR-10). | Replication with a time guarantee and an alarm on lag; files not yet replicated are marked unavailable after failover. |
| Email isn't ready in Osaka when Tokyo fails. | Recipients can't verify, so the service is down for them even though the API is up. | SES set up and approved in both regions (section 10); the failover drill sends real verification emails from Osaka. |
| Scope: a React app, multi-region DR and three environments for one maintainer. | Schedule slips. | Must/Should split; thin slices; the Osaka pilot light comes after the single-region slice works. |

## 12. Open questions

| # | Question | Owner | Decide in |
|---|---|---|---|
| 1 | Member sign-in for v1: a managed identity provider with mandatory MFA, tenant SSO, or both (FR-25, FR-26)? | Rashid | Phase 3 (security design) |
| 2 | Which malware scan engine handles 5 GB files within NFR-5? | Rashid | Phase 4 (ADR) |
| 3 | One KMS key per tenant, or shared keys with per-tenant encryption context? | Rashid | Phase 3 |
| 4 | One AWS account per environment (AWS Organizations), or one account for all three? | Rashid | Phase 4 (ADR) |
| 5 | Which domain name does the service use (web app, links, email sender)? | Rashid | Before phase 5 |
| 6 | Is Japanese localization (FR-33) in v1 or the first release after? | Rashid | Phase 5 (delivery plan) |
| 7 | Monthly AWS budget for the prod operating period, and how long that period is. | Rashid | Phase 6 (operations) |
| 8 | Must each download be single-use or bound to the verified client (for example by streaming through the service), or is a bearer URL that lives ≤ 60 s an acceptable risk? | Rashid | Phase 3 |

## 13. Glossary

| Term | Meaning |
|---|---|
| Transfer | One send: a set of files shared with one or more external recipients through expiring links. |
| Upload request | One request for an external person to deliver files to a member. |
| Tenant | One customer company and everything that belongs to it. |
| Verification | Proof that an external person controls the invited email address at the moment of access. |
| Held transfer | A transfer that can't be sent because a file failed the malware scan. |
| Pilot light | A disaster recovery setup where data is replicated to a second region continuously, but compute there starts only during a failover. |
| RPO / RTO | Recovery point objective (how much recent data can be lost) and recovery time objective (how long until service is back). |
| SLI / SLO | Service level indicator (what is measured) and service level objective (the target for it). |
