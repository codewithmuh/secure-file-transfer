# 0012. Use S3 with versioning and replication to Osaka for files and the audit archive

- Status: accepted
- Date: 2026-11-03
- Issue: [#32](https://github.com/codewithmuh/secure-file-transfer/issues/32)

## Context

Browsers upload file contents straight to object storage in multipart uploads with pre-signed part URLs, and the API
completes and checks each upload ([architecture](../architecture.md), section 4.1). Files are up to 5 GB, about 1 TB
arrives a day, and about 15 TB is stored per region at steady state ([capacity](../design/capacity-and-cost.md) 3.4).
The [PRD](../prd.md) sets what storage must do:

- **NFR-10.** Losing an AZ loses no acknowledged upload; losing Tokyo loses at most the last 15 minutes of uploads for
  99.99 % of files, and files that hadn't reached Osaka are shown as unavailable.
- **NFR-8.** A file is gone from every copy, Osaka included, within 7 days of its deletion trigger.
- **NFR-15.** In prod, archived audit records can't be changed or deleted for 365 days, and no failover removes them.
- **NFR-13 and NFR-21.** KMS encryption at rest; storage only in Tokyo and Osaka.

The scan result pins the object version it scanned, and downloads serve that version
([threat model](../threat-model.md), T-32). The [encryption design](../security/encryption-and-keys.md) (sections
3.1, 4 and 8) fixes the keys, and puts the prod audit archive and its key in a retained stack that outlives teardown.

## Decision

Use **S3 Standard in Tokyo and Osaka** for file contents and the audit archive.

- **Files.** One bucket per region with versioning on. A replication rule copies every object from Tokyo to Osaka with
  **S3 Replication Time Control** and re-encrypts it with the Osaka replica of the files key. The replication role
  has `s3:GetObjectVersionTagging` and `s3:ReplicateTags`, so object tags reach Osaka, the `scan` tag included.
  Default encryption is SSE-KMS with **S3 Bucket Keys**; the bucket policy refuses other keys, SSE-C and requests
  without TLS. Public access is blocked and ACLs are disabled. No Object Lock and no AWS Backup plan, so nothing keeps
  a copy deletion can't reach.
- **Large files.** Files over 2 GB go to a **second files bucket pair** (Tokyo and Osaka) with the same settings, keys
  and key layout, chosen at upload start from the declared size. GuardDuty Malware Protection covers that whole bucket,
  because ClamAV can't scan files over 2 GB ([ADR-0019](0019-malware-scanning-clamav-guardduty.md)). Everything below
  about "the files buckets" applies to both pairs.
- **Audit archive.** One bucket per region with versioning and **Object Lock**: compliance mode with 365-day retention
  in prod, governance mode with 1 day in dev and staging. Batches replicate from Tokyo to Osaka, without RTC. The API
  also writes security-critical records straight to both regions before it answers, or answers `503` (architecture
  5.2). These are revocations of transfers, upload requests and API keys, user deactivations and demotions, lockouts
  and unlocks, sign-in resets and download grants, and they never depend on this rule.
- **Only lifecycle jobs and lifecycle rules delete.** Only the lifecycle jobs' role has `s3:DeleteObjectVersion` on the
  files buckets; the API may only abort unfinished multipart uploads. The deletion job deletes **every version by
  version ID in Tokyo and again in Osaka**, because S3 replication doesn't copy deletes of specific versions. Delete
  marker replication stays off, since nothing creates delete markers on purpose.
- **Lifecycle rules as safety nets** on every files bucket, in each region, because lifecycle rules don't replicate:
  expire noncurrent versions after 7 days, abort multipart uploads still unfinished after 7 days, and remove expired
  delete markers.
- **Archive lifecycle.** Each archive bucket, Tokyo and Osaka, has its own rule (NFR-9):
  - Current versions expire at 365 days, when their Object Lock retention ends. In a versioned bucket that only adds a
    delete marker and leaves the version itself in place.
  - `NoncurrentVersionExpiration` with `NoncurrentDays` = 1 deletes the version. The 1 day is counted from the moment
    the version becomes noncurrent, which is day 365, so records go about day 366. A 365-day setting would keep them
    two years.
  - Expired delete markers are removed.
- **Object keys** start with `tenants/{tenant_id}/` and use file IDs, never file names (architecture 5.1).

## Options considered

| Option | Pros | Cons |
|---|---|---|
| **S3, versioning, replication with RTC** (chosen) | Data stored across at least three AZs, so an AZ loss loses nothing. RTC replicates 99.99 % of objects within 15 minutes, the exact NFR-10 bound, and adds replication metrics and missed-threshold events to alarm on. Direct multipart upload from the browser. Versioning lets a scan pin the bytes it checked. Object Lock in compliance mode makes the archive immutable even to the root user. | Replication is the largest cost at design load, $3,214 a month, about $456 of it the RTC fee (capacity 5.1). Deletion runs twice, once per region, and a replica that lands after the job ran becomes an orphan for reconciliation. With Bucket Keys, KMS can't tell one tenant's objects from another's (encryption and keys, decision 4). A compliance-mode mistake in the prod archive can't be undone for 365 days. |
| **S3 replication without RTC** | About $456 a month cheaper at design load; otherwise the same design. | No time commitment: most objects replicate quickly, but none is bounded, so NFR-10's 15 minutes would be a hope rather than a commitment, and the drill report couldn't cite one. |
| **S3 in Tokyo, with AWS Backup copies to Osaka** | No continuous replication charge; point-in-time copies. | The RPO for uploads becomes the backup interval, hours rather than minutes. Restoring about 15 TB in Osaka doesn't fit a 1-hour RTO. Backup vaults hold file contents, which every deletion would also have to reach within 7 days (NFR-8). |
| **Application writes to both regions** | No replication lag once an upload completes. | The browser uploads to one region. A second upload would double the client's work and break NFR-3's 8 minutes for 5 GB; a server-side copy job is replication rebuilt by us, with half-written pairs to repair. |

## Consequences

- **Rejected uploads.** Rejecting a file sets `delete_after` to now. The deletion job then removes its object in both
  regions, and aborts the multipart upload if it still exists. The API role keeps no delete permission
  ([threat model](../threat-model.md), T-51).
- **Reconciliation.** The daily job lists objects and versions in both regions, compares them with `files`, reports
  leftovers and deletes orphans older than 24 hours, so a late replica is gone within 2 days (encryption and keys 8.1).
  Its report is the evidence for NFR-8.
- **Alarms.** Replication latency, missed-threshold and failed-replication events page, with a runbook. After a regional
  failover, files whose replica never arrived are shown as unavailable (NFR-10).
- **Cost.** Replication and download egress are about $6,200 a month at design load; load tests move file bytes at a
  sampled rate (capacity 7.2). S3 Standard in both regions: Standard-IA would cost more, because it bills at least 30
  days per object and most objects live about 10 days (capacity 3.4). Bucket Keys keep KMS requests near 3 M a month.
- **Archive.** Object Lock has to be on in both archive buckets for replication of locked objects, and replicas keep
  their retention. In prod the buckets, their replication rule and role sit in the retained stack, so an environment
  teardown can't reach them (encryption and keys 8.4).
- **Disaster-recovery gaps**, open in [#42](https://github.com/codewithmuh/secure-file-transfer/issues/42), not
  settled here:
  - **Archive cursor.** Archive replication has no time bound, but the archive cursor travels with the database, so
    after a failover the cursor can be past batches that never reached Osaka. The fix is RTC on the archive, or
    rewinding the cursor to the newest batch in Osaka.
  - **Failback.** Replication runs one way, Tokyo to Osaka. After a failover nothing copies Osaka's new objects back,
    so failing back needs reverse replication.
  - **Osaka-only outage.** Security-critical records must reach both archives before the API answers. While Osaka's
    archive can't be written, new download grants and the other security-critical changes answer `503`. The degraded
    mode for that case, and its effect on NFR-1, are not designed yet.

## When to revisit

If replication-lag alarms fire regularly at design load, if replication cost doesn't fit the operating budget (open
question 7), if per-tenant KMS keys arrive (open question 3) and need replication rules per key, or if S3 starts to
replicate deletes of specific versions, which would remove the second deletion pass.
