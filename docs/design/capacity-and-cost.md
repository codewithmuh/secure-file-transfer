# Capacity estimate and cost model

| | |
|---|---|
| Requirements | [PRD](../prd.md), especially section 6.1 (design load), FR-2, NFR-1, NFR-2, NFR-5, NFR-10, NFR-11, NFR-16, NFR-19, NFR-20 |
| Architecture | [architecture.md](../architecture.md) |
| Security design | Phase 3 drafts: encryption and keys ([#22](https://github.com/codewithmuh/secure-file-transfer/issues/22)), authentication and authorization ([#23](https://github.com/codewithmuh/secure-file-transfer/issues/23)), abuse and rate limits ([#24](https://github.com/codewithmuh/secure-file-transfer/issues/24)) |
| Tracking | [#15](https://github.com/codewithmuh/secure-file-transfer/issues/15), part of phase 2 ([#16](https://github.com/codewithmuh/secure-file-transfer/issues/16)) |

This page turns the PRD design load into workload numbers, sizes each component for prod, and prices dev, staging
and prod with AWS on-demand prices for Tokyo (ap-northeast-1) and Osaka (ap-northeast-3). Every number is an
estimate. Each one traces to the PRD, the [data model](data-model.md) (section 8) or a named assumption in section 2.
The first load test (section 8) replaces the assumptions with measurements.

Technologies are the architecture's current candidates (architecture section 9). If a phase 4 ADR picks something
else, this page is updated in the same pull request. Lines and assumptions marked #22, #23 or #24 follow the phase 3
security drafts for those issues; if a draft changes before it merges, so does this page.

## 1. Summary

| Environment | Running | Per month | Per day |
|---|---|---:|---:|
| prod, (a) idle or demo traffic | 24×7 | $3,036 | $100 |
| prod, (b) full design load, steady state | 24×7 | $12,065 | $397 |
| staging | 24×7 | $2,250 | $74 |
| staging | Expected: 162 billed hours a month (A22) | $501 | — |
| dev | 24×7 | $817 | $27 |
| dev | Expected: 260 billed hours a month (A22) | $292 | — |
| Shared container registry (section 5.4) | Every phase until the final teardown | $4 | — |

- Prod includes the Osaka pilot light: $747 a month at idle, $4,406 at design load.
- Scenario (a) is the realistic case for a reference service: fixed infrastructure, the synthetic probe and a few demo
  users. Scenario (b) is a month at the full design load after 12 months of growth, with every byte moved for real.
- At design load the three biggest costs are S3 replication to Osaka ($3,214), internet egress for downloads
  ($2,962) and EKS worker nodes ($1,354). At idle they are worker nodes ($1,100), the three Aurora instances ($728),
  and NAT gateways, interface endpoints and public IPv4 addresses in two regions ($686).
- The phase 3 drafts add, at design load, Cognito on the Plus plan ($501, #23), streamed downloads on the load
  balancer ($243, #24), and smaller lines for WAF, KMS, CloudTrail data events and SES tenants. The scan workers' own
  node pool (#22) is inside the worker-node cost.
- ClamAV can't scan files over 2 GB, so the totals cost a hybrid: ClamAV up to 2 GB, GuardDuty above. GuardDuty for
  every file would cost $443 a month less at idle and $2,904 more at design load (section 5.5). The scan ADR decides.
- Recommended budget for the operating period (open question 7): **$6,000 a month**, with alarms at $3,000, $4,800
  and $6,000. The planned month, load tests included, is $4,081: 68 % of the budget (section 7.3).

## 2. Assumptions

| ID | Assumption | Why |
|---|---|---|
| A1 | A month is 730 hours or 30.4 days. 1 TB is 1,000 GB. Prices are on-demand, in USD, without tax, and ignore free tiers. | Keeps the arithmetic simple and slightly conservative |
| A2 | The 10,000 daily items are 8,000 transfers and 2,000 upload requests. | Matches the PRD's 80/20 split of new data |
| A3 | About 2 recipients per transfer. | Data model section 8 |
| A4 | The mean file is 33 MB (1 TB ÷ 30,000 files). Downloads move about 1 TB a day, a mean of 25 MB per download. | PRD 6.1, including its load-test note |
| A5 | The peak hour carries 3× the average. File bytes burst to 6× the average for a few minutes. | PRD 6.1 for the peak hour; the burst is ours |
| A6 | Each recipient or uploader needs 1.25 verification codes on average (resends, a second visit after the 24-hour session). | NFR-14 session length |
| A7 | Half of all transfers ask for a first-download notice (FR-8). Each upload request sends one files-arrived notice. Held, blocked and lockout notices are about 1 %. | Estimate |
| A8 | An API request uses 10 ms of CPU on Graviton4 on average. API pods run at ≤ 50 % CPU at the burst rate. Streaming file bytes through the API, the download mechanism #24 chose, costs about 1 vCPU per 100 MB/s. | Estimate for FastAPI + SQLAlchemy; to measure |
| A9 | ClamAV scans 20 MB/s per vCPU and can't scan files over 2 GB (section 3.3). Each file also costs 1 s to receive the message and record the result, plus the copy to scratch disk (A39). clamd requests 4 GiB: about 1.2 GiB holds the signatures, and twice that for a short time while a reload loads new ones. Files over 100 MB are about 8 % of files and 70 % of bytes. | Throughput and size mix are estimates (open question 2); memory from ClamAV's container guidance: 3 GiB minimum, 4 GiB preferred |
| A10 | Multipart part size is 16 MB; files ≤ 16 MB upload in one part. That is about 80,000 parts a day. | Estimate |
| A11 | Transfer files are kept 7 days (the FR-3 default), upload-request files 30 days (the FR-13 default), plus 3.5 days on average until deletion completes (half the NFR-8 limit). | Reproduces the PRD's 15 TB |
| A12 | Objects are never overwritten (keys are file IDs) and deletion removes every version (architecture 4.5), so noncurrent versions stay near zero. | Architecture 4.5 |
| A13 | Aurora at design load does 3 M write I/Os and 7 M read I/Os a day. At most 4 KB crosses to Osaka per replicated write I/O. | Estimate from about 1 M write transactions a day; to measure |
| A14 | The audit archive stores 0.2 KB per audit row after compression, plus about 40,000 security-critical records a day as separate objects in each region (download grants dominate). That is about 0.1 GB a day per region. | Architecture 5.2 |
| A15 | The web app serves 30,000 sessions a day, each 0.5 MB and 20 requests through CloudFront. | Estimate (25,000 members, about 18,000 external people a day) |
| A16 | Prod's main node pool runs 4 nodes at idle, 6 in the peak hour and 9 at 2× design load; its scan node pool 5, 10 and about 20. At design load each pool averages a third of the way from idle to peak: 4.67 and 6.67 nodes. | Section 4.2; the peak hour carries 3× the average hour |
| A17 | NAT traffic is 1 GB a day at idle and 2 GB a day at design load: SES API calls, writes to Osaka, Git and signature updates. S3 and image layers use endpoints. | Architecture 3.1 |
| A18 | Cross-AZ traffic is 3 GB a day at idle and 40 GB a day at design load (database, metrics, logs). | Estimate |
| A19 | EKS control-plane logs go to CloudWatch Logs: prod 1 GB a day at idle and 2 GB at design load, staging 0.5, dev 0.3. VPC flow logs go to S3: prod 0.5 and 5 GB a day, staging 0.2, dev 0.1. WAF logs keep only blocked, challenged and counted requests (#24 3.4); with Cognito's user activity logs that is about 1 GB a month at idle and 4 GB at design load. | Estimate |
| A20 | GuardDuty threat detection (with S3 Protection, $1.04 per million data events: about $16 a month at design load) and AWS Config bill by usage. Their lines are estimates, not price lookups. | — |
| A21 | S3 Bucket Keys are on, so S3's KMS requests stay near 3 M a month at design load. | Estimate |
| A22 | dev runs 200 hours a month (10 hours on 20 working days) and staging 144 (six 24-hour windows for release rehearsals and drills). Each window also bills for its rebuild (≤ 2 hours) and teardown (≤ 1 hour), counted at the full hourly rate: dev 260 billed hours, staging 162. The Terraform state key (#22) bills all month: $1 in dev, $2 in staging. | NFR-19 and NFR-20; conservative, since resources come and go during those hours |
| A23 | Idle prod traffic is the synthetic probe every 5 minutes (NFR-1) plus a few demo users: about 10 GB of file bytes and 20,000 emails a month. | NFR-1 |
| A24 | Rate limiting costs 2 counter operations per API request. | NFR-14 |
| A25 | SQS costs 3 requests per message (send, receive, delete), plus 20-second long polling by about 8 consumers. | Architecture 5.3 |
| A26 | Platform requests: prod's cluster-level components 6.4 vCPU and 17.5 GiB; the cut-down set in dev and staging 2.6 vCPU and 7 GiB; per-node agents 0.3 vCPU and 0.4 GiB on every node. Breakdown in section 4.3. | Our starting requests, from the components' chart defaults where they give one; to measure |
| A27 | Allocatable per node: m8g.xlarge about 3.9 vCPU and 14 GiB, m8g.large about 1.9 vCPU and 6.5 GiB. Requests fill at most 80 % of allocatable CPU. | EKS node reservations; the 20 % leaves room for rollouts (`maxSurge: 25%`, #24 5.7) and node churn |
| A28 | EBS gp3: a 100 GB root volume per main-pool node and 50 GB per scan node (image, signatures, one file of up to 2 GB). Observability volumes: 300 GB in prod (Prometheus 2 × 100 GB for 15 days, Loki and Tempo write-ahead logs 4 × 25 GB), 100 GB in staging, 50 GB in dev. | Sized for 2× the expected series and log rate; to measure |
| A29 | WAF per #24 3.1 and 3.2: in each region an API web ACL with 12 rules and a sign-in web ACL with 3; the CloudFront web ACL for the web app with 4. Requests: every API request, every CloudFront request and about 10 per sign-in (A36): 1 M a month at idle, 155 M at design load; under 1 M challenges. | #24 |
| A30 | KMS: 8 customer managed keys per environment (#22 4.1), each with an Osaka replica in staging and prod, billed as a key each. Requests: A21's 3 M a month plus up to 6 M for unwrapping field data keys at design load (#22 3.2); about 0.35 M at idle. A key costs $1 a month until its first yearly rotation, which comes after an operating period of under a year. | #22 |
| A31 | 10 secrets per environment and region: the 4 application secrets of #22 6.1 and up to 6 for platform components. Pods that read secrets call Secrets Manager every 5 minutes, External Secrets every hour: about 0.05 M calls a month in prod at idle, 0.07 M at design load. | #22 |
| A32 | Route 53: one hosted zone per environment, 2 health checks with HTTPS and string matching in prod and staging. Queries: 1 M a month at idle, 10 M at design load (A15's 30,000 sessions a day × about 10 lookups, with 60-second TTLs on the failover records). | Estimate |
| A33 | Log and trace storage in S3: 90 days of VPC flow logs (A19), plus about 0.5 GB a day at design load (0.05 GB at idle) of load balancer, WAF, CloudFront, Cognito and CloudTrail logs, Loki chunks (90 days) and Tempo traces (14 days, 10 % sampled). That is about 50 GB at idle and 500 GB at design load, with 0.5 M and 3 M PUTs a month. CloudWatch Logs keeps control-plane logs 90 days, stored at about 15 % of their ingested size. | PRD data lifecycle (logs kept 90 days); the compression ratio is an estimate |
| A34 | CloudWatch alarms on AWS-service metrics: prod 60 (about 4 on each of 15 resources), staging 40, dev 10. Custom metrics (synthetic probe, job heartbeats): prod 30, staging 10, dev 5. Application alerts run in Alertmanager at no AWS charge. | Estimate |
| A35 | Idle Aurora: 10 GB stored and about 1 M I/Os a day, a third of them writes (the probe's 288 transfers a day, lifecycle jobs, vacuum). | Estimate |
| A36 | Cognito (#23): the Plus plan at $0.02 per monthly active user; all 25,000 members active at design load and priced as local members (federated members cost $0.015, so this is the top of #23's range); about 50 at idle. 20,000 sign-ins a day at design load, each about 10 requests through the sign-in web ACL and two trigger invocations (pre- and post-authentication, #24 2.3) of about 100 ms at 256 MB on Arm. The Osaka standby pool has no users until a failover. | #23, #24; sign-ins estimated from 12-hour sessions on working days |
| A37 | CloudTrail S3 data events on the files and audit buckets (#22): one event per S3 request in Tokyo (section 3.1), 15.7 M a month at design load and 0.3 M at idle, plus 1.2 M a month for the API's direct writes to the Osaka archive. | #22 |
| A38 | Files over 2 GB are about 0.1 % of files (30 a day) and 10 % of bytes (100 GB a day, a mean of about 3.3 GB). | Between a Pareto fit of A9's large-file tail (about 6 % of bytes) and a log-normal fit of the PRD's median and p95 (about 17 %); to measure |
| A39 | A scan worker copies a file from S3 to its scratch disk at about 125 MB/s, the gp3 volume's baseline throughput: 16 s for 2 GB, 40 s for 5 GB. | gp3 baseline; to measure |
| A40 | The registry holds 20 GB per region: the application image (one image for the API and workers, architecture 2) at about 0.4 GB × 30 kept versions, plus about 8 GB of platform images through pull-through cache. About 5 GB of new layers a month replicate to Osaka. | Estimate |
| A41 | App pods: dev runs 1 API pod, 1 outbox relay, 1 notification worker and 1 scan pod for both queues; staging 3 API pods (one per AZ, for AZ drills), 1 relay, 1 notification worker and 2 scan pods (one per queue). Requests per pod as in prod. | Smallest shapes that still exercise every path |
| A42 | In the operating period, at most two load-test windows and one prod drill a month. A window runs 12 hours in prod: 8 at 1× and 4 at 2× the peak-hour rate (NFR-16), with file bytes at a 10 % sample except one 4-hour full-byte window; 2 × m8g.2xlarge load generators; 1,000 test members. A drill runs Osaka's idle compute shape for 8 hours. | Input to the phase 6 test plan (PRD 6.1) |
| A43 | SES tenant management (#24 7.3): one SES tenant per tenant, in Tokyo and in Osaka. | #24 |
| A44 | An Aurora Serverless v2 secondary in Osaka would run at about 1 ACU idle and 1.5 ACU on average at design load. | It only applies the writer's changes to its cache, and AWS notes that a global database can keep instances above their minimum; to measure (section 4.5) |

## 3. Workload at the design load

### 3.1 Requests and bytes

| Measure | Average | Peak hour | Burst | From |
|---|---|---|---|---|
| API requests | 50/s, 4.3 M a day | 150/s | 300/s | PRD 6.1 |
| Transfers + upload requests | 10,000 a day (8,000 + 2,000) | 1,250/h | — | PRD 6.1, A2 |
| Files uploaded (new S3 objects) | 30,000 a day | 3,750/h, about 1/s | — | 10,000 × 3 files |
| Upload throughput | 1 TB a day: 11.6 MB/s (93 Mbit/s) | 35 MB/s (280 Mbit/s) | about 70 MB/s | PRD 6.1, A5 |
| Multipart parts | about 80,000 a day | about 10,000/h | — | A10 |
| Downloads | 40,000 a day | 5,000/h | — | PRD 6.1 |
| Download throughput, streamed through the API (#24) | 1 TB a day: 11.6 MB/s | 35 MB/s | about 70 MB/s | A4, A5 |
| Scan volume | 30,000 files, 1 TB a day | about 1 file/s, 35 MB/s | — | Every file is scanned (FR-16) |
| Emails | about 46,600 a day, 1.42 M a month | about 5,800/h (1.6/s) | about 5/s | Section 3.2 |
| Queue messages | about 100,000 a day; about 10 M SQS requests a month | — | — | Data model section 8, A25 |
| Audit rows | about 300,000 a day | — | — | Data model section 8 |
| S3 requests in Tokyo | about 216,000 PUT-class and 300,000 GET-class a day | — | — | 30,000 each of create, complete and tag; 80,000 parts; 40,000 download-grant records; reads for scans, checks and downloads |
| Rate-limit operations | about 100/s | 300/s | 600/s | A24 |
| Member sign-ins | 20,000 a day | — | — | A36 |

File bytes never pass through the API on upload: the browser sends parts straight to S3 (architecture 4.1). Data
coming into AWS is free. Downloads stream through the API (#24 5.2), so their bytes pass the load balancer and the
API pods.

### 3.2 Emails

| Email | Per day | How |
|---|---:|---|
| Transfer link | 16,000 | 8,000 transfers × 2 recipients (A2, A3) |
| Upload-request invitation | 2,000 | A2 |
| Verification code | 22,500 | 18,000 recipients and uploaders × 1.25 (A6) |
| First-download notice (FR-8) | 4,000 | Half of the transfers (A7) |
| Files-arrived notice (FR-12) | 2,000 | One per upload request (A7) |
| Held, blocked and lockout notices | 100 | About 1 % (A7) |
| **Total** | **46,600** | 1.42 M a month |

SES quotas are per region and per account. A new production account often starts at 50,000 emails a day, which is
too close to this load: request at least 100,000 a day and 20 a second in both Tokyo and Osaka before the load test.

### 3.3 Scanning

NFR-5 asks for p95 ≤ 2 minutes to shareable when the largest file is ≤ 100 MB, and ≤ 15 minutes for any transfer
up to 20 GB.

**ClamAV can't scan the largest files FR-2 allows.** The `MaxFileSize` entry of the `clamd.conf.sample` that ships
with ClamAV says: "Technical design limitations prevent ClamAV from scanning files greater than 2 GB at this time."
A file between 2 and 5 GB would end `unscannable`, because a limit is never a pass (#24 6.4), and stay blocked by
default (FR-18). ClamAV alone therefore can't deliver a clean 5 GB file. GuardDuty Malware Protection for S3 scans
objects up to 100 GB, a quota AWS doesn't adjust (section 6). The scan ADR (open question 2) chooses between three
options; section 5.5 compares their cost:

| Option | Files up to 2 GB | Files over 2 GB | What changes |
|---|---|---|---|
| (a) GuardDuty for every file | GuardDuty | GuardDuty | No scan engine of ours; the scan worker only records GuardDuty's results |
| (b) Hybrid | ClamAV in the scan workers | GuardDuty, on a key prefix only those files use | Two engines and two result paths |
| (c) Lower FR-2's file limit to 2 GB | ClamAV | Not accepted | A PRD change, which this page doesn't make |

The totals in section 5 cost **(b)**: it keeps FR-2 and is the cheaper of the two options that do at design load.
That is a costing baseline, not a decision.

Each ClamAV scan keeps a worker busy for 1 s, plus the copy to scratch disk at 125 MB/s (A39), plus the scan at
20 MB/s per vCPU (A9): about 1 s + 0.058 s per MB. A 2 GB file takes about 2 minutes, a 100 MB file about 7 s. For
(b) the sizing uses **two queues and two worker pools**, split at 100 MB, so large files don't delay small ones.
Files over 2 GB never reach them.

| Pool | Share of files | Bytes in the peak hour | Busy workers in the peak hour | Pods, min / peak |
|---|---|---|---|---|
| Small files, ≤ 100 MB, ClamAV | about 92 % | about 10.5 MB/s | about 1.6 (0.96 files/s × 1 s + 10.5 MB/s × 0.058 s/MB) | 3 / 4 |
| Large files, 100 MB to 2 GB, ClamAV | about 7.9 % | about 21 MB/s | about 1.3 (0.08 files/s × 1 s + 21 MB/s × 0.058 s/MB) | 2 / 6 |
| Over 2 GB, GuardDuty (A38) | about 0.1 % | about 3.5 MB/s | none of ours | — |

- **Peak pods.** The small pool's 4 pods run at about 40 % in the peak hour, enough for the minutes-long bursts at
  twice that rate (A5). The large pool's 6 cover its burst (about 2.6 busy workers) with room for three tenants'
  large transfers at once, each tenant limited to 2 large-file scans (#24 6.4). Both pools scale on queue age.
- **A 20 GB transfer.** Under (b), four 5 GB files go to GuardDuty, which scans outside our pods. Ten 2 GB files run
  2 at a time (the tenant cap) in about 10 minutes, leaving 5 of NFR-5's 15 for queueing. GuardDuty publishes no
  time-to-result target, so the scan ADR must measure it for 5 GB objects and, for option (a), for small files
  against the 2-minute target.
- **clamd memory during signature updates.** With `ConcurrentDatabaseReload` on (the default), clamd loads a second
  engine while the first keeps scanning, so for a short time it holds two copies of the signatures. ClamAV's Docker
  documentation puts that at about 2.4 GiB, against 1.2 GiB normally. This page sizes for it rather than turning the
  option off: clamd requests 4 GiB, ClamAV's preferred container size, so scans never block during an update. One
  scan pod per m8g.large node (section 4.2) leaves that memory free anyway, so it costs no extra node. The private
  signature mirror tests each new database once, and the updater in each pod runs with `TestDatabases no`, so
  freshclam doesn't load a third copy.
- At 2× design load (NFR-16) the pools need about 8 small-file and 12 large-file pods at peak (section 4.2).

### 3.4 Storage over time

From day 1 at design load. S3 follows A11; Aurora grows roughly linearly because transfer metadata and audit rows are
kept 365 days, and reaches the data model's 100–150 GB (this page costs the upper end). The audit archive follows A14.

| Day | S3 files, Tokyo | S3 replica, Osaka | Noncurrent versions | Aurora, per region | Audit archive, per region |
|---|---|---|---|---|---|
| 7 | 7 TB | 7 TB | about 0 | 3 GB | 0.7 GB |
| 14 | 11 TB | 11 TB | about 0 | 6 GB | 1.4 GB |
| 30 | 14 TB | 14 TB | about 0 | 12 GB | 3 GB |
| 34 onward | 15 TB, steady state | 15 TB | about 0 | 14 GB | 3.4 GB |
| 90 | 15 TB | 15 TB | about 0 | 37 GB | 9 GB |
| 180 | 15 TB | 15 TB | about 0 | 74 GB | 18 GB |
| 365 onward | 15 TB | 15 TB | about 0 | 150 GB, steady state | 37 GB, steady state |

- **Noncurrent versions** stay near zero (A12). If deletes ever left versions behind, the 7-day lifecycle rule bounds
  the extra at about 7 TB per region (7 days of deletions).
- **Unfinished multipart uploads** are aborted after 24 hours by the lifecycle job; they add a few tens of GB at most.
- **Aurora backups:** continuous backup for the 14-day restore window (NFR-11) is free up to the cluster's size;
  about 50 GB beyond that is billed at steady state.
- **Storage class:** S3 Standard in both regions. Standard-IA in Osaka would cost more, because it bills at least 30
  days per object and most objects live about 10 days.

## 4. Sizing for prod

### 4.1 Per component

| Component | Size | Basis |
|---|---|---|
| API service | Pods request 1 vCPU and 1 GiB (limit 1.5 GiB), one Uvicorn worker each. 3 pods minimum (one per AZ), 8 at the 300/s burst, autoscaled up to 15 for 2× design load. Pods also scale on active download streams (#24 5.7). | A8: 1 vCPU at 50 % serves 50 requests/s; streaming adds 0.35 vCPU in the peak hour and 0.7 at the burst |
| Scan workers | Each pod: the worker (0.2 vCPU, 0.25 GiB) and clamd (1 vCPU, 4 GiB). Small pool 3–4 pods, large pool 2–6, scaled by queue age, in their own node pool, one pod per node (#22). Up to 2 GB of scratch disk per pod; files over 2 GB go to GuardDuty. | Section 3.3, A9 |
| Outbox relay | 2 pods, 0.25 vCPU and 0.25 GiB each | Architecture 2 |
| Notification worker | 2 pods, 0.25 vCPU and 0.5 GiB each; peaks at about 5 emails/s | Section 3.2 |
| Lifecycle jobs | Scheduled jobs, 0.5 vCPU and 1 GiB while they run | Architecture 4.5 |
| Platform | Argo CD, Prometheus (2 replicas), Alertmanager, Grafana, Loki, Tempo, OpenTelemetry collectors, Karpenter, AWS Load Balancer Controller, External Secrets, KEDA, CoreDNS: 6.4 vCPU and 17.5 GiB of requests, plus 0.3 vCPU and 0.4 GiB of agents on every node. dev and staging run a cut-down set. | A26, section 4.3 |
| EKS worker nodes | Two Karpenter node pools over 3 AZs. **Main pool, m8g.xlarge** (Graviton4, 4 vCPU, 16 GiB): 4 at idle, 6 in the peak hour, 9 at 2× design load. **Scan pool, m8g.large** (2 vCPU, 8 GiB), one scan pod per node, volumes under the files key (#22): 5 at idle, 10 in the peak hour, about 20 at 2×. | Section 4.2, A27 |
| Aurora PostgreSQL | **db.r8g.large** (2 vCPU, 16 GiB) writer and reader in different Tokyo AZs, plus one db.r8g.large in the Osaka secondary. Standard storage, 150 GB per region at steady state. Move up to db.r8g.xlarge if writer CPU stays above 60 % in the peak hour or the buffer cache hit ratio drops below 99 %. | Sections 4.4 and 4.5 |
| Rate-limit counters | ElastiCache Serverless for Valkey, one cache per environment and region (#24), at its 100 MB minimum; about 600 operations/s at burst. It also holds stream and scan leases and sign-in state (#23, #24). | A24 |
| SQS | Standard queues with dead-letter queues; the scan queues are fair queues keyed by tenant (#24 6.4). About 100,000 messages a day, each under 1 KB. Large-file scans extend their visibility timeout while they run. | Architecture 5.3 |
| Cognito | One user pool per environment in Tokyo on the Plus plan, and a standby pool in Osaka for staging and prod; pre- and post-authentication triggers on Lambda (#23, #24) | A36 |
| NAT gateways | 3 per region (one per AZ); about 2 GB a day of traffic | A17 |
| Load balancer | One Application Load Balancer per region; about 2 LCU of API traffic plus 41.7 LCU of streamed downloads at design load (#24) | Section 5.6 |
| CloudFront | One distribution, for the web app bundle only | Architecture 4.2 |
| GuardDuty Malware Protection for S3 | Under option (b), one protection plan on the files bucket, scoped to the prefix that files over 2 GB use | Section 5.5 |

Even at 2× design load the API needs about 200 database connections (15 pods × 10, plus workers), far below what a
db.r8g.large allows. Streaming downloads (#24) adds about 35 MB/s in the peak hour and about 15 concurrent streams,
well within the pods' and nodes' network capacity.

### 4.2 Node packing

**Main pool, m8g.xlarge** (A27: 3.9 vCPU and 14 GiB allocatable, filled to at most 80 % of CPU):

| Workload | Pods, idle / peak / 2× | Requests per pod | Idle | Peak hour | 2× design load |
|---|---|---|---|---|---|
| API | 3 / 8 / 15 | 1 vCPU, 1 GiB | 3 vCPU, 3 GiB | 8 vCPU, 8 GiB | 15 vCPU, 15 GiB |
| Outbox relay and notification worker | 4 / 4 / 4 | 0.25 vCPU, 0.25–0.5 GiB | 1 vCPU, 1.5 GiB | 1 vCPU, 1.5 GiB | 1 vCPU, 1.5 GiB |
| Lifecycle jobs | while running | 0.5 vCPU, 1 GiB | 0.5 vCPU, 1 GiB | 0.5 vCPU, 1 GiB | 0.5 vCPU, 1 GiB |
| Platform, cluster-level (A26) | — | — | 6.4 vCPU, 17.5 GiB | 6.4 vCPU, 17.5 GiB | 6.4 vCPU, 17.5 GiB |
| Per-node agents, 0.3 vCPU and 0.4 GiB a node | — | — | 1.2 vCPU, 1.6 GiB | 1.8 vCPU, 2.4 GiB | 2.7 vCPU, 3.6 GiB |
| **Total** | | | **12.1 vCPU, 24.6 GiB** | **17.7 vCPU, 30.4 GiB** | **25.6 vCPU, 38.6 GiB** |
| **m8g.xlarge nodes** | | | **4** (78 % of CPU) | **6** (76 %) | **9** (73 %) |

**Scan pool, m8g.large**, one scan pod per node: the pod's 1.2 vCPU and 4.25 GiB plus 0.3 vCPU and 0.4 GiB of
agents fill 79 % of a node's 1.9 allocatable vCPU and 72 % of its 6.5 GiB.

| Pool | Idle | Peak hour | 2× design load |
|---|---:|---:|---:|
| Small-file scan pods | 3 | 4 | 8 |
| Large-file scan pods | 2 | 6 | 12 |
| **m8g.large nodes** | **5** | **10** | **20** |

CPU requests decide the node count in both pools; eight main-pool nodes at 2× would be 81 %, so it takes nine. The
main pool's memory stays under half used, but a compute-optimised type (c8g.xlarge, 8 GiB) would fill it to about
90 % at idle, so m8g.xlarge stays. The scan pool uses the smaller m8g.large because one pod per node keeps hostile
files on their own nodes (#22) and leaves room for clamd's reload, and two m8g.large cost the same as one
m8g.xlarge.

If an AZ fails at idle, the main pool can lose 2 of its 4 nodes: the API pods keep a higher priority, and Karpenter
adds nodes in the other two AZs within minutes, inside NFR-11's 5-minute target. The scan pool loses one or two
nodes; files wait in the queues meanwhile and are never downloadable before their scan (FR-16).

### 4.3 Platform per environment

dev and staging run every platform component, so the same manifests are tested before prod, but without the
high-availability replicas, with Loki and Tempo in single-binary mode, and with shorter retention. Nothing is shared
between environments: each cluster keeps its own Argo CD and observability, so each environment tears down alone and
stays inside its own account if open question 4 chooses one per environment.

| Component | prod: vCPU, GiB | dev and staging: vCPU, GiB |
|---|---|---|
| Argo CD | Controller, 2 repo servers, 2 API servers, Redis, ApplicationSet: 1.0, 2.5 | One of each: 0.5, 1.0 |
| Prometheus | 2 replicas, 15 days: 2.0, 7.0 | 1 replica, 3 days (dev) or 7 days (staging): 0.5, 2.0 |
| Alertmanager and Grafana | 2 + 1: 0.4, 1.0 | 1 + 1: 0.2, 0.5 |
| Loki | Simple scalable (2 write, 2 read, 1 backend): 1.0, 2.5 | Single binary: 0.25, 1.0 |
| Tempo | Distributor, 2 ingesters, querier, compactor: 0.5, 1.5 | Single binary: 0.25, 0.75 |
| OpenTelemetry gateway collectors | 2: 0.4, 0.8 | 1: 0.2, 0.4 |
| Karpenter | 2: 0.5, 1.0 | 1: 0.25, 0.5 |
| Load Balancer Controller, External Secrets, KEDA, CoreDNS (2), metrics-server | 0.6, 1.2 | 0.45, 0.85 |
| **Cluster-level total** | **6.4, 17.5** | **2.6, 7.0** |
| Per-node agents: VPC CNI, kube-proxy, EBS CSI node, Pod Identity agent, node exporter, log and telemetry agent | 0.3, 0.4 per node | 0.3, 0.4 per node |

| Environment | App pods (A41) | Platform and agents | Total requests | Main pool | Scan pool |
|---|---|---|---|---|---|
| staging | 4.0 vCPU, 4.75 GiB | 2.6 + 0.9 vCPU, 7.0 + 1.2 GiB | 7.5 vCPU, 12.95 GiB | 3 m8g.xlarge, one per AZ (64 % of CPU) | 2 m8g.large |
| dev | 2.0 vCPU, 2.75 GiB | 2.6 + 0.6 vCPU, 7.0 + 0.8 GiB | 5.2 vCPU, 10.55 GiB | 2 m8g.xlarge (67 %) | 1 m8g.large |

### 4.4 Aurora: Standard or I/O-Optimized

At design load, for the three instances and 150 GB per region (A13). Replicated write I/O is left out of both
columns because it is assumed to be the same in both.

| Configuration | Instances | Storage, 300 GB | Read and write I/O | Total per month |
|---|---:|---:|---:|---:|
| Aurora Standard | $729 | $36 | $73 (304 M I/O) | $838 |
| Aurora I/O-Optimized | $948 | $81 | $0 | $1,029 |

Choose **Standard**. I/O-Optimized wins only above about 1,100 M I/Os a month (36 M a day, 3.6× A13). The load test
measures I/O; a cluster can switch to I/O-Optimized once every 30 days.

An Aurora global database needs memory-optimised instance classes or Aurora Serverless v2 (section 6), so staging's
writer is also a db.r8g.large; section 4.5 looks at Serverless v2. Only dev, which has no global database, uses a
burstable db.t4g.medium.

### 4.5 Aurora Serverless v2 for the Osaka secondary and staging

AWS documents that a global database's secondary clusters can use Aurora Serverless v2, ready to take over in a
disaster and scaled down while quiet. An ACU is about 2 GiB of memory with matching CPU and costs $0.15 an hour in
both regions (Standard storage). Instances in a secondary cluster never auto-pause, and AWS recommends at least
8 ACUs for the primary cluster of a global database (section 6 cites all three).

| Cluster | Provisioned today | Serverless v2 | Difference per month |
|---|---|---|---|
| prod Osaka secondary, idle | db.r8g.large, $242 | About 1 ACU (A44), $110 | Saves $132 |
| prod Osaka secondary, design load | db.r8g.large, $242 | About 1.5 ACU (A44), $164 | Saves $78 |
| staging Osaka secondary | db.r8g.large, $242 24×7 | About 1 ACU, $110 24×7 | Saves $132 24×7, about $29 at its 162 hours |
| staging and prod Tokyo writer | db.r8g.large, $243 | At least 8 ACUs, $876 | Costs $633 more: keep provisioned |

- **Promotion starts small.** After a failover the promoted secondary begins near 1 ACU with a cold buffer cache and
  scales towards the writer's size (about 8 ACUs for 16 GiB), faster as it grows. The runbook then sets its minimum
  to 8 ACUs, AWS's recommendation for a primary. That should fit the 5-minute promote step (architecture section 7),
  but it is unmeasured.
- **Recommendation.** Run staging's Osaka secondary on Serverless v2 first, and measure its ACUs (A44) and the
  promotion in the first failover drill. Adopt it for prod if both hold. The database ADR decides; the totals keep
  db.r8g.large until then.

## 5. Cost per environment

Line items use the Tokyo price for Tokyo resources and the Osaka price for Osaka resources. Each line is rounded to
whole dollars; each total is the sum of the rounded lines. Per-day figures are the monthly total ÷ 30.4. Lines marked
#22, #23 or #24 follow those phase 3 drafts.

### 5.1 prod

(a) is idle or demo traffic (A23). (b) is the full design load at steady state, month 12 or later.

**Tokyo and global services**

| Service | What | Unit price | (a) Quantity | (a) $/month | (b) Quantity | (b) $/month |
|---|---|---|---|---:|---|---:|
| EKS | Control plane, 1 cluster | $0.10/h | 730 h | 73 | 730 h | 73 |
| EC2 | Main node pool, m8g.xlarge (4 vCPU, 16 GiB), 3 AZs | $0.23188/h | 4 nodes | 677 | 4.67 nodes avg (peak 6) | 790 |
| EC2 | Scan node pool, m8g.large (2 vCPU, 8 GiB), one scan pod each (#22) | $0.11594/h | 5 nodes | 423 | 6.67 nodes avg (peak 10) | 564 |
| EBS | gp3: 100 GB root per main node, 50 GB per scan node, 300 GB observability volumes (A28) | $0.096/GB-mo | 950 GB | 91 | 1,100 GB | 106 |
| VPC | NAT gateways, one per AZ | $0.062/h + $0.062/GB | 3 × 730 h + 30 GB | 138 | 3 × 730 h + 61 GB | 140 |
| VPC | Public IPv4: 3 NAT + 3 load balancer | $0.005/h | 6 | 22 | 6 | 22 |
| VPC | Interface endpoints: SQS, KMS, Secrets Manager, ECR ×2, STS; 3 AZs | $0.014/h per AZ + $0.01/GB | 18 ENIs + 10 GB | 184 | 18 ENIs + 50 GB | 184 |
| ELB | Application Load Balancer; carries the streamed downloads (#24) | $0.0243/h + $0.008/LCU-h | 730 h + 0.1 LCU | 18 | 730 h + 43.7 LCU | 273 |
| WAF | API (12 rules) and sign-in (3) web ACLs, web app web ACL on CloudFront (4) (#24, A29) | $5/ACL + $1/rule + $0.60/M req + $0.40/M challenges | 3 ACLs, 19 rules + 1 M req | 35 | 3 ACLs, 19 rules + 155 M req + 1 M challenges | 127 |
| CloudFront | Web app bundle (Japan edge prices) | $0.114/GB + $0.012/10k req | 5 GB + 1 M req | 2 | 456 GB + 18 M req | 74 |
| Data transfer | File downloads to the internet | $0.114/GB first 10 TB, $0.089/GB next 40 TB | 10 GB | 1 | 30,400 GB | 2,962 |
| Data transfer | Cross-AZ (database, metrics, logs) | $0.01/GB each way | 91 GB | 2 | 1,216 GB | 24 |
| Route 53 | 1 hosted zone, 2 health checks with HTTPS + string match, queries (A32) | $0.50/zone + $1/option + $0.40/M | 1 M queries | 5 | 10 M queries | 9 |
| Aurora | Writer + reader, db.r8g.large (Standard) | $0.333/h | 2 × 730 h | 486 | 2 × 730 h | 486 |
| Aurora | Storage, I/O, backup beyond the free allowance (A35) | $0.12/GB-mo + $0.24/M I/O + $0.023/GB-mo | 10 GB + 30 M I/O | 8 | 150 GB + 304 M I/O + 50 GB | 92 |
| ElastiCache | Serverless Valkey for counters and leases (100 MB minimum, #24) | $0.101/GB-h + $0.0027/M ECPU | 0.1 GB + 10 M ECPU | 7 | 0.1 GB + 263 M ECPU | 8 |
| SQS, SES | Queue requests; emails; SES tenant management (#24, A43) | $0.40/M req; $0.10/1,000 emails; $0.005/tenant-mo + $0.005/1,000 emails | 2 M req + 20 k emails + 5 tenants | 3 | 10.2 M req + 1.42 M emails + 500 tenants | 155 |
| Cognito, Lambda | User pool on the Plus plan; sign-in triggers (#23, #24, A36) | $0.02/MAU; $0.20/M req + $0.0000133/GB-s | 50 MAU | 1 | 25,000 MAU + 1.2 M invocations | 501 |
| KMS | 8 customer managed keys; requests with S3 Bucket Keys and field data keys (#22, A30) | $1/key + $0.03/10k req | 8 keys + 0.35 M req | 9 | 8 keys + 9 M req | 35 |
| Secrets Manager | 10 secrets (A31) | $0.40/secret + $0.05/10k calls | 10 + 0.05 M calls | 4 | 10 + 0.07 M calls | 4 |
| S3 | Files + audit archive: storage and requests | $0.025/GB-mo + $0.0047/1k PUT + $0.00037/1k GET | 21 GB + 0.1 M PUT | 1 | 15,037 GB + 6.6 M PUT + 9.1 M GET | 410 |
| S3 | Logs, traces, web bundle, Terraform state (A33) | $0.025/GB-mo + $0.0047/1k PUT | 50 GB + 0.5 M PUT | 4 | 500 GB + 3 M PUT | 27 |
| CloudWatch | EKS control-plane logs; VPC flow, WAF and Cognito logs delivered to S3; 60 alarms, 30 metrics (A19, A33, A34) | $0.76/GB ingest, $0.38/GB delivered to S3, $0.033/GB-mo, $0.10/alarm, $0.30/metric | 30 GB + 16 GB to S3 | 45 | 61 GB + 156 GB to S3 | 121 |
| CloudTrail | S3 data events on the files and audit buckets (#22, A37) | $1/M events | 0.3 M | 0 | 15.7 M | 16 |
| GuardDuty | Malware Protection for S3, files over 2 GB only (option (b), A38) | $0.1185/GB + $0.000282/object | none | 0 | 3,040 GB + 912 objects | 360 |
| Security services | GuardDuty threat detection with S3 Protection, AWS Config (A20) | estimate | — | 50 | — | 96 |
| **Tokyo and global** | | | | **2,289** | | **7,659** |

**Osaka pilot light**

| Service | What | Unit price | (a) Quantity | (a) $/month | (b) Quantity | (b) $/month |
|---|---|---|---|---:|---|---:|
| EKS | Control plane, no worker nodes | $0.10/h | 730 h | 73 | 730 h | 73 |
| VPC | NAT gateways, one per AZ | $0.062/h | 3 × 730 h | 136 | 3 × 730 h | 136 |
| VPC | Public IPv4: 3 NAT + 3 load balancer | $0.005/h | 6 | 22 | 6 | 22 |
| VPC | Interface endpoints, same 6 services, 3 AZs | $0.014/h per AZ | 18 ENIs | 184 | 18 ENIs | 184 |
| ELB | Application Load Balancer, idle | $0.0243/h | 730 h | 18 | 730 h | 18 |
| WAF | API (12 rules) and sign-in (3) web ACLs (#24) | $5/ACL + $1/rule | 2 ACLs, 15 rules | 25 | 2 ACLs, 15 rules | 25 |
| Aurora | Global database secondary, db.r8g.large (Serverless v2 in section 4.5) | $0.332/h | 730 h | 242 | 730 h | 242 |
| Aurora | Secondary storage | $0.12/GB-mo | 10 GB | 1 | 150 GB | 18 |
| Aurora | Global database: replicated write I/O + cross-Region transfer (≤ 4 KB per I/O) | $0.24/M I/O + $0.09/GB | 9 M I/O + 36 GB | 5 | 91 M I/O + 365 GB | 55 |
| S3 | Replica storage: files + audit archive | $0.025/GB-mo | 21 GB | 1 | 15,037 GB | 376 |
| S3 | Replication: Tokyo → Osaka transfer, RTC fee, replica PUTs | $0.09/GB + $0.015/GB + $0.0047/1k PUT | 10 GB + 0.05 M PUT | 1 | 30,400 GB + 4.6 M PUT | 3,214 |
| ElastiCache | Serverless Valkey, idle (100 MB minimum) | $0.101/GB-h | 0.1 GB | 7 | 0.1 GB | 7 |
| KMS, Secrets Manager | 8 multi-Region key replicas (#22), 10 secret replicas | $1/key, $0.40/secret | 8 + 10 | 12 | 8 + 10 | 12 |
| CloudWatch and idle services | Replication-lag alarms; idle SQS and SES; SES tenants (#24) and data events for the API's direct archive writes (#22) | estimate + $0.005/tenant-mo + $1/M events | 5 tenants | 5 | 500 tenants + 1.2 M events | 9 |
| Security services | GuardDuty threat detection, AWS Config | estimate | — | 15 | — | 15 |
| **Osaka pilot light** | | | | **747** | | **4,406** |

The Osaka standby user pool (#23) has no users, so it bills nothing until a failover, when re-enrolled local members
become monthly active users there too (up to $500 in that month at design load).

| prod total | (a) idle or demo | (b) design load |
|---|---:|---:|
| Per month | $3,036 | $12,065 |
| Per day | $100 | $397 |

At design load that is about $0.040 per transfer or upload request and about $0.40 per GB delivered. During a
regional failover, Osaka adds worker nodes at the same hourly price as Tokyo (the idle shape, 4 main and 5 scan
nodes, costs about $36 a day).

### 5.2 staging

Prod's shape at smaller sizes, with the Osaka pilot light, so drills can run here first (PRD section 7). Traffic is
test traffic only, and the platform is the cut-down set (section 4.3). Running 24×7 costs $2,250 a month ($74 a day);
torn down outside its windows and billed for 162 hours (A22) it costs about $501 a month.

**Tokyo**

| Service | What | Unit price | Quantity | $/month |
|---|---|---|---|---:|
| EKS | Control plane | $0.10/h | 730 h | 73 |
| EC2 | Main node pool, m8g.xlarge, one per AZ (section 4.3) | $0.23188/h | 3 nodes | 508 |
| EC2 | Scan node pool, m8g.large (#22) | $0.11594/h | 2 nodes | 169 |
| EBS | gp3: 100 GB root per main node, 50 GB per scan node, 100 GB volumes (A28) | $0.096/GB-mo | 500 GB | 48 |
| VPC | NAT gateways, one per AZ | $0.062/h + $0.062/GB | 3 × 730 h + 10 GB | 136 |
| VPC | Public IPv4: 3 NAT + 3 load balancer | $0.005/h | 6 | 22 |
| VPC | Interface endpoints, 6 services, 3 AZs | $0.014/h per AZ | 18 ENIs | 184 |
| ELB | Application Load Balancer | $0.0243/h + $0.008/LCU-h | 730 h + 0.1 LCU | 18 |
| WAF | 3 web ACLs, 19 rules, as prod (#24) | $5/ACL + $1/rule + $0.60/M req | 3 ACLs + 0.5 M req | 34 |
| Aurora | Writer only, db.r8g.large (sections 4.4 and 4.5) | $0.333/h | 730 h | 243 |
| Aurora | Storage and I/O | $0.12/GB-mo + $0.24/M I/O | 10 GB + 10 M I/O | 4 |
| ElastiCache | Serverless Valkey (100 MB minimum) | $0.101/GB-h | 0.1 GB | 7 |
| KMS, Secrets Manager | 8 keys (#22), 10 secrets | $1/key, $0.40/secret | 8 + 10 | 12 |
| S3, CloudFront, Route 53, SQS, SES, Cognito | Small buckets, web bundle, zone + 2 health checks, test email, test users in two pools (#23) | various | — | 8 |
| CloudWatch | EKS control-plane logs, flow logs to S3, 40 alarms, 10 metrics (A19, A34) | $0.76/GB ingest, $0.38/GB to S3 | 15 GB + 6 GB to S3 | 21 |
| Security services | GuardDuty, AWS Config | estimate | — | 25 |
| **Tokyo** | | | | **1,512** |

**Osaka pilot light**

| Service | What | Unit price | Quantity | $/month |
|---|---|---|---|---:|
| EKS | Control plane, no worker nodes | $0.10/h | 730 h | 73 |
| VPC | NAT gateways, one per AZ | $0.062/h | 3 × 730 h | 136 |
| VPC | Public IPv4 | $0.005/h | 6 | 22 |
| VPC | Interface endpoints, 3 AZs | $0.014/h per AZ | 18 ENIs | 184 |
| ELB | Application Load Balancer, idle | $0.0243/h | 730 h | 18 |
| WAF | API and sign-in web ACLs (#24) | $5/ACL + $1/rule | 2 ACLs, 15 rules | 25 |
| Aurora | Global database secondary, db.r8g.large (section 4.5) | $0.332/h | 730 h | 242 |
| Aurora, S3 | Secondary storage, replication, replica buckets | various | — | 4 |
| ElastiCache | Serverless Valkey, idle | $0.101/GB-h | 0.1 GB | 7 |
| KMS, Secrets Manager | 8 key replicas (#22), 10 secret replicas | $1/key, $0.40/secret | 8 + 10 | 12 |
| CloudWatch, security services | Alarms, GuardDuty, AWS Config | estimate | — | 15 |
| **Osaka pilot light** | | | | **738** |

| staging total | 24×7 | Expected, 162 billed hours (A22) |
|---|---:|---:|
| Per month | $2,250 | $501 |
| Per day while running | $74 | $74 |

The expected figure is $2,248 × 162 ÷ 730, plus the $2 of Terraform state keys that bill all month.

### 5.3 dev

Tokyo only, smallest sizes, single-AZ where AWS allows it (PRD section 7), with the cut-down platform (section 4.3).
The load balancer still needs two AZs. Running 24×7 costs $817 a month ($27 a day); billed for 260 hours a month
(A22) it costs about $292.

| Service | What | Unit price | Quantity | $/month |
|---|---|---|---|---:|
| EKS | Control plane | $0.10/h | 730 h | 73 |
| EC2 | Main node pool, m8g.xlarge (section 4.3) | $0.23188/h | 2 nodes | 339 |
| EC2 | Scan node pool, m8g.large (#22) | $0.11594/h | 1 node | 85 |
| EBS | gp3: 50 GB root per node + 50 GB volumes (A28) | $0.096/GB-mo | 200 GB | 19 |
| VPC | 1 NAT gateway | $0.062/h + $0.062/GB | 730 h + 10 GB | 46 |
| VPC | Public IPv4: 1 NAT + 2 load balancer | $0.005/h | 3 | 11 |
| VPC | Interface endpoints, 6 services, 1 AZ | $0.014/h per AZ | 6 ENIs | 61 |
| ELB | Application Load Balancer (needs 2 AZs) | $0.0243/h + $0.008/LCU-h | 730 h + 0.1 LCU | 18 |
| WAF | 3 web ACLs, 19 rules, as prod (#24) | $5/ACL + $1/rule | 3 ACLs | 34 |
| Aurora | Single instance, db.t4g.medium, no global database | $0.113/h | 730 h | 82 |
| Aurora | Storage and I/O | $0.12/GB-mo + $0.24/M I/O | 5 GB + 5 M I/O | 2 |
| ElastiCache | Serverless Valkey (100 MB minimum) | $0.101/GB-h | 0.1 GB | 7 |
| KMS, Secrets Manager | 8 keys (#22), 10 secrets | $1/key, $0.40/secret | 8 + 10 | 12 |
| S3, CloudFront, Route 53, SQS, SES, Cognito | Small buckets, web bundle, dev zone, sandbox email, test users | various | — | 2 |
| CloudWatch | EKS control-plane logs, flow logs to S3, 10 alarms, 5 metrics (A19, A34) | $0.76/GB ingest, $0.38/GB to S3 | 9 GB + 3 GB to S3 | 11 |
| Security services | GuardDuty, AWS Config | estimate | — | 15 |
| **dev, if left running** | | | | **817** |

The expected figure is $816 × 260 ÷ 730, plus the $1 Terraform state key that bills all month.

### 5.4 Shared: container registry

The registry can't live with prod. CI builds and promotes images from the first dev deploy, months before prod
exists, and prod's teardown (NFR-19) must neither take the images dev and staging still use nor leave a registry
billing afterwards. ECR therefore lives in its own shared stack, from the bootstrap until the final teardown. If open
question 4 chooses an account per environment, that stack gets its own shared account, and each environment account
is allowed to pull.

| Phase | Where | Why |
|---|---|---|
| Build, before staging exists | Tokyo | dev pulls images by digest |
| Build, once staging exists | Tokyo, replicated to Osaka | Staging's Osaka pilot light and its drills need the images there (architecture 3.2) |
| Operating period | Tokyo, replicated to Osaka | dev, staging and prod pull the same digests (NFR-18) |
| After teardown | Deleted with the last environment | NFR-19 leaves only the audit archive and its key |

| Service | What | Unit price | Quantity | $/month |
|---|---|---|---|---:|
| ECR | Images in Tokyo (A40) | $0.10/GB-mo | 20 GB | 2 |
| ECR | Replica in Osaka, plus new layers replicated in | $0.10/GB-mo + $0.09/GB | 20 GB + 5 GB | 2 |
| **Shared registry** | | | | **4** |

Nodes pull through their VPC's ECR interface endpoints and the S3 gateway endpoint, so pulls add nothing to NAT.

### 5.5 Malware scanning options (open question 2)

Section 3.3 explains why ClamAV alone doesn't meet FR-2. This is the cost side of the scan ADR; the totals in 5.1 use
option (b). The scan node pool is its own node pool (#22), so removing ClamAV removes whole nodes.

| Option | Meets FR-2 | (a) idle or demo | (b) design load | Notes |
|---|---|---:|---:|---|
| (a) GuardDuty Malware Protection for S3 for every file | Yes: objects up to 100 GB | $4: 10 GB + 10,000 objects | $3,860: 30,400 GB × $0.1185 + 912,000 objects × $0.000282 | No scan pods and no signature mirror; the scan worker only records results from EventBridge, in 2 small pods on the main pool. No published time-to-result target. The files key policy must let GuardDuty's role decrypt (#22). Osaka prices are about 5 % higher. |
| (b) Hybrid: ClamAV up to 2 GB, GuardDuty above (in the totals) | Yes | $447: 5 scan nodes ($423) and their volumes ($24); GuardDuty about $0 | $956: 6.67 scan nodes ($564), their volumes ($32), GuardDuty for 3,040 GB ($360, A38) | Two engines, two result paths and a signature mirror. A GuardDuty plan covers a whole bucket or up to five prefixes, so the API puts files declared over 2 GB under their own prefix, ahead of the tenant ID (architecture 5.1); per-tenant deletion then covers two prefixes. |
| (c) Lower FR-2's limit to 2 GB, ClamAV only | No: a PRD change | $447 | $596 | One engine and the lowest cost at design load, but it changes a Must requirement. A 20 GB transfer still fits, as ten 2 GB files. |

- Against (b), option (a) saves **$443 a month at idle, net**: five whole m8g.large nodes and their volumes ($447),
  less $4 of GuardDuty. At design load it costs **$2,904 a month more**. Break-even is about 4,000 GB a month (about
  130 GB a day, 13 % of the design load); below that, (a) is cheaper.
- Option (c) saves the $360 of GuardDuty at design load and nothing at idle.
- GuardDuty's results map to file states as #24 6.4 lists, including `UNSUPPORTED` for encrypted and over-limit
  archives. Its S3 reads, optional object tags and EventBridge events bill separately, a few dollars a month at
  design load.
- For the ADR: decide capability first (5 GB files, archives, NFR-5 latency for each engine), then cost. For a
  reference run that stays near idle, (a) is the cheaper and simpler option; at the design load, (b) is.

### 5.6 Download mechanism (open question 8)

#24 decided to stream downloads through the API (#24 5.2), so the load balancer line in 5.1 carries 41.7 more LCU an
hour at design load (1 LCU = 1 GB processed per hour): about $243 a month, as #24 says. The API pods
carry about 0.35 vCPU of streaming in the peak hour and 0.7 at the burst (section 4.1). Internet egress is the same
for every candidate: $0.114/GB for the first 10 TB a month, then $0.089/GB. The rejected alternative, CloudFront
signed cookies, would have cost a few dollars a month in range-chunk requests instead (#24 5.1 has the reasons).

## 6. Prices: date and sources

Prices were looked up on **2026-11-03**, on-demand, in USD, from the AWS Price List bulk offer files
(`https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/<service>/current/<region>/index.json`, index at
[offers/v1.0/aws/index.json](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/index.json)) for ap-northeast-1 and
ap-northeast-3. The m8g instance prices come from the data file behind the EC2 on-demand pricing page, published
the same day as the EC2 offer file. The human-readable pages below show the same prices. They exclude tax: an
account billed in Japan also pays 10 % consumption tax.

| Service | Offer file published | Pricing page |
|---|---|---|
| EC2 instances (m8g.large, m8g.xlarge, m8g.2xlarge) | 2026-10-29 | [EC2 on-demand](https://aws.amazon.com/ec2/pricing/on-demand/) |
| NAT gateway, EBS gp3 (EC2 offer) | rows effective 2026-10-01 | [VPC](https://aws.amazon.com/vpc/pricing/), [EBS](https://aws.amazon.com/ebs/pricing/) |
| Interface endpoints, public IPv4 (VPC offer) | 2026-11-03 | [PrivateLink](https://aws.amazon.com/privatelink/pricing/), [VPC](https://aws.amazon.com/vpc/pricing/) |
| EKS | 2026-10-27 | [EKS](https://aws.amazon.com/eks/pricing/) |
| Elastic Load Balancing | 2026-11-02 | [ELB](https://aws.amazon.com/elasticloadbalancing/pricing/) |
| WAF, including challenges ($0.40 per million) | 2026-09-14 | [WAF](https://aws.amazon.com/waf/pricing/) |
| CloudFront | 2026-10-19 | [CloudFront](https://aws.amazon.com/cloudfront/pricing/) |
| Route 53 | 2026-09-11 | [Route 53](https://aws.amazon.com/route53/pricing/) |
| Aurora PostgreSQL, including Serverless v2 at $0.15 per ACU-hour in both regions (RDS offer) | 2026-10-29 | [Aurora](https://aws.amazon.com/rds/aurora/pricing/) |
| S3, including RTC | 2026-10-15 | [S3](https://aws.amazon.com/s3/pricing/) |
| Data transfer (internet, inter-Region, cross-AZ) | 2026-09-16 | [EC2 data transfer](https://aws.amazon.com/ec2/pricing/on-demand/#Data_Transfer) |
| SQS | 2026-09-11 | [SQS](https://aws.amazon.com/sqs/pricing/) |
| SES, including tenant management in both regions | 2026-10-27 | [SES](https://aws.amazon.com/ses/pricing/) |
| KMS | 2026-10-26 | [KMS](https://aws.amazon.com/kms/pricing/) |
| Secrets Manager | 2026-09-11 | [Secrets Manager](https://aws.amazon.com/secrets-manager/pricing/) |
| ElastiCache | 2026-10-28 | [ElastiCache](https://aws.amazon.com/elasticache/pricing/) |
| ECR | 2026-09-11 | [ECR](https://aws.amazon.com/ecr/pricing/) |
| CloudWatch, including log delivery to S3 ($0.38/GB in Tokyo and Osaka; the $0.25/GB rate is for MediaTailor logs only) | 2026-10-07 | [CloudWatch](https://aws.amazon.com/cloudwatch/pricing/) |
| CloudTrail (data events $0.10 per 100,000) | 2026-11-02 | [CloudTrail](https://aws.amazon.com/cloudtrail/pricing/) |
| Cognito (Plus $0.02 per MAU; federated users $0.015) | 2026-10-20 | [Cognito](https://aws.amazon.com/cognito/pricing/) |
| Lambda | 2026-10-30 | [Lambda](https://aws.amazon.com/lambda/pricing/) |
| GuardDuty, including Malware Protection for S3 (Tokyo $0.1185/GB and $0.000282 per object; Osaka $0.1245 and $0.000297) | 2026-10-30 | [GuardDuty](https://aws.amazon.com/guardduty/pricing/) |
| AWS Config | 2026-09-11 | [Config](https://aws.amazon.com/config/pricing/) |

Facts from AWS documentation:

- Aurora global databases need memory-optimised instance classes
  ([configuration requirements](https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/aurora-global-database.configuration.requirements.html)).
  Secondary clusters can use Aurora Serverless v2
  ([how Aurora Serverless v2 works](https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/aurora-serverless-v2.how-it-works.html),
  high availability). AWS recommends a minimum of 8 ACUs for a global database's primary cluster only
  ([performance and scaling](https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/aurora-serverless-v2.setting-capacity.html)),
  and Serverless v2 instances in secondary clusters don't auto-pause
  ([auto-pause](https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/aurora-serverless-v2-auto-pause.html)).
- GuardDuty Malware Protection for S3 scans objects up to 100 GB (not adjustable), extracts up to 100,000 files and
  100 nesting levels, and protects up to 25 buckets per account and Region
  ([quotas](https://docs.aws.amazon.com/guardduty/latest/ug/malware-protection-s3-quotas-guardduty.html)). A plan
  covers a whole bucket or up to five prefixes and publishes each result to EventBridge
  ([enabling](https://docs.aws.amazon.com/guardduty/latest/ug/enable-malware-protection-s3-bucket.html)). S3
  requests, object tagging and EventBridge events bill separately
  ([usage cost](https://docs.aws.amazon.com/guardduty/latest/ug/pricing-malware-protection-for-s3-guardduty.html)).
- ElastiCache Serverless for Valkey meters at least 100 MB per cache ([ElastiCache pricing](https://aws.amazon.com/elasticache/pricing/)).

From ClamAV: the `clamd.conf.sample` shipped with ClamAV states the 2 GB limit under `MaxFileSize` and describes
`ConcurrentDatabaseReload`; `freshclam.conf.sample` describes `TestDatabases`. ClamAV's
[Docker documentation](https://docs.clamav.net/manual/Installing/Docker.html) gives the memory figures in A9: about
1.2 GiB to load the signatures, about 2.4 GiB while reloading, 3 GiB minimum and 4 GiB preferred per container.

**Not confirmed for these regions, used as assumptions:**

- Aurora global database cross-Region transfer: the pricing page says it is charged but gives no Tokyo example. This
  page applies the Tokyo → Osaka rate ($0.09/GB) to at most 4 KB per replicated write I/O (A13).
- Whether I/O-Optimized clusters still pay for replicated write I/O. Assumed yes, so section 4.4 leaves it out of both.
- How many ACUs a Serverless v2 secondary uses in practice (A44).
- The CloudFront-scoped web ACL is billed globally. Assumed to cost the same as the Tokyo regional rates ($5 per ACL,
  $1 per rule, $0.60 per million requests).
- ElastiCache ECPUs per rate-limit command: the page says 1 ECPU per KB for simple reads and writes; assumed 1 per
  `INCR` or `EXPIRE`.
- No cross-AZ charge between the Application Load Balancer and its targets.
- KMS bills $1 per key a month, and each of the first two yearly rotations adds $1 (#22 7.1). The operating period is
  assumed to be under a year, so the totals use $1 per key; section 7.4 covers the case after teardown.
- Which Cognito rate applies to federated members on the Plus plan: the price list has both the Plus rate ($0.02)
  and a federated rate ($0.015 after 50). The totals price every member at $0.02.
- SES tenant management: the price list has rows for both regions, but #24 asks to confirm the feature in Tokyo and
  Osaka before the email ADR.
- GuardDuty's time to result for large objects, which no AWS page gives (section 3.3).
- Security services and CloudWatch volumes are usage estimates (A19, A20, A33, A34), not price lookups.
- Free tiers are ignored (for example 100 GB a month of internet egress, 1 TB a month from CloudFront, 1 M SQS
  requests, 1 GB and 1,000 objects of GuardDuty malware scanning).

## 7. Cost drivers, savings and budget

### 7.1 Biggest cost drivers

| Rank | (a) idle or demo, $3,036 | (b) design load, $12,065 |
|---|---|---|
| 1 | EKS worker nodes, both pools: $1,100 (36 %) | S3 replication to Osaka: $3,214 (27 %) |
| 2 | Aurora, 3 × db.r8g.large: $728 (24 %) | Internet egress for downloads: $2,962 (25 %) |
| 3 | NAT, interface endpoints and IPv4 in two regions: $686 (23 %) | EKS worker nodes, both pools: $1,354 (11 %) |

The byte-driven costs (replication and egress, $6,176 together) come to about $0.10 for each GB that moves, whether
it is replicated to Osaka or downloaded. Every uploaded GB is replicated once and, at design load, downloaded about
once, so that is about $0.20 per GB uploaded. They dominate at design load. At idle, the bill is almost entirely
fixed infrastructure that exists for NFR-1, NFR-10 and NFR-11.

### 7.2 How to cut them

| Lever | Saves | Trade-off | Recommendation |
|---|---|---|---|
| Move file bytes at a sampled rate in load tests (PRD 6.1) | About $239 per day at the full byte rate ($114 egress, $105 replication, $12 GuardDuty share, $8 load balancer) | The byte path is not tested at full rate | Keep. One 4-hour full-byte window per load test costs about $40 (A42). |
| Run byte-heavy load generators inside Tokyo | Regional transfer via public IPs is $0.01/GB each way, not $0.114/GB | Downloads stream through the load balancer (#24), so this applies; it doesn't exercise the internet path | Use for the full-byte window |
| Tear down dev and staging when idle (NFR-20) | About $2,274 a month against running both 24×7 ($525 dev, $1,749 staging) | Rebuild time, bounded by NFR-19 (≤ 2 hours); rebuild and teardown hours bill too (A22) | Keep, as planned |
| Osaka network in one AZ until failover (1 NAT gateway, endpoints in 1 AZ) | About $220 a month | Adds a Terraform step to the 55-minute failover budget (architecture section 7) | Decide in the compute ADR |
| Drop the Tokyo Aurora reader | $243 a month | AZ failover becomes creating a new instance, which can miss NFR-11's 5 minutes | Don't |
| Run the Osaka secondary without an instance (headless) | $242 a month | Failover must first add an instance | Not for prod; fine for staging outside drills |
| Aurora Serverless v2 for the Osaka secondary (section 4.5) | $132 a month at idle, $78 at design load; staging about $29 at its expected hours | Promotion starts near 1 ACU with a cold cache; the ACUs are assumptions (A44) | Try in staging and measure in the first drill; the database ADR decides |
| GuardDuty for every file instead of the hybrid (option (a), section 5.5) | About $443 a month at idle, net of GuardDuty's own $4, in whole nodes | About $2,904 a month more at design load | Decide on capability first, in the scan ADR |
| Lower FR-2's file limit to 2 GB (option (c), section 5.5) | $360 a month at design load, nothing at idle | Changes a Must requirement | The PRD owner's call; input to the scan ADR |
| Stay on EKS standard support | Extended support adds $365 a month per cluster ($730 for prod's two) | Upgrade at least yearly | Upgrade within standard support |
| Shared KMS keys instead of one per tenant (open question 3) | About $1,000 a month for 500 per-tenant keys in two regions, up to $3,000 after two rotations | No cryptographic separation of file contents between tenants; names and messages still get per-tenant data keys | Chosen in #22 |
| Downloads through CloudFront signed cookies instead of streaming through the API | About $243 a month of load balancer capacity at design load | Doesn't meet FR-14 and NFR-6 together, and needs a chunked-download engine (#24 5.1) | Rejected in #24 |
| Filter WAF logs; keep EKS audit logs and log retention tight | Tens of dollars a month; logging every request at design load would add about $88 (1.5 KB per record, 155 M requests, $0.38/GB) | Less detail for forensics | Log blocked, challenged and counted requests (#24 3.4) |
| Spot instances for dev nodes | A share of dev's $151 of EC2 at its expected 260 hours (Spot prices vary; not modelled) | Interruptions | dev only, not staging during drills |
| Savings Plans or reserved instances | A discount for a 1- or 3-year commitment | Commits beyond a bounded operating period | Don't, unless the operating period runs a year or more |

Interface endpoints cost more than the NAT traffic they save at this volume ($368 a month for both regions). They stay,
because they keep traffic to AWS services off the internet (architecture 3.1); that is a security choice, not a
saving.

### 7.3 Recommended budget (open question 7)

Each budget is set so that the expected month, load-test windows included, sits at or below about 70 % of it. The
80 % alarm then fires only on unplanned spend, not every month.

| Phase | What runs | Expected per month | Monthly budget | Alarms at 50 / 80 / 100 % | Expected share |
|---|---|---:|---:|---|---:|
| Build, before prod exists | dev for 260 billed hours ($292), the shared registry ($4), staging for up to 162 hours of rehearsals ($501) | $296–797 | $1,200 | $600 / $960 / $1,200 | 25–66 % |
| Operating period | prod (a) $3,036, dev $292, staging $501, registry $4, load-test windows and a drill $248 (below) | $4,081 | **$6,000** | **$3,000 / $4,800 / $6,000** | 68 % |
| After teardown (NFR-19) | The prod audit archive in both regions and its key (section 7.4) | about $2.10 | $5 | $2.50 / $4 / $5 | 42 % |

**Load-test windows and drills (A42).** The operating-period line includes this headroom:

| Item, above idle | First window in a month | Each later window |
|---|---:|---:|
| Extra nodes: 8 hours at 1× (2 main, 5 scan), 4 hours at 2× (5 main, 15 scan) | $20 | $20 |
| File bytes: 217 GB uploaded and downloaded (4 full-byte hours, 8 hours at 10 %): egress, replication, GuardDuty share, load balancer | $52 | $52 |
| Test files kept about 10 days in both regions | $4 | $4 |
| Load generators: 2 × m8g.2xlarge for 12 hours | $11 | $11 |
| Requests and emails: WAF, Aurora I/O, SQS, SES (the mailbox simulator bills like real email), CloudTrail, logs | $21 | $21 |
| 1,000 test members in Cognito, billed once a month | $20 | — |
| **Total** | **$128** | **$108** |

Two windows ($236) and one prod drill (Osaka's 4 main and 5 scan nodes for 8 hours, $12) make $248 a month.

- Without load tests the operating month is $3,833 (64 % of the budget); with them, $4,081 (68 %). The 80 % alarm at
  $4,800 fires only after about $720 of unplanned spend: for example dev left running 24×7 for the whole month
  (+$525) and two extra load-test windows. At a budget of $5,100 or less, the planned month itself would cross 80 %; a
  reasonable range is **$5,500 to $6,500** a month.
- The 50 % alarm watches actual spend and fires around day 22 to 24 of a planned month. It is a pacing check: if it
  fires before day 15, spend is running ahead. The 80 % and 100 % alarms watch both actual and forecast spend.
- The length of the operating period stays Rashid's call. Each extra month costs about $4,080; each extra day of prod
  about $100.
- AWS Budgets alarms are defined in Terraform (NFR-20). If each environment has its own account (open question 4),
  each account gets a budget on the same rule:

| Account | Expected per month | Budget | Alarms at 50 / 80 / 100 % | Expected share |
|---|---:|---:|---|---:|
| dev | $292 | $450 | $225 / $360 / $450 | 65 % |
| staging | $501 | $800 | $400 / $640 / $800 | 63 % |
| prod, with load-test windows and the drill | $3,284 | $4,700 | $2,350 / $3,760 / $4,700 | 70 % |
| shared (registry) | $4 | $10 | $5 / $8 / $10 | 40 % |
| audit archive, if it gets its own account (#22 8.4) | about $2.10 after teardown | $5 | $2.50 / $4 / $5 | 42 % |

- A dev environment left running 24×7 ($817 a month, $27 a day) crosses its $360 alarm by day 14, and its forecast
  alarm sooner.
- A sustained month at the full design load ($12,065) is not planned. A full week of it would cost about $2,780.
- Tag every resource with environment and component, so Cost Explorer can be compared line by line with section 5.

### 7.4 After teardown (NFR-19)

NFR-19 lets only the prod audit archive and the key that encrypts it outlive prod, for at most $5 a month. #22 8.4
keeps both in a retained stack and turns the audit key's rotation off at teardown, because no new records are written
after it.

| Item | Planned: prod ran under a year, mostly idle | Worst case: a year or more at design load |
|---|---:|---:|
| Audit key: primary in Tokyo and replica in Osaka, rotation off from teardown (#22 8.4) | $2.00 (2 keys × $1) | $4.00 (2 keys × $2, after one rotation) |
| Archive storage at teardown, S3 Standard in both regions ($0.025/GB-mo); it falls as retention ends | $0.05 (under 1 GB each) | $1.85 (37 GB each, section 3.4) |
| What watches the archive: CloudTrail management events (first trail free), the Config rule `kms-cmk-not-scheduled-for-deletion`, EventBridge alerts | $0.05 (estimate) | $0.05 (estimate) |
| **Total, against NFR-19's ≤ $5** | **about $2.10: inside** | **about $5.90: over** |

Only an operating period of a year or more at design load breaks the cap. A colder storage class wouldn't help: most
archive objects are single records of about 0.2 KB (A14), and the infrequent-access and Glacier Instant Retrieval
classes bill at least 128 KB per object. If the operating period grows that long, #22 would need to set the audit
key's rotation period beyond it, or NFR-19 would need an exception.

## 8. What to measure

The first load test (k6 at 1× and 2× design load, NFR-16) and its first week in prod must confirm or replace these
assumptions. Each result goes into the load-test report, and this page is updated in the same pull request.

| Measure | Confirms | How |
|---|---|---|
| CPU per API request and per streamed MB/s; p95/p99 latency by pod count | A8, NFR-2 | Pod CPU metrics and latency histograms at 150/s and 300/s, with downloads streaming |
| ClamAV MB/s per vCPU, copy rate to scratch, and clamd memory through a signature reload, on a realistic mix including 1–2 GB files and archives | A9, A39, open question 2 | Scan worker metrics; a reload forced during the test |
| GuardDuty time to result for 100 MB, 2 GB and 5 GB objects | Sections 3.3 and 5.5, NFR-5 | EventBridge result times against upload completion |
| Share of files and bytes over 100 MB and over 2 GB | A9, A38 | File sizes from upload metadata |
| Time to shareable, p95, in the peak hour, for each scan pool | Section 3.3, NFR-5 | File state timestamps |
| Aurora read and write I/O per day, writer CPU, buffer cache hit ratio, global database lag | A13, A35, sections 4.1 and 4.4 | CloudWatch `VolumeReadIOPs`, `VolumeWriteIOPs`, `AuroraGlobalDBReplicationLag` |
| Serverless v2 secondary ACUs, and promotion time in the first failover drill | A44, section 4.5 | `ServerlessDatabaseCapacity`; the drill report |
| S3 requests per uploaded file, CloudTrail data events, replication bytes and latency | A10, A37, NFR-10 | S3 request metrics, CloudTrail, replication metrics |
| Bytes per download, egress per day and load balancer LCU from streams | A4, section 5.6 | Load balancer `ProcessedBytes` and `ConsumedLCUs` |
| Platform and app requests against use; node count and packing in both pools at 1× and 2× | A16, A26, A27, section 4.2 | Karpenter and cluster metrics |
| NAT, cross-AZ, flow log, WAF log and log storage volumes | A17, A18, A19, A33 | VPC flow logs, Cost Explorer by usage type |
| Emails per transfer and per upload request | A6, A7 | Notification worker metrics |
| ECPUs per API request in the counter cache | A24 | ElastiCache metrics |
| Sign-ins per member a day, trigger duration, sign-in web ACL requests per sign-in | A36 | Cognito, Lambda and WAF metrics |
| Cost of one load-test window | A42 | Cost Explorer by hour, with environment and component tags |
| Daily cost by service against section 5 | The whole model | Cost Explorer with environment and component tags |

The first load test must confirm A8, A9, A13, A16, A24, A26, A27, A36, A37, A38, A39 and A42. Its first week in prod
confirms A17, A18, A19, A33 and A35, and the first failover drill A44. The counts in A28, A29, A30, A31, A32 and A34
are set in Terraform, so the first bill confirms them.
