# Capacity estimate and cost model

| | |
|---|---|
| Requirements | [PRD](../prd.md), especially section 6.1 (design load), NFR-1, NFR-2, NFR-5, NFR-10, NFR-11, NFR-16, NFR-19, NFR-20 |
| Architecture | [architecture.md](../architecture.md) |
| Tracking | [#15](https://github.com/codewithmuh/secure-file-transfer/issues/15), part of phase 2 ([#16](https://github.com/codewithmuh/secure-file-transfer/issues/16)) |

This page turns the PRD design load into workload numbers, sizes each component for prod, and prices dev, staging
and prod with AWS on-demand prices for Tokyo (ap-northeast-1) and Osaka (ap-northeast-3). Every number is an
estimate. Each one traces to the PRD, the [data model](data-model.md) (section 8) or a named assumption in section 2.
The first load test (section 8) replaces the assumptions with measurements.

Technologies are the architecture's current candidates (architecture section 9). If a phase 4 ADR picks something
else, this page is updated in the same pull request.

## 1. Summary

| Environment | Running | Per month | Per day |
|---|---|---:|---:|
| prod, (a) idle or demo traffic | 24×7 | $2,926 | $96 |
| prod, (b) full design load, steady state | 24×7 | $10,680 | $351 |
| staging | 24×7 | $2,056 | $68 |
| staging | Expected: 144 h a month (A22) | $406 | — |
| dev | 24×7 | $715 | $24 |
| dev | Expected: 200 h a month (A22) | $196 | — |

- Prod includes the Osaka pilot light: $735 a month at idle, $4,389 at design load.
- Scenario (a) is the realistic case for a reference service: fixed infrastructure, the synthetic probe and a few demo
  users. Scenario (b) is a month at the full design load after 12 months of growth, with every byte moved for real.
- At design load the three biggest costs are S3 replication to Osaka ($3,213), internet egress for downloads
  ($2,962) and EKS worker nodes ($1,185). At idle they are worker nodes ($1,016), the three Aurora instances ($728),
  and NAT gateways, interface endpoints and public IPv4 addresses in two regions ($686).
- Recommended budget for the operating period (open question 7): **$4,000 a month**, with alarms at $2,000, $3,200
  and $4,000 (section 7).

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
| A8 | An API request uses 10 ms of CPU on Graviton4 on average. API pods run at ≤ 50 % CPU at the burst rate. Streaming file bytes, if open question 8 chooses it, costs about 1 vCPU per 100 MB/s. | Estimate for FastAPI + SQLAlchemy; to measure |
| A9 | ClamAV scans 20 MB/s per vCPU, plus 1 s per file to fetch and record the result. clamd needs 2.5 GiB per pod. Files over 100 MB are about 8 % of files and 70 % of bytes. | Estimate; to measure (open question 2) |
| A10 | Multipart part size is 16 MB; files ≤ 16 MB upload in one part. That is about 80,000 parts a day. | Estimate |
| A11 | Transfer files are kept 7 days (the FR-3 default), upload-request files 30 days (the FR-13 default), plus 3.5 days on average until deletion completes (half the NFR-8 limit). | Reproduces the PRD's 15 TB |
| A12 | Objects are never overwritten (keys are file IDs) and deletion removes every version (architecture 4.5), so noncurrent versions stay near zero. | Architecture 4.5 |
| A13 | Aurora at design load does 3 M write I/Os and 7 M read I/Os a day. At most 4 KB crosses to Osaka per replicated write I/O. | Estimate from about 1 M write transactions a day; to measure |
| A14 | The audit archive stores 0.2 KB per audit row after compression, plus about 40,000 security-critical records a day as separate objects in each region (download grants dominate). That is about 0.1 GB a day per region. | Architecture 5.2 |
| A15 | The web app serves 30,000 sessions a day, each 0.5 MB and 20 requests through CloudFront. | Estimate (25,000 members, about 18,000 external people a day) |
| A16 | Prod runs 6 worker nodes at idle, 9 in the peak hour and 7 on average at design load. | Section 4.2 |
| A17 | NAT traffic is 1 GB a day at idle and 2 GB a day at design load: SES API calls, writes to Osaka, Git and signature updates. S3 and image layers use endpoints. | Architecture 3.1 |
| A18 | Cross-AZ traffic is 3 GB a day at idle and 40 GB a day at design load (database, metrics, logs). | Estimate |
| A19 | EKS control-plane logs are 1 GB a day at idle and 2 GB at design load; VPC flow logs 0.5 and 5 GB. WAF logs keep only blocked and sampled requests. | Estimate |
| A20 | GuardDuty threat detection and AWS Config bill by usage. Their lines are estimates, not price lookups. | — |
| A21 | S3 Bucket Keys are on, so KMS requests stay near 3 M a month at design load. | Estimate |
| A22 | dev runs 200 hours a month (10 hours on 20 working days). staging runs 144 hours a month (six 24-hour windows for release rehearsals and drills). | NFR-20: torn down when idle |
| A23 | Idle prod traffic is the synthetic probe every 5 minutes (NFR-1) plus a few demo users: about 10 GB of file bytes and 20,000 emails a month. | NFR-1 |
| A24 | Rate limiting costs 2 counter operations per API request. | NFR-14 |
| A25 | SQS costs 3 requests per message (send, receive, delete), plus 20-second long polling by about 8 consumers. | Architecture 5.3 |

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
| Download throughput | 1 TB a day: 11.6 MB/s | 35 MB/s | about 70 MB/s | A4, A5 |
| Scan volume | 30,000 files, 1 TB a day | about 1 file/s, 35 MB/s | — | Every file is scanned (FR-16) |
| Emails | about 46,600 a day, 1.42 M a month | about 5,800/h (1.6/s) | about 5/s | Section 3.2 |
| Queue messages | about 100,000 a day; about 10 M SQS requests a month | — | — | Data model section 8, A25 |
| Audit rows | about 300,000 a day | — | — | Data model section 8 |
| S3 requests in Tokyo | about 216,000 PUT-class and 300,000 GET-class a day | — | — | 30,000 each of create, complete and tag; 80,000 parts; 40,000 download-grant records; reads for scans, checks and downloads |
| Rate-limit operations | about 100/s | 300/s | 600/s | A24 |

File bytes never pass through the API on upload: the browser sends parts straight to S3 (architecture 4.1). Data
coming into AWS is free.

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
up to 20 GB. One 5 GB file takes about 250 s to scan at 20 MB/s (A9), so large files must not delay small ones. The
sizing therefore uses **two queues and two worker pools**, split at 100 MB; the scan ADR confirms this.

| Pool | Share of files | Bytes in the peak hour | Busy workers in the peak hour | Pods, min / peak |
|---|---|---|---|---|
| Small files, ≤ 100 MB | about 92 % | about 10 MB/s | about 1.5 (0.96 files/s × 1 s + 10 MB/s ÷ 20 MB/s) | 3 / 4 |
| Large files, > 100 MB | about 8 % | about 25 MB/s | about 1.3 on average | 2 / 6 |

- A 20 GB transfer is at most four 5 GB files. With four large-file workers free, all four finish in about 5 minutes,
  inside the 15-minute target. The large pool scales on queue age, not only queue length.
- ClamAV's behaviour on files over 2 GiB is not confirmed; some builds stop at 2 GiB. This is the PRD's scan-engine
  risk, and the scan ADR (open question 2) must test 5 GB files before this sizing holds.
- At 2× design load (NFR-16) the pools need about 16 to 20 pods at peak.

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
| API service | Pods request 1 vCPU and 1 GiB (limit 1.5 GiB), one Uvicorn worker each. 3 pods minimum (one per AZ), 6 at the 300/s burst, autoscaled up to 12 for 2× design load. | A8: 1 vCPU at 50 % serves 50 requests/s |
| Scan workers | Each pod: the worker (0.25 vCPU, 0.25 GiB) and clamd (1 vCPU, 2.5 GiB). Small pool 3–4 pods, large pool 2–6, scaled by queue age. Up to 5 GB of scratch disk per large-file pod. | Section 3.3, A9 |
| Outbox relay | 2 pods, 0.25 vCPU and 0.25 GiB each | Architecture 2 |
| Notification worker | 2 pods, 0.25 vCPU and 0.5 GiB each; peaks at about 5 emails/s | Section 3.2 |
| Lifecycle jobs | Scheduled jobs, 0.5 vCPU and 1 GiB while they run | Architecture 4.5 |
| Platform | Argo CD, Prometheus (2 replicas), Alertmanager, Grafana, Loki, Tempo, OpenTelemetry collectors, Karpenter, AWS Load Balancer Controller, External Secrets, KEDA, CoreDNS and per-node agents: about 8 vCPU and 19 GiB of requests | Architecture 5.5 |
| EKS worker nodes | **m8g.xlarge** (Graviton4, 4 vCPU, 16 GiB, about 3.9 vCPU and 14 GiB allocatable), spread over 3 AZs by Karpenter. 6 at idle (2 per AZ), 9 in the peak hour, about 13 at 2× design load. | Section 4.2 |
| Aurora PostgreSQL | **db.r8g.large** (2 vCPU, 16 GiB) writer and reader in different Tokyo AZs, plus one db.r8g.large in the Osaka secondary. Standard storage, 150 GB per region at steady state. Move up to db.r8g.xlarge if writer CPU stays above 60 % in the peak hour or the buffer cache hit ratio drops below 99 %. | Section 4.3 |
| Rate-limit counters | ElastiCache Serverless for Valkey, at its 100 MB minimum in each region; about 600 operations/s at burst | A24 |
| SQS | Standard queues with dead-letter queues; about 100,000 messages a day, each under 1 KB. Large-file scans extend their visibility timeout while they run. | Architecture 5.3 |
| NAT gateways | 3 per region (one per AZ); about 2 GB a day of traffic | A17 |
| Load balancer | One Application Load Balancer per region; about 2 LCU at design load, or about 44 LCU if downloads stream through it | Section 5.5 |
| CloudFront | One distribution for the web app bundle; it also serves downloads if open question 8 picks signed cookies | Architecture 4.2 |

Even at 2× design load the API needs under 200 database connections (12 pods × 10, plus workers), far below what a
db.r8g.large allows. Streaming downloads through the API (open question 8) would add about 35 MB/s in the peak hour
and about 15 concurrent downloads (at about 10 seconds each), well within the pods' and nodes' network capacity.

### 4.2 Node packing

| Workload | Pods, idle / peak | Requests per pod | Idle total | Peak-hour total |
|---|---|---|---|---|
| API | 3 / 6 | 1 vCPU, 1 GiB | 3 vCPU, 3 GiB | 6 vCPU, 6 GiB |
| Scan workers | 5 / 10 | 1.25 vCPU, 2.75 GiB | 6.25 vCPU, 13.75 GiB | 12.5 vCPU, 27.5 GiB |
| Outbox relay and notification worker | 4 / 4 | 0.25 vCPU, 0.25–0.5 GiB | 1 vCPU, 1.5 GiB | 1 vCPU, 1.5 GiB |
| Lifecycle jobs | while running | 0.5 vCPU, 1 GiB | 0.5 vCPU, 1 GiB | 0.5 vCPU, 1 GiB |
| Platform | — | — | 8 vCPU, 18.7 GiB | 8 vCPU, 18.7 GiB |
| **Total** | | | **about 19 vCPU, 38 GiB** | **about 28 vCPU, 55 GiB** |
| **m8g.xlarge nodes** | | | **6** (80 % of CPU requested) | **9** (79 %) |

CPU requests decide the node count, but a compute-optimised type (8 GiB per 4 vCPU) would leave little memory headroom
for clamd, so m8g.xlarge is the better fit. If an AZ fails, 4 nodes remain for 19 vCPU of requests: the API pods keep
a higher priority, and Karpenter adds nodes in the other two AZs within minutes, inside NFR-11's 5-minute target.

### 4.3 Aurora: Standard or I/O-Optimized

At design load, for the three instances and 150 GB per region (A13). Replicated write I/O is left out of both
columns because it is assumed to be the same in both.

| Configuration | Instances | Storage, 300 GB | Read and write I/O | Total per month |
|---|---:|---:|---:|---:|
| Aurora Standard | $729 | $36 | $73 (304 M I/O) | $838 |
| Aurora I/O-Optimized | $948 | $81 | $0 | $1,029 |

Choose **Standard**. I/O-Optimized wins only above about 1,100 M I/Os a month (36 M a day, 3.6× A13). The load test
measures I/O; a cluster can switch to I/O-Optimized once every 30 days.

An Aurora global database needs memory-optimised (r) instance classes in every region, so staging also uses
db.r8g.large. Only dev, which has no global database, uses a burstable db.t4g.medium.

## 5. Cost per environment

Line items use the Tokyo price for Tokyo resources and the Osaka price for Osaka resources. Each line is rounded to
whole dollars; each total is the sum of the rounded lines. Per-day figures are the monthly total ÷ 30.4.

### 5.1 prod

(a) is idle or demo traffic (A23). (b) is the full design load at steady state, month 12 or later.

**Tokyo and global services**

| Service | What | Unit price | (a) Quantity | (a) $/month | (b) Quantity | (b) $/month |
|---|---|---|---|---:|---|---:|
| EKS | Control plane, 1 cluster | $0.10/h | 730 h | 73 | 730 h | 73 |
| EC2 | Worker nodes, m8g.xlarge (4 vCPU, 16 GiB), 3 AZs | $0.23188/h | 6 nodes | 1,016 | 7 nodes avg (peak 9) | 1,185 |
| EBS | gp3: 100 GB root per node + 300 GB observability volumes | $0.096/GB-mo | 900 GB | 86 | 1,000 GB | 96 |
| VPC | NAT gateways, one per AZ | $0.062/h + $0.062/GB | 3 × 730 h + 30 GB | 138 | 3 × 730 h + 61 GB | 140 |
| VPC | Public IPv4: 3 NAT + 3 load balancer | $0.005/h | 6 | 22 | 6 | 22 |
| VPC | Interface endpoints: SQS, KMS, Secrets Manager, ECR ×2, STS; 3 AZs | $0.014/h per AZ + $0.01/GB | 18 ENIs + 10 GB | 184 | 18 ENIs + 50 GB | 184 |
| ELB | Application Load Balancer | $0.0243/h + $0.008/LCU-h | 730 h + 0.1 LCU | 18 | 730 h + 2 LCU | 29 |
| WAF | 2 web ACLs (load balancer, CloudFront), 8 rules each | $5/ACL + $1/rule + $0.60/M req | 2 ACLs + 1 M req | 27 | 2 ACLs + 150 M req | 116 |
| CloudFront | Web app bundle (Japan edge prices) | $0.114/GB + $0.012/10k req | 5 GB + 1 M req | 2 | 456 GB + 18 M req | 74 |
| Data transfer | File downloads to the internet | $0.114/GB first 10 TB, $0.089/GB next 40 TB | 10 GB | 1 | 30,400 GB | 2,962 |
| Data transfer | Cross-AZ (database, metrics, logs) | $0.01/GB each way | 91 GB | 2 | 1,216 GB | 24 |
| Route 53 | 1 hosted zone, 2 health checks with HTTPS + string match, queries | $0.50/zone + $1/option + $0.40/M | 1 M queries | 5 | 10 M queries | 9 |
| Aurora | Writer + reader, db.r8g.large (Standard) | $0.333/h | 2 × 730 h | 486 | 2 × 730 h | 486 |
| Aurora | Storage, I/O, backup beyond the free allowance | $0.12/GB-mo + $0.24/M I/O + $0.023/GB-mo | 10 GB + 30 M I/O | 8 | 150 GB + 304 M I/O + 50 GB | 92 |
| ElastiCache | Serverless Valkey for rate-limit counters (100 MB minimum) | $0.101/GB-h + $0.0027/M ECPU | 0.1 GB + 10 M ECPU | 7 | 0.1 GB + 263 M ECPU | 8 |
| SQS, SES | Queue requests; emails (links, codes, notices) | $0.40/M req; $0.10/1,000 emails | 2 M req + 20 k emails | 3 | 10.2 M req + 1.42 M emails | 146 |
| KMS | 6 customer managed keys; requests (S3 Bucket Keys on) | $1/key + $0.03/10k req | 6 keys + 0.3 M req | 7 | 6 keys + 3 M req | 15 |
| Secrets Manager | 10 secrets | $0.40/secret | 10 | 4 | 10 | 4 |
| S3 | Files + audit archive: storage and requests | $0.025/GB-mo + $0.0047/1k PUT + $0.00037/1k GET | 21 GB + 0.1 M PUT | 1 | 15,037 GB + 6.6 M PUT + 9.1 M GET | 410 |
| S3 | Logs, traces, web bundle, Terraform state | $0.025/GB-mo + $0.0047/1k PUT | 50 GB + 0.5 M PUT | 4 | 500 GB + 3 M PUT | 27 |
| ECR | Images, 20 GB | $0.10/GB-mo | 20 GB | 2 | 20 GB | 2 |
| CloudWatch | EKS control-plane logs, VPC flow logs to S3, 60 alarms, 30 metrics | $0.76/GB ingest, $0.25/GB to S3, $0.10/alarm | 30 GB logs | 45 | 61 GB logs | 107 |
| Security services | GuardDuty threat detection, AWS Config (usage-based, A20) | estimate | — | 50 | — | 80 |
| **Tokyo and global** | | | | **2,191** | | **6,291** |

**Osaka pilot light**

| Service | What | Unit price | (a) Quantity | (a) $/month | (b) Quantity | (b) $/month |
|---|---|---|---|---:|---|---:|
| EKS | Control plane, no worker nodes | $0.10/h | 730 h | 73 | 730 h | 73 |
| VPC | NAT gateways, one per AZ | $0.062/h | 3 × 730 h | 136 | 3 × 730 h | 136 |
| VPC | Public IPv4: 3 NAT + 3 load balancer | $0.005/h | 6 | 22 | 6 | 22 |
| VPC | Interface endpoints, same 6 services, 3 AZs | $0.014/h per AZ | 18 ENIs | 184 | 18 ENIs | 184 |
| ELB | Application Load Balancer, idle | $0.0243/h | 730 h | 18 | 730 h | 18 |
| WAF | 1 regional web ACL, 8 rules | $5/ACL + $1/rule | 1 ACL | 13 | 1 ACL | 13 |
| Aurora | Global database secondary, db.r8g.large | $0.332/h | 730 h | 242 | 730 h | 242 |
| Aurora | Secondary storage | $0.12/GB-mo | 10 GB | 1 | 150 GB | 18 |
| Aurora | Global database: replicated write I/O + cross-Region transfer (≤ 4 KB per I/O) | $0.24/M I/O + $0.09/GB | 9 M I/O + 36 GB | 5 | 91 M I/O + 365 GB | 55 |
| S3 | Replica storage: files + audit archive | $0.025/GB-mo | 21 GB | 1 | 15,037 GB | 376 |
| S3 | Replication: Tokyo → Osaka transfer, RTC fee, replica PUTs | $0.09/GB + $0.015/GB + $0.0047/1k PUT | 10 GB + 0.05 M PUT | 1 | 30,400 GB + 4.6 M PUT | 3,213 |
| ElastiCache | Serverless Valkey, idle (100 MB minimum) | $0.101/GB-h | 0.1 GB | 7 | 0.1 GB | 7 |
| KMS, Secrets Manager | 6 multi-Region key replicas, 10 secret replicas | $1/key, $0.40/secret | 6 + 10 | 10 | 6 + 10 | 10 |
| ECR | Replicated images, 20 GB | $0.10/GB-mo | 20 GB | 2 | 20 GB | 2 |
| CloudWatch and idle services | Replication-lag alarms; idle SQS, SES | estimate | — | 5 | — | 5 |
| Security services | GuardDuty threat detection, AWS Config | estimate | — | 15 | — | 15 |
| **Osaka pilot light** | | | | **735** | | **4,389** |

| prod total | (a) idle or demo | (b) design load |
|---|---:|---:|
| Per month | $2,926 | $10,680 |
| Per day | $96 | $351 |

At design load that is about $0.035 per transfer or upload request and about $0.35 per GB delivered. During a
regional failover, Osaka adds worker nodes at the same hourly price as Tokyo (6 nodes cost about $34 a day).

### 5.2 staging

Prod's shape at smaller sizes, with the Osaka pilot light, so drills can run here first (PRD section 7). Traffic is
test traffic only. Running 24×7 costs $2,056 a month ($68 a day); torn down outside 144 hours of windows (A22) it
costs about $406 a month.

**Tokyo**

| Service | What | Unit price | Quantity | $/month |
|---|---|---|---|---:|
| EKS | Control plane | $0.10/h | 730 h | 73 |
| EC2 | Worker nodes, m8g.xlarge, one per AZ | $0.23188/h | 3 nodes | 508 |
| EBS | gp3: 100 GB root per node + 200 GB volumes | $0.096/GB-mo | 500 GB | 48 |
| VPC | NAT gateways, one per AZ | $0.062/h + $0.062/GB | 3 × 730 h + 10 GB | 136 |
| VPC | Public IPv4: 3 NAT + 3 load balancer | $0.005/h | 6 | 22 |
| VPC | Interface endpoints, 6 services, 3 AZs | $0.014/h per AZ | 18 ENIs | 184 |
| ELB | Application Load Balancer | $0.0243/h + $0.008/LCU-h | 730 h + 0.1 LCU | 18 |
| WAF | 2 web ACLs, 8 rules each | $5/ACL + $1/rule | 2 ACLs | 26 |
| Aurora | Writer only, db.r8g.large (a global database needs an r class) | $0.333/h | 730 h | 243 |
| Aurora | Storage and I/O | $0.12/GB-mo + $0.24/M I/O | 10 GB + 10 M I/O | 4 |
| ElastiCache | Serverless Valkey (100 MB minimum) | $0.101/GB-h | 0.1 GB | 7 |
| KMS, Secrets Manager | 6 keys, 10 secrets | $1/key, $0.40/secret | 6 + 10 | 10 |
| S3, CloudFront, Route 53, SQS, SES | Small buckets, web bundle, zone + 2 health checks, test email | various | — | 8 |
| CloudWatch | EKS control-plane logs, flow logs, alarms | $0.76/GB ingest | 20 GB | 20 |
| Security services | GuardDuty, AWS Config | estimate | — | 25 |
| **Tokyo** | | | | **1,332** |

**Osaka pilot light**

| Service | What | Unit price | Quantity | $/month |
|---|---|---|---|---:|
| EKS | Control plane, no worker nodes | $0.10/h | 730 h | 73 |
| VPC | NAT gateways, one per AZ | $0.062/h | 3 × 730 h | 136 |
| VPC | Public IPv4 | $0.005/h | 6 | 22 |
| VPC | Interface endpoints, 3 AZs | $0.014/h per AZ | 18 ENIs | 184 |
| ELB | Application Load Balancer, idle | $0.0243/h | 730 h | 18 |
| WAF | 1 regional web ACL | $5/ACL + $1/rule | 1 ACL | 13 |
| Aurora | Global database secondary, db.r8g.large | $0.332/h | 730 h | 242 |
| Aurora, S3 | Secondary storage, replication, replica buckets | various | — | 4 |
| ElastiCache | Serverless Valkey, idle | $0.101/GB-h | 0.1 GB | 7 |
| KMS, Secrets Manager | 6 key replicas, 10 secret replicas | $1/key, $0.40/secret | 6 + 10 | 10 |
| CloudWatch, security services | Alarms, GuardDuty, AWS Config | estimate | — | 15 |
| **Osaka pilot light** | | | | **724** |

| staging total | 24×7 | Expected, 144 h (A22) |
|---|---:|---:|
| Per month | $2,056 | $406 |
| Per day while running | $68 | $68 |

### 5.3 dev

Tokyo only, smallest sizes, single-AZ where AWS allows it (PRD section 7). The load balancer still needs two AZs.
Running 24×7 costs $715 a month ($24 a day); at 200 hours a month (A22) about $196.

| Service | What | Unit price | Quantity | $/month |
|---|---|---|---|---:|
| EKS | Control plane | $0.10/h | 730 h | 73 |
| EC2 | Worker nodes, m8g.xlarge | $0.23188/h | 2 nodes | 339 |
| EBS | gp3: 50 GB root per node + 50 GB volumes | $0.096/GB-mo | 150 GB | 14 |
| VPC | 1 NAT gateway | $0.062/h + $0.062/GB | 730 h + 10 GB | 46 |
| VPC | Public IPv4: 1 NAT + 2 load balancer | $0.005/h | 3 | 11 |
| VPC | Interface endpoints, 6 services, 1 AZ | $0.014/h per AZ | 6 ENIs | 61 |
| ELB | Application Load Balancer (needs 2 AZs) | $0.0243/h + $0.008/LCU-h | 730 h + 0.1 LCU | 18 |
| WAF | 2 web ACLs, 8 rules each | $5/ACL + $1/rule | 2 ACLs | 26 |
| Aurora | Single instance, db.t4g.medium, no global database | $0.113/h | 730 h | 82 |
| Aurora | Storage and I/O | $0.12/GB-mo + $0.24/M I/O | 5 GB + 5 M I/O | 2 |
| ElastiCache | Serverless Valkey (100 MB minimum) | $0.101/GB-h | 0.1 GB | 7 |
| KMS, Secrets Manager | 6 keys, 10 secrets | $1/key, $0.40/secret | 6 + 10 | 10 |
| S3, CloudFront, Route 53, SQS, SES | Small buckets, web bundle, dev zone, sandbox email | various | — | 2 |
| CloudWatch | EKS control-plane logs, 10 alarms | $0.76/GB ingest | 10 GB | 9 |
| Security services | GuardDuty, AWS Config | estimate | — | 15 |
| **dev, if left running** | | | | **715** |

The container registry lives with prod (one registry, images promoted by digest, NFR-18), so dev and staging carry
no ECR line.

### 5.4 Malware scanning options (open question 2)

Not added to the totals: the ClamAV cost is already inside the EC2 line, and GuardDuty is the alternative.

| Option | (a) idle or demo | (b) design load | Notes |
|---|---:|---:|---|
| ClamAV in the scan workers (candidate) | about $271 a month: 5 pods ≈ 1.6 nodes | about $339 a month: about 2 nodes on average | Plus running a signature mirror and tuning the engine; behaviour above 2 GiB unconfirmed (section 3.3) |
| GuardDuty Malware Protection for S3 | about $3 a month | about $3,859 a month: 30,400 GB × $0.1185 + 912,000 objects × $0.000282 | No scan pods; objects up to 100 GB; Osaka prices are about 5 % higher |

Break-even is about 2,100 GB a month (70 GB a day, 7 % of the design load). Below that GuardDuty is cheaper; at the
design load ClamAV is about 11× cheaper. The ADR should decide on capability first (5 GB files, archives, NFR-5
latency), then cost.

### 5.5 Download mechanism (open question 8)

Both candidates pay the same internet egress: $0.114/GB for the first 10 TB a month, then $0.089/GB, from the Tokyo
region or from CloudFront's Japan edges. The difference is elsewhere:

| Candidate | Extra at design load |
|---|---|
| Stream through the API | About 42 more LCU per hour on the load balancer (1 LCU = 1 GB processed per hour): about $243 a month, plus about 0.4 vCPU in the API pods |
| CloudFront signed cookies | Range-chunk requests at $0.012 per 10,000 (a few dollars a month). S3 to CloudFront transfer is free. |

## 6. Prices: date and sources

Prices were looked up on **2026-11-03**, on-demand, in USD, from the AWS Price List bulk offer files
(`https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/<service>/current/<region>/index.json`, index at
[offers/v1.0/aws/index.json](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/index.json)) for ap-northeast-1 and
ap-northeast-3. The human-readable pages below show the same prices. They exclude tax: an account billed in Japan
also pays 10 % consumption tax.

| Service | Offer file published | Pricing page |
|---|---|---|
| EC2 instances | 2026-10-29 | [EC2 on-demand](https://aws.amazon.com/ec2/pricing/on-demand/) |
| NAT gateway, EBS gp3 (EC2 offer) | rows effective 2026-10-01 | [VPC](https://aws.amazon.com/vpc/pricing/), [EBS](https://aws.amazon.com/ebs/pricing/) |
| Interface endpoints, public IPv4 (VPC offer) | 2026-11-03 | [PrivateLink](https://aws.amazon.com/privatelink/pricing/), [VPC](https://aws.amazon.com/vpc/pricing/) |
| EKS | 2026-10-27 | [EKS](https://aws.amazon.com/eks/pricing/) |
| Elastic Load Balancing | 2026-11-02 | [ELB](https://aws.amazon.com/elasticloadbalancing/pricing/) |
| WAF | 2026-09-14 | [WAF](https://aws.amazon.com/waf/pricing/) |
| CloudFront | 2026-10-19 | [CloudFront](https://aws.amazon.com/cloudfront/pricing/) |
| Route 53 | 2026-09-11 | [Route 53](https://aws.amazon.com/route53/pricing/) |
| Aurora PostgreSQL (RDS offer) | 2026-10-29 | [Aurora](https://aws.amazon.com/rds/aurora/pricing/) |
| S3, including RTC | 2026-10-15 | [S3](https://aws.amazon.com/s3/pricing/) |
| Data transfer (internet, inter-Region, cross-AZ) | 2026-09-16 | [EC2 data transfer](https://aws.amazon.com/ec2/pricing/on-demand/#Data_Transfer) |
| SQS | 2026-09-11 | [SQS](https://aws.amazon.com/sqs/pricing/) |
| SES | 2026-10-27 | [SES](https://aws.amazon.com/ses/pricing/) |
| KMS | 2026-10-26 | [KMS](https://aws.amazon.com/kms/pricing/) |
| Secrets Manager | 2026-09-11 | [Secrets Manager](https://aws.amazon.com/secrets-manager/pricing/) |
| ElastiCache | 2026-10-28 | [ElastiCache](https://aws.amazon.com/elasticache/pricing/) |
| ECR | 2026-09-11 | [ECR](https://aws.amazon.com/ecr/pricing/) |
| CloudWatch | 2026-10-07 | [CloudWatch](https://aws.amazon.com/cloudwatch/pricing/) |
| GuardDuty | 2026-10-30 | [GuardDuty](https://aws.amazon.com/guardduty/pricing/) |
| AWS Config | 2026-09-11 | [Config](https://aws.amazon.com/config/pricing/) |

Facts from AWS documentation: Aurora global databases need memory-optimised instance classes
([configuration requirements](https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/aurora-global-database.configuration.requirements.html));
GuardDuty Malware Protection for S3 scans objects up to 100 GB
([quotas](https://docs.aws.amazon.com/guardduty/latest/ug/malware-protection-s3-quotas-guardduty.html));
ElastiCache Serverless for Valkey meters at least 100 MB per cache ([ElastiCache pricing](https://aws.amazon.com/elasticache/pricing/)).

**Not confirmed for these regions, used as assumptions:**

- Aurora global database cross-Region transfer: the pricing page says it is charged but gives no Tokyo example. This
  page applies the Tokyo → Osaka rate ($0.09/GB) to at most 4 KB per replicated write I/O (A13).
- Whether I/O-Optimized clusters still pay for replicated write I/O. Assumed yes, so section 4.3 leaves it out of both.
- The CloudFront-scoped web ACL is billed globally. Assumed to cost the same as the Tokyo regional rates ($5 per ACL,
  $1 per rule, $0.60 per million requests).
- ElastiCache ECPUs per rate-limit command: the page says 1 ECPU per KB for simple reads and writes; assumed 1 per
  `INCR` or `EXPIRE`.
- No cross-AZ charge between the Application Load Balancer and its targets.
- KMS bills $1 per key version: with automatic rotation a key costs up to $3 a month after its second rotation. The
  totals use $1 per key.
- Security services and CloudWatch volumes are usage estimates (A19, A20), not price lookups.
- Free tiers are ignored (for example 100 GB a month of internet egress, 1 TB a month from CloudFront, 1 M SQS
  requests).

## 7. Cost drivers, savings and budget

### 7.1 Biggest cost drivers

| Rank | (a) idle or demo, $2,926 | (b) design load, $10,680 |
|---|---|---|
| 1 | EKS worker nodes: $1,016 (35 %) | S3 replication to Osaka: $3,213 (30 %) |
| 2 | Aurora, 3 × db.r8g.large: $728 (25 %) | Internet egress for downloads: $2,962 (28 %) |
| 3 | NAT, interface endpoints and IPv4 in two regions: $686 (23 %) | EKS worker nodes: $1,185 (11 %) |

The byte-driven costs (replication and egress) come to about $0.20 per GB moved and dominate at design load; at idle,
the bill is almost entirely fixed infrastructure that exists for NFR-1, NFR-10 and NFR-11.

### 7.2 How to cut them

| Lever | Saves | Trade-off | Recommendation |
|---|---|---|---|
| Move file bytes at a sampled rate in load tests (PRD 6.1) | About $220 per day at the full byte rate ($114 egress + $105 replication) | The byte path is not tested at full rate | Keep. Add one 4-hour full-byte window per load test: about $36. |
| Run byte-heavy load generators inside Tokyo | Regional transfer via public IPs is $0.01/GB each way, not $0.114/GB | Applies only if downloads stream through the load balancer; doesn't exercise the internet path | Use for the full-byte window |
| Tear down dev and staging when idle (NFR-20) | About $2,170 a month against running both 24×7 | Rebuild time, bounded by NFR-19 (≤ 2 hours) | Keep, as planned |
| Osaka network in one AZ until failover (1 NAT gateway, endpoints in 1 AZ) | About $220 a month | Adds a Terraform step to the 55-minute failover budget (architecture section 7) | Decide in the compute ADR |
| Drop the Tokyo Aurora reader | $243 a month | AZ failover becomes creating a new instance, which can miss NFR-11's 5 minutes | Don't |
| Run the Osaka secondary without an instance (headless) | $242 a month | Failover must first add an instance | Not for prod; fine for staging outside drills |
| GuardDuty Malware Protection instead of ClamAV | About $271 a month at idle | About $3,859 a month at design load | Decide on capability in the scan ADR (section 5.4) |
| Stay on EKS standard support | Extended support adds $365 a month per cluster ($730 for prod's two) | Upgrade at least yearly | Upgrade within standard support |
| Shared KMS keys with per-tenant encryption context (open question 3) | Avoids about $1,000 a month for 500 per-tenant keys in two regions | Weaker per-tenant key isolation | Phase 3 decides |
| Downloads through CloudFront instead of streaming through the API | About $243 a month of load balancer capacity | Harder download counting (architecture 4.2) | Phase 3 decides (open question 8) |
| Filter WAF logs; keep EKS audit logs and log retention tight | Tens of dollars a month; logging every request at design load would add about $85 (1.5 KB per record) | Less detail for forensics | Log blocked and sampled requests |
| Spot instances for dev nodes | A large share of dev's $339 of EC2 (Spot prices vary; not modelled) | Interruptions | dev only, not staging during drills |
| Savings Plans or reserved instances | A discount for a 1- or 3-year commitment | Commits beyond a bounded operating period | Don't, unless the operating period runs a year or more |

Interface endpoints cost more than the NAT traffic they save at this volume ($368 a month for both regions). They stay,
because they keep traffic to AWS services off the internet (architecture 3.1); that is a security choice, not a
saving.

### 7.3 Recommended budget (open question 7)

| Phase | What runs | Expected per month | Monthly budget | Alarms at 50 / 80 / 100 % |
|---|---|---:|---:|---|
| Build, before prod exists | dev for 200 h; staging for the first rehearsals | $200–600 | $750 | $375 / $600 / $750 |
| Operating period | prod (a) $2,926, dev 200 h $196, staging 144 h $406, load tests and drills about $200 | about $3,730 | **$4,000** | **$2,000 / $3,200 / $4,000** |
| After teardown (NFR-19) | Prod audit archive in both regions and its KMS key | ≤ $5 | $5 | $2.50 / $4 / $5 |

- A reasonable range for the operating period is **$3,500 to $4,500** a month; the length of the period stays
  Rashid's call. Each extra month costs about $3,700; each extra day of prod about $96.
- AWS Budgets alarms fire on actual and forecast spend, defined in Terraform (NFR-20). If each environment has its own
  account (open question 4), split the $4,000 as dev $250, staging $500 and prod $3,250, each with the same 50/80/100 %
  alarms. A dev environment left running 24×7 ($715) trips its 80 % alarm within about 9 days.
- A sustained month at the full design load ($10,680) is not planned. A full week of it would cost about $2,460.
- The after-teardown cap is tight: two archive keys (primary and Osaka replica) cost $2 a month, or up to $6 after two
  rotations. Phase 3 should size key rotation and the number of archive copies against NFR-19's $5.
- Tag every resource with environment and component, so Cost Explorer can be compared line by line with section 5.

## 8. What to measure

The first load test (k6 at 1× and 2× design load, NFR-16) and its first week in prod must confirm or replace these
assumptions. Each result goes into the load-test report, and this page is updated in the same pull request.

| Measure | Confirms | How |
|---|---|---|
| CPU per API request and p95/p99 latency by pod count | A8, NFR-2 | Pod CPU metrics and latency histograms at 150/s and 300/s |
| ClamAV MB/s per vCPU and memory on a realistic file mix, including 2–5 GB files and archives | A9, open question 2 | Scan worker metrics; a dedicated 5 GB test |
| Time to shareable, p95, in the peak hour, for each scan pool | Section 3.3, NFR-5 | File state timestamps |
| Aurora read and write I/O per day, writer CPU, buffer cache hit ratio, global database lag | A13, sections 4.1 and 4.3 | CloudWatch `VolumeReadIOPs`, `VolumeWriteIOPs`, `AuroraGlobalDBReplicationLag` |
| S3 requests per uploaded file and replication bytes and latency | A10, NFR-10 | S3 request metrics, replication metrics |
| Bytes per download and egress per day, extrapolated from the sampled rate | A4 | Load balancer or CloudFront bytes |
| Node count and request packing at 1× and 2× | A16, section 4.2 | Karpenter and cluster metrics |
| NAT, cross-AZ and log volumes | A17, A18, A19 | VPC flow logs, Cost Explorer by usage type |
| Emails per transfer and per upload request | A6, A7 | Notification worker metrics |
| ECPUs per API request in the rate-limit cache | A24 | ElastiCache metrics |
| Daily cost by service against section 5 | The whole model | Cost Explorer with environment and component tags |
