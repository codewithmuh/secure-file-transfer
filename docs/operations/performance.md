# Performance: the load test, the inspection benchmark and the upload test

| | |
|---|---|
| Requirements | [PRD](../prd.md) NFR-2, NFR-3, NFR-4, NFR-5, NFR-16, NFR-23; design load 6.1 |
| Design | [Capacity estimate](../design/capacity-and-cost.md) 3.1, 3.3, 3.5, A42 and section 8; [abuse and rate limits](../security/abuse-and-rate-limits.md) 2.2 |
| Tracking | [#249](https://github.com/codewithmuh/secure-file-transfer/issues/249) load test, [#250](https://github.com/codewithmuh/secure-file-transfer/issues/250) NFR-23 benchmark, [#251](https://github.com/codewithmuh/secure-file-transfer/issues/251) NFR-3 upload test; the synthetic probe ([#248](https://github.com/codewithmuh/secure-file-transfer/issues/248)) has its own [runbook](../runbooks/synthetic-probe.md) |

Three measurements, each with a scaled-down run that needs only a laptop and a full run in staging. Every staging run
is **pending the AWS run**: the code, the workflow and the job are written and checked statically; the numbers in
section 5 come with the first staging window.

| NFR | Target | Measured by | Section |
|---|---|---|---|
| NFR-2 | API calls p95 ≤ 300 ms, p99 ≤ 1 s at design load, file bytes excluded | k6 thresholds; `http_request_duration_seconds` | 1 |
| NFR-4 | A download's first byte p95 ≤ 1 s | k6 threshold on the stream's wait; the synthetic probe's `synthetic_probe_download_first_byte_seconds` | 1 |
| NFR-5 | Time to shareable p95 ≤ 2 min (largest file ≤ 100 MB), ≤ 15 min otherwise | k6 thresholds; `time_to_shareable_seconds` | 1 |
| NFR-16 | The design load at 1× and 2× with no manual action | The 1× and 2× staging runs, with Karpenter and the scan pools scaling on their own | 1 |
| NFR-23 | Scan start to both results: p95 ≤ 60 s, p99 ≤ 3 min up to 100 MB; p95 ≤ 10 min up to 2 GB | The benchmark; `scan_pass_duration_seconds` during the load test | 2 |
| NFR-3 | 5 GB over 100 Mbit/s in ≤ 8 min; resume without re-sending a completed part | The browser test | 3 |

## 1. The design-load test (k6, #249)

[`loadtest/k6/design-load.js`](../../loadtest/k6/design-load.js), run in the pinned `grafana/k6` image by
[`loadtest/run.sh`](../../loadtest/run.sh). It drives the peak hour of the design load (the PRD's 6.1 and [CAP] 3.1)
times a profile's `factor`, through the public API only, as the web app and a customer's integration do:

| Scenario | At 1× | One iteration |
|---|---|---|
| `transfers` | 1,000 an hour | `createTransfer` to 2 recipients; 1 to 5 files of the mix, each `addTransferFile`, part URLs, the parts `PUT` 4 at a time, `completeUpload`; `sendTransfer`; `getTransfer` until `sent` (time to shareable); then each recipient reads the link email, verifies with a code and downloads about 83 % of the files |
| `upload_requests` | 250 an hour | `createUploadRequest`; the uploader verifies and uploads 1 to 5 files through the link session; `listUploadRequestFiles` until each file is available (time to shareable per file) |
| `api_reads` | 138 a second | One read a member's web app or integration makes: transfer and request lists, the tenant policy |

That is about 150 API calls a second, 5,000 downloads and about 2,250 verifications an hour at 1×. **The file mix**
([`lib/corpus.js`](../../loadtest/k6/lib/corpus.js)) follows [CAP] A4, A9, A38 and A45: sizes in log-uniform bands
(25 % up to 1 MB, 50 % 1–10 MB, 17 % 10–100 MB, 7.4 % 100–500 MB, 0.5 % 500 MB–2 GB, 0.1 % 2–5 GB; a mean of about
36 MB); 42 % of files up to 100 MB and 20 % above carry text, so about 40 % of files and 25 % of bytes; a quarter of the
text files hold a synthetic My Number, made at run time (A46). **Bytes are sampled** ([PRD] 6.1, A42): each file keeps
its drawn size with the profile's `bytesSample` probability and is otherwise 64 KiB, so every API call happens at full
rate while only a share of the bytes moves; NFR-5's size class follows the bytes that moved.

**Thresholds** (a missed one fails the run):

| Threshold | NFR |
|---|---|
| `http_req_duration{kind:api}` p95 ≤ 300 ms, p99 ≤ 1 s | NFR-2: every API call, part uploads and download streams excluded (`kind:bytes`) |
| `http_req_waiting{name:getSessionDownloadContent}` p95 ≤ 1 s | NFR-4 |
| `time_to_shareable{kind:transfer, size_class:small}` p95 ≤ 2 min, `large` ≤ 15 min; the same for `kind:request_file` | NFR-5: from the last `completeUpload` to `sent`, or a received file to `shareable` |
| `http_req_failed{kind:api}` < 0.1 %, `journeys_completed` ≥ 99.9 % | NFR-1's budget for the run |

The client's view stops at `sent`; the recipients' emails reach SES after it (NFR-7, p95 ≤ 10 s), which the
server-side `time_to_shareable_seconds` histogram (APP, #242) includes. The run's record is the server's histograms in
Grafana for its window; k6's thresholds fail the run without anyone opening a dashboard.

### Decisions

- **API keys, not member sessions.** Each load-test tenant's keys act as its admin. Group H allows 300 calls a minute
  per key and 1,000 per tenant, and group G 200 recipient emails an hour per key and 2,000 per tenant ([ABUSE] 2.2):
  1× needs 10 tenants and 2× 20, so staging has **25 tenants with 3 keys each**, round-robin by iteration.
- **Monitor mode.** An API key can't confirm a DLP warning (`confirmTransfer`), and the default policy warns on a new
  recipient domain, so the load-test tenants' policies are in monitor mode: every decision is still made and recorded
  (FR-52), and inspection runs on every file.
- **A fresh address per recipient and uploader** (`lt-<kind>-<shard>-<vu>-<iteration>-<time>@loadtest.<domain>`), so
  no per-address cap counts the test twice.
- **Shards for per-IP limits.** NFR-14 keeps 60 link steps a minute and 300 download grants an hour per IP. At 1× the
  recipients make about 8,400 link steps and 5,000 grants an hour, so one source address would be refused. The
  workflow splits the load into k6 execution segments, one per job on its own GitHub-hosted runner, each from its own
  address: 20 shards at 1× (250 grants an hour each), 40 at 2×. A plan that runs fewer than 40 jobs at once runs 2× as
  two 20-shard halves of the profile on the same window, or accepts `429`s on grants, which then fail the run and say so.
- **Expiry, not revocation, ends the test's transfers** (`expires_in: PT1H`): the lifecycle jobs delete them, so the
  run exercises deletion at its real rate too.
- **The mailbox.** Recipients and uploaders read their link and code emails through Mailpit's search API: Mailpit
  locally, and in staging [`loadtest/mailbox_bridge.py`](../../loadtest/mailbox_bridge.py), which serves the same two
  calls from the SES receipt rule's bucket (`loadtest/`, the probe mailbox bucket), one bridge per shard taking only its
  own shard's mail.
- **No URL in any metric**: part URLs carry their signature, so `url` isn't a system tag; requests are named by
  operation ID.

### Locally (the scaled-down run)

The `local` profile is 5 % of the peak hour for 5 minutes, files up to 8 MB, all bytes moved: about 4 transfers, 1 upload
request and 7 reads a second, inside every per-IP and per-key limit from one address.

```bash
make up && make seed
uv run --project services/api python loadtest/setup_local.py --out /tmp/sft-loadtest-keys.json
loadtest/run.sh local /tmp/sft-loadtest-keys.json /tmp/sft-loadtest
```

`setup_local.py` writes two load-test tenants, their admins, monitor mode and two keys each into the local database,
as the seed does, and the keys to the file only (mode 0600). On Docker Desktop the k6 container reaches the stack as
`host.docker.internal`; part URLs and Mailpit's `Host` check are adjusted by `run.sh`. The summary is
`/tmp/sft-loadtest/summary-local.json`, and the run exits non-zero when a threshold is missed.

### In staging (1× and 2×; pending the AWS run)

The manual workflow [`loadtest.yml`](../../.github/workflows/loadtest.yml) (Actions → loadtest → Run workflow, from
`main`): a profile (`staging-1x`: 5 hours inside GitHub's 6-hour job limit; `staging-2x`: 4 hours) and the shards. It
never runs against prod: it has no environment input, assumes only staging's load-test role, and `run.sh` refuses any
API but `https://api.staging.<domain>`. Before the first window:

1. SES quotas in both regions of at least 100,000 emails a day and 20 a second ([CAP] 3.2), production access.
2. The receipt rule for `loadtest.<staging domain>` writing to the mailbox bucket under `loadtest/` (the probe's rule
   writes `probe/`), and its MX record.
3. 25 tenants (`createTenant`), each admin signed in once with a passkey, monitor mode, 3 keys each with the four
   transfer and upload-request scopes; the 75 keys as `[{"tenant": ..., "key": ...}]` in `sft/staging/loadtest/api-keys`.
4. The role `LOADTEST_ROLE_ARN` (OIDC, `loadtest-staging` environment, main only): read that secret, list, read and
   delete under `loadtest/` in the mailbox bucket. Repository variables `STAGING_SERVICE_DOMAIN`,
   `LOADTEST_MAILBOX_BUCKET`.
5. The budget: one window is about $276 ([CAP] 7.3, A42); tear staging down after it (NFR-20).

**Where the results go.** Each shard's summary is a workflow artifact. The run's numbers (k6's thresholds per shard
and the server-side percentiles from Grafana for the window), with node counts, pod CPU and the scan pools' sizes, go in
section 5 below, and the capacity estimate's section 8 assumptions are confirmed or replaced in the same pull request.

## 2. The NFR-23 inspection benchmark (#250)

[`services/api/tools/benchmark_inspection.py`](../../services/api/tools/benchmark_inspection.py) feeds the design-load
mix of file types through the scan worker's own pass: `ScanConsumer._read_once`, the one read teed to clamd and the DLP
inspector with the worker's lanes, stall rule and timeouts, then `_decide` as on a last attempt. It times each file and
reports p95 and p99 per size class (up to 100 MB; 100 MB to 2 GB), and per type, and exits 1 if a threshold is missed or
a file failed. The corpus is made in memory at run time from a seed: plain text (UTF-8 and Shift_JIS), CSV, `.docx`,
`.xlsx`, PDF with a text layer and zip archives, a quarter with a synthetic My Number, and binaries; 42 % text up to
100 MB and 20 % above ([CAP] A45). Each file is made when its scan starts and dropped after, so memory holds
`--concurrency` files.

It leaves out the S3 read and the database transaction around the pass; the load test's `scan_pass_duration_seconds`
(APP, #242) is the whole pass at design load, so the two together are NFR-23's measure: the benchmark isolates the
engines, the load test adds the platform.

**Locally**, against the stack's clamd and inspector (their ports published, or from a container on the stack's
networks):

```bash
cd services/api
uv run python -m tools.benchmark_inspection --clamd 127.0.0.1:3310 --inspector 127.0.0.1:8070 \
  --files 60 --large 1 --max-bytes 20000000 --max-large-bytes 120000000 --concurrency 2 --json /tmp/nfr23.json
```

The inspector listens only on its internal network in compose; publish its port for the run, or run the tool inside a
container on the `inspection` network. `tests/test_benchmark_inspection.py` runs the same pass against the worker's
stand-ins with the real extraction and detectors in process, in CI.

**In staging (pending the AWS run)**, as a Job on each scan node beside its trio
([`loadtest/benchmark-inspection-job.yaml`](../../loadtest/benchmark-inspection-job.yaml)): the application image
staging runs, the tool from a ConfigMap, 300 files up to 100 MB and 10 from 100 MB to 2 GB, during the load test's
window so the engines share the node as they do at design load.

## 3. The NFR-3 upload test in the browser (#251, #267)

[`web/e2e/upload-resume.e2e.ts`](../../web/e2e/upload-resume.e2e.ts), a browser flow of `make web-e2e`, in CI's Local
stack job on every pull request. A member uploads a large file through the web app's upload engine over a link the
test controls (#267): every request of the page goes through `page.route`, and the part PUTs to the S3 stand-in go on
through a small proxy in the test that sends each body at the line rate, shared by every part in flight as one link
is, and times each part. When half the parts have landed the link drops: every request fails until it comes back, and
each part in flight is cut half sent, so S3 never assembles it. Chromium's own throttle
(`Network.emulateNetworkConditions`), which #251 used, didn't slow the part PUTs in CI, so every part had landed
before the cut. The file is a PNG signature then pseudo-random bytes, which the DLP inspector names unsupported without
decoding (`sft.dlp.extract._sniff`), so the scan takes seconds: #251's 40 MiB of words held the stack's one small-pool
scan worker for 214 s and starved the specs beside it. It passes when:

- the throttle reached the part PUTs: no part landed faster than its size at the line rate, and the link carried no
  more than the rate (5 % for timer slack);
- the cut stopped at least one part in flight, so the test proved something;
- every part is in S3 and none landed twice, and no part was sent again after it landed: not one that landed before
  the cut, not one whose answer the cut lost (the engine finds it with `listUploadedParts`), so the spec fails if a
  completed part is sent again;
- `completeUpload` answers `200`, within the line rate plus 10 %, plus the outage and 20 s for the engine's retry wait
  and the bytes the cut threw away.

| Run | File | Link | Outage |
|---|---|---|---|
| Scaled (default) | 40 MiB, 8 parts | 40 Mbit/s | 5 s |
| NFR-3 (manual) | 5 GB (`E2E_UPLOAD_MIB=4769`) | 100 Mbit/s (`E2E_UPLOAD_MBITS=100`) | 5 s, or `E2E_UPLOAD_OUTAGE_SECONDS` |

```bash
make up && make seed
E2E_ARGS='e2e/upload-resume.e2e.ts' E2E_UPLOAD_MIB=4769 E2E_UPLOAD_MBITS=100 make web-e2e
```

The full run writes the 5 GB file to the Playwright container's temporary directory and needs that much free disk. The
time it reports (the test's `NFR-3` annotation) against 8 minutes, without the outage, is NFR-3's number.

## 4. The synthetic probe

NFR-1's outside view and NFR-4's synthetic measure: [runbooks/synthetic-probe.md](../runbooks/synthetic-probe.md).
`tests/test_probe_local.py` runs it against the local stack.

## 5. Results

| Measurement | Where | Result |
|---|---|---|
| k6, local profile | Laptop | Pending: to be run with `make up` (the build's container runtime was unavailable) |
| k6, 1× | Staging | Pending the AWS run |
| k6, 2× | Staging | Pending the AWS run |
| NFR-23 benchmark, local | Laptop, real clamd and inspector | Pending: to be run with `make up` |
| NFR-23 benchmark, stand-ins | 60 files to 20 MB and one of 110 MB, concurrency 2, real extraction and detectors in process, a stand-in for clamd | Small p95 7.9 s, p99 18.7 s; large 7.1 s: passes, as a check of the tool, not of NFR-23 |
| NFR-23 benchmark | Staging, scan nodes | Pending the AWS run |
| NFR-3, scaled | CI's Local stack job | Runs on the pull request |
| NFR-3, 5 GB at 100 Mbit/s | Laptop | Pending: manual run |
