# 0022. Inspect files for sensitive data with our own detectors, in sandboxed pods beside the scan workers

- Status: accepted
- Date: 2026-11-04
- Issue: [#64](https://github.com/codewithmuh/secure-file-transfer/issues/64)

## Context

The [PRD](../prd.md) adds data loss prevention to v1 (FR-36 to FR-56). Every uploaded file is inspected for sensitive
data before it can become shareable (FR-36), and a tenant's rules decide whether a transfer is sent, needs the sender's
confirmation, needs an approver, or is blocked (FR-40, FR-41). The inspection has to:

- **Gate sending, inline.** Nothing reaches a recipient until the decision allows it (FR-41), and NFR-5's 2-minute
  target for files up to 100 MB includes inspection (NFR-23). Finding data at rest a day later is too late.
- **Find Japanese identifiers in Japanese text.** My Numbers and corporate numbers with their check digits, Japanese
  bank accounts, passports, driver's licences and phone numbers, in UTF-8 and Shift_JIS files, with tenant keywords in
  full-width and half-width forms and no word boundaries ([detectors](../design/dlp-detectors.md), FR-37, FR-38).
- **Cover the formats people send.** Text and CSV, Office Open XML, PDF and zip archives, up to the sizes of FR-2,
  and say what isn't covered instead of reporting "no findings" (FR-47, NFR-24).
- **Keep file contents where they are.** File contents are Restricted data: only in our files buckets, our scan pods
  and the API's memory, and only in Japan ([encryption and keys](../security/encryption-and-keys.md) 1, NFR-21).
- **Keep the moving parts few** (CLAUDE.md): one API service plus workers, one system of record.

Two facts of the existing design shape the answer. The scan worker reads each file's recorded version once, streams it
to clamd, and then sets the `scan` tag; its IAM role may read only untagged objects
([ADR-0019](0019-malware-scanning-clamav-guardduty.md), architecture 3.1). So inspection has to happen in that same
pass, or the worker needs a wider read permission. And document parsers are a large attack surface: PDF, XML and zip
parsing is where crafted files find memory bugs and resource exhaustion, which is why ADR-0019 moved clamd into pods
with no credentials.

**What was checked on 2026-11-04:**

- **Amazon Macie.** Its managed data identifiers have no Japanese types: no My Number, corporate number, Japanese
  passport, driver's licence or bank account, and phone numbers only for eight other countries. Custom identifiers
  are a regular expression with keywords and can't check a check digit. Discovery runs as jobs, one-time or on a
  daily, weekly or monthly schedule, with results written to S3 and findings sent to EventBridge; there is no call that
  inspects one object on demand, so it can't gate a transfer. It costs about $1 per GB inspected in US East, and
  analyses at most 5 TB a month per account by default. It doesn't analyse a PDF over 1,024 MB or a Word or Excel file
  over 512 MB.
- **Amazon Comprehend.** PII detection supports English and Spanish only, and it takes text, so extraction would stay
  ours anyway.
- **Microsoft Presidio** (MIT licence). Its list of supported entities has country-specific recognizers for the US,
  the UK, several EU countries, India, Australia, Singapore, Korea and others, and none for Japan. Named-entity
  recognition in Japanese needs a Japanese NLP pipeline.
- **Hosted DLP APIs** from another cloud provider or a DLP vendor. The larger ones have Japanese identifier types. The
  largest lists content inspection at $2–3 per GB after the first GB.

## Decision

Inspect with **our own detector library**, in a **DLP inspector**: its own Deployment of pods with no credentials and
no network, one beside each scan worker, fed by the same pass that streams the file to clamd.

- **Detectors.** A Python package in the one codebase (ADR-0002, ADR-0010): patterns compiled with RE2, which runs in
  linear time; validators in Python for check digits, Luhn, IBAN's mod 97 and phone numbers (the `phonenumbers` port
  of libphonenumber); context keywords and CSV and spreadsheet column headers for confidence. The built-in set, the
  normalisation of Japanese text and the accuracy tests are in the [detector specification](../design/dlp-detectors.md).
- **One pass.** The scan worker reads the recorded object version and streams it to clamd and to its inspector at the
  same time. It records the malware result, the inspection result and the findings in one transaction, then sets the
  `scan` tag. Its IAM permissions don't change: it still reads only untagged objects. Files over 2,000,000,000 bytes,
  which GuardDuty scans and the worker never reads, aren't inspected; they are marked `not_inspected` with the reason
  `too_large`, and the tenant's rules decide (FR-47).
- **Formats.** Plain text, CSV and TSV in UTF-8 (with or without a byte order mark), UTF-16 with a byte order mark,
  Shift_JIS (CP932), EUC-JP and ISO-2022-JP; Office Open XML (`.docx`, `.xlsx`, `.pptx` and their macro-enabled forms)
  and OpenDocument text, spreadsheets and presentations; PDF text layers; zip, gzip and tar archives, recursively. The
  type comes from the bytes, never from the name or the declared type. **Not in v1:** OCR of images and of PDFs with no
  text layer, legacy binary Office files (`.doc`, `.xls`, `.ppt`) and RTF, 7z, RAR and LZH archives, email files and
  their attachments, and text inside images embedded in documents. Each of these gets a reason, never a pass.
- **Limits per file.** At most 2,000,000,000 bytes in; 3 levels of nesting (an Office file counts as one); 10,000
  archive members; 4 GiB decompressed and a 100:1 ratio per member; 256 MiB of extracted text; 5,000 PDF pages;
  10 minutes of CPU and 15 of wall-clock time; 2 GiB of memory. Past a limit, the rest isn't inspected, the file is
  `partial` with the reason `limit_exceeded`, and the findings so far count. A limit is never a pass.
- **Parsers.** `zipfile` and `tarfile` from the standard library behind our own limit checks; XML through `lxml` with
  DTDs, entity expansion and network access off; PDF text through PDFium (`pypdfium2`, Apache-2.0 or BSD-3-Clause), a
  build without JavaScript or XFA. No parser with a copyleft licence, and none that shells out.
- **Isolation, as for clamd.** The inspector runs from the application image with its own entry point. Its pods get no
  service account token and no IAM role, and reach no database, counter store or secret. Their network policy allows
  ingress only from the scan workers, and no egress at all, not even DNS. They run non-root, with a read-only root file
  system, no capabilities, no privilege escalation and the `RuntimeDefault` seccomp profile, on the scan node pool
  whose volumes use the files key.
- **A fresh process per file.** The inspector's parent process only receives the stream and writes it to a 4 GiB
  scratch volume; it never parses. For each file it forks a child that sets resource limits (address space, CPU time,
  file size, no core dumps), installs a seccomp filter that refuses new sockets, `execve` and `ptrace`, then extracts,
  runs the detectors and writes the result to a pipe. The parent kills a child that passes the wall-clock limit, and
  deletes the scratch files after every file. An exploited parser can falsify only its own file's result, and holds
  nothing to authenticate with.
- **Untrusted output.** The scan worker treats the inspector's answer as hostile input: a strict schema, known detector
  IDs only, bounded counts, at most 10 location hints and 3 masked previews per detector, bounded lengths. Anything
  else counts as an engine error: retried, then `failed`, which blocks the file and alerts an operator (FR-47), as
  `scan_failed` does.
- **Early stop.** The inspector reads the first 64 KiB. For a type it can't extract, such as an image, a video or a
  binary, it tells the worker to stop sending, so only clamd gets the rest of the bytes.
- **Tenant detectors travel with the file.** The worker reads the tenant's keyword lists and patterns, decrypts them
  with the tenant's DLP data key ([encryption and keys](../security/encryption-and-keys.md) 3.3) and sends them with
  the file; the inspector keeps nothing between files.
- **Decisions stay outside the sandbox.** The inspector only returns findings. The transfer's evaluation, under its row
  lock, applies the tenant's rules (architecture 4.6, data model 3.2). A transfer's message is plain text of at most
  2,000 characters, so the API runs the same detectors on it in process when the transfer is created (FR-50).
- **Fuzzing.** The extraction entry points are fuzzed nightly with Atheris (Apache-2.0), seeded from the synthetic
  corpus, and the parser libraries are tracked for advisories and patched weekly with the rest of the image.

## Options considered

| Option | Pros | Cons |
|---|---|---|
| **Our own detectors in sandboxed inspector pods beside the scan workers** (chosen) | Inline: one read of the bytes, in parallel with clamd, so it gates sending within NFR-5. Japanese identifiers with their real check digits, Japanese keywords without word boundaries, Shift_JIS. File contents stay in our pods, in Japan. No new queue, service or per-GB fee: one more Deployment in the scan pipeline, from the same image, scaled with the scan workers. Detectors, limits and results are ours to test in CI on a synthetic corpus. | We write and maintain every detector and its corpus, and accuracy is only as good as our tests. Parsers of hostile documents run in our pods, so the sandbox, the limits and the patching are ours. The scan nodes double in size: about $423 a month more at idle (capacity 3.5). No names, addresses or OCR in v1. |
| Presidio with custom recognizers, in the same pods | A recognizer framework with context words and anonymizers; adds named-entity recognition for names and places if a model is loaded | No Japanese recognizers, so every one is ours anyway. Named-entity recognition in Japanese needs a Japanese NLP pipeline and models of hundreds of MB, CPU-heavy at 1 TB a day. Its context scoring uses the NLP pipeline's lemmas, which our column-header context doesn't need. Its recognizer shape can be copied without its runtime; it can come later if names and addresses are added. |
| Amazon Macie | Managed, no parsers in our pods; many file types and archive limits built in; good at finding data at rest | No Japanese identifiers. Jobs run on a schedule, not per object, so it can't hold a transfer within NFR-5. About $27,000 a month at design load (about 27 TB inspected a month at $1 per GB), with the 5 TB default quota raised. It reads every object through its own role. Size caps (512 MB for Office files) below FR-2. |
| Amazon Comprehend PII detection, with our own extraction | Managed text analysis | PII detection in English and Spanish only, and no Japanese identifiers. Extraction, and its sandbox, stay ours anyway. Text of every file goes to another service, per unit of text. |
| A hosted third-party DLP API | Japanese identifier types in the larger services; maintained by the vendor | File contents leave AWS: a new trust boundary, a credential, an egress allowlist entry, and residency only where the vendor has a Japan endpoint. About $55,000–82,000 a month at design load at $2–3 per GB, plus egress. A vendor outage holds every transfer. |
| Inspection inside the scan worker process | Fewest parts: no new pods | The worker holds an IAM role, database access and the counter store. A parser exploit would get all three, the reason ADR-0019 moved clamd out of the worker. |
| A separate inspection service with its own queue | Scales on its own; could re-inspect files later | A second queue, a second consumer and a second read of every file, which needs a role that reads tagged objects. More moving parts for the same inspection. |

## Consequences

- **Sizing and cost** (capacity 3.5, 4.2 and 7.3). The inspector requests 1.5 vCPU and 2.5 GiB (limit 3 GiB) with 4 GiB
  of scratch. A worker, its clamd pod and its inspector no longer fit an m8g.large, so the scan pool moves to
  m8g.xlarge, still one trio per node at 77 % of allocatable CPU, with the same node counts. That adds about $423 a
  month to prod at idle and about $620 at design load, with the KMS requests, email and Aurora storage DLP adds. The
  planned operating month becomes about $5,292, **81 % of the $6,500 cap and about $90 over its 80 % alarm**. Capacity
  7.3 recommends raising the cap to $7,500, or cutting about $490 a month; the maintainer decides (PRD open question 7).
  This amends the scan pool's instance type in ADR-0004 and ADR-0019.
- **Latency.** Inspection runs while clamd scans, so a scan job takes the longer of the two. A 100 MB document takes
  about 9 s to inspect against clamd's 7 s; a text-heavy 2 GB archive about 3 minutes against 2. Both writers share
  the node volume's 125 MB/s, so a 2 GB file lands on both scratches in about 32 s, not 16. Staging measures it
  (NFR-23); provisioned gp3 throughput is the lever, about $6 a node a month.
- **No re-inspection.** The worker never reads a file after its tag is set, so a keyword or pattern added later
  applies only to files inspected after the change; drafts open across the change keep their findings. That follows
  the rule the scan already uses for `unscannable_allowed` (data model 3.1). Re-inspecting would need a role that reads
  every tagged file, a wider permission than this design accepts.
- **The determined insider.** A sender who encrypts, splits data over days, photographs or retypes it gets past any
  content inspection. Encrypted and uninspectable files get a reason that rules act on (FR-47), and counts add up
  across a transfer and, optionally, 24 hours (FR-48, FR-49); what remains is accepted as threat model R-16 and R-17.
- **Detection quality is ours.** The synthetic corpus and its CI targets (NFR-25) are the only measure: there is no
  real data to tune on. False positives cost senders a confirmation, so the default policy warns rather than blocks,
  and monitor mode (FR-52) lets a tenant see a policy's effect first.
- **The scan worker gets more to do and to hold.** It decrypts the tenant's DLP data key, under a key policy limited to
  that purpose ([encryption and keys](../security/encryption-and-keys.md) 4.3), reads the tenant's rules and
  recipient domains for the evaluation, and writes findings it can't read back (data model 4.2).
- **Supply chain.** PDFium, libxml2 (through lxml), RE2 and libphonenumber's metadata join the image's patched,
  scanned dependencies, and the fuzzing job and its crashes become part of CI's signal.
- **Where it is recorded.** The [architecture](../architecture.md) (containers, 3.1, 4.1 and 4.6), the
  [data model](../design/data-model.md) (2.7, 3.5), the [threat model](../threat-model.md) (TB-6, 4.19), the
  [detector specification](../design/dlp-detectors.md) and the [capacity estimate](../design/capacity-and-cost.md)
  (3.5).

When to revisit: if NFR-25's targets can't be met for a detector; if tenants need OCR or names and addresses, which
would bring an OCR engine or a Japanese named-entity model into the inspector, and probably a GPU-free model budget; if
an AWS service gains on-demand inspection with Japanese identifiers in Tokyo; if staging misses NFR-23; or if the
operating budget can't carry the larger scan nodes.
