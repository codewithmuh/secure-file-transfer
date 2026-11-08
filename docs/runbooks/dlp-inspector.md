# Runbook: DlpInspectorFailing

The alert of FR-47 ([abuse and rate limits](../security/abuse-and-rate-limits.md) 8.2), defined in
[`deploy/alerts/scanning.rules.yaml`](../../deploy/alerts/scanning.rules.yaml), with two conditions. Severity: page.

## Symptoms

- `condition="failure_rate"`: failed inspection attempts are above 1 % of inspections for 10 minutes
  (`dlp_inspector_failures_total{kind}`: the inspector's error codes `engine_error`, `sandbox_unavailable` and
  `bad_request`, and the worker's `malformed`, `protocol`, `timeout`, `connection` and `read`).
- `condition="failed_inspection"`: a file's inspection failed on every attempt
  (`dlp_inspection_results_total{state="failed"}`), so the file is blocked.

The NFR-23 p95 condition joins when staging measures NFR-23.

## Impact

A file whose inspection `failed` is blocked like a `scan_failed` file (FR-16, FR-47): its transfer is held, and its
`scan` tag is `inspection_failed`, so the API can't read it. A rising failure rate delays every scan, because a failed
attempt retries the whole scan.

## Confirm

```bash
# The worker's side: which kind of failure (never a file name or a value, NFR-26)
kubectl -n sft logs deploy/scan-worker-small --since=30m | grep 'inspection attempt failed'
# The inspector's side: one line per file with its state, reasons, size and duration
kubectl -n sft logs deploy/dlp-inspector-small --since=30m | tail -50
kubectl -n sft get pods -l app.kubernetes.io/component=dlp-inspector -o wide
```

The inspector's probes are on its own port, 8001, plain HTTP (#184): liveness `/healthz` says the process runs,
readiness `/readyz` that it listens on 8070. A probe never reaches the framed protocol, so probes add no
`bad_request`. A pod that restarts often with failed liveness is a crashed or wedged parent, not a slow file.

- `malformed` means the inspector answered outside its schema (an unknown detector, too many previews): an image
  mismatch between the worker and the inspector, or an exploited parser (threat model T-92). Treat a burst as a
  security event.
- `sandbox_unavailable` means the child process couldn't start its sandbox (seccomp, rlimits): check the node's kernel
  and the pod's security context.
- `timeout` on most files means the inspector is starved of CPU, or the scratch volume is slow.
- `bad_request` on every file of **one tenant** means the inspector refuses that tenant's own detectors (#218), which
  the API checks when they are saved: an inspector image newer than the API's, whose detector library is stricter.
  Scans of one tenant failing before any engine runs (the message reaches the dead-letter queue, the file waits for
  the scan sweep) mean the worker couldn't open a stored detector definition.

## Mitigate

1. **Inspector pods crash-looping**: roll back the last image change; the worker's and the inspector's images must be
   the same build (one image, ADR-0022).
2. **Timeouts**: check the scan nodes' CPU and scratch throughput; capacity 4.2 sizes the inspector.
3. **One file fails every attempt** (a parser bug on that input): the file stays blocked, which is correct. Keep the
   inspector's log line and the file's ID for the fuzzing corpus; the member removes the file.
4. **One tenant's files fail** (`bad_request`, or a definition the worker can't open): bring the worker and the
   inspector to the same build; if that isn't it, ask the tenant's admin to change or delete the keyword list the
   newer library refuses (`updateDlpDetector`, `deleteDlpDetector`).

## Escalate

If more than a few files fail in 30 minutes, or `malformed` appears at all, escalate to the owner in
[CODEOWNERS](../../.github/CODEOWNERS).

## Afterwards

Write a blameless postmortem: timeline, impact, root cause, action items with owners.
