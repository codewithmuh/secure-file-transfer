"""The synthetic probe (NFR-1, NFR-4; #248): `python -m sft.probe`, every 5 minutes, as a CronJob.

One run is the whole external journey, through the public API only, as the dedicated synthetic
tenant's API key and as a recipient in the probe's own mailbox (docs/runbooks/synthetic-probe.md):

1. `edge`: the public API host serves no probe, metric or docs path, and the web app's origin, over
   HTTPS, sends HSTS, a CSP with `frame-ancestors` and `Referrer-Policy` ([THREAT] T-01 to T-05).
2. `create`: a transfer to one address in the probe mailbox, a fresh one each run
   (`<local part>+<run>@<mailbox domain>`), so no per-address cap of NFR-14 ever binds and no
   exemption exists in the service.
3. `upload`: one small file of words, different every run, through a part URL straight to S3.
4. `send`: `sendTransfer`.
5. `shareable`: the transfer reaches `sent` (scanned, inspected, decided, NFR-5).
6. `link_email`: the link email arrives in the mailbox (NFR-7).
7. `verify`: resolve the link, ask for a code, read it from the mailbox, start a link session.
8. `download`: a grant and the streamed bytes, compared with what was uploaded; the time to the
   first byte is NFR-4's synthetic measure.
9. `revoke`: `revokeTransfer`, which triggers the deletion of the file (PRD data lifecycle). It runs
   whatever happened before, once a transfer exists, so a failed run leaves nothing shared.

A failing step names itself: in the log line, in `synthetic_probe_step_failures_total{step}` and in
the exit status. The result goes to the Pushgateway (`sft.probe.report`) and, in AWS, to CloudWatch
(`SecureFileTransfer/Probe`, `ProbeSuccess`), which the promotion gate and the watchdog read.

Of the service's own code the package imports only `sft.core` (pyproject's import contracts): it
sees the service exactly as a customer does.
"""
