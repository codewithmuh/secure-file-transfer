# Runbook: SyntheticProbeFailing, SyntheticProbeStale, probe-failing

The synthetic probe of NFR-1 and NFR-4 ([#248](https://github.com/codewithmuh/secure-file-transfer/issues/248)): every
5 minutes, a CronJob (`synthetic-probe`, [`deploy/charts/sft/templates/probe.yaml`](../../deploy/charts/sft/templates/probe.yaml))
runs `python -m sft.probe`, the whole send → verify → download journey through the public API, as the dedicated
synthetic tenant and as a recipient in the probe's own mailbox. The alerts on it are in
[`deploy/alerts/probe.rules.yaml`](../../deploy/alerts/probe.rules.yaml): `SyntheticProbeFailing` on
`synthetic_probe_success` (failed for 10 minutes) and `SyntheticProbeStale` on
`synthetic_probe_last_success_timestamp_seconds` (no pass for 15 minutes, a probe that stopped reporting included);
and, outside the cluster, the `probe-failing` CloudWatch alarm on `SecureFileTransfer/Probe` `ProbeSuccess` for the
environment ([`infra/modules/alarms/probe.tf`](../../infra/modules/alarms/probe.tf), once `TF_VAR_probe_enabled` is
true), which treats missing data as breaching, so a probe that stops running alarms too (ADR-0009). Severity: page,
in every environment, like every page (each environment pages its own topic). The same metric, by image digest, is
what `promotion-gate` reads before a promotion (ADR-0005).

## What a run does

| Step | What it checks | A failure usually means |
|---|---|---|
| `edge` | `/metrics`, `/healthz`, `/readyz`, `/docs`, `/redoc` and `/openapi.json` are not served on the public API host; over HTTPS the web app sends HSTS, a CSP with `frame-ancestors` and `Referrer-Policy` ([THREAT] T-01 to T-05) | A routing or CDN change exposed an internal path or dropped a header: treat as a security incident first |
| `create` | `createTransfer` as the synthetic tenant's API key, to `probe+<run>@probe.<serviceDomain>` | The key was revoked or expired (401), the tenant suspended, or the API is down |
| `upload` | `addTransferFile`, one part URL, the `PUT` to S3, `completeUpload` | S3, the files key, or the API's S3 permissions |
| `send` | `sendTransfer` | The evaluation or the outbox |
| `shareable` | The transfer reaches `sent` within 150 s (NFR-5's 2 minutes, plus margin) | The scan pipeline: the relay, the small scan pool, clamd, the DLP inspector ([scan-failed.md](scan-failed.md), [dlp-inspector.md](dlp-inspector.md)). `the transfer became awaiting_confirmation` means the synthetic tenant's DLP policy left monitor mode (setup, step 4) |
| `link_email` | The link email reaches the probe mailbox within 90 s | The notification worker, SES sending, or SES receiving into the mailbox bucket |
| `verify` | `resolveLink`, `requestVerificationCode`, the code email, `createLinkSession` | Codes not sent, the counter store (link steps fail closed), or a WAF rule |
| `download` | `listSessionFiles`, `createSessionDownload` and the stream; the bytes match what was uploaded; the time to the first byte is NFR-4's synthetic measure | The download path: the grant's audit write (fails closed, NFR-15), the archive in both regions, S3 reads |
| `revoke` | `revokeTransfer`, whatever happened before, once a transfer exists | A `503` means the revocation took effect but its record isn't in both regions' archive yet ([THREAT] T-81) |

A failed run names its step, with the operation and its status or problem code, in its log line (`probe failed`) and
in `synthetic_probe_step_failures_total{step}`. Nothing secret is logged: no key, token, code or address.

## Symptoms

- `synthetic_probe_success == 0`, or `time() - synthetic_probe_last_success_timestamp_seconds` above 15 minutes (three
  runs missed or failed), or
- the CloudWatch alarm on `ProbeSuccess` (also when no datapoint arrived: the CronJob isn't running).

## Impact

The probe is the outside view of NFR-1: a failing probe means a customer's send, a recipient's verification or a
download is failing right now, or will fail the next promotion's gate. One failed run among passes is usually a blip
(a pod restart mid-run); two in a row is real.

## Confirm

```bash
# The last runs and the failing step (one JSON line per run; reason is the operation and its status).
kubectl -n sft get jobs -l app.kubernetes.io/component=synthetic-probe --sort-by=.metadata.creationTimestamp | tail -5
kubectl -n sft logs job/<the latest synthetic-probe job> | grep -E '"probe (passed|failed)"'
# A run now, by hand, instead of waiting 5 minutes.
kubectl -n sft create job --from=cronjob/synthetic-probe synthetic-probe-manual-$(date +%s)
# The CloudWatch side, as the alarm and the promotion gate see it.
aws cloudwatch get-metric-statistics --namespace SecureFileTransfer/Probe --metric-name ProbeSuccess \
  --dimensions Name=Environment,Value=<env> --statistics Minimum --period 300 \
  --start-time "$(date -u -d '-1 hour' +%FT%TZ)" --end-time "$(date -u +%FT%TZ)"
```

Grafana's probe panels (OBS, #244) show `synthetic_probe_step_duration_seconds{step}`: a step that slowly grows towards
its limit (`shareable` towards 150 s) warns before it fails.

Locally, with the stack up and seeded: `SFT_E2E=1 uv run pytest --no-cov tests/test_probe_local.py` in `services/api`.

## Mitigate

Follow the failing step in the table above to the component's own runbook. For the probe's own parts:

1. **`create` answers `401`**: the synthetic tenant's key expired (keys last at most 365 days) or was revoked. Make a
   new one (setup, step 5), put it in `sft/<env>/app/probe-api-key`, then
   `kubectl -n sft annotate externalsecret probe-secrets force-sync=$(date +%s) --overwrite`; the next run reads it.
2. **`link_email` or `verify` times out but customers' email works**: check the probe domain's MX record and the SES
   receipt rule (active rule set, the rule's recipient `probe.<serviceDomain>`, its S3 action and the bucket policy
   that lets SES write under `probe/`). A message in the bucket that the probe didn't match: compare its `To` header.
3. **No run at all**: `kubectl -n sft get cronjob synthetic-probe` (suspended? only in the pilot light), the Pod
   Identity association for `synthetic-probe`, the proxy listener's allowlist (ADR-0021).
4. **The probe itself is wrong** (a contract change it doesn't follow): fix it like any code, and say so in the
   promotion pull request; never pass a promotion gate by hand.

## Setting up the synthetic tenant

Once per environment, after its first deploy, by the maintainer; the probe stays off (`probe.enabled: false`) until
then. Pending the AWS run.

1. **Infrastructure** (Terraform): the `sft-<env>-synthetic-probe` role bound by Pod Identity to `sft/synthetic-probe`,
   allowed `cloudwatch:PutMetricData` with `cloudwatch:namespace = SecureFileTransfer/Probe` and
   `s3:ListBucket`/`GetObject`/`DeleteObject` under `probe/` in the mailbox bucket; the mailbox bucket
   `sft-<env>-<region-short>-probe-mailbox-<account>` (SSE-KMS, a 1-day expiry rule, a policy that lets SES write under
   `probe/` and `loadtest/` for this account only); the MX record for `probe.<serviceDomain>` and the SES receipt rule
   that writes its mail there; the egress proxy listener `synthetic-probe` on 3134 allowing `api.<serviceDomain>`,
   `app.<serviceDomain>` and `monitoring.<region>.amazonaws.com`; and the secret `sft/<env>/app/probe-api-key`, which
   the application store may read.
2. **The tenant**: `createTenant` (operator API) named "Synthetic probe", its first admin an address the maintainer
   controls.
3. The admin signs in once, with a passkey.
4. **Monitor mode**: the tenant's DLP policy (`updateDlpPolicy`, `mode: monitor`). An API key can't confirm a DLP
   warning (`confirmTransfer`), and the default policy warns on a new recipient domain; monitor mode still makes and
   records every decision (FR-52).
5. **The key**: `createApiKey` with `transfers:read` and `transfers:write`, expiry 365 days, stored straight into
   `sft/<env>/app/probe-api-key` as `{"api_key": "..."}`, never anywhere else.
6. Turn the probe on in the environment's values file (`probe.enabled: true`) and watch the first run pass.

**Per-address limits.** Each run sends to a fresh address, `probe+<run>@probe.<serviceDomain>`, so the per-address
code and link-email caps (NFR-14, [ABUSE] 2.2 A and G) never count the probe twice, and the service carries no
exemption for it. **Product metrics** exclude the synthetic tenant by its ID.

## Escalate

If the probe fails for 15 minutes in prod and the failing step's own runbook doesn't explain it, escalate to the owner
in [CODEOWNERS](../../.github/CODEOWNERS): customers are affected or the next release can't be promoted.

## Afterwards

Every page on the probe in prod counts against NFR-1's budget: note it in the operating period's availability report
(SLOs, [`docs/operations/slos.md`](../operations/slos.md)), and write a blameless postmortem when customers were affected.
