# Runbook: AuditArchiveWriteFailing

The archive write alert of architecture 6 ("Osaka archive unreachable"; NFR-10, NFR-15, T-81), defined in
[`deploy/alerts/audit.rules.yaml`](../../deploy/alerts/audit.rules.yaml). Severity: page. The `region` label names the
archive that refuses: usually `ap-northeast-3`, Osaka's, reached across Regions from Tokyo.

## Symptoms

For 5 minutes, writes of security-critical records to one Region's audit archive keep failing
(`audit_archive_write_failures_total{region}`, from the API and the operator API). The API and the operator API log
`audit archive write failed`, with the Region, the S3 error code, the event ID and the action, never its contents
(`sft.service.audit_archive`).

## Impact

Security-critical records go straight to the Object Lock archive in both Regions before the API confirms them
(architecture 5.2, 4.4):

- **New download grants fail closed:** their intent record must reach both archives before anything is counted, so
  the API answers `503` and counts nothing. Streams under existing grants continue (4.2, T-81).
- **Revocations, lockouts, unlocks, deactivations, demotions, forced sign-outs and sign-in resets commit first** and
  take effect at once; their `503` means "done, not yet confirmed in the archive" (4.4). The web app retries the
  confirmation.
- Sign-in, sending and uploads don't wait on Osaka.

Accepted as R-11: an Osaka-only outage stops new downloads in Tokyo. A degraded mode for grants is a disaster-recovery
gap tracked in [#42](https://github.com/codewithmuh/secure-file-transfer/issues/42).

## Confirm

```bash
kubectl -n sft logs deploy/api --since=15m | grep 'audit archive write failed' | tail -20   # the S3 error codes
```

With the `ReadOnly` profile (pending the AWS run): the AWS Health Dashboard for S3 in the Region; the archive bucket
(`sft-<env>-<rs>-audit-archive-<account>`) and its policy, unchanged; the Osaka S3 interface endpoint in Tokyo's VPC
(architecture 3.1) and its policy. The error code says which: `AccessDenied` is a policy or the audit key; a timeout
or `ServiceUnavailable` is S3 or the endpoint.

## Mitigate

1. **S3 in that Region is impaired:** nothing to fix on our side. Tell the owner that new downloads fail until it
   returns, and watch the AWS Health Dashboard. If Tokyo itself is the impaired Region, this is
   [region-health.md](region-health.md)'s decision.
2. **AccessDenied after a change:** the API's role, the archive bucket policy (`infra/modules/audit-archive`; in prod
   the retained stack) or the audit key policy changed. Revert through Terraform.
3. **The endpoint:** a change to the network layer's Osaka S3 endpoint, its policy, or DNS Firewall; revert.
4. **When writes succeed again**, nothing is left to do by hand: a retry of each `503` call writes its missing record
   and answers `200`, background grant records keep retrying until both Regions confirm, and the archive job copies
   every committed event within a minute anyway (5.2, #183; its own lag alert is in
   [audit-archive-lag.md](audit-archive-lag.md), the APP track's runbook). Check that its lag returns to normal.

## Escalate

If new downloads fail for 30 minutes, escalate to the owner in [CODEOWNERS](../../.github/CODEOWNERS), and open an AWS
support case if S3 is at fault.

## Afterwards

Write a blameless postmortem: how long grants failed, root cause, and whether #42's degraded mode would have helped.
