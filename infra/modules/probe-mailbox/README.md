# probe-mailbox module

One Region's mailbox for the synthetic probe ([#248](https://github.com/codewithmuh/secure-file-transfer/issues/248))
and, in staging, the load test ([#249](https://github.com/codewithmuh/secure-file-transfer/issues/249)): SES receives
their link and code emails and writes each, raw, to a bucket the reader lists, reads once and deletes. Written by
[#259](https://github.com/codewithmuh/secure-file-transfer/issues/259) and called by every `identity` root. Nothing here
has been applied (infra/README.md); the probe stays off until the AWS run (below).

## Where SES receives

SES receives email in both of our Regions: the AWS General Reference, "Amazon Simple Email Service endpoints and
quotas", lists `inbound-smtp.ap-northeast-1.amazonaws.com` and `inbound-smtp.ap-northeast-3.amazonaws.com` among its
email receiving endpoints (<https://docs.aws.amazon.com/general/latest/gr/ses.html#ses_inbound_endpoints>, checked
2026-11-09). So each Region has its own receipt rule set, rules and bucket, and the mailbox needs nothing outside Japan
(NFR-21).

| | Tokyo's stack | Osaka's stack |
|---|---|---|
| Bucket | `sft-<env>-apne1-probe-mailbox-<account-id>` | `sft-<env>-apne3-probe-mailbox-<account-id>` |
| Receipt rule set | `sft-<env>-apne1-inbound`, active | `sft-<env>-apne3-inbound`, active |
| Rules | `probe.<service domain>` to `probe/`; in staging `loadtest.<service domain>` to `loadtest/` | The same |
| SES identities | Each mailbox domain, with Easy DKIM (SES receives only for verified domains) | The same, with Osaka's DKIM domain |
| MX records | Each mailbox domain: `10 inbound-smtp.ap-northeast-1`, then `20 inbound-smtp.ap-northeast-3` in staging and prod | None: Tokyo's stack writes them |
| Load test | Staging only: `sft-staging-loadtest` and `sft/staging/loadtest/api-keys` | — |

Senders try Tokyo first and fall back to Osaka when it doesn't answer, so after a failover the probe in Osaka reads
Osaka's mailbox (docs/runbooks/regional-failover.md, "Afterwards").

## The bucket

| | |
|---|---|
| Encryption | SSE-KMS with the Region's platform key and S3 Bucket Keys. The key's policy lets SES's receipt rules (`ses.amazonaws.com`, this account's rule set) generate data keys, and only the probe and the load test decrypt, through S3, for this bucket (modules/kms-keys) |
| Expiry | A day, current and noncurrent versions: a message matters only to the run that waits for it |
| Writes | SES only, under `probe/` and `loadtest/`, for this account's rule set (`aws:SourceAccount`, `aws:SourceArn`); every other `PutObject` is denied, so nobody plants a message for the probe |
| Reads and deletes | `probe/` by `sft-<env>-synthetic-probe` only, `loadtest/` by `sft-<env>-loadtest` only, plus the deploy role and Admin, who empty it at teardown (`force_destroy`) |
| Settings | Only the deploy role and Admin |

## The load test's role (staging)

`sft-staging-loadtest` trusts GitHub's OIDC provider for `repo:codewithmuh/secure-file-transfer:environment:loadtest-staging`
only; that environment accepts deployments from main only, which the maintainer sets in the repository settings. It
may read `sft/staging/loadtest/api-keys` (made here without a value) and list, read and delete under `loadtest/` in
Tokyo's mailbox; nothing else. Its ARN is the identity root's `probe_mailbox.load_test_role_arn` output, the workflow's
`LOADTEST_ROLE_ARN`; the bucket's name is `LOADTEST_MAILBOX_BUCKET` (docs/operations/performance.md).

## Switching the probe on (pending the AWS run)

The Terraform here is all the probe needs from AWS besides its role (modules/eks-cluster) and its egress (the egress
proxy and DNS Firewall's `api.` and `app.` names, modules/network). Once the environment is applied and deployed, the
maintainer sets up the synthetic tenant (docs/runbooks/synthetic-probe.md), then turns the probe on in one change:
`probe.enabled: true` in the cluster's values file and `TF_VAR_probe_enabled=true` for the `alarms` root, whose alarm
treats missing data as breaching. Neither is set here.
