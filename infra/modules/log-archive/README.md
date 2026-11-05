# log-archive module

The organization's log archive and the organization trail, in the shared account
([ADR-0006](../../../docs/adr/0006-aws-account-per-environment.md), T-73, T-75, authn-authz 8.3, encryption 3.1).
Written by [#105](https://github.com/codewithmuh/secure-file-transfer/issues/105). Nothing here has been applied
(infra/README.md).

| Piece | What it does |
|---|---|
| Logs key | `alias/sft/shared/logs`. CloudTrail encrypts with it only for our accounts' trails; AuditReader decrypts through S3 |
| Bucket | `sft-shared-apne1-log-archive-<account-id>`: versioned, Object Lock in compliance mode for 90 days, records expire after that. TLS only. Its guards (policy, lock, lifecycle, versioning, encryption, public access, deletion) change only by the shared deploy role or `Admin` |
| Organization trail | `sft-organization`: every account and Region, management events, and S3 data events on every Terraform state bucket (`sft-<env>-<region-short>-tfstate-*` for each account and Region, and `sft-prod-apne1-retained-tfstate-*`). Log file validation on |
| Environment trails | Each member account's own trail may write its files buckets' data events under `AWSLogs/<account-id>/` (authn-authz 8.3) |

The state buckets' data events are their access log: `.trivyignore.yaml`'s AVD-AWS-0089 exception for
`modules/tfstate-backend` relies on this trail. The organization stack makes the shared account CloudTrail's delegated
administrator first (#55).

Compliance mode means nobody, BreakGlass and the account's administrators included, can delete a record before its
90 days end. After the final teardown the bucket stays until its last records expire, a few cents (NFR-19); remove it
from state rather than destroying it.
