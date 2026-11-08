# ses module

One Region's SES setup ([ADR-0015](../../../docs/adr/0015-email-ses.md); abuse and rate limits 7.3, 7.4). Written by
[#185](https://github.com/codewithmuh/secure-file-transfer/issues/185) and called by the `identity` root of each
environment and Region. Nothing here has been applied (infra/README.md).

| | |
|---|---|
| Identity | The domain `mail.<service domain>`, with Easy DKIM (RSA 2048) and the configuration set as its default. Each Region signs with its own three DKIM keys |
| MAIL FROM | `<region-short>.mail.<service domain>`, one per Region, because SES wants exactly one MX there, pointing at that Region's feedback endpoint. SPF `include:amazonses.com -all` on it; a missing MX rejects the send |
| DMARC | `_dmarc.mail.<service domain>`, `p=reject` with strict alignment, written once, by Tokyo's stack. Aggregate reports go to `TF_VAR_dmarc_report_address` |
| Configuration set | `sft-<env>`, the same name in both Regions, so `SES_CONFIGURATION_SET` never differs. TLS required to receiving servers, reputation metrics on, and an empty suppressed-reasons list: the account-level suppression list never blocks our sends, because suppression is per tenant, in our own table (ADR-0015) |
| Events | Bounces, complaints, deliveries, rejects and delivery delays to the topic `sft-<env>-<region-short>-ses-events` (under the platform key), which delivers into the data layer's `ses-events` queue with SNS's envelope on. The topic admits only SES for this configuration set (`aws:SourceArn`); the queue only this topic; the platform key both (modules/kms-keys). The notification worker reads them (`sft.service.ses_events`) |
| Identity policy | Cognito may send as the identity, for this account's user pools in this Region only: the pool's own few emails (ADR-0016, developer email sending) |

The records go into the shared zone through the environment's DNS role (`aws.dns`), which may change only that
environment's names, `mail` and `*.mail` among them (modules/dns-zone).

Not here: production access, which the maintainer requests per Region in the console; sending quotas; and SES
tenants, which the API creates per tenant (`createTenant`, ADR-0015).
