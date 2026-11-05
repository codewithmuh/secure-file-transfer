# dns-zone module

The public zone `sft.<domain>` in the shared account, DNSSEC-signed, with the roles through which each environment
writes its own names ([ADR-0021](../../../docs/adr/0021-network-design-and-egress.md), T-01, capacity A32). Written by
[#105](https://github.com/codewithmuh/secure-file-transfer/issues/105). Nothing here has been applied (infra/README.md).

| Piece | What it does |
|---|---|
| Zone | `sft.<domain>`, one for every environment. It delegates nothing. A CAA record lets only ACM issue, and no wildcards |
| DNSSEC | An ECC P-256 signing key in us-east-1 (`alias/sft/shared/dnssec`), which only Route 53's DNSSEC service may use for this account's zones; the key-signing key `sft_ksk`; signing on |
| Environment roles | `sft-shared-dns-<env>-plan` (read) trusted only by `sft-<env>-terraform-plan`, and `sft-shared-dns-<env>-deploy` (write) trusted only by `sft-<env>-terraform-deploy`, each in its own account |

Names per environment: prod's directly under the zone, dev's and staging's under `<env>.`. The write role may change
only `<label>.<env-domain>` and `*.<label>.<env-domain>` for the labels `app`, `api`, `api-apne1`, `api-apne3`,
`auth` and `mail` (ACM's validation records and SES's DKIM and DMARC records fall under these), and only records of
type A, AAAA, CNAME, MX and TXT: never NS or DS, so no environment can delegate.

## First apply

1. Apply the shared stack: the zone is created and signed.
2. At the maintainer's DNS host, add the NS records (`zone_name_servers`) for `sft.<domain>`, then the DS record
   (`zone_ds_record`) once the zone answers signed. A DS record before signing would make the zone fail validation.
3. Final teardown runs the other way: remove the DS and NS records at the parent first, then the zone (T-01).

The environment roles trust roles by exact ARN, which IAM checks when the trust is written, so each environment's
bootstrap stack comes before the shared stack lists that environment in `member_account_ids`.
