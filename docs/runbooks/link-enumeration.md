# Runbook: LinkProbing

The link enumeration alert of abuse and rate limits 8.2 (AB-1, NFR-14), defined in
[`deploy/alerts/abuse.rules.yaml`](../../deploy/alerts/abuse.rules.yaml). Severity: ticket. Abuse 8.2 calls this
runbook `link-enumeration`; this file is it.

## Symptoms

More than 200 lookups a minute, for 5 minutes, are for links that don't exist
(`link_lookups_total{result="not_found"}`).

## Impact

Little, by design. Link tokens are 256-bit HMAC outputs, so guessing one is hopeless (AB-1); the per-IP limits (60
link-step requests a minute in the app, 100 at the WAF) and the not-found rule (after 20 `link_not_found` in an hour,
that IP gets `429` on every link step for the rest of the hour) slow a guesser further. The cost is load and noise. A
burst of old links being replayed (a leaked list, a mail archive) is the more likely cause, and is worth knowing about.

## Confirm

In Grafana: `rate(link_lookups_total[5m])` by `result`, and `rate_limit_rejections_total{group="A"}` by `key_type`.
Metrics carry no IP or token (abuse 8.1); the sources are in the edge logs. With the environment's `ReadOnly` profile
(pending the AWS run), the WAF logs of the API web ACL and the load balancer's access logs, both in S3 in Tokyo
(abuse 3.4): count requests to `/v1/links/` by client IP and ASN for the window, and the WAF's link-step rule that
counts per ASN.

## Mitigate

1. **A few addresses:** add them to the WAF block list `sft-<env>-<rs>-block-list` (abuse 8.3), as the `Operator`
   (pending the AWS run):

   ```bash
   aws wafv2 get-ip-set --scope REGIONAL --name sft-<env>-<rs>-block-list --id <id> --region <region>
   aws wafv2 update-ip-set --scope REGIONAL --name sft-<env>-<rs>-block-list --id <id> \
     --addresses <existing> <new>/32 --lock-token <token> --region <region>
   ```

   Terraform creates the set and ignores its addresses, so the list is the operators' (`infra/modules/edge/waf.tf`).
2. **Many addresses from anonymous or hosting networks:** turn on `attack_mode_links` (rule 9, abuse 3.2) with a commit
   to the edge root's module call (`infra/environments/<env>/<region>/edge/main.tf`), applied by CI. Real recipients on
   a VPN are refused while it is on, so turn it off when the burst ends.
3. **From one country only:** `blocked_countries` (rule 10) the same way, as a last resort: recipients may be anywhere.
4. **Replayed links of one tenant:** the logs' `tenant_id` on the `link_not_found` lines may show one; tell the tenant's
   admins that their old links are circulating.

## Escalate

If it is part of a wider attack (an error or latency burn too, see [slo-burn.md](slo-burn.md)), escalate to the
owner in [CODEOWNERS](../../.github/CODEOWNERS).

## Afterwards

Remove block-list entries and levers once the burst has stopped for a day, and note what was blocked and why.
