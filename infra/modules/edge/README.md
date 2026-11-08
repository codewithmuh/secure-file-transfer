# edge module

One environment's edge in one Region, from the same code in Tokyo and Osaka (T-79): the API's load balancer, its
certificate and web ACL, the sign-in web ACL, the edge's log buckets, the Region's web bundle bucket, the API records
in the shared zone and the Region's Route 53 health check ([ADR-0021](../../../docs/adr/0021-network-design-and-egress.md),
[ADR-0008](../../../docs/adr/0008-web-app-s3-cloudfront.md), [abuse](../../../docs/security/abuse-and-rate-limits.md)
2 and 3, [encryption](../../../docs/security/encryption-and-keys.md) 2.1 and 3.1). Written by
[#105](https://github.com/codewithmuh/secure-file-transfer/issues/105). Nothing here has been applied (infra/README.md).

| File | Holds |
|---|---|
| `main.tf` | Names, and the lookups of what other layers made: the VPC, its public subnets and `main_nodes` group (network), the NAT addresses, the logs key (data), the shared zone (through `aws.dns`) |
| `load-balancer.tf` | Security group and its rule on `main_nodes`, load balancer, target group, HTTPS listener, the fixed health response, the health check |
| `dns.tf` | The load balancer's certificate, its validation records, `api-<region-short>` and, in the primary Region, `api` |
| `waf.tf` | The API and sign-in web ACLs, the block list and NAT IP sets, their logging |
| `tests/waf.tftest.hcl` | `terraform test` against a mocked provider: every rule's priority, action, limit, window and `429`, the levers and the rollout switch, the NAT IP set, the logging filter and redaction (#235; `infra/scripts/check.sh test`) |
| `logs.tf` | `aws-waf-logs-sft-<env>-<region-short>-<account-id>` (SSE-KMS, logs key) and `sft-<env>-<region-short>-lb-logs-<account-id>` (SSE-S3) |
| `web-bucket.tf` | `sft-<env>-<region-short>-web-<account-id>`, read only by the distribution |

## Names

The zone is `sft.<domain>`. prod's names sit at its apex, dev's and staging's under their own label, so the
environment's domain is `sft.<domain>` or `<env>.sft.<domain>`:

| Name | Points at | Owned by |
|---|---|---|
| `api.<env-domain>` | Tokyo's load balancer; Osaka's during a failover (`api_alias_target`, T-78) | Tokyo's stack |
| `api-apne1.<env-domain>`, `api-apne3.<env-domain>` | That Region's load balancer | That Region's stack |
| `app.<env-domain>` | The CloudFront distribution | Tokyo's stack, `web-cdn` module |

Both Regions' certificates carry `api.<env-domain>` and their own regional name, so Osaka can take the API's name in a
failover without a new certificate. ACM's validation record for a name is the same in every Region of an account, so
the primary Region's stack owns the one for `api.<env-domain>`, and Osaka's waits for it.

## Load balancer and pods

Terraform owns the load balancer, its listener and its target group (IP targets, HTTPS to the pods' public port,
8000). The AWS Load Balancer Controller registers the API pods through a `TargetGroupBinding` that names the group,
`sft-<env>-<region-short>-api` (#106), so the controller creates no load balancer of its own, teardown leaves none
behind (NFR-19), and no output has to reach the cluster-bootstrap stack, which is applied before this one. The
controller manages no security group rules: this stack's rule on `main_nodes` admits the load balancer.

The target group speaks HTTPS to the pods (encryption 2.2): each API pod serves TLS 1.2 or later on 8000 with a
certificate it makes at start (`PUBLIC_TLS=generated`, [#184](https://github.com/codewithmuh/secure-file-transfer/issues/184)); the load balancer doesn't validate it. The target
health check is `GET /readyz` over plain HTTP on the internal port, 8001, which no listener routes.
`deploy/tests/test_rendered.py` checks the chart against this target group.

The listener answers `GET /edge-health` itself with `sft-edge-ok` and no target. The Region's Route 53 HTTPS
health check matches that string on `api-<region-short>.<env-domain>`: it shows whether the Region's edge answers,
and passes in Osaka during the pilot light. It drives alarms only, never DNS (ADR-0021); the alarm itself comes with
the operations work in M7.

## Web ACLs

| Web ACL | Rules (abuse 3.2) |
|---|---|
| `sft-<env>-<region-short>-api` | 0 block list, 1 IP reputation, 2 anonymous IP (Count), 3 known bad inputs, 4 core rule set with its body rule in Count, 5 body size except the three large-body routes, 6 `/v1/links/` 100 per IP in 60 s (429), 7 6,000 per IP in 300 s (429), 8 `/v1/links/` 3,000 per ASN in 300 s (Count), 9 attack mode (`attack_mode_links`), 10 geo block (`blocked_countries`) |
| `sft-<env>-<region-short>-sign-in` | 0 block list, 1 IP reputation, 2 token paths only from the NAT IP set, 3 those from NAT 10,000 per IP in 300 s, 4 others 2,000 per IP in 300 s, 5 their `POST`s 500 per IP in 300 s |

`managed_rules_in_count` puts the managed rules and the sign-in rate rules in Count for the two-week rollout; staging
and prod start with it set. The block list is created empty and maintained by operators (Terraform ignores its
addresses). The sign-in web ACL is associated with the Cognito user pool by the stack that creates the pool. Both log
to the WAF bucket with the `authorization` and `cookie` headers redacted, keeping only blocks, CAPTCHAs, challenges
and counts.

## Inputs from other layers

The module looks up the network layer's VPC (`sft-<env>-<region-short>-vpc`), public subnets (`tier = public`),
`main_nodes` security group and NAT addresses by name and tag, and the data layer's logs key by alias
(`alias/sft/<env>/logs`, #102), so the edge applies after both. Its records go through the provider `aws.dns`, which
the root configures to assume `sft-shared-dns-<env>-plan` or `-deploy` in the shared account (`terraform_role`).
