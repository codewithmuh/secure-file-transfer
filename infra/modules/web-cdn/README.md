# web-cdn module

The environment's one CloudFront distribution, which serves only the web bundle
([ADR-0008](../../../docs/adr/0008-web-app-s3-cloudfront.md), [abuse](../../../docs/security/abuse-and-rate-limits.md)
3.2 and 3.4, [encryption](../../../docs/security/encryption-and-keys.md) 2.1). Called once per environment, by the
Tokyo edge stack. Written by [#105](https://github.com/codewithmuh/secure-file-transfer/issues/105). Nothing here has
been applied (infra/README.md).

| Piece | What it does |
|---|---|
| Origins | Tokyo's web bucket, and in staging and prod an origin group that fails over to Osaka's on 500, 502, 503, 504 and connection errors, for `GET` and `HEAD`. Both through one origin access control; no other origin, so no file contents reach an edge. |
| `routes.js` | A CloudFront Function: a path whose last segment has no file extension serves `/index.html` |
| Headers | CSP `default-src 'self'; script-src 'self'; connect-src 'self' https://api.<env-domain> <upload origins>; frame-ancestors 'none'; base-uri 'none'; object-src 'none'`, HSTS two years with subdomains, `no-referrer`, `nosniff`, `DENY` framing |
| TLS | `TLSv1.2_2025`, HTTP redirects to HTTPS, an ACM certificate for `app.<env-domain>` in us-east-1 |
| Web ACL | `sft-<env>-apne1-web` in us-east-1: block list, IP reputation, core rule set, 2,000 per IP in 300 s, and a Challenge above 30 link page loads (`/t`) per IP in 300 s |
| Logs | The web ACL's through WAF's log delivery, CloudFront's standard logs through CloudWatch Logs delivery, both configured in us-east-1 and written to the Tokyo `aws-waf-logs-*` bucket; no log group anywhere |
| Record | `app.<env-domain>`, an alias to the distribution, through `aws.dns` |

IPv6 is off, like the API's load balancer: WAF rate rules key each IPv6 address on its own (abuse 2.1). Osaka's
bucket is named, not looked up: the Tokyo stack applies first, and Osaka's then grants this distribution read access
by its ARN (`web_distribution_arn`).
