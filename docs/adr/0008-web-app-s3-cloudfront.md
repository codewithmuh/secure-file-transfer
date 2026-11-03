# 0008. Use S3 and CloudFront to host the web app

- Status: accepted
- Date: 2026-11-03
- Issue: [#31](https://github.com/codewithmuh/secure-file-transfer/issues/31)

## Context

- **A static app.** The React + TypeScript web app (FR-30) is static files served through a CDN, not another service
  ([PRD](../prd.md) section 7). The same versioned bundle is promoted dev → staging → prod, and rolls back in
  ≤ 10 minutes (NFR-18). If Tokyo fails, CloudFront serves the Osaka copy and the API is unaffected
  ([architecture](../architecture.md) section 2).
- **Data residency.** CloudFront, its certificate and its WAF are global services that NFR-21 exempts, but file
  contents are never cached or stored at edges outside Japan, and their logs are delivered to Tokyo. Downloads stream
  from the API in Tokyo, never through the CDN ([abuse](../security/abuse-and-rate-limits.md) 5.2).
- **The page is a target.** Recipient pages read the link token from the URL fragment, so injected script would
  collect tokens and codes ([threat model](../threat-model.md) T-01, T-02). The defence is a private bucket that only
  the release pipeline writes, no third-party script, and a strict Content-Security-Policy.
- **Edge controls already designed.** The TLS policy and certificate ([encryption](../security/encryption-and-keys.md)
  2.1), the CloudFront web ACL and its challenge on link pages (abuse 3.2), and WAF logging to S3 (abuse 3.4).
- **Cost.** About $2 a month at idle and $74 at design load ([capacity](../design/capacity-and-cost.md) 5.1).

## Decision

Each environment has **one CloudFront distribution** that serves only the web bundle, from a private **S3 bucket in
Tokyo** through origin access control, in an origin group whose failover origin is a copy in **Osaka** (staging and
prod). A response headers policy sets the security headers, with `script-src 'self'`. A **CloudFront-scope WAF web
ACL** applies the rules of abuse 3.2. The API keeps its own hostname on the load balancer: no cache behavior routes
to the API or the files buckets, so file contents never reach an edge.

## Options considered

| Option | Pros | Cons |
|---|---|---|
| **S3 and CloudFront** (chosen) | Edges near every user, for a few dollars a month. A private bucket and no servers to patch. Origin failover to Osaka is built in, separate from the API's failover. Web releases are independent of API deploys. WAF challenges protect page loads only, never API calls (abuse 3.2). | A global service: the certificate and web ACL live in us-east-1 and CloudFront's metrics only exist there, so the region guard needs exemptions ([ADR-0006](0006-aws-account-per-environment.md)). The API is a second origin, so CORS and the CSP name it explicitly. Distribution changes take minutes to deploy, so releases mustn't depend on them. |
| **Serve the bundle from the API pods** | One origin, no CORS and nothing in us-east-1; the web app fails over with the API. | Ties web releases to API deploys and to the image, where NFR-18 promotes them separately; API pods serve static traffic; no edge caching for users abroad; makes the web app part of a service, against PRD section 7. |
| **AWS Amplify Hosting** | Build, hosting, headers and custom domains managed in one place. | Builds in its own pipeline, so promoting one tested artifact means deploying outside that pipeline; hosting runs in one region, with no failover to Osaka; another control plane to secure. |
| **One distribution for the web app and the API** | One hostname and no CORS. | File bytes would pass through edges outside Japan (NFR-21, abuse 5.1), WAF rate rules would need the forwarded client IP (abuse 3.1), and the API's regional failover would be tied to the CDN's. |

## Consequences

- **Buckets.** One per region and environment (dev has Tokyo only), private with Block Public Access, SSE-S3 for
  public content (encryption 3.1), written only by the release pipeline's role and read only by the distribution.
- **Release** ([ADR-0005](0005-terraform-github-actions-argo-cd.md)). The bundle is built once on `main` with
  content-hashed file names and stored by version in the shared account. Promotion copies that version into both
  regions' buckets, Osaka first, and writes `index.html` last. Hashed files are served with
  `Cache-Control: public, max-age=31536000, immutable`; `index.html` and `config.json` with `no-cache`.
- **Rollback** writes the previous version's `index.html` back: seconds, with no distribution change and no
  invalidation, well inside NFR-18.
- **One bundle for every environment.** Environment settings (the API origin, the upload endpoints, the sign-in
  domain) come from a `config.json` that the pipeline writes per environment, never from the build.
- **Routing.** A CloudFront Function rewrites app routes, paths without a file extension, to `/index.html`, so error
  responses aren't used for routing and a missing asset stays a 404.
- **Failover.** The origin group fails over on 500, 502, 503 and 504 and on connection errors, for GET and HEAD. The
  synthetic probe checks both origins.
- **Headers**, per environment. The `Content-Security-Policy` sets `default-src 'self'`, `script-src 'self'`,
  `frame-ancestors 'none'`, `base-uri 'none'` and `object-src 'none'`, and
  `connect-src 'self' https://api.<domain> <S3 upload origins>`: `'self'` for `config.json`, the API origin, and the
  files buckets' upload endpoints in Tokyo and Osaka; no inline script. HSTS as in encryption 2.1,
  `Referrer-Policy: no-referrer` and `X-Content-Type-Options: nosniff`. No third-party scripts, fonts or analytics;
  the WAF JavaScript SDK isn't used (T-02).
- **TLS** with the `TLSv1.2_2025` policy and an ACM certificate in us-east-1; HTTP only redirects (encryption 2.1).
- **Logs.** CloudFront standard logs and the web ACL's logs go to S3 in Tokyo under the logs key and are kept 90 days
  (architecture 5.5, abuse 3.4). The web ACL's are sent by CloudWatch Logs delivery, configured in us-east-1 as the
  region guard allows (ADR-0006), with no log group there; none are stored in us-east-1. The link token stays in the fragment, so it
  never reaches CloudFront, the WAF or their logs.
- **Checks.** AWS Config rules for viewer HTTPS, origin access control and the security policy (encryption 9.2), and a
  CI check that fails a distribution with any origin other than the bundle buckets, so nothing else can ever be cached
  at an edge. DNS records are Terraform-managed only, in the shared zone (T-01,
  [ADR-0021](0021-network-design-and-egress.md)).

When to revisit: if a page needs server-side rendering, or the product wants a third-party script such as analytics
or error reporting, which the CSP and T-02 rule out today.
