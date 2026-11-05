# 0014. Use ElastiCache Serverless for Valkey and WAF rate-based rules for rate-limit counters

- Status: accepted
- Date: 2026-11-03
- Issue: [#32](https://github.com/codewithmuh/secure-file-transfer/issues/32)

## Context

NFR-14 in the [PRD](../prd.md) sets rate limits per IP address, account, tenant and invited email address on sign-in,
verification, link access, uploads and downloads. ADR-0002 left open where the counters live, with one rule: every API
replica sees the same count. The [abuse and rate-limits design](../security/abuse-and-rate-limits.md) defines every
limit and key (section 2), the WAF rules (section 3) and the store's requirements (section 4.2):

- **Atomic and shared.** Check and increment in one operation per key; a request refused by one limit never counts
  against a wider one.
- **Fast.** p99 ≤ 5 ms per check, ≤ 10 ms of NFR-2's budget per request; 600 operations a second at the burst, 1,200
  at 2× design load ([capacity](../design/capacity-and-cost.md) A24), and ten times that during an attack.
- **Not durable.** Nothing in the store is needed after a failover. Code attempts, lockouts, download counts, grant
  byte use and storage quotas decide access, so they stay in PostgreSQL and fail over with it (abuse design 4.1).
- **Fail closed** for sign-in and link verification, which are the main defence against AB-1 to AB-3 and AB-8.

The same store also holds stream and scan leases, the notification worker's per-address caps across tenants (abuse
design 7.2), and the short sign-in state between redirect and callback
([authentication](../security/authn-authz.md), 2.4).

## Decision

Keep the counters in **ElastiCache Serverless for Valkey**, one cache per environment and region, with **WAF
rate-based rules** in front for coarse per-IP floods. PostgreSQL keeps the security state.

- **Scope.** Counters, leases and sign-in state only. Every key has a TTL of at most 25 hours and looks like
  `rl:{group}.{limit}:{key type}:{value}`, where the value is an ID, an HMAC or an IP address (an IPv6 /64), never
  an email address, token or cookie value.
- **Algorithms** (abuse design 4.4): GCRA for request rates; a sliding log for small quotas such as codes per address;
  a sorted set of leases for concurrent streams and scans. Limits run narrowest first, one script per key. GCRA admits
  a burst of ⌊N/2⌋ + 1 requests for a limit of N per period, then ⌈N/2⌉ per period, evenly spaced, so no window of
  one period holds more than N.
- **Access.** IAM authentication over TLS for five workloads only, each with its own role, through a security group
  open to them:
  - the API;
  - the sign-in triggers;
  - the scan worker, for scan leases;
  - the notification worker, for the per-address caps across tenants;
  - the operator API, for its own rate limits (authentication and authorization 8.2; added with #106, when the
    chart wired the operator API's settings).

  Nothing is replicated between regions; Osaka's cache idles at its minimum until a failover.
- **Failure.** 50 ms per call; after 5 errors in a row the API stops calling the store for 10 seconds. Link steps
  answer `503` with `Retry-After: 5` and the sign-in trigger denies sign-in (fail closed). Other groups fall back to a
  per-pod limiter at a third of each limit; checks held in PostgreSQL are unchanged (abuse design 4.5). The scan worker
  skips the per-tenant scan cap and the fair queues alone apply (abuse design 6.4). The notification worker holds the
  per-address cap with a per-pod limiter, as group G does (abuse design 2.2).
- **WAF** carries the per-IP backstops on the API, sign-in and web app web ACLs (abuse design 3.2).

## Options considered

| Option | Pros | Cons |
|---|---|---|
| **ElastiCache Serverless for Valkey + WAF rules** (chosen) | About 1 ms per call in the region, with atomic scripts for every algorithm the abuse design uses. Attack traffic lands on the cache, not the system of record. Multi-AZ with managed failover and no capacity planning. About $7 a month per cache at its 100 MB minimum, $8 at design load (capacity 5.1). WAF stops floods before they reach the pods. | One more stateful service to secure, monitor and drill. Serverless runs in cluster mode, so one script can't span keys in different slots: up to four round trips per request. Counts since the last replication are lost in a cache failover. IAM tokens last 15 minutes and connections are closed after 12 hours, so the client must re-authenticate. While the cache is down, nobody can verify or sign in. Windows start empty in Osaka after a failover. |
| **ElastiCache for Valkey on nodes** (non-cluster mode) | One script can check every key in a single call. Fixed hourly price with no per-request metering. | Multi-AZ needs a primary and a replica per cache, several times the serverless minimum at this size, across five caches (dev, staging and prod in two regions). Node types to size and scale by hand. |
| **PostgreSQL counters** | No new service; transactional with business data; fails over with the database. | About 260 M extra writes a month at design load, several times the business writes, and every one replicates to Osaka. Under attack, hot counter rows load the system of record at the worst moment. 1–5 ms on the writer. |
| **WAF rate rules only** | No application latency; already paid for; stops traffic at the edge. | Keys are limited to IP, ASN, header, cookie and path: no tenant, invited address, subject or failure counts, so most of NFR-14 can't be expressed. Approximate and delayed, by up to minutes; at least 10 requests per window; windows of 1, 2, 5 or 10 minutes. |
| **DynamoDB** | Serverless, conditional updates, TTL, highly available. | Pays for each of about 260 M counter writes a month, where the cache bills mostly its minimum, and adds latency, for data that doesn't need to survive. |
| **In-process limiter per pod** | No dependency and no latency. | The effective limit changes with the pod count (3 to 15). Kept only as the fallback above. |

## Consequences

- **Latency.** Up to four round trips of about 1 ms each, inside the 10 ms that NFR-2 allows for limits. The load
  test measures `rate_limit_store_latency_seconds` and ECPUs per request (capacity section 8).
- **Availability.** Fail closed puts the cache on the critical path for verification and sign-in (NFR-1).
  `RateLimitStoreUnavailable` pages, and existing sessions keep working meanwhile. Fallback alerts show when the
  per-pod limiter is active; the service as a whole then allows up to (pods ÷ 3) × each limit.
- **Failover.** Osaka's cache starts empty, so short windows reset once; the state that decides access arrives with the
  database (abuse design 4.1).
- **Key rotation.** For 25 hours after an email HMAC key rotation, each per-address limit adds the old pseudonym's
  count, so a rotation never resets a cap ([encryption and keys](../security/encryption-and-keys.md), 6.5).

## When to revisit

If the load test shows p99 above 5 ms per check or the round trips pushing NFR-2, if the cache's outages block
verification more than NFR-1 can absorb, or if a failover drill shows the reset windows being abused. A node-based,
non-cluster cache is the first alternative.
