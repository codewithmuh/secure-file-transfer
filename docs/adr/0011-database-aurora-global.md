# 0011. Use Aurora PostgreSQL with a global database secondary in Osaka

- Status: accepted
- Date: 2026-11-03
- Issue: [#32](https://github.com/codewithmuh/secure-file-transfer/issues/32)

## Context

PostgreSQL is the single system of record ([architecture](../architecture.md), section 2). The API and workers reach
it through SQLAlchemy and psycopg (ADR-0002), all tenants share one schema (ADR-0003), and the
[data model](../design/data-model.md) needs PostgreSQL 17 or later (`transaction_timeout`, section 2.5), monthly
partitions for `audit_events` and `FOR UPDATE SKIP LOCKED` for the outbox. The [PRD](../prd.md) sets the targets:

- **Durability and RPO (NFR-10).** Losing an AZ loses nothing; losing Tokyo loses at most 5 minutes of metadata.
- **Recovery (NFR-11).** AZ failure within 5 minutes; Tokyo failure within 1 hour, of which the architecture's runbook
  budgets 5 minutes to promote Osaka (architecture section 7); a restore to any point in the last 14 days, accurate to
  5 minutes, within 2 hours.
- **Security and residency.** KMS encryption of the database and its backups (NFR-13), Tokyo and Osaka only (NFR-21),
  one login role per workload with IAM database authentication and TLS
  ([encryption and keys](../security/encryption-and-keys.md), sections 2.2 and 6.3).

At design load the database holds 100–150 GB, takes about 1 M write transactions a day (3 M write and 7 M read I/Os,
[capacity](../design/capacity-and-cost.md) A13) and needs about 200 connections at 2× load (capacity 4.1). One
maintainer runs it, with Osaka as a pilot light that has no compute until a failover.

## Decision

Run **Aurora PostgreSQL 17 or later as an Aurora global database**: a primary cluster in Tokyo with a writer and a
reader in different AZs, and a secondary cluster in Osaka.

- **Standard storage, not I/O-Optimized.** At design load Standard costs $838 a month and I/O-Optimized $1,029; the
  break-even is about 1,100 M I/Os a month, 3.6× our estimate (capacity 4.4).
- **Instances.** db.r8g.large for the Tokyo writer and reader and, for now, the prod Osaka secondary. Staging's Osaka
  secondary runs **Aurora Serverless v2** so the first failover drill measures its ACUs and its promotion; prod's
  secondary moves to Serverless v2 only if that drill shows promotion inside the 5-minute step and ACUs close to
  capacity A44 (capacity 4.5). dev runs one db.t4g.medium with no global database.
- **Access.** IAM database authentication for every workload role, TLS with `sslmode=verify-full`, and a master
  password set through Terraform write-only arguments (encryption and keys 6.3).
- **Backups.** 14 days of point-in-time recovery on the primary cluster (NFR-11), encrypted with the database key.
- **Regional failover** uses Aurora's managed failover (allow data loss) first, and detach-and-promote if that can't
  run. The old Tokyo cluster only ever returns as a secondary ([threat model](../threat-model.md), T-78).

## Options considered

| Option | Pros | Cons |
|---|---|---|
| **Aurora PostgreSQL global database** (chosen) | Six copies of the data across three AZs, so losing an AZ loses nothing, and failover to the reader typically takes under a minute. Storage-level replication to Osaka, normally under a second behind and independent of the writer's load, well inside NFR-10's 5 minutes. Managed cross-region failover, plus switchover with no data loss for drills and failing back. Continuous backups with point-in-time restore. Wire-compatible PostgreSQL, so ADR-0002's stack is unchanged. | Aurora-specific storage and billing: on Standard every I/O is billed, so cost follows query efficiency. A global database needs memory-optimised or Serverless v2 instances, so staging can't use a cheap burstable writer. Aurora can't manage the master password in Secrets Manager for a global cluster. A point-in-time restore creates a standalone cluster outside the global database. Aurora releases trail community PostgreSQL, and managed failover needs the same engine version in both regions, so upgrades are coordinated. Leaving Aurora means a dump or logical replication. |
| **RDS for PostgreSQL Multi-AZ with a cross-region read replica** | Community PostgreSQL, with new versions sooner. No I/O charges, so cost is predictable. Secrets Manager can manage the master password. A Multi-AZ DB cluster gives readable standbys and fast AZ failover. | The Osaka replica is fed by WAL streaming from the writer, so its lag grows with write bursts and vacuum, and shipping costs the writer resources. Promotion is a one-way detach with no managed switchover or failback; a new replica has to be built after every drill. A Multi-AZ instance's standby isn't readable, so audit search needs one more replica. |
| **Self-managed PostgreSQL** (an open-source operator such as CloudNativePG on EKS, or EC2) | Full control of version, extensions and parameters. The cheapest compute. Portable. | HA, WAL archiving, point-in-time restore, the Osaka standby, upgrades and failover are ours to build, run and drill, by one maintainer. A standby in Osaka needs nodes running all the time, which the pilot light doesn't have (architecture 3.2). The database shares failure domains with the application cluster. |

## Consequences

- **Cost.** The three instances are $728 a month, the second-largest line at idle (capacity section 1). The load test
  measures I/O, writer CPU and the buffer cache hit ratio: switch to I/O-Optimized above about 36 M I/Os a day
  (allowed once every 30 days), and move to db.r8g.xlarge if writer CPU stays above 60 % in the peak hour or the hit
  ratio falls below 99 % (capacity 4.1). Serverless v2 in prod's Osaka secondary would save $78–132 a month.
- **Connections.** IAM tokens last 15 minutes and are used only when a connection opens, so pools sign a new token per
  connection. AWS asks for 300–1,000 MiB of spare instance memory for IAM authentication, which matters on dev's
  db.t4g.medium. CloudTrail doesn't log IAM database sign-ins, so the database's own connection log is the record.
  No RDS Proxy: about 200 connections at 2× design load are far below a db.r8g.large's limit.
- **RPO.** An alarm on `AuroraGlobalDBRPOLag` fires above 1 minute. We don't set `rds.global_db_rpo`: with only two
  regions it would stop commits in Tokyo whenever Osaka falls behind, and AWS advises against it for that topology.
- **Regional failover.** Managed failover tries to fence writes in Tokyo and snapshots the old Tokyo volume when it
  comes back; rows missing from Osaka are reconciled from that snapshot, never trusted as a writer. The runbook then
  starts a new audit archive generation (data model 2.5) and re-applies security-critical changes before any worker
  starts (architecture section 7). The first drill times the promote step against its 5-minute budget.
- **Restore after corruption.** A point-in-time restore goes to a new cluster (Aurora PostgreSQL has no backtrack), then
  follows architecture section 6. Until a new Osaka secondary is added and caught up, which can take hours at 150 GB,
  a regional loss would fall back to backups, so the restore runbook adds it straight away and the drill times both.
- **Upgrades.** Both regions run the same engine version; minor and major upgrades are rehearsed in staging first.

## When to revisit

After the first load test (I/O, CPU and hit ratio against the thresholds above) and the first staging failover drill
(Serverless v2 ACUs and promotion time). Revisit the whole choice if the promote step can't fit its 5-minute budget, if
replication lag regularly passes a minute at design load, or if the 2-hour restore target can't be met with a new
cluster plus a new secondary.
