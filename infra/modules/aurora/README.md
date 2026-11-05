# aurora module

One Region's Aurora PostgreSQL cluster ([ADR-0011](../../../docs/adr/0011-database-aurora-global.md)): standalone in
dev, the primary of the global database in Tokyo, its secondary in Osaka. Written by
[#101](https://github.com/codewithmuh/secure-file-transfer/issues/101). Nothing here has been applied
(infra/README.md).

| `cluster_role` | Used by | Creates |
|---|---|---|
| `standalone` | dev | The cluster, its instance, the master secret |
| `primary` | Tokyo, staging and prod | The global database `sft-<env>-aurora`, the cluster, its instances, the master secret and its Osaka replica |
| `secondary` | Osaka, staging and prod | A cluster that joins the global database by name; no master password of its own |

## What each environment gets

| Environment | Tokyo | Osaka | Backups |
|---|---|---|---|
| dev | 1 × db.t4g.medium, no global database | none | 7 days |
| staging | 1 × db.r8g.large writer | Serverless v2, 1 to 16 ACUs | 14 days in each Region |
| prod | db.r8g.large writer and reader in two AZs | 1 × db.r8g.large | 14 days in each Region |

Sizes are capacity 4.1, 4.5, 5.2 and 5.3. Osaka keeps 14 days too, so the restore target still holds after a failover;
whether that stays, and cross-Region backup copies, are open in
[#42](https://github.com/codewithmuh/secure-file-transfer/issues/42).

## Security

| | |
|---|---|
| Encryption | Storage, backups, snapshots and Performance Insights under the Region's database key; the log group under the logs key (encryption 3.1) |
| Network | Isolated subnets; one security group that admits 5432 from the caller's groups only (the main and scan node groups) and has no egress rules |
| Sign-in | IAM database authentication for every workload login role (encryption 6.3). `rds.force_ssl = 1`, TLS 1.2 or later, and the `rds-ca-ecc384-g1` CA for `sslmode=verify-full` |
| Master password | An ephemeral random password, sent to the cluster's `master_password_wo` and to `sft/<env>/db/master`'s `secret_string_wo` in the same run, so it is never in the plan or the state. Raising `master_password_version` sets a new one |
| Master secret | Under the secrets key; replicated to Osaka under Osaka's secrets key. Its policy denies `GetSecretValue` to everyone but `sft-<env>-db-bootstrap` and BreakGlass, and writes to everyone but the deploy role |
| Log | `log_connections` and `log_disconnections` on, because CloudTrail doesn't log IAM database sign-ins. No bound values, no DETAIL lines, `log_statement = none`; pgaudit logs DDL and role changes for every session. A data protection policy masks email addresses |
| Upgrades | `auto_minor_version_upgrade = false`: a version change is a reviewed change, rehearsed in staging first. In a global database the global cluster upgrades its members |
| Deletion | Deletion protection on, and a final snapshot on delete, except in the teardown apply (`teardown = true` in the root) |

Not set: `rds.global_db_rpo`, which would stop commits in Tokyo whenever Osaka falls behind (ADR-0011).

## Follow-ups outside this module

- The database bootstrap job sets `pgaudit.log = 'all'` on the master user, so every break-glass statement is
  recorded (authn-authz 8.3).
- The alarm on `AuroraGlobalDBRPOLag` above 1 minute (ADR-0011) belongs with the other alarms (phase 6).
