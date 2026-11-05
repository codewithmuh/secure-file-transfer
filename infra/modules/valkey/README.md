# valkey module

One Region's counter store ([ADR-0014](../../../docs/adr/0014-rate-limit-counters.md)): ElastiCache Serverless for
Valkey for rate-limit counters, leases and sign-in state. Written by
[#101](https://github.com/codewithmuh/secure-file-transfer/issues/101). Nothing here has been applied
(infra/README.md).

| | |
|---|---|
| Cache | `sft-<env>-<region-short>-valkey`, Valkey 9 (the version `compose.yaml` runs locally), in the isolated subnets. Nothing replicates between Regions; Osaka's idles at the minimum |
| Encryption | At rest with the Region's platform key; TLS always (encryption 2.2, 3.1) |
| Network | One security group that admits 6379 from the caller's groups only (the main and scan node groups) and has no egress rules |
| Users | IAM authentication only: `sft-<env>-api`, `sft-<env>-signin-trigger`, `sft-<env>-scan`, `sft-<env>-notify` and `sft-<env>-operator`, each the same name as its IAM role. A Valkey user group needs no default user, so no user has a password |
| Access | `on ~rl:* -@all +@read +@write +@connection -@dangerous -function +evalsha +script\|load +cluster\|slots +cluster\|shards`: keys under `rl:` only (ADR-0014's key format), no admin or dangerous commands, no pub/sub. Of scripting, only `EVALSHA` and `SCRIPT LOAD`, which valkey-py's `Script` sends for `sft.data.counters`; no `EVAL`, `FCALL`, `SCRIPT FLUSH`/`KILL` or `FUNCTION LOAD`/`DELETE`/`FLUSH`. The two `CLUSTER` subcommands are the read-only topology calls a cluster client makes at start; a serverless cache runs in cluster mode |
| Limits | At most 1 GB of data and 30,000 ECPUs a second: room for ten times 2× design load during an attack (abuse 4.2), and a ceiling on what an attack can cost. The load test measures ECPUs per request (capacity section 8). Above the ECPU ceiling ElastiCache throttles, and the callers' failure modes apply (fail closed for sign-in and link verification, ADR-0014) |
| Eviction | Not configurable on a serverless cache: at the data limit it evicts keys that have a TTL, least recently used first (`volatile-lru`), and refuses writes once nothing can go. Every key has a TTL of at most 25 hours (ADR-0014), so a full store resets the oldest windows first rather than refusing every check. 1 GB holds millions of counters, and the keys come only from identifiers the service creates or validates (threat model T-85). The alarm on `BytesUsedForCache` at 75 % of the limit belongs to phase 6 |
| TLS | Always on for a serverless cache; clients connect with `rediss://` (`VALKEY_URL`, services/api) |
| Snapshots | None: nothing here must survive (abuse 4.1) |

The sign-in triggers reach the store by security group (ADR-0021). Their group doesn't exist yet: the issue that
builds the triggers adds it to `client_security_group_ids` in the data roots.

Checked with `ACL DRYRUN` against Valkey 9.0.7, the local image. Allowed: `EVALSHA` and `SCRIPT LOAD`; `GET`, `SET`,
`PEXPIRE`, `DEL`, `SCAN` and the sorted-set commands the scripts use, on `rl:` keys only; `CLUSTER SLOTS`, `CLUSTER
SHARDS`, `HELLO`, `PING`, `CLIENT SETNAME`, `READONLY`. Refused: any key outside `rl:`, `EVAL`, `EVAL_RO`, `FCALL`,
`SCRIPT EXISTS`, `SCRIPT FLUSH`, `SCRIPT KILL`, `FUNCTION LOAD`, `FUNCTION DELETE`, `FUNCTION FLUSH`, `FLUSHDB`, `KEYS`,
`CLUSTER INFO`, `CLUSTER NODES`, `PUBLISH`, `SUBSCRIBE`, `DEBUG`, `CONFIG GET` and `INFO`. Change the access string only
with the same check, and with the client code that needs the new command.
