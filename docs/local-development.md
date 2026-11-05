# Local development

| | |
|---|---|
| Delivery plan | [Local before AWS](delivery-plan.md#1-principles): M0–M3 run on a laptop with `make up` |
| Tracking | [#52](https://github.com/codewithmuh/secure-file-transfer/issues/52) |

The local stack stands in for every AWS service the API and workers use until M4, so a fresh clone runs
`make setup && make up && make check` with no AWS account. It is a stand-in, not a copy: section 4 lists the
differences that matter for tests. Code that talks to AWS stays behind thin adapters with contract tests, and the M2
journey runs again against real AWS in M4 ([delivery plan](delivery-plan.md), section 5).

## 1. Requirements and commands

- **Docker** with Compose v2.20 or later and Docker Engine 25 or later (the healthchecks use start intervals). Give
  Docker about 3 GB of memory: clamd and Keycloak use about 1 GB each, the rest about 300 MB together.
- **uv** and **pre-commit**. `make setup` checks for all three and says which one is missing.
- These ports free on 127.0.0.1: 1025, 3310, 5432, 6379, 8000, 8001, 8025, 8180, 9090 and 9324.

| Command | What it does |
|---|---|
| `make setup` | Checks the prerequisites, installs the API's dependencies and the git hooks |
| `make up` | Builds the API, starts the stack, runs the database jobs (section 3), then starts the API and waits until every service is healthy (under a minute once images are pulled) |
| `make smoke` | One real round trip to each stack service, from the host ([`local/smoke.py`](../local/smoke.py)), and a check that `sft_api` reads no tenant's rows without a scope |
| `make test` | The API's tests. While the stack runs, the database tests use its server as `sft`, unless `TEST_DATABASE_URL` is set; they make and drop their own databases and leave `sft` alone |
| `make down` | Stops and removes the containers; the database and S3 objects stay |
| `make reset` | Stops everything and deletes the local data; the next `make up` starts empty and seeds again |
| `make logs` | Follows the logs of every container |

Connection settings for code on the host are in [`.env.example`](../.env.example). Containers in the stack reach
each other by service name instead: `postgres:5432`, `s3:9090`, `sqs:9324`, `valkey:6379`, `mail:1025`,
`clamd:3310` and `oidc:8080`.

## 2. Services

Each image is pinned by version and digest in [`compose.yaml`](../compose.yaml), and Dependabot proposes updates
weekly. The configuration files are in [`local/`](../local/).

| Service | Stands in for | Image | Port on 127.0.0.1 | Seeded with |
|---|---|---|---|---|
| `postgres` | Aurora PostgreSQL 17 ([ADR-0011](adr/0011-database-aurora-global.md)) | `postgres:17.11-trixie` | 5432 | Database `sft` and login `sft`, a superuser standing in for the master user |
| `s3` | S3 ([ADR-0012](adr/0012-object-storage-s3.md)) | `adobe/s3mock:5.2.3` | 9090 | Created by `s3-init`: `sft-local-files` and `sft-local-large-files` with versioning on; `sft-local-audit-archive` with versioning and Object Lock (governance, 1 day, as in dev) |
| `sqs` | SQS ([ADR-0013](adr/0013-queues-sqs-outbox.md)) | `softwaremill/elasticmq-native:1.7.1` | 9324 | `sft-local-` plus `scan-small`, `scan-large` and `notify` (work queues) and `signin-events`, `ses-events`, `guardduty-results` and `ses-tenant-status` (intake queues), each with a `-dlq` after 5 receives |
| `valkey` | ElastiCache Serverless for Valkey ([ADR-0014](adr/0014-rate-limit-counters.md)) | `valkey/valkey:9.0.7-alpine` | 6379 | ACL user `sft-local`; the default user is off |
| `mail` | SES ([ADR-0015](adr/0015-email-ses.md)) | `axllent/mailpit:v1.33.0` | 1025 (SMTP), 8025 (web UI and API) | Nothing; it catches every message |
| `clamd` | The clamd pods ([ADR-0019](adr/0019-malware-scanning-clamav-guardduty.md)) | `clamav/clamav:1.5.4-debian` | 3310 | The signatures built into the pinned image |
| `oidc` | The Cognito user pool and its app client ([ADR-0016](adr/0016-member-sign-in-cognito.md)) | `quay.io/keycloak/keycloak:26.8.1` | 8180 | Realm `sft`, confidential client `sft-api-local` and a test member, re-imported on every start |

The stack also runs the API (`:8000`). `s3-init` is a one-shot container that seeds the S3 stand-in on every
`make up` and exits; repeating it is safe. So are the three database jobs of section 3, which run before the API
starts.

## 3. Local credentials

Every credential below is fake and local-only. It works only against this stack on 127.0.0.1, and gitleaks passes
over all of them.

| What | Value |
|---|---|
| PostgreSQL superuser | `sft` / `sft-local-only`, for the bootstrap job, `make smoke` and `make test` only |
| PostgreSQL login roles | `sft_api`, `sft_migrate` and every other `sft_` role that logs in, all with `test-only-password` |
| AWS SDK, for S3 and SQS | Access key `local-only`, secret `local-only`. Fake keys mean a local run never picks up a real AWS identity. |
| SSE-KMS key IDs | Files `00000000-0000-4000-8000-000000000001`, audit `00000000-0000-4000-8000-000000000002` |
| Valkey | `sft-local` / `local-only-valkey-password` |
| OIDC client | `sft-api-local` / `local-only-oidc-client-secret`, callback `http://localhost:8000/v1/auth/callback` |
| Test member | `dev.member@example.com` / `local-only-member-password`. User ID (`cognito:username`) `22222222-2222-4222-8222-222222222222`, tenant (`custom:tenant_id`) `11111111-1111-4111-8111-111111111111`, subject (`sub`) `33333333-3333-4333-8333-333333333333`. Seed data for M1 uses these IDs. |
| Keycloak admin console | `admin` / `local-only-admin` at <http://localhost:8180/admin> |
| Mail catcher | No sign-in; it accepts any SMTP credentials. Web UI at <http://localhost:8025> |

### PostgreSQL roles and passwords

The API never logs in as `sft`: a superuser bypasses row-level security, so tenant isolation would go untested
locally. On every `make up`, before the API starts, three one-shot services run in order, each only if the one before
it succeeded (`service_completed_successfully`):

1. **`db-bootstrap`**, from the API image: `python -m sft.data.bootstrap` as `sft`, with `BOOTSTRAP_IAM_AUTH=false`.
   It creates `sft_owner`, `sft_lookup`, one login role per workload and `sft_migrate`, or repairs them (ADR-0020,
   authentication and authorization 7.3). In AWS the master user runs it.
2. **`db-passwords`**, from the PostgreSQL image: [`local/postgres/passwords.sql`](../local/postgres/passwords.sql)
   gives every `sft_` login role the password `test-only-password`. It is local only: in AWS the roles have no
   password and sign in with IAM tokens (encryption and keys 6.3), and no application code sets a password. It is the
   test suite's value because roles belong to the whole server: `make test` against the stack sets the same one, so
   a test run never locks the API out.
3. **`db-migrate`**, from the API image: `python -m sft.data.migrate` as `sft_migrate`, which becomes `sft_owner` and
   upgrades to the image's head, or does nothing when the database is there already. In AWS it is the Argo CD PreSync
   job (ADR-0005).

The API then connects as `sft_api` (`postgres:5432` in the stack, `DATABASE_URL` in [`.env.example`](../.env.example)
from the host). If a job fails, `make up` stops and the API doesn't start; `docker compose logs db-migrate` says why.
Each workload added later, such as the outbox relay (#51), depends on `db-migrate` the same way and logs in as its own
role with the same password.

## 4. Differences from AWS that matter for tests

### PostgreSQL

- **No TLS and no IAM authentication.** Locally a password goes over plain TCP; Aurora uses IAM tokens and
  `sslmode=verify-full` (ADR-0011), so the connection code needs both paths. The login roles' local password comes
  from `db-passwords` (section 3), not from the bootstrap job.
- **The `sft` login is a superuser, and superusers bypass row-level security.** The API and tests of tenant isolation
  connect as the workload roles that the bootstrap job creates, never as `sft` (ADR-0020).
- Community PostgreSQL 17.11 against Aurora's 17.x, with Aurora's own storage, failover and parameter defaults.

### S3 (S3Mock)

- **No signature checks.** S3Mock verifies neither signatures nor pre-signed URLs, and an expired URL still works.
  Signing mistakes, the signed `Content-Length` of part URLs and expiry ([abuse and rate limits](security/abuse-and-rate-limits.md)
  6.2) are tested against S3 in M4.
- **No IAM or bucket policies.** The API's read permission on `scan=clean` objects, `s3:signatureAge`, the TLS rule and
  the deny on SSE-C don't exist locally. Test what the code asks for here, and what AWS refuses in M4.
- **No encryption.** SSE-KMS headers are accepted and returned, and a key other than the files or audit key is
  refused (`KMS.NotFoundException`), like the bucket policy. Nothing is encrypted. Name the key by its bare ID: S3Mock
  refuses ARNs and aliases, which AWS accepts. There is no bucket default encryption, so an upload without SSE headers
  comes back without them, where AWS applies the bucket's SSE-KMS default.
- **Object Lock is configuration only.** The audit archive's lock configuration is stored, but no retention is
  applied, so archived records can be deleted locally. Immutability (NFR-15) is tested in AWS.
- **CORS allows every origin.** In AWS, browser part uploads need the bucket's CORS rule, which exposes `ETag`
  (Terraform, M3 and M4).
- **No lifecycle rules, replication to Osaka or GuardDuty Malware Protection.** Large-file scans can't be tested
  locally; tests put recorded GuardDuty events on `sft-local-guardduty-results` themselves.
- Versioning, object tags, `GetObjectAttributes`, multipart uploads with `ListParts` and pre-signed part URLs behave as
  the design uses them, and objects survive restarts in the `s3-data` volume.

### SQS (ElasticMQ)

- **No fairness.** The scan queues are fair queues in AWS. ElasticMQ accepts and returns `MessageGroupId` on standard
  queues but doesn't schedule by it; fairness is tested in staging (abuse and rate limits 9.2).
- **Messages live in memory.** Restarting `sqs` loses them. There are no retention periods (4 and 14 days in AWS), no
  KMS and no queue policies, so any sender is accepted: the one-sender rule of the intake queues (threat model T-50)
  is tested in AWS.
- **No AWS event sources.** SES sending events, GuardDuty results, SES tenant status and the sign-in triggers send
  nothing locally. Tests put recorded events on the intake queues themselves.
- Per-message delays, visibility timeouts and their extension, redrive to the dead-letter queue after 5 receives and
  `StartMessageMoveTask` behave as in SQS.

### Valkey

- **Not cluster mode.** ElastiCache Serverless runs in cluster mode, where one script can't touch keys in different
  hash slots (ADR-0014). Locally such a script works, so keep keys a script uses together under one hash tag
  (`{...}`), and test the key builder for it.
- **A static password over plain TCP.** AWS uses TLS and IAM tokens that last 15 minutes, and closes connections after
  12 hours; the re-authentication path is tested in AWS.
- Valkey 9.0, a version ElastiCache supports, with nothing persisted, like the counters it holds.

### Email (Mailpit)

- **SMTP locally, the SES API v2 in AWS.** The notification worker needs a sender adapter with both.
- **No SES features.** No configuration sets and their bounce, complaint, delivery and delay events, no SES tenants,
  no suppression lists, quotas or throttling. Tests put recorded SES events on `sft-local-ses-events`.
- Every message is caught, whatever the address: nothing leaves the laptop. Tests read messages from the catcher's
  API (`MAIL_CATCHER_URL`).

### Member sign-in (Keycloak)

- **Different issuer and endpoints.** The issuer is `http://localhost:8180/realms/sft`; Cognito's is
  `https://cognito-idp.ap-northeast-1.amazonaws.com/<pool ID>`, with managed login on `auth.<domain>`. Read the
  endpoints from discovery, and take the token revocation URL from settings, since Cognito has its own
  (`/oauth2/revoke` on the managed login domain).
- **Cognito-shaped claims, not all of them.** The ID token carries `token_use`, `cognito:username` and
  `custom:tenant_id`, and `sub` is Keycloak's own ID for the user. There is no `identities` claim, because there is no
  federated SSO, and no `amr`, so the admin passkey rule's launch switch stays off locally, as it does until the
  staging test (ADR-0016).
- **No MFA.** The test member signs in with a password only; Cognito requires TOTP or a passkey. The `identity_provider`
  parameter is ignored. Tenant SSO, threat protection and the breached-password check are tested in staging (M6). The
  password policy matches the pool's: 15 to 99 characters.
- **No sign-in triggers**, so no counting of failed sign-ins and no `sign_in.attempted` events. Tests put trigger events
  on `sft-local-signin-events`.
- **Secure cookies.** Keycloak marks its sign-in cookies `Secure`. Browsers send them to `http://localhost`; scripted
  clients must send them too, as `local/smoke.py` does.
- **Nothing persists.** The realm is re-imported from [`local/keycloak/sft-realm.json`](../local/keycloak/sft-realm.json)
  on every start, so change that file, not the admin console.

### ClamAV

- **Frozen signatures.** freshclam is off, so the signatures are those built into the pinned image and every machine
  gets the same results. In EKS, clamd updates from the signature mirror.
- **Scratch in memory.** INSTREAM writes to a tmpfs, not to 4 GiB of disk, so scanning a file near 2 GB locally needs
  that much free memory in Docker.
- The size limits and the alerts for exceeded limits and encrypted content follow ADR-0019 and abuse and rate limits
  6.4; nesting, file-count and ratio limits keep ClamAV's defaults until the scan worker sets and tests them.

## 5. Hardening

Every stack service uses the `x-hardening` anchor of `compose.yaml`: a read-only root file system, every capability
dropped, `no-new-privileges` and a tmpfs `/tmp`. Each runs as a non-root user, including the images that default to
root (ElasticMQ, Mailpit and the ClamAV entrypoint), and every port binds to 127.0.0.1. The exceptions:

- **`oidc`** has a writable root file system, because Keycloak's `start-dev` rebuilds into `/opt/keycloak/lib` at
  startup. It still runs as uid 1000 with every capability dropped. A read-only Keycloak needs a pre-built image,
  which isn't worth one more build for a local stand-in.
- **`s3-init`, `db-bootstrap`, `db-passwords` and `db-migrate`** have `restart: "no"`, because each exits once its
  work is done. The API waits for all of them, which also lets `make up` accept their exit when the stack is already
  running.

## 6. Why these emulators

Checked on 2026-11-04 against the features the design uses. For S3 each candidate ran the same boto3 probe:
versioning, tags, `GetObjectAttributes`, a multipart upload through pre-signed part URLs, SSE-KMS headers, pre-signed
expiry, signature checks and CORS.

| Stand-in | Chosen | Why | Not chosen |
|---|---|---|---|
| S3 | **Adobe S3Mock 5.2.3**: Apache-2.0, Adobe, a release every few weeks (5.2.3 in September 2026) | The only candidate that accepts SSE-KMS headers and keeps objects readable across restarts, and it refuses unknown keys like our bucket policy. Every other call the design uses works. Buckets and keys are declared in configuration. | **MinIO**: AGPL-3.0; community images stopped in October 2025 and the repository is archived. **LocalStack**: its community repository is archived, and since 2026.03 the image needs an auth token, so a fresh clone can't start it without an account. **SeaweedFS 4.52** (Apache-2.0) checks signatures and CORS, but SSE-KMS needs a KMS: its local provider keeps keys in memory, so objects can't be read after a restart, and it refuses ARNs. **Versity Gateway 1.10.0** (Apache-2.0) is the smallest and checks signatures, but answers `NotImplemented` to any SSE header. **RustFS 1.0.4** (Apache-2.0) has been 1.0 only since October 2026, its KMS refuses key IDs containing `/`, such as ARNs, and buckets need API calls to create. **Garage**: AGPL-3.0 and no SSE-KMS. |
| SQS | **ElasticMQ 1.7.1**, native image: Apache-2.0, SoftwareMill, maintained (1.7.1 in April 2026, commits into November 2026) | Queues and dead-letter queues declared in one file; delays, visibility timeouts, redrive and `StartMessageMoveTask` work with current SDKs; a 33 MB image that starts in 0.1 s and runs as `nobody` on a read-only file system | **LocalStack**, as above |
| Valkey | **The official Valkey image**, BSD-3-Clause | The engine ElastiCache runs | — |
| SES | **Mailpit 1.33.0**: MIT, released weekly | 14 MB, SMTP plus a JSON API that tests can read, Host header checks against DNS rebinding | — |
| ClamAV | **The official ClamAV image**, GPL-2.0, run unmodified as its own service (ADR-0019) | The Debian tags are multi-arch; the Alpine tags are amd64 only | — |
| Cognito | **Keycloak 26.8.1**: Apache-2.0, a CNCF project, released monthly | The only candidate with real users and passwords, an enforced confidential client with PKCE S256, `prompt=login`, token revocation and per-user claims that mimic Cognito's. It costs about 700 MB of memory and 20 s to start. | **Dex 2.46** (Apache-2.0) is small, but its static users have only an email, a name, groups and an ID, so it can't issue `custom:tenant_id` or `token_use`; claim mapping with CEL is still a 2026 enhancement proposal. **mock-oauth2-server 6.1** (MIT) is light, but its login page takes any username with no password and lets the caller add claims, so there is no seeded member to sign in as. |
| PostgreSQL | **The official PostgreSQL 17 image** | The major version Aurora runs (ADR-0011); the Debian variant uses glibc collations, like most servers | — |
