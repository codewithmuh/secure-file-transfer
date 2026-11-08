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
- These ports free on 127.0.0.1 and on `::1`: 1025, 3000, 3310, 5432, 6379, 8000, 8001, 8025, 8180, 9090 and 9324.
  A browser tries `localhost` on `::1` first, so another program listening on `[::]:3000` (a dev server, say) answers
  in place of the web app: stop it before `make up`.

| Command | What it does |
|---|---|
| `make setup` | Checks the prerequisites, installs the API's dependencies and the git hooks |
| `make up` | Builds the API, starts the stack, runs the database jobs (section 3), then starts the API and waits until every service is healthy (under a minute once images are pulled) |
| `make smoke` | One real round trip to each stack service, from the host ([`local/smoke.py`](../local/smoke.py)), and a check that `sft_api` reads no tenant's rows without a scope |
| `make seed` | Writes a tenant, an admin and a member who sign in through Keycloak, and prints how (section 7). Idempotent |
| `make jobs JOB=<job>` | Runs one lifecycle job once: `expiry`, `deletion`, `reconciliation`, `storage-audit` or `cleanup` (section 7) |
| `make e2e` | The M2 journey test against the running, seeded stack (section 7) |
| `make web-e2e` | The web app's browser flows against the running, seeded stack, in the pinned Playwright image (section 8) |
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
| `s3` | S3 ([ADR-0012](adr/0012-object-storage-s3.md)) | `adobe/s3mock:5.2.3` | 9090 | Created by `s3-init`: `sft-local-files` and `sft-local-large-files` with versioning on; `sft-local-audit-archive`, and `sft-local-audit-archive-osaka` standing in for Osaka's (#177), each with versioning and Object Lock (governance, 1 day, as in dev) |
| `sqs` | SQS ([ADR-0013](adr/0013-queues-sqs-outbox.md)) | `softwaremill/elasticmq-native:1.7.1` | 9324 | `sft-local-` plus `scan-small`, `scan-large` and `notify` (work queues) and `signin-events`, `ses-events`, `guardduty-results` and `ses-tenant-status` (intake queues), each with a `-dlq` after 5 receives |
| `valkey` | ElastiCache Serverless for Valkey ([ADR-0014](adr/0014-rate-limit-counters.md)) | `valkey/valkey:9.1.3-alpine` | 6379 | ACL user `sft-local`; the default user is off |
| `mail` | SES ([ADR-0015](adr/0015-email-ses.md)) | `axllent/mailpit:v1.33.0` | 1025 (SMTP), 8025 (web UI and API) | Nothing; it catches every message |
| `clamd` | The clamd pods ([ADR-0019](adr/0019-malware-scanning-clamav-guardduty.md)) | `clamav/clamav:1.5.4-debian` | 3310 | The signatures built into the pinned image |
| `oidc` | The Cognito user pool and its app client ([ADR-0016](adr/0016-member-sign-in-cognito.md)) | `quay.io/keycloak/keycloak:26.8.1` | 8180 | Realm `sft`, confidential client `sft-api-local`, the notification worker's client `sft-notify-local` (it may only manage the realm's users) and the test admin and member, re-imported when the container is created |
| `web` | The web app on its own origin: S3 and CloudFront ([ADR-0008](adr/0008-web-app-s3-cloudfront.md)) | Built from [`web/Dockerfile`](../web/Dockerfile): the production bundle behind `nginxinc/nginx-unprivileged:1.30.6-alpine` | 3000 | [`local/web/config.json`](../local/web/config.json), mounted read-only (section 8) |

The stack also runs the API (`:8000`) and the scan pipeline of ADR-0019 and ADR-0022 (#175, #176): a scan worker per
pool, `scan-worker-small` (`:8012`, files up to 100 MB) and `scan-worker-large` (`:8013`, over 100 MB up to 2 GB),
each port serving only `/healthz`, `/readyz` and `/metrics`, and `inspector`, the DLP inspector, from the API image.
The inspector is only on the `inspection` network, which is internal: it can open no connection out and reach neither
the database nor the counter store, and only the scan workers reach it (`make smoke` checks both). It runs non-root on
a read-only root file system, with 4 GiB of scratch in memory. The notification worker, `notifier` (`:8014`, #178,
#179), sends every link, code and notice into Mailpit, linking to `WEB_ORIGIN`. It is also the only service that may
manage the user pool's users (authn-authz 2.5, #197): for an invitation or a sign-in reset it creates the member's
Keycloak user with a temporary password, records the identity, then emails the invitation (section 4, member sign-in). `s3-init` is a one-shot container that seeds the S3
stand-in on every `make up` and exits; repeating it is safe. So are the three database jobs of section 3, which run
before the API starts.

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
| Test member | `dev.member@example.com` / `local-only-member-password`. User ID (`cognito:username`) `22222222-2222-4222-8222-222222222222`, tenant (`custom:tenant_id`) `11111111-1111-4111-8111-111111111111`, subject (`sub`) `33333333-3333-4333-8333-333333333333`. `make seed` writes this user and its identity (section 7). |
| Test admin | `dev.admin@example.com` / `local-only-admin-password`. User ID `44444444-4444-4444-8444-444444444444`, the same tenant, subject `55555555-5555-4555-8555-555555555555`. `make seed` writes it too. |
| Notification worker's pool client | `sft-notify-local` / `local-only-notify-pool-secret`: a Keycloak client whose service account may only manage the realm's users (#197) |
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
- **Both archive regions are one S3Mock.** The API writes each security-critical record to `sft-local-audit-archive`
  and to `sft-local-audit-archive-osaka` (#177), so a test can stop one, by pointing its setting at a bucket that
  doesn't exist, and see the `503`. In AWS, Tokyo reaches Osaka's archive through the network layer's cross-Region S3
  endpoint, with the IAM and bucket policy of both Regions' archive (#185).
- **CORS allows every origin.** In AWS, browser part uploads need the bucket's CORS rule, which exposes `ETag`
  (Terraform, M3 and M4). `completeUpload` lists the parts server side, so the browser never needs `ETag`.
- **Part URLs name `localhost:9090`.** The API calls S3Mock in-network (`s3:9090`), but a browser uploads parts from
  the host, so compose sets `S3_PRESIGN_ENDPOINT_URL=http://localhost:9090`, used only to sign part URLs (#195). S3Mock
  checks no signature, so the different host costs nothing; the settings refuse it without `S3_ENDPOINT_URL`, so it is
  never set in AWS, where S3 signs its own host. The scan workers keep reading through `s3:9090`.
- **No lifecycle rules, replication to Osaka or GuardDuty Malware Protection.** Large-file scans can't be tested
  locally; tests put recorded GuardDuty events on `sft-local-guardduty-results` themselves.
- **Files over 2,000,000,000 bytes are never scanned, locally and in dev, until M6.** Only GuardDuty scans them, and
  nothing records its result before M6. So completion records such a file `scan_failed` at once, with
  `scan_detail = large_file_scanning_unavailable`; `getFile` shows that, and sending its transfer holds it. It doesn't
  page `ScanFailed`. Send files of up to 2 GB to test a journey end to end.
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
- Valkey 9.1, with nothing persisted, like the counters it holds. ElastiCache added 9.1 for node-based clusters in June
  2026; a serverless cache names only the major version (9) and AWS picks the minor, so keep to commands Valkey 9.0 has.

### Email (Mailpit)

- **SMTP locally, the SES API v2 in AWS.** One adapter has both (`sft.data.mail`, #100): `MAIL_BACKEND=smtp` with
  `SMTP_HOST` and `SMTP_PORT` here, `ses` in AWS. Mailpit's reverse DNS lookup of the client is off
  (`MP_SMTP_DISABLE_RDNS`), because on Docker Desktop it can outlast the adapter's 5 s timeout.
- **No SES features.** No configuration sets and their bounce, complaint, delivery and delay events, no SES tenants,
  no suppression lists, quotas or throttling. Tests put recorded SES events on `sft-local-ses-events`.
- Every message is caught, whatever the address: nothing leaves the laptop. Tests read messages from the catcher's
  API (`MAIL_CATCHER_URL` in the smoke test; `TEST_MAIL_CATCHER_URL` and `TEST_SMTP_PORT` for the adapter's
  integration test, `services/api/README.md`, Email).

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
  clients must send them too, as `local/smoke.py` does. The API's own cookies (`__Host-sft_session`, and
  `__Host-sft_link` for recipients' link sessions, #179) are `Secure` and `__Host-` locally too: browsers treat
  `http://localhost` as a secure context and keep them, so nothing about them differs from AWS.
- **Nothing persists.** The realm is imported from [`local/keycloak/sft-realm.json`](../local/keycloak/sft-realm.json)
  when the container is created, so change that file, not the admin console, and run `make down && make up` to pick a
  change up: `make up` alone keeps a running container and its realm. That includes the users the notification worker
  created for invited members: after `make down`, their identities are still in the database but their Keycloak users
  are gone, so they can't sign in until an admin resets their sign-in ("Reset sign-in" on the users page), which
  creates them again and emails a new invitation.
- **Invitations** (#197, authn-authz 2.5). Locally the notification worker plays Cognito's admin side: it creates the
  invited member's Keycloak user (username = our user ID, the address verified, `tenant_id` set) with a temporary
  password, records the identity, and emails `member_invitation` through Mailpit. At the first sign-in Keycloak makes
  them choose their own password, as Cognito does; there is no TOTP enrollment locally. Keycloak's temporary passwords
  don't expire, where Cognito's work for 3 days. An address that already signs in for another tenant gets
  `invitation_address_in_use` instead; the inviting tenant's audit log records an invitation email as for anyone, and
  the conflict is in the platform audit log only. "Resend invitation" on an invited user, and "Reset sign-in" on an
  active one, send a new invitation; a newer one replaces one still on its way. In AWS the worker does the same
  through Cognito's admin API (`USER_POOL_BACKEND=cognito`, #193), and members invited before the pool existed are
  invited by the one-off `invite-backlog` pass.
- **Sign-out.** The API's logout URL is Keycloak's logout endpoint without an ID token hint, so Keycloak asks to
  confirm the logout. The API session has ended either way, and the next sign-in asks for the password again
  (`prompt=login`).

### ClamAV

- **Frozen signatures.** freshclam is off, so the signatures are those built into the pinned image and every machine
  gets the same results. In EKS, clamd updates from the signature mirror.
- **Scratch in memory.** INSTREAM writes to a tmpfs, not to 4 GiB of disk, so scanning a file near 2 GB locally needs
  that much free memory in Docker.
- The size limits and the alerts for exceeded limits and encrypted content follow ADR-0019 and abuse and rate limits
  6.4. The zip-bomb limits are set and tested (#175, `services/api/tests/test_scan_engines.py`): archives nested more
  than 10 deep, more than 10,000 files in one scan and a scan over 5 minutes are limit alerts, so `unscannable`.
  ClamAV has no compression-ratio setting; a ratio bomb stops at `MaxFileSize` or `MaxScanSize` instead. The chart's
  clamd uses the same values.

## 5. Hardening

Every stack service uses the `x-hardening` anchor of `compose.yaml`: a read-only root file system, every capability
dropped, `no-new-privileges` and a tmpfs `/tmp`. Each runs as a non-root user, including the images that default to
root (ElasticMQ, Mailpit and the ClamAV entrypoint), and every port binds to 127.0.0.1. The exceptions:

- **`web`** runs nginx as uid 101 with a read-only root file system; it writes only its pid and temporary files to
  `/tmp`.
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

## 7. Seed, lifecycle jobs and the M2 journey

**The seed** (#182). `make seed` runs [`local/seed.py`](../local/seed.py) against the stack's database, as `sft`. It
writes the `local-keycloak` connection in `idp_connections` (the pool's row, with no tenant), the tenant
`Local Example Co` with its policy, and the test admin and member of section 3, each with a `user_identities` row
bound to its Keycloak subject, so both sign in through Keycloak as members do through Cognito. Every row has a fixed
ID and is written with `ON CONFLICT DO NOTHING`: run it twice and nothing changes. `--suppress ADDRESS` adds a
suppression for that address in the tenant (#174), to show `422 recipient_undeliverable`. It refuses any database but
the local stack's (the loopback address, the `sft` database, the stack's roles and schema), and it prints the sign-in
details:

```bash
make up && make seed
# then sign in at http://localhost:3000 (the web app, M3), or start at http://localhost:8000/v1/auth/sign-in
```

**The lifecycle jobs** (#181) are one-shot commands, as the CronJobs that run them in AWS (M4): `make jobs JOB=expiry`
runs `python -m sft.workers.jobs expiry` in the `jobs` service, which `make up` never starts (compose profile `jobs`).
`expiry` records expired transfers and cancels drafts idle for 7 days; `deletion` deletes every version of each due
file, and any unfinished upload of it, in the local buckets; `reconciliation` rejects uploads with no part for 24
hours, finishes completions left for 15 minutes, runs the scan sweep and rewrites missing grant records;
`storage-audit` deletes orphan objects and stale uploads over 24 hours old and reports what is left; `cleanup` deletes
expired codes, link sessions and grants. Each logs its report as one JSON line. The local buckets have no Osaka
replicas, so "every copy" means every object version in `sft-local-files` and `sft-local-large-files`; the Osaka copies
are checked when the journey runs against AWS in M4.

**The clock's test hook** (#182). `CLOCK_OFFSET_SECONDS` moves what the API and the jobs read as "now"
(`sft.core.clock`). The settings refuse it unless `ENVIRONMENT` is `local` or `test`, so it can't be set in dev,
staging or prod. The API keeps it at 0; the journey moves only the jobs:
`CLOCK_OFFSET_SECONDS=7200 make jobs JOB=expiry` runs expiry two hours from now.

**The M2 journey** (#182, [`services/api/tests/test_journey.py`](../services/api/tests/test_journey.py)) is one test
of M2's exit criterion, step by step, against the running stack: the seeded member signs in through Keycloak, sends a
transfer of two files to two recipients (one file with a synthetic My Number, one upload interrupted and resumed),
ClamAV scans and the inspector inspects both, Mailpit holds a link email per recipient, a recipient verifies with the
code from Mailpit and downloads a file in two ranges, the member revokes the transfer, and a second transfer expires
under the clock's hook and its files leave the buckets. It ends by checking the audit log has an event for each step
and no token, code, address, file name or My Number. A failure names its step.

```bash
make up && make seed && make e2e
```

It talks to the service only through the public API, Mailpit's API, S3's API, the job commands and the clock's hook,
so in M4 it runs against dev with the seed and the clock replaced there. Two local shortcuts are named in the test:
it sends part URLs, which name `localhost:9090` (section 4), to `127.0.0.1:9090`, and it reads the audit log from the
database until an audit search operation exists. It is skipped unless `SFT_E2E=1` (`make e2e` sets it), so `make test`
never starts it. CI's Local stack job runs `make seed` and `make e2e` after the smoke checks, on every pull request.

## 8. The web app and how to test locally

**The `web` service** (#195) serves the production bundle the way CloudFront does in AWS ([ADR-0008](adr/0008-web-app-s3-cloudfront.md),
[`web/nginx.conf`](../web/nginx.conf)), on its own origin, so CORS, `Origin` and `Sec-Fetch-Site: same-site` are
exercised as in AWS:

- `http://localhost:3000`, always `localhost`, never `127.0.0.1`, which redirects (`308`) to `localhost`: the API
  checks `Origin` against `WEB_ORIGIN` exactly, and cookies are kept per host name. Chrome, Edge and Firefox keep the
  `Secure` and `__Host-` cookies on `http://localhost`; Safari is checked in dev behind real TLS (M4).
- A path without a file extension serves `index.html` (the router takes it from there); a missing file is a `404`.
  `index.html` and `config.json` are `no-cache`, hashed assets `immutable`.
- CloudFront's response headers with the local origins: `Content-Security-Policy: default-src 'self'; script-src
  'self'; connect-src 'self' http://localhost:8000 http://localhost:9090; frame-ancestors 'none'; base-uri 'none';
  object-src 'none'; form-action 'self' http://localhost:8000`, `X-Content-Type-Options: nosniff`, `X-Frame-Options:
  DENY` and `Referrer-Policy: no-referrer`. No HSTS: the stack is plain http.
- [`local/web/config.json`](../local/web/config.json) names the API (`http://localhost:8000/v1`), the S3 stand-in for
  part uploads (`http://localhost:9090`) and Keycloak (`http://localhost:8180`), which sign-out may go to; SSO is off.

`make smoke` checks the web app, its headers, the part-URL host and CORS (the web app's preflight passes, another
origin's doesn't).

**Hot reload.** `docker compose stop web`, then `cd web && npm install && npm run dev`: the same
`http://localhost:3000`, with Vite's proxy sending `/v1` to the API, so the API is same-origin there
(`web/public/config.json`) and `WEB_ORIGIN` doesn't change. Vite injects inline scripts, so the CSP is checked only on
the compose build. `make up` starts the built app again.

**Browser flows** (`make web-e2e`, #195 to #200): Playwright, in the image pinned in the Makefile, against the running,
seeded stack, so no browser is installed on the host. The browser must see `localhost:3000`, `:8000`, `:8180`,
`:8025` and `:9090` exactly as a person does. On Linux (CI) the container shares the host's network. Docker Desktop
(macOS) has no host networking by default, so there `web/e2e/support/forward.mjs` listens on those ports inside the
container and forwards them to `host.docker.internal`, which reaches the stack's `127.0.0.1` ports; the browser still
sees `localhost`. CI's Local stack job runs it after `make e2e`. It includes the M3 journey (#200) in English and
Japanese, which runs the expiry and deletion jobs with the clock moved on: the container has no Docker, so
`local/e2e-jobs.sh` runs them on the host while `make web-e2e` runs, answering request files in a temporary folder.
Traces, screenshots and the HTML report land in `web/test-results/`. `E2E_ARGS='--project ja'` runs the Japanese
journey alone. The lockout test's 20 wrong codes count against the per-IP quota of 30 failed codes an hour
(abuse-and-rate-limits 2.2 A), so run the whole suite at most once an hour, or `make down && make up` first: Valkey
keeps no volume, so that clears the counters.

### How to test locally

```bash
make setup                # once: prerequisites, API dependencies, git hooks
make up                   # API, workers, Keycloak, Mailpit, S3Mock, ... and the web app on :3000
make seed                 # once per fresh database: tenant, admin and member with Keycloak identities
make smoke                # optional: one round trip to every service, the web app and CORS
```

Open **http://localhost:3000** (always `localhost`, never `127.0.0.1`).

| Who | Sign in | Where |
|---|---|---|
| Member | `dev.member@example.com` / `local-only-member-password` | http://localhost:3000 |
| Admin | `dev.admin@example.com` / `local-only-admin-password` | http://localhost:3000 |
| Recipient | no sign-in: the link and the code arrive in Mailpit | http://localhost:8025 |
| Uploader | no sign-in: the upload link and the code arrive in Mailpit | http://localhost:8025 |
| Keycloak console | `admin` / `local-only-admin` | http://localhost:8180/admin |

1. **Send.** Sign in as the member, "New transfer": add a recipient (any address; Mailpit catches everything), pick
   files, send. The detail page shows each file going `Scanning`, then `Clean` and `Inspected`. To see the scanner and
   DLP work: an EICAR test file becomes `Infected` and holds the transfer; a text file with a synthetic My Number shows
   the `jp_my_number` detector ("My Number (Individual Number)"), and "Show findings" lists where. Write the EICAR file
   yourself, never into the repository: `make web-e2e` builds both at run time (`web/e2e/support/stack.ts`). The
   default DLP policy (#219) warns on a recipient domain the tenant hasn't sent to in 365 days and on My Numbers, so a
   first send waits as `Awaiting confirmation`: "Send anyway" sends it, and a rule that needs approval asks for a
   reason and goes to an approver's queue ("Approvals", #220).
2. **Resume an upload.** Cut the network mid-upload: the page retries each part and, when the network is back,
   carries on from the parts S3 already holds. Reload mid-upload, open the draft from "Transfers", choose the same file
   again: only the missing parts go.
3. **Receive.** Open Mailpit, open the link email (in the recipient's language), click the link. Use a different
   browser profile or a private window, so the member's session and the recipient's don't mix. The page is in the
   link's language whatever the browser's. "Email me a code", read the code in Mailpit, verify, then download each
   file; the member's detail page shows that recipient verified, with the download and its time. A reload forgets the
   link (it is kept in memory only): open it from the email again, and the page carries on without a new code. Twenty
   wrong codes lock the recipient (five a code, one code every 30 seconds); the member's "Unlock and send a new link"
   emails a new link, and the old one stops working. "Revoke transfer" stops new downloads at once. Tick "Email me when
   the files are first downloaded" when sending, and the first download puts one notice in Mailpit (#214); "Extend
   expiry" on the detail page offers later times up to 30 days, or the tenant's maximum, after sending.
4. **Ask for files** (#212, #213). As the member, "Upload requests", "New upload request": any uploader address, their
   language, how long it stays open and a message. Mailpit gets the upload request email in that language, with a
   `/u#` link. Open it in a private window: "Email me a code", read the code in Mailpit, verify, and the page shows who
   asks, the message, the expiry and the limits; choose files and they upload, each shown `Received`, `Blocked by the
   company's policy` (an EICAR file), `Couldn't be scanned`, or `Accepted` for an unscannable file the tenant policy
   allows; "Remove" takes a file back while the request is open (#229). The member's request page lists what
   arrived, with "Download", "Delete", findings and the day each file is deleted; Mailpit gets the "files arrived"
   notice. Revoking the request ends the uploader's page.
5. **Administer.** Sign in as the admin (the sign-in always asks for the password, so switching users needs no
   cleanup): "Users" to invite (the invitation, with a temporary password, arrives in Mailpit; sign in with it in a
   private window and choose a password), change a role or the DLP approver flag, sign someone out everywhere, reset a
   sign-in (a new invitation arrives) or deactivate; "Tenant policy" for the longest expiry (the member's form follows
   it), unscannable files, the retention of received files, the default language, the allowed and blocked recipient
   domains and clearing a suppressed address (#217); "Audit log" to search and export (#216); "API keys" to create, use
   and revoke a key (#215); "Data loss prevention" for the DLP settings, rules and keyword lists (#218). The admin's
   "Show every … in the organization" switch on "Transfers" and "Upload requests" lists and revokes other members'.
6. **Expiry.** `make e2e`'s clock hook and job commands (#181, #182) expire and delete a transfer on demand:
   `CLOCK_OFFSET_SECONDS=7200 make jobs JOB=expiry`. Its link then shows "This link has expired", and the member's
   list shows it `Expired`.
7. **Automated.** `make web-a11y` (axe on every page, dialog and link state, no backend), then `make web-e2e` (every
   browser flow and the M3 journey in both languages, against the seeded stack).

Not available locally yet: SSO, passkeys and step-up prompts beyond "Sign in again" (M6).
