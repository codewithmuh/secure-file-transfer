# Deploy config

What runs in each Kubernetes cluster, as Argo CD syncs it from `main` (ADR-0004, ADR-0005). Terraform owns AWS;
this directory owns everything inside the clusters that belongs to the application.

> [!IMPORTANT]
> **Nothing here has been deployed.** Until the maintainer names the AWS profiles, the chart is only rendered and
> checked: `helm lint`, `helm template` for every cluster, kubeconform, Trivy, the runtime-contract test and the
> cluster's admission policies (`make deploy-check`, and the `deploy` job in CI).

## Layout

```
deploy/
  argocd/                              the apps chart: AppProject `sft` and the Applications `sft` and `sft-operator`
  charts/sft/                          the application chart: the API and every worker from one image
  environments/<env>/<region>/values.yaml   one file per cluster: the image digest, the pilot light, the network, sizes
  check.sh, render.sh                  the static checks and the renderer they use
  policies.sh                          the cluster's Kyverno policies (#104) against every rendered pod
  tests/                               the runtime-contract test on the rendered manifests
```

Clusters: dev in Tokyo; staging and prod in Tokyo (`ap-northeast-1`) and Osaka (`ap-northeast-3`).

## How a cluster gets its config

1. The `cluster-bootstrap` stack (#104) installs Argo CD and a root Application, `root`, which renders
   `deploy/argocd` with the cluster's `environment`, `region` and `cluster` facts: the registry host, the database
   and counter store endpoints, the account ID, the Operator role name, the files key ARN, the environment's names
   in the shared zone (`serviceDomain`), and from the `identity` layer (#185) the user pool's ID, login domain and
   app client, the SES configuration set and, in Tokyo outside dev, Osaka's pool and client. Only Terraform knows
   them, and account IDs are never committed. Until the identity layer exists, the application part refuses to render
   and names the missing facts; the operator part doesn't need them.
2. That chart makes the AppProject `sft`: this repository only, the namespaces `sft` and `sft-operator` only, and only
   the kinds the chart renders. No Secrets, no Roles, nothing cluster-scoped but the two Namespaces. It also makes two
   Applications from `deploy/charts/sft` with the cluster's values file. `sft` renders the application (`part:
   application`) into `sft`; `sft-operator` renders the operator API alone (`part: operator`) into `sft-operator`.
   Both auto-sync with prune and self-heal, and create their namespace with Pod Security Admission at `restricted`.
3. The migration job runs first, as a PreSync hook. If it fails, or refuses an image its schema can't serve, the sync
   stops before any pod changes (ADR-0005, data model 7).

Nobody syncs or changes an Application by hand. A change, a rollback or a failover is a commit.

## The values files

`image.digest` is the line the promotion workflow (#107) edits: dev's on every build, then staging's and prod's by
promotion pull requests. Keep it as one line, `  digest: sha256:<64 hex>`, inside the top-level `image:` block. A
rollback reverts that commit. The all-zeros digest means "never built".

`pilotLight: true` holds a cluster in Osaka's pilot light (architecture 3.2): every Deployment at zero, every CronJob
suspended, and no migration job, because Osaka's database is a read-only replica. The failover's fencing commit sets
it to `false` in Osaka and `true` in Tokyo (ADR-0004, T-78). The replica counts in an Osaka file are what it runs
after a failover.

## Workloads

| Workload | Kind | Entry point | Identity (Pod Identity, #103) | Reaches |
|---|---|---|---|---|
| `api` | Deployment, 3+ across AZs, TargetGroupBinding | `python -m sft.api` | `api`, sft_api | Its proxy listener, endpoints, Aurora, Valkey, S3 |
| `relay` | Deployment, 2 | `python -m sft.workers.relay` | `relay`, sft_relay | Endpoints (SQS), Aurora |
| `notifier` | Deployment, 2 | `python -m sft.workers.notify` | `notifier`, sft_notify | Its proxy listener, endpoints (SES, SQS), Aurora, Valkey |
| `scan-worker-{small,large}` | Deployment per pool, scan nodes | `python -m sft.workers.scan` | `scan-worker`, sft_scan | Endpoints, Aurora, Valkey, S3, the clamd and inspector beside it |
| `clamd-{small,large}` | Deployment per pool, scan nodes | the clamav image's `/init-unprivileged` | none | The signature mirror only |
| `dlp-inspector-{small,large}` | Deployment per pool, scan nodes, port 8070, its own protocol; probes on 8001 | `python -m sft.dlp.inspector` | none | Nothing at all |
| `signature-mirror` | Deployment, 1 | freshclam, and `python -m http.server` from our image | none | Its proxy listener (ClamAV's database) |
| `operator-api` | Deployment in `sft-operator`, port-forward only | `python -m sft.api.operator` | `operator-api`, sft_operator | Endpoints (STS), Aurora, Valkey |
| `expiry`, `deletion`, `reconciliation`, `storage-audit`, `cleanup`, `audit-partitions` | CronJobs | `python -m sft.workers.<job>` | `jobs`, sft_jobs | Endpoints, Aurora; S3 for deletion, reconciliation and the storage audit (both Regions' files buckets outside dev, and the audit archive for reconciliation, #181) |
| `audit-archive` | CronJob, every minute | `python -m sft.workers.audit_archive` | `audit-archive`, sft_archive | Endpoints, Aurora, S3 |
| `key-rotation` | CronJob, hourly, Tokyo only | `python -m sft.workers.key_rotation` | `key-rotation`, no database; the one projected Kubernetes token | Its proxy listener (Cognito; Osaka's Secrets Manager and Cognito outside dev), endpoints (Secrets Manager), the cluster API |
| `field-keys` | CronJob, daily, Tokyo only | `python -m sft.workers.field_keys` (`FIELD_KEY_STEPS=rotate,backfill,purge`, #236) | `api`, sft_api: it acts as the API, the only role that unwraps field data keys | The database and the endpoints (KMS) |
| `invite-backlog` | CronJob, always suspended, run by hand | `python -m sft.workers.invite_backlog` | `notifier`, sft_notify | As the notifier |
| `migrate` | Job, PreSync hook | `python -m sft.data.migrate` | `migrate`, sft_migrate | Endpoints, Aurora |

Each scan node runs one trio: a worker, a clamd pod and an inspector, held together by required pod affinity. The
`clamd` and `dlp-inspector` Services keep traffic on the node (`internalTrafficPolicy: Local`), so a worker streams
only to the engines beside it. Entry points that don't exist yet are the contract for the issues that build them. Each
of those issues adds its settings to the workload's `env` in `charts/sft/values.yaml`.

The API's pods register in the edge stack's target group through a TargetGroupBinding that names the group,
`sft-<env>-<region-short>-api` (#105), so no ARN has to travel from the edge stack, which is applied after the
cluster bootstrap.

## Settings and secrets

Every setting without a default in `sft.core.settings` is in the pod spec of the entry point that reads it, and no
other; `tests/test_rendered.py` checks this against the settings classes themselves, so a new required setting fails
CI until the chart sets it. Settings come from the cluster facts and the values: the database and Valkey URLs name
the workload's own login role and user, with no password: `DATABASE_IAM_AUTH` and `VALKEY_IAM_CACHE`
(`sft-<env>-<region-short>-valkey`) make each pod sign an IAM token for every new connection (encryption 6.3, ADR-0014,
#184). The API and the operator API serve TLS on 8000 with a certificate each pod makes at start (`PUBLIC_TLS=generated`,
encryption 2.2); 8001 stays plain HTTP. The queue prefix is `sft-<env>-<region-short>-`; the API's sign-in URLs follow the user pool and `api.` and `app.` under
`serviceDomain`; its trusted proxies are the load balancer's subnets.

**One rule for overrides.** A workload's `env` in `charts/sft/values.yaml` or a cluster's values file may add
settings, never replace one the chart computes: the computed settings (the origins and sign-in URLs, the trusted
proxies, the queue prefix, the buckets and key, the database and Valkey URLs, the proxy settings, the operator API's
account and role) and the secret references win in every workload, and a values entry with one of their names is
dropped. `tests/test_overrides.py` checks this for the API, relay, notifier, scan workers and operator API, and that an
extra setting still reaches the pod.

The keyrings are read from Secrets Manager by the workloads themselves (encryption 6.4, #184): the API's
`CSRF_KEYRING`, `EMAIL_HMAC_KEYRING` and `CODE_HMAC_KEYRING`, and the notification worker's `EMAIL_HMAC_KEYRING`,
`LINK_HMAC_KEYRING` and `CODE_HMAC_KEYRING` (#178, #179), each set to `secretsmanager:sft/<env>/app/<name>`. Each pod
reads them as its own role at start, refuses to start without them, and reads them again every 5 minutes, so a rotation
step reaches every pod within one interval and needs no restart (`sft.runtime.secrets`). Only the notifier's role may
read K_link. The API's user pool client (`OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`) still comes through the ExternalSecret
`api-secrets`, from the cluster-bootstrap stack's `application-secrets` store, which serves the `sft` namespace only,
as `secretKeyRef`s. No secret value is ever in Git, the values or a rendered manifest.
The API also gets both regions' audit archive buckets (#177), Tokyo's alone in dev, which has no Osaka.
The notifier sends with the Region's configuration set (`SES_CONFIGURATION_SET`, `sft-<env>`), whose bounces and
complaints come back on the `ses-events` queue, and invites members through Cognito's admin API on the Region's pool
(`USER_POOL_BACKEND=cognito`, #193).

**The first deploy of an environment.** The `identity` layer creates the `sft/<env>/app/*` secrets without a value,
and only the key rotation job writes them (encryption 6.4). So after the first sync the API and the notifier refuse to
start without their keyrings, and the API waits on `api-secrets` too, until the job has run once (it then restarts the
API; the notifier's next restart finds its keyrings); start it rather than wait for the hour:

```bash
kubectl -n sft create job --from=cronjob/key-rotation key-rotation-first
```

**Members invited before the pool existed** (#193) stay `invited` until the one-off backlog pass invites them. Run it
once, after the notifier is up with `USER_POOL_BACKEND=cognito`; running it again is safe, because a member who already
has an identity on the pool is skipped:

```bash
kubectl -n sft create job --from=cronjob/invite-backlog invite-backlog-1
```

## What every pod gets

The runtime contract of architecture 8 and the pod rules of ADR-0004, written once in `charts/sft/templates/_helpers.tpl`
and checked on every rendered container by `tests/test_rendered.py`:

- Probes on the internal port 8001, plain HTTP: liveness `/healthz`, readiness `/readyz`, for every server of ours.
  Third-party containers are probed on their own port. The DLP inspector serves its probes from a thread on 8001
  (#184), apart from its framed protocol on 8070, where a probe would count as a bad request and wait behind the file
  being inspected.
- A `preStop` sleep (15 s) on the API and the operator API, inside their grace periods. The API's is 150 s, for 15 s of
  sleep and 120 s of download drain (abuse 5.7).
- `enableServiceLinks: false`, and no Kubernetes API token: `automountServiceAccountToken: false` on every pod and
  ServiceAccount. Pod Identity needs no token.
- Non-root, a read-only root file system with `/tmp` on an `emptyDir`, no capabilities, no privilege escalation and
  the `RuntimeDefault` seccomp profile. No host namespaces, ports or paths.
- Images by digest from our registry in the cluster's own region: `sft/app` for ours, `mirror/…` for third-party ones
  (ADR-0007).
- Memory limits and CPU requests from capacity 4.1. No CPU limits, so the API isn't throttled under load. Trivy's
  low-severity CPU-limit check flags that, by design.
- A PodDisruptionBudget for every Deployment (one pod at a time), default-deny NetworkPolicies in both namespaces, and
  one policy per workload with exactly what it may reach (ADR-0021). The DLP inspector has no egress at all.
- Only the API and the notification worker get `HTTPS_PROXY`, each its own listener. `NO_PROXY` keeps AWS calls on the
  VPC endpoints. Cognito is left out of it, so Cognito calls go through the listener.

## Alerts

`alerts/` holds alert rules in Prometheus rule format, each with its runbook and a `promtool test rules` unit test in
`alerts/tests/` (`alerts/test.sh`, CI's deploy job): `ScanFailed` (#175) and `DlpInspectorFailing` (#176), and
`BreakGlassActive`, `BreakGlassSelfApproved` and `BreakGlassSweepStalled` from the operator API's metrics (#232). The
chart doesn't load them yet: nothing in the clusters evaluates rules before ADR-0009's monitoring stack and M7's
alerting as code, which take them from here.

## Checks

```bash
make deploy-check   # helm lint, template and kubeconform per cluster, the runtime-contract test, the admission policies,
                    # the alert rules' unit tests
```

It needs helm 3, kubeconform and Docker, at the versions pinned in `.github/workflows/ci.yml` and `policies.sh`.
`policies.sh` renders the cluster's own Kyverno policies (`infra/modules/cluster-bootstrap/charts/kyverno-policies`)
for each cluster's registry, turns every rendered Deployment, Job and CronJob into the Pod it makes, and runs the
Kyverno CLI on them: a pod the cluster would refuse fails here first. The signature policy needs a live registry and
isn't run. `tests/test_secret_stores.py` renders the cluster bootstrap's External Secrets stores
(`infra/modules/cluster-bootstrap/charts/secret-stores`) and checks that each assumes its own role (encryption 6.4).
CI's `deploy` job also scans every rendered manifest with Trivy, and the repository-wide Trivy scan renders
the charts with `tests/trivy-values.yaml`.

## Not here yet

- KEDA ScaledObjects (ADR-0004). Replica counts are fixed per cluster until KEDA is installed.
- Prometheus scrape configuration: ADR-0009's issue adds the PodMonitors. The network policies already admit
  `monitoring` on 8001.
- A PriorityClass for the API (capacity 4.2), which is cluster-scoped and so belongs to the cluster bootstrap.
- The RDS certificate bundle in the image. `sslmode=verify-full` needs the CA that signed Aurora's certificate
  (`rds-ca-ecc384-g1`, infra/modules/aurora), which isn't in the system's trust store: the image needs the bundle and
  the URL `sslrootcert=<its path>` before the first connection in AWS (#184 left it open).
