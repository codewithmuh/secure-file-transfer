# Observability

How each cluster collects, keeps and shows its metrics, logs and traces, and how its alerts leave it. The design is
[ADR-0009](../adr/0009-observability-opentelemetry-self-hosted.md); this page is what [#243](https://github.com/codewithmuh/secure-file-transfer/issues/243)
and [#244](https://github.com/codewithmuh/secure-file-transfer/issues/244) built. The metrics themselves are in the
catalogue ([metrics.md](metrics.md), #242), the objectives in [slos.md](slos.md) (#245) and the alert rules in
[`deploy/alerts/`](../../deploy/alerts/).

> [!IMPORTANT]
> **Nothing here has run in AWS yet.** The stack is rendered and checked statically (`deploy/check.sh`, the tests in
> `deploy/observability/tests`, `deploy/policies.sh`, Trivy) and its Terraform validates. Every live check in
> [section 9](#9-checks) is pending the AWS run.

## 1. What runs where

Every cluster runs the same stack, cut down in dev and staging ([capacity](../design/capacity-and-cost.md) 4.3). An
Osaka pilot light runs none of it (architecture 3.2): it starts with the fencing commit of a failover, with empty
history, while Tokyo's logs and traces stay in Tokyo's buckets.

| Component | Namespace | Kind | prod | dev, staging | Calls AWS as |
|---|---|---|---|---|---|
| Prometheus (Prometheus Operator's `Prometheus`) | `monitoring` | StatefulSet, made by the operator | 2 replicas, 30 days, 200 GB each | 1 replica; 3 days on 20 GB (dev), 7 days on 50 GB (staging) | nothing |
| Alertmanager (`Alertmanager`, `AlertmanagerConfig`) | `monitoring` | StatefulSet, made by the operator | 2 | 1 | `sft-<env>-alertmanager`: SNS publish |
| Pushgateway | `monitoring` | StatefulSet, 1 GB volume | 1 | 1 | nothing |
| CloudWatch exporter | `monitoring` | Deployment | 1 | 1 | `sft-<env>-cloudwatch-exporter`: CloudWatch reads |
| Loki | `monitoring` | simple scalable: 2 write (25 GB), 2 read, 1 backend (25 GB) | as left | single binary (15 GB dev, 25 GB staging) | `sft-<env>-loki`: its bucket |
| Tempo | `monitoring` | single binary, StatefulSet | 1, 25 GB | 1 (15 GB dev, 25 GB staging) | `sft-<env>-tempo`: its bucket |
| OpenTelemetry gateway collector | `monitoring` | Deployment | 2 | 1 | nothing |
| OpenTelemetry agent collector | `node-agents` | DaemonSet, every node of every pool | one per node | one per node | nothing |
| Grafana | `grafana` | Deployment | 1 | 1 | nothing |
| Prometheus Operator, kube-state-metrics | `monitoring` | Deployments, from cluster-bootstrap | 1 each | 1 each | nothing |

Retention: metrics 30 days in prod (NFR-1's 28-day window from local data), 7 in staging, 3 in dev; logs 90 days in
prod (PRD data lifecycle), 14 in staging, 7 in dev; traces 14 days in prod (capacity A33), 7 in staging, 3 in dev.
Loki and Tempo enforce their own; each bucket's lifecycle rule removes anything a few days older, in case a compactor
stops.

## 2. How it is deployed

Two halves, split by who may grant what:

- **Terraform's cluster-bootstrap layer** ([`infra/modules/cluster-bootstrap/observability.tf`](../../infra/modules/cluster-bootstrap/observability.tf))
  makes what is cluster-wide: the three namespaces, the `observability` storage class (gp3 under the account's default
  EBS key, the platform key), the Prometheus Operator with its CRDs and kube-state-metrics from the pinned
  kube-prometheus-stack chart with everything else in it switched off, and Prometheus' read-only discovery role
  `sft:prometheus`. Both controllers need cluster-wide RBAC, which a project synced from Git should not be able to
  grant. In an Osaka pilot light they sit idle on its one system node, so a failover needs no apply. Helm installs
  the chart's CRDs on the first install only, so a chart bump applies the new CRDs first (section 11).
  The layer's [`infra/modules/observability`](../../infra/modules/observability/README.md) makes the AWS side: Loki's
  and Tempo's buckets in the cluster's Region, the four roles (from Tokyo) and their Pod Identity associations.
- **Argo CD** syncs everything else from `main`. Terraform's root release adds a second root Application,
  `observability`, beside the application's `root`. It renders [`deploy/observability/argocd`](../../deploy/observability/argocd)
  with the cluster's facts and the cluster's own values file, whose `pilotLight` decides whether there is a stack:
  - the AppProject `observability`: this repository only; the namespaces `monitoring`, `grafana` and `node-agents`
    only; no cluster-scoped kind, no Secret and no Role; one RoleBinding kind, for Grafana's port-forward;
  - one Application per chart in [`deploy/observability/charts`](../../deploy/observability/charts): `prometheus`,
    `loki`, `tempo`, `collectors` and `grafana`. Each gets the cluster's values file (for its network), then
    `deploy/observability/environments/<env>.yaml` (its sizes), then the facts only Terraform knows under `global`:
    the registry, the environment, the Region and the account. Auto-sync with prune and self-heal, server-side apply.

Loki and Tempo are their vendors' charts, pinned and vendored in each chart's `charts/` with their checksums in
`charts/SHA256SUMS`, so Argo CD renders them from Git alone and no cluster reaches a chart repository (ADR-0005,
ADR-0007). The rest are short charts of our own: the Prometheus Operator's resources, the collectors, Grafana.
Every image is a mirror of the upstream's by digest, pinned in cluster-bootstrap's `images.tf` (which the mirror
workflow copies and Kyverno admits) and named by the same digest in the charts; a test checks they agree.

## 3. Metrics

Prometheus scrapes, every 30 s:

- **The application**, on its internal port only (architecture 8): the `api`, `relay`, `notifier` and `scan-worker`
  pods in `sft` and the `operator-api` in `sft-operator`, the components whose network policy admits Prometheus there.
  A test checks the two lists agree. clamd and the DLP inspector serve no metrics on it.
- **The scheduled jobs and the synthetic probe**, through the Pushgateway: a one-shot job has nothing to scrape, so
  each run pushes its registry to `http://pushgateway.monitoring.svc.cluster.local:9091` (`METRICS_PUSHGATEWAY_URL`,
  set by the application chart's `metricsPushgateway`, whose network policies admit the gateway's pods). The gateway
  keeps the last push of every job on its volume, so `lifecycle_job_last_success_timestamp_seconds` survives a
  restart; it is scraped with `honor_labels`, so each push keeps its own `job` label (`job="purge"`, the grouping
  key). The drill scripts push `sft_drill_active` here too ([drill-in-progress.md](../runbooks/drill-in-progress.md)).
- **AWS**, through the CloudWatch exporter every 2 minutes: SQS queue age and depth (dead-letter queues included),
  Aurora's global replication lag, CPU and connections, S3 replication latency and backlog, and the load balancer's
  requests and 5xx. The exporter's own naming applies: `aws_<namespace>_<metric>_<statistic>`, with the namespace
  lower-cased and the metric and statistic in snake case, and a `dimension_<Name>` label per dimension
  (`aws_sqs_approximate_number_of_messages_visible_maximum{dimension_QueueName=...}`). Each metric is narrowed to the
  cluster's own `sft-<env>-<region-short>-` resources. The list is `cloudwatchExporter.metrics` in the prometheus
  chart's values; add a metric there and the dashboards' test knows its name.
- **The platform**: the stack's own pods, the egress proxy's Envoy statistics (port 9902, whose policy admits pods
  labelled `app.kubernetes.io/name: prometheus` in `monitoring`, the operator's label), Argo CD's application
  controller (`argocd_app_info`, port 8082, which its chart's policy admits from any namespace), the Prometheus
  Operator and kube-state-metrics, and the kubelets' container CPU and memory and volume usage (only those series are
  kept).

**Traces** leave the application the same way from every workload that makes them: the API, the operator API and the
workers get `OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-agent.node-agents.svc.cluster.local:4318` from the application
chart's `telemetry` values, and their network policies admit the node's agent on 4318 (section 5).

Every rule file in `deploy/alerts/*.rules.yaml` becomes a PrometheusRule by glob (the prometheus chart's `alerts/` is a
link to that directory), and Prometheus evaluates every rule in its namespace: **a new rule file needs no wiring**.
A test checks each file arrives with the same groups. The rules' unit tests stay in `deploy/alerts/test.sh`.

## 4. Logs

The agent on each node tails every container's log file under `/var/log/pods` (read-only), except its own, takes the
namespace, pod and container from the file's path, and sends the lines to Loki over OTLP (`loki-push`). It runs as a
non-root user in the root group, which may read the runtime's `0640` files, with no capability; that host path is
why its namespace, `node-agents`, is the one Kyverno lets mount one (cluster-bootstrap's host-access namespaces), and
why it is at Pod Security `privileged` rather than `restricted`. Privileged containers, host namespaces and host
ports stay refused there too. It also runs on the system nodes, so the platform's logs, the egress proxy's among
them, are in Loki.

What reaches the logs is decided where they are written: one JSON line per event with `request_id`, `trace_id` and
`tenant_id`, and never tokens, codes, addresses or file names (ADR-0009, T-49, T-88, the canary test). Loki keeps them
under the logs key in its bucket in the cluster's Region (NFR-21).

## 5. Traces

The API and the workers send spans over OTLP/HTTP to `http://otel-agent.node-agents.svc.cluster.local:4318`, a Service
with `internalTrafficPolicy: Local`, so each pod reaches the agent on its own node. The agents route every span of a
trace to the same gateway by trace ID (the load-balancing exporter over the gateways' headless Service), and the
gateway's tail sampling keeps every trace with an error, every trace slower than 1 s (NFR-2's p99) and 10 % of the
rest, then sends them to Tempo. Grafana links a log line's `trace_id` to its trace and a trace to its logs.

## 6. Alerts and the heartbeat

Alertmanager routes by each rule's `severity` label: `page` to `sft-<env>-<region-short>-alerts-page`, `ticket` to
`-alerts-ticket`, and the always-firing `Watchdog` alert every minute to `-heartbeat`. It signs each SNS call with its
Pod Identity role and sends it through the egress proxy's platform listener, since SNS has no endpoint here
(ADR-0021); the platform key's policy admits that role through SNS, for the topics' encryption. A CloudWatch alarm
that treats a silent heartbeat topic as breaching pages when the cluster, Prometheus, Alertmanager or the proxy stops
(#246). The routing is [`deploy/alerts/alertmanager.yaml`](../../deploy/alerts/alertmanager.yaml) (#245), which
`deploy/alerts/test.sh` checks with amtool: the prometheus chart reads it through its `alerts/` link, fills its four
placeholders with the cluster's facts and writes it as the operator's `AlertmanagerConfig`, adding SNS's Regional URL
and the proxy to every receiver, so no Secret holds it. A test checks every route, matcher, inhibition and topic
arrives unchanged.

## 7. Grafana

Nobody signs in to Grafana. It has no admin account (`disable_initial_admin_creation`), no login form and no basic
auth, and every visitor is an anonymous Viewer who may open Explore and change a dashboard in the browser, never save
one. Who can reach it is decided outside it: only `ReadOnly` and `Operator` may port-forward to the `grafana`
namespace through the cluster tunnel (authn-authz 8.1, T-63), by the RoleBinding of cluster-bootstrap's
`sft:portforward` that the grafana chart makes, and it has no Service a load balancer could reach (T-05):

```bash
kubectl -n grafana port-forward svc/grafana 3000   # then http://localhost:3000
```

Data sources (Prometheus, Loki, Tempo, Alertmanager) and dashboards are provisioned from Git on every start and can't
be changed in the UI; it keeps nothing worth a volume. Nothing leaves the cluster: no usage reports, update checks,
news, snapshots or plugin downloads.

### Dashboards as code (#244)

Each dashboard is a JSON file in [`deploy/observability/charts/grafana/dashboards/`](../../deploy/observability/charts/grafana/dashboards/),
provisioned by glob into the folder `secure-file-transfer`, so a new file needs no wiring:

| Dashboard | What it shows |
|---|---|
| SLO overview (`sft-slo-overview`) | Availability and the 28-day error budget (NFR-1), the synthetic probe, API latency without file bytes (NFR-2), time to shareable (NFR-5), scan pass and inspection time (NFR-23) |
| User journeys (`sft-journeys`) | Send, verify, download and request files: requests and latency by route, with each journey's outbox, emails, codes, streams and limits |
| Scanning and DLP (`sft-scanning-dlp`) | Scan and inspection results, inspector failures and their rate, scan pass and inspection time, scan queues and their dead-letter queues |
| Data and replication (`sft-data-replication`) | Aurora's lag to Osaka, S3 replication, the audit archive's lag and writes, the outbox, queue age and dead-letter queues |
| Lifecycle jobs (`sft-lifecycle-jobs`) | When each job last succeeded, items handled, deletion lag and overdue deletions (NFR-8), unarchived grants, the metadata purge, audit partitions |

`deploy/observability/tests/test_dashboards.py` checks that every dashboard parses, is read-only, uses a provisioned
data source, and **queries only known metrics**: those in the catalogue (`docs/operations/metrics.md`), those the
service's code defines, and the AWS series the exporter is configured to make. A panel that queries anything else
fails the test, and a test plants one to prove it. Until the catalogue exists on `main`, the metric names agreed
across M7's tracks stand in for it.

## 8. Network policies and pod rules

Each of the three namespaces denies everything by default, and each workload has a policy naming what it may reach
(ADR-0021): Prometheus reaches its targets on their metrics ports only (the application's internal port, the stack's
pods, the proxy's health port, the kubelets on the nodes) and the cluster API; Alertmanager and the CloudWatch exporter
reach only the proxy's platform listener and their credentials; Loki and Tempo reach only S3 and their credentials;
the agents reach the gateways and Loki, the gateways Tempo; Grafana reaches its four data sources. A port-forward
enters the pod's own network namespace and needs no rule.

Every pod follows ADR-0004's rules (non-root, read-only root file system, no capabilities, no escalation,
`RuntimeDefault` seccomp, memory limits, no service account token but Prometheus', which discovery needs), and every
Deployment and StatefulSet has a disruption budget of one pod. `deploy/policies.sh` runs the cluster's Kyverno policies
on every pod the charts render; `deploy/observability/tests` checks the rest, the project's kinds and the images.

## 9. Checks

| Check | How | Status |
|---|---|---|
| The stack renders for every cluster; Osaka's pilot light renders none of it | `deploy/check.sh`, `deploy/render.sh` | Every pull request |
| Helm lint, kubeconform (Argo CD's and the operator's kinds included), Trivy on the rendered manifests | CI's `deploy` job | Every pull request |
| Kyverno admits every pod | `deploy/policies.sh` | Every pull request |
| Images, pod rules, network policies, budgets, rule files, scrape targets, sizes, vendored charts | `deploy/observability/tests` | Every pull request |
| Dashboards parse and query only known metrics | `deploy/observability/tests/test_dashboards.py` | Every pull request |
| The vendored CRDs are the pinned chart's, byte for byte, for the operator `images.tf` pins, and serve every kind the stack renders (section 11) | `deploy/observability/crds/check.sh` (in `deploy/check.sh`), `deploy/observability/tests/test_crds.py` | Every pull request |
| Terraform (the module, cluster-bootstrap, the deploy role's permissions) validates; tflint and Trivy | `infra/scripts/check.sh` | Every pull request |
| Prometheus scrapes every target (`up == 1` for each PodMonitor and ServiceMonitor) | Grafana or `kubectl port-forward` to Prometheus | Pending the AWS run |
| A rule from each `deploy/alerts` file is loaded and evaluating | Prometheus' rules page | Pending the AWS run |
| A lifecycle job's push shows in Prometheus with its own job label | Run a job, query `lifecycle_job_last_success_timestamp_seconds` | Pending the AWS run |
| The CloudWatch exporter's series arrive through the proxy | `aws_sqs_approximate_age_of_oldest_message_maximum` in Prometheus | Pending the AWS run |
| Logs from every node, the system nodes included, reach Loki | Explore, `{k8s_namespace_name="sft"}` and `egress-proxy` | Pending the AWS run |
| A request's trace is in Tempo, with its logs linked | Explore, a `trace_id` from a log line | Pending the AWS run |
| An error trace is always kept; a fast trace about one time in ten | Tempo search over a load test | Pending the AWS run |
| A page reaches its SNS topic; the heartbeat publishes every minute and its alarm fires when it stops | Fire a test alert; scale Alertmanager to zero in staging | Pending the AWS run (#246) |
| A chart bump's CRDs apply server-side and the new operator reconciles (section 11) | The procedure's checks, on the first bump | Pending the AWS run |
| Grafana answers on the port-forward and nowhere else | Port-forward as ReadOnly; the synthetic probe from outside (T-05) | Pending the AWS run |
| Loki and Tempo objects are under the logs key | `aws s3api head-object` on one of each | Pending the AWS run |

## 10. Changing it

- **A new alert rule file:** add `deploy/alerts/<area>.rules.yaml` with its tests; nothing else.
- **A new dashboard:** add a JSON file to `deploy/observability/charts/grafana/dashboards/` with a unique `uid`
  (`sft-<name>`, also the file's name), `editable: false`, and the `prometheus` data source; its metrics must be in the
  catalogue.
- **A new AWS series:** add it to `cloudwatchExporter.metrics` in `deploy/observability/charts/prometheus/values.yaml`.
- **A new scrape target in the application:** its network policy must admit Prometheus on the internal port
  (`deploy/charts/sft`), then add its component to `application.scraped`; the test checks the two agree.
- **An image or chart upgrade:** the digest in `infra/modules/cluster-bootstrap/images.tf` and in the chart's values
  together (and `infra/shared`'s mirror list for a new repository); for Loki or Tempo, the vendored archive, its
  version in `Chart.yaml` and its line in `charts/SHA256SUMS`; for kube-prometheus-stack, its CRDs and the
  procedure in section 11. At least 7 days old (T-68).

## 11. Upgrading the Prometheus Operator's CRDs

Terraform installs the operator from the kube-prometheus-stack chart pinned in cluster-bootstrap's `images.tf`, with
its CRDs. Helm installs a chart's CRDs only on its first install and never upgrades them
([#264](https://github.com/codewithmuh/secure-file-transfer/issues/264)), so a bump on its own would leave the
cluster's CRDs at the old version under the new operator: fields that it, or our charts, start to use would be
pruned or refused, and the observability Applications' syncs would fail or silently lose settings. So every bump
applies the new chart's CRDs first, by server-side apply. Client-side `kubectl apply` can't: it stores the whole
object in the `last-applied-configuration` annotation, and the largest of these CRDs is over its 256 KiB limit.

The CRDs come from Git, not from the chart repository at apply time: `deploy/observability/crds/` holds the pinned
chart's own CRD bundle, `kube-prometheus-stack-<version>.crds.bz2` (the chart's `charts/crds/files/crds.bz2`, all ten
CRDs, 0.2 MB). Two checks run on every pull request: `deploy/observability/crds/check.sh`, from `deploy/check.sh`,
pulls the version `images.tf` pins and fails unless the bundle is that chart's byte for byte and the only one; the
tests in `deploy/observability/tests/test_crds.py` fail unless every CRD in it is for the operator image `images.tf`
pins, and unless it serves every kind and version the stack renders.

**The bump**, one pull request, at least 7 days after the chart's release (T-68):

```bash
version=<the new chart version>
work=$(mktemp -d)
helm pull kube-prometheus-stack --repo https://prometheus-community.github.io/helm-charts --version "$version" \
  --untar --untardir "$work"
rm deploy/observability/crds/kube-prometheus-stack-*.crds.bz2
cp "$work/kube-prometheus-stack/charts/crds/files/crds.bz2" \
  "deploy/observability/crds/kube-prometheus-stack-$version.crds.bz2"
grep appVersion "$work/kube-prometheus-stack/Chart.yaml"   # the operator version it runs
```

Then, in `infra/modules/cluster-bootstrap/images.tf`, the chart's `version` and the `prometheus_operator` and
`prometheus_config_reloader` images (tag and digest) at that operator version, which the mirror workflow copies. The
pull request's diff of the bundle can't be read as text: compare the two versions' CRDs with `bzcat` if a schema
change matters to our charts. `deploy/check.sh` and the tests must pass.

**The apply**, after the merge, in each cluster in the apply order (dev; then staging and prod, Tokyo before Osaka,
the pilot light too, since its operator runs), before that cluster's cluster-bootstrap apply. It runs as the
identity that applies cluster-bootstrap, the deploy role through the Systems Manager tunnel
([modules/cluster-bootstrap](../../infra/modules/cluster-bootstrap/README.md)): people's permission sets may not
change cluster-scoped objects (authn-authz 8.1), and break-glass is not for planned changes. From a checkout of the
merged commit, with the tunnel's kubeconfig:

```bash
deploy/observability/crds/check.sh   # the bundle is the pinned chart's
bundle=$(ls deploy/observability/crds/kube-prometheus-stack-*.crds.bz2)
bzcat "$bundle" | kubectl apply --server-side --force-conflicts --field-manager=sft-crds -f -
bzcat "$bundle" | kubectl wait --for condition=Established --timeout=120s -f -
kubectl get crd prometheuses.monitoring.coreos.com \
  -o jsonpath='{.metadata.annotations.operator\.prometheus\.io/version}'   # the new operator version
```

`--force-conflicts` takes the fields over from Helm, the manager that installed them; Helm never writes them again,
so nothing fights over them. Then apply cluster-bootstrap, which upgrades the operator, and check that its logs show
no errors and that Argo CD's `observability` Applications are Synced and Healthy.

The order is what makes it safe. A newer CRD only adds fields and versions, so the old operator keeps working
between the two steps; the reverse order would run the new operator against the old schema. A rollback of the chart
leaves the newer CRDs in place, which is safe for the same reason: never apply an older bundle over newer CRDs,
which would prune what the newer schema allowed. A new cluster needs none of this: its first install brings the
chart's CRDs, which the check proves are the bundle's.

Decided in #264 over two alternatives. The chart's own `crds.upgradeJob` applies the CRDs from a Helm hook Job at
every upgrade, but it needs two more images (kubectl and busybox) mirrored and admitted, and a Job in the cluster that
may write any CRD. A separate CRD chart with the CRDs as templates, as Karpenter's are, lets Helm upgrade them, but
uninstalling that release would delete every CRD and every object of their kinds. Both stay options for when the
cluster-bootstrap apply job exists; until then the bundle and the two commands above are the whole procedure.
