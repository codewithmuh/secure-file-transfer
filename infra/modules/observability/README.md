# observability module

The AWS side of one cluster's observability stack ([ADR-0009](../../../docs/adr/0009-observability-opentelemetry-self-hosted.md),
[#243](https://github.com/codewithmuh/secure-file-transfer/issues/243)). Called by each `cluster-bootstrap` root, the
layer that runs once the cluster exists. The stack itself runs from `deploy/observability` through Argo CD, and the
cluster-wide part (the Prometheus Operator, the namespaces, the storage class) is `modules/cluster-bootstrap`'s
`observability.tf`. [docs/operations/observability.md](../../../docs/operations/observability.md) describes the whole.
Nothing here has been applied (infra/README.md).

| File | Holds |
|---|---|
| `buckets.tf` | Loki's and Tempo's buckets in this Region, `sft-<env>-<rs>-{loki,tempo}-<account>`: SSE-KMS with the environment's logs key and a bucket key, owner-enforced, private, TLS only, writes under no other key; a lifecycle rule a few days past each store's own retention; no versioning; emptied and removed at teardown |
| `roles.tf` | From Tokyo only (`create_iam`), the account's roles `sft-<env>-{loki,tempo,alertmanager,cloudwatch-exporter}`, each trusted only by Pod Identity for its one service account in `monitoring` in any of the environment's clusters, under the observability boundary; in every Region, their Pod Identity associations with this cluster |

| Role | Service account | May |
|---|---|---|
| `sft-<env>-loki` | `monitoring/loki` | List, read, write and delete objects in the Loki buckets; the logs key through S3 |
| `sft-<env>-tempo` | `monitoring/tempo` | The same on the Tempo buckets |
| `sft-<env>-alertmanager` | `monitoring/alertmanager` | Publish to `sft-<env>-<rs>-{alerts-page,alerts-ticket,heartbeat}`; the platform key through SNS |
| `sft-<env>-cloudwatch-exporter` | `monitoring/cloudwatch-exporter` | `cloudwatch:GetMetricData`, `GetMetricStatistics` and `ListMetrics` in the environment's Regions |

The key policies already name these roles: the logs key admits Loki and Tempo through S3, the platform key
Alertmanager through SNS (`modules/kms-keys`). The deploy role may create these buckets and roles, each role only with
the boundary `sft-<env>-observability-boundary`, which allows no IAM change and no role assumption
(`modules/terraform-oidc-roles/permissions-observability.tf`). Osaka's root goes after Tokyo's, whose roles it binds.
