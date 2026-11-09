# The AWS side of one cluster's observability stack (ADR-0009, #243): Loki's and Tempo's buckets in this Region under
# the logs key, and, from Tokyo, the account's four observability roles, each reached only through EKS Pod Identity by
# its own service account in the monitoring namespace. The in-cluster side is deploy/observability, which Argo CD
# syncs; cluster-bootstrap installs the Prometheus Operator, the namespaces and the storage class.
#
# Called by each cluster-bootstrap root, the one layer that runs after the cluster exists, so Pod Identity has a
# cluster to associate with. Torn down with it: logs and traces are derived data, kept 90 and 14 days at most.

locals {
  region_short = { "ap-northeast-1" = "apne1", "ap-northeast-3" = "apne3" }

  global_prefix = "sft-${var.environment}"
  name_prefix   = "${local.global_prefix}-${local.region_short[var.region]}"

  # Every Region's prefix, for policies that must work in Osaka after a failover.
  regional_prefixes = { for r in var.regions : r => "${local.global_prefix}-${local.region_short[r]}" }
  cluster_arns      = [for r, p in local.regional_prefixes : "arn:aws:eks:${r}:${var.account_id}:cluster/${p}-eks"]

  namespace = "monitoring"

  # Role => what binds it: its service account in monitoring (deploy/observability/charts).
  roles = {
    loki                = { service_account = "loki", description = "Loki: its buckets, under the logs key" }
    tempo               = { service_account = "tempo", description = "Tempo: its buckets, under the logs key" }
    alertmanager        = { service_account = "alertmanager", description = "Alertmanager: publish to the alert and heartbeat topics" }
    cloudwatch-exporter = { service_account = "cloudwatch-exporter", description = "CloudWatch exporter: read metrics" }
  }

  role_arns = { for k, _ in local.roles : k => "arn:aws:iam::${var.account_id}:role/${local.global_prefix}-${k}" }
}
