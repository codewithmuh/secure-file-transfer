# The cluster-wide part of the observability stack (ADR-0009, #243). Argo CD installs the stack itself from Git
# (deploy/observability, through the observability root Application in argocd.tf), into namespaces it may not create
# and with no cluster-scoped kinds, like the application's project. What needs the cluster is here, with the other
# controllers:
#
# - the namespaces: monitoring and grafana at Pod Security restricted, and node-agents for the node agents, whose log
#   collector reads the node's pod logs from a host path; Kyverno exempts node-agents from the restricted rule and
#   the host-path rule, and lets it on the system nodes (main.tf), while privileged containers stay refused there too;
# - the storage class for the stack's volumes, gp3 under the account's default EBS key, the platform key (encryption
#   3.1);
# - the Prometheus Operator with its CRDs, and kube-state-metrics, from the pinned kube-prometheus-stack chart with
#   everything else in it off: both need cluster-wide RBAC, which a project in Git should not grant;
# - Prometheus' discovery role: read pods, services, endpoints and nodes, and the kubelets' metrics.
#
# In an Osaka pilot light the operator and kube-state-metrics run on the one system node and stay idle (main.tf's
# main_scheduling), so a failover needs no apply here; the stack's Applications start when the fencing commit turns
# the pilot light off (deploy/observability/argocd).

locals {
  node_agents_namespace = "node-agents"

  # Pod Security level per namespace. Only node-agents may hold pods with host paths (kyverno.tf).
  observability_namespaces = {
    monitoring                    = "restricted"
    grafana                       = "restricted"
    (local.node_agents_namespace) = "privileged"
  }

  host_access_namespaces = distinct(concat([local.node_agents_namespace], var.host_access_namespaces))

  observability_component = {
    nodeSelector = local.main_scheduling.nodeSelector
    tolerations  = local.main_scheduling.tolerations
  }
}

resource "kubernetes_namespace_v1" "observability" {
  for_each = local.observability_namespaces

  metadata {
    name = each.key
    labels = {
      "pod-security.kubernetes.io/enforce" = each.value
      "pod-security.kubernetes.io/audit"   = each.value
      "pod-security.kubernetes.io/warn"    = each.value
      "app.kubernetes.io/part-of"          = "sft-observability"
    }
  }

  # Kyverno's namespace policy judges these labels (charts/kyverno-policies).
  depends_on = [helm_release.kyverno_policies]
}

resource "kubernetes_storage_class_v1" "observability" {
  metadata {
    name   = "observability"
    labels = { "app.kubernetes.io/part-of" = "sft-observability" }
  }

  storage_provisioner    = "ebs.csi.aws.com"
  reclaim_policy         = "Delete"
  volume_binding_mode    = "WaitForFirstConsumer"
  allow_volume_expansion = true

  # No kmsKeyId: the account's default EBS key, which the data layer sets to the platform key and which the EBS CSI
  # driver's role may use (modules/eks-cluster).
  parameters = {
    type      = "gp3"
    encrypted = "true"
  }
}

resource "helm_release" "prometheus_operator" {
  name             = "prometheus-operator"
  repository       = local.charts.kube_prometheus_stack.repository
  chart            = local.charts.kube_prometheus_stack.chart
  version          = local.charts.kube_prometheus_stack.version
  namespace        = kubernetes_namespace_v1.observability["monitoring"].metadata[0].name
  create_namespace = false
  atomic           = true
  wait             = true
  timeout          = 600

  values = [yamlencode({
    fullnameOverride = "prometheus-operator"
    global = {
      imageRegistry = local.registry
      rbac          = { create = true }
    }
    commonLabels = { "app.kubernetes.io/part-of" = "sft-observability" }
    crds         = { enabled = true }

    # Everything the stack's Applications bring from Git, or this design doesn't run, is off.
    defaultRules          = { create = false }
    alertmanager          = { enabled = false }
    grafana               = { enabled = false }
    prometheus            = { enabled = false }
    nodeExporter          = { enabled = false } # the kubelets' own metrics instead (deploy/observability)
    windowsMonitoring     = { enabled = false }
    kubeApiServer         = { enabled = false }
    kubelet               = { enabled = false } # scraped by deploy/observability's ServiceMonitor
    kubeControllerManager = { enabled = false }
    kubeScheduler         = { enabled = false }
    kubeEtcd              = { enabled = false }
    kubeProxy             = { enabled = false }
    coreDns               = { enabled = false }
    kubeDns               = { enabled = false }

    prometheusOperator = merge(local.observability_component, {
      enabled = true
      # Rules are checked by promtool in CI (deploy/alerts/test.sh), so no admission webhook and no certificate job.
      admissionWebhooks = { enabled = false, patch = { enabled = false } }
      tls               = { enabled = false }
      # The kubelet endpoints in kube-system that deploy/observability's ServiceMonitor scrapes.
      kubeletService = { enabled = true, namespace = "kube-system", name = "kubelet" }
      image = {
        repository = local.images.prometheus_operator.repository
        tag        = local.images.prometheus_operator.tag
        sha        = trimprefix(local.images.prometheus_operator.digest, "sha256:")
      }
      prometheusConfigReloader = {
        image = {
          repository = local.images.prometheus_config_reloader.repository
          tag        = local.images.prometheus_config_reloader.tag
          sha        = trimprefix(local.images.prometheus_config_reloader.digest, "sha256:")
        }
      }
      resources = {
        requests = { cpu = "50m", memory = "128Mi" }
        limits   = { memory = "256Mi" }
      }
    })

    kubeStateMetrics = { enabled = true }
    "kube-state-metrics" = merge(local.observability_component, {
      image = {
        repository = local.images.kube_state_metrics.repository
        tag        = local.images.kube_state_metrics.tag
        sha        = local.images.kube_state_metrics.digest # this subchart prints it after "@" as it is
      }
      resources = {
        requests = { cpu = "10m", memory = "64Mi" }
        limits   = { memory = "256Mi" }
      }
    })
  })]

  depends_on = [helm_release.kyverno_policies, kubernetes_namespace_v1.observability]
}

# Prometheus' service discovery and the kubelet scrape (deploy/observability/charts/prometheus): read only, no Secrets.
resource "kubernetes_cluster_role_v1" "prometheus" {
  metadata {
    name   = "sft:prometheus"
    labels = { "app.kubernetes.io/part-of" = "sft-observability" }
  }

  rule {
    api_groups = [""]
    resources  = ["nodes", "nodes/metrics", "services", "endpoints", "pods"]
    verbs      = ["get", "list", "watch"]
  }

  rule {
    api_groups = ["discovery.k8s.io"]
    resources  = ["endpointslices"]
    verbs      = ["get", "list", "watch"]
  }

  rule {
    non_resource_urls = ["/metrics"]
    verbs             = ["get"]
  }
}

resource "kubernetes_cluster_role_binding_v1" "prometheus" {
  metadata {
    name   = "sft:prometheus"
    labels = { "app.kubernetes.io/part-of" = "sft-observability" }
  }

  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "ClusterRole"
    name      = kubernetes_cluster_role_v1.prometheus.metadata[0].name
  }

  subject {
    kind      = "ServiceAccount"
    name      = "prometheus"
    namespace = kubernetes_namespace_v1.observability["monitoring"].metadata[0].name
  }
}
