# Karpenter (ADR-0004) on the system nodes, and the main and scan node pools the cluster layer defines (#103). Its IAM
# role and Pod Identity association (karpenter/karpenter), node instance profile and interruption queue are the
# cluster layer's; nothing here touches IAM. Isolated-VPC mode: no pricing API, and AWS calls go to the endpoints or,
# for SSM's Bottlerocket parameters and EKS, through the platform listener (ADR-0021).
#
# The CRDs have their own release, because Helm installs a chart's crds/ only once and never upgrades them.

resource "helm_release" "karpenter_crd" {
  name             = "karpenter-crd"
  repository       = local.charts.karpenter_crd.repository
  chart            = local.charts.karpenter_crd.chart
  version          = local.charts.karpenter_crd.version
  namespace        = kubernetes_namespace_v1.platform["karpenter"].metadata[0].name
  create_namespace = false
  atomic           = true
  wait             = true
  timeout          = 300
}

resource "helm_release" "karpenter" {
  name             = "karpenter"
  repository       = local.charts.karpenter.repository
  chart            = local.charts.karpenter.chart
  version          = local.charts.karpenter.version
  namespace        = kubernetes_namespace_v1.platform["karpenter"].metadata[0].name
  create_namespace = false
  skip_crds        = true
  atomic           = true
  wait             = true
  timeout          = 600

  values = [yamlencode({
    replicas     = local.replicas
    nodeSelector = local.system_scheduling.nodeSelector
    tolerations  = local.system_scheduling.tolerations
    serviceAccount = {
      name = "karpenter"
    }
    controller = {
      image = {
        repository = local.image_repo["karpenter"]
        tag        = local.images.karpenter.tag
        digest     = local.images.karpenter.digest
      }
      env = local.proxy_env["platform"]
      resources = {
        requests = { cpu = "250m", memory = "512Mi" }
        limits   = { memory = "1Gi" }
      }
    }
    settings = {
      clusterName       = var.cluster.name
      clusterEndpoint   = var.cluster.endpoint
      interruptionQueue = var.cluster.karpenter_interruption_queue
      isolatedVPC       = true
    }
  })]

  depends_on = [helm_release.karpenter_crd, helm_release.kyverno_policies]
}

# The EC2NodeClasses and NodePools, as the cluster layer outputs them.
resource "helm_release" "karpenter_node_pools" {
  name             = "karpenter-node-pools"
  chart            = "${path.module}/charts/manifests"
  namespace        = kubernetes_namespace_v1.platform["karpenter"].metadata[0].name
  create_namespace = false
  atomic           = true
  wait             = true
  timeout          = 300

  values = [yamlencode({
    manifests = concat(
      values(var.cluster.karpenter_node_class_manifests),
      values(var.cluster.karpenter_node_pool_manifests),
    )
  })]

  depends_on = [helm_release.karpenter]
}
