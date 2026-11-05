# The AWS Load Balancer Controller (ADR-0004), for TargetGroupBinding only: the edge layer's Terraform owns the load
# balancer, its listeners, target groups and security group rules, and the controller registers pods in those target
# groups. Its role, bound to kube-system/aws-load-balancer-controller by Pod Identity in the cluster layer (#103), may
# only describe and register or deregister targets. So no Ingress class, no Service webhook, no WAF or Shield calls,
# and no security group management.
#
# Its CRDs are in the chart's crds/, which Helm installs only once: an upgrade that changes them applies them first,
# by hand from the chart, as the vendor documents.

resource "helm_release" "load_balancer_controller" {
  name             = "aws-load-balancer-controller"
  repository       = local.charts.load_balancer_controller.repository
  chart            = local.charts.load_balancer_controller.chart
  version          = local.charts.load_balancer_controller.version
  namespace        = "kube-system"
  create_namespace = false
  atomic           = true
  wait             = true
  timeout          = 600

  values = [yamlencode({
    clusterName  = var.cluster.name
    region       = var.region
    vpcId        = var.cluster.vpc_id
    replicaCount = local.replicas
    image = {
      repository = local.image_repo["load_balancer_controller"]
      tag        = local.image_tag["load_balancer_controller"]
    }
    serviceAccount = {
      create = true
      name   = "aws-load-balancer-controller"
    }
    nodeSelector = local.main_scheduling.nodeSelector
    tolerations  = local.main_scheduling.tolerations
    resources = {
      requests = { cpu = "50m", memory = "128Mi" }
      limits   = { memory = "512Mi" }
    }
    # Elastic Load Balancing has no endpoint here: through the platform listener (ADR-0021).
    env = {
      HTTPS_PROXY = local.proxy_url["platform"]
      NO_PROXY    = local.no_proxy
    }
    createIngressClassResource            = false
    enableServiceMutatorWebhook           = false
    enableShield                          = false
    enableWaf                             = false
    enableWafv2                           = false
    enableBackendSecurityGroup            = false
    enableManageBackendSecurityGroupRules = false
  })]

  depends_on = [helm_release.karpenter_node_pools]
}
