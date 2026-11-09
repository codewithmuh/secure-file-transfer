# The egress proxy (ADR-0021): Envoy as an HTTPS CONNECT proxy on the system nodes, one listener and allowlist per
# workload. Installed first, because Argo CD reaches GitHub, and the controllers reach AWS APIs with no endpoint here,
# only through it. Each allowlist is a subset of DNS Firewall's (modules/network, dns_firewall_allowed_domains).

locals {
  proxy_listeners = [
    {
      # The API: Cognito's token endpoint and signing keys, and our managed login domain (abuse 3.2).
      name    = "api"
      port    = local.proxy_ports["api"]
      domains = compact(["cognito-idp.${var.region}.amazonaws.com", var.cognito_login_domain])
      clients = [{ namespace = "sft", podLabels = { "app.kubernetes.io/component" = "api" } }]
    },
    {
      # The notification worker: Cognito's admin API, for invitations; and its one-off invitation backlog (#193).
      name    = "notifier"
      port    = local.proxy_ports["notifier"]
      domains = ["cognito-idp.${var.region}.amazonaws.com"]
      clients = [
        { namespace = "sft", podLabels = { "app.kubernetes.io/component" = "notifier" } },
        { namespace = "sft", podLabels = { "app.kubernetes.io/component" = "invite-backlog" } },
      ]
    },
    {
      # The key rotation job, Tokyo only (encryption 6.4, #185): the app clients' secrets in Cognito, and in staging and
      # prod Osaka's pool and Osaka's Secrets Manager, where Osaka's idp-client lives. Tokyo's Secrets Manager is the
      # endpoint's.
      name = "key-rotation"
      port = local.proxy_ports["key-rotation"]
      domains = concat(
        ["cognito-idp.${var.region}.amazonaws.com"],
        var.region == "ap-northeast-1" && var.environment != "dev"
        ? ["cognito-idp.ap-northeast-3.amazonaws.com", "secretsmanager.ap-northeast-3.amazonaws.com"] : [],
      )
      clients = [{ namespace = "sft", podLabels = { "app.kubernetes.io/component" = "key-rotation" } }]
    },
    {
      # The synthetic probe (#248, NFR-1): the API and the web app the way a customer reaches them, from outside, and
      # CloudWatch for its ProbeSuccess metric. S3 (its uploads and the probe mailbox) is the gateway endpoint's.
      name    = "synthetic-probe"
      port    = local.proxy_ports["synthetic-probe"]
      domains = ["api.${var.service_domain}", "app.${var.service_domain}", "monitoring.${var.region}.amazonaws.com"]
      clients = [{ namespace = "sft", podLabels = { "app.kubernetes.io/component" = "synthetic-probe" } }]
    },
    {
      # The signature mirror: ClamAV's database (ADR-0019).
      name    = "signature-mirror"
      port    = local.proxy_ports["signature-mirror"]
      domains = ["database.clamav.net"]
      clients = [{ namespace = "sft", podLabels = { "app.kubernetes.io/component" = "signature-mirror" } }]
    },
    {
      # Argo CD: Git, and the deployment statuses its notifications post (ADR-0005).
      name    = "argocd"
      port    = local.proxy_ports["argocd"]
      domains = ["github.com", "api.github.com"]
      clients = [
        { namespace = "argocd", podLabels = { "app.kubernetes.io/name" = "argocd-repo-server" } },
        { namespace = "argocd", podLabels = { "app.kubernetes.io/name" = "argocd-notifications-controller" } },
      ]
    },
    {
      # The platform: AWS APIs with no endpoint here, for Karpenter (Bottlerocket's AMI parameters), the Load Balancer
      # Controller, Alertmanager (SNS) and the CloudWatch exporter (CloudWatch) (ADR-0009), and ECR's layer bucket for
      # Kyverno's signature reads.
      name = "platform"
      port = local.proxy_ports["platform"]
      domains = [
        "ssm.${var.region}.amazonaws.com",
        "eks.${var.region}.amazonaws.com",
        "elasticloadbalancing.${var.region}.amazonaws.com",
        "sns.${var.region}.amazonaws.com",
        "monitoring.${var.region}.amazonaws.com",
        "prod-${var.region}-starport-layer-bucket.s3.${var.region}.amazonaws.com",
      ]
      clients = [
        { namespace = "karpenter", podLabels = { "app.kubernetes.io/name" = "karpenter" } },
        { namespace = "kube-system", podLabels = { "app.kubernetes.io/name" = "aws-load-balancer-controller" } },
        { namespace = "kyverno", podLabels = { "app.kubernetes.io/component" = "admission-controller" } },
        { namespace = "kyverno", podLabels = { "app.kubernetes.io/component" = "reports-controller" } },
        { namespace = "monitoring", podLabels = { "app.kubernetes.io/name" = "alertmanager" } },
        { namespace = "monitoring", podLabels = { "app.kubernetes.io/name" = "cloudwatch-exporter" } },
      ]
    },
  ]
}

resource "helm_release" "egress_proxy" {
  name             = "egress-proxy"
  chart            = "${path.module}/charts/egress-proxy"
  namespace        = kubernetes_namespace_v1.platform["egress-proxy"].metadata[0].name
  create_namespace = false
  atomic           = true
  wait             = true
  timeout          = 600

  values = [yamlencode({
    image        = local.image_ref["envoy"]
    replicas     = local.proxy_count
    nodeSelector = local.system_scheduling.nodeSelector
    tolerations  = local.system_scheduling.tolerations
    listeners    = local.proxy_listeners
  })]
}
