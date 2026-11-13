# The cluster's platform, installed by Terraform through the cluster tunnel on main only (ADR-0004, ADR-0005,
# ADR-0021): the egress proxy, Kyverno and its policies, Karpenter and its node pools, External Secrets and its store,
# the Load Balancer Controller, the operator RBAC, and Argo CD with the root Application, which installs everything
# else from Git. Each component has its own file; this one holds what they share.
#
# Order on a fresh cluster: namespaces, the proxy (Argo CD and the controllers reach AWS and GitHub only through it),
# Kyverno and its policies (before anything Kyverno should judge), Karpenter, then External Secrets, the Load Balancer
# Controller and Argo CD. Only kube-system, karpenter, kyverno and argocd are outside Kyverno's webhooks, so a Kyverno
# outage never blocks what brings it back (ADR-0004).

locals {
  # The system node group (#103): tainted, so only what tolerates it runs there.
  system_scheduling = {
    nodeSelector = { "sft.io/pool" = "system" }
    tolerations  = [{ key = "sft.io/pool", operator = "Equal", value = "system", effect = "NoSchedule" }]
  }

  # The main pool's controllers (capacity 4.3). In a pilot light there is no main-pool node, and starting one for two
  # controllers would cost a node, so they run on the one system node and a failover needs no apply here.
  main_scheduling = var.pilot_light ? local.system_scheduling : {
    nodeSelector = { "sft.io/pool" = "main" }
    tolerations  = []
  }

  # Namespaces whose pods may run on system nodes. Kyverno refuses the system toleration and node selector anywhere
  # else (ADR-0021).
  system_namespaces = concat(
    ["kube-system", "argocd", "kyverno", "karpenter", "egress-proxy"],
    var.pilot_light ? ["external-secrets"] : [],
    # The node agents run on every node, the system nodes included, to collect their pods' logs (ADR-0009).
    [local.node_agents_namespace],
  )

  # Outside Kyverno's webhooks (ADR-0004, ADR-0007). Their images are pinned here and Kyverno's background reports
  # still check them.
  webhook_excluded_namespaces = ["kube-system", "karpenter", "kyverno", "argocd"]

  replicas    = var.high_availability ? 2 : 1
  proxy_count = var.pilot_light ? 1 : 2

  # The egress proxy (ADR-0021): one listener per workload. Application listeners serve namespace sft; their ports
  # are agreed with the application chart (#106).
  proxy_host = "egress-proxy.egress-proxy.svc.cluster.local"
  proxy_ports = {
    api              = 3128
    notifier         = 3129
    signature-mirror = 3130
    argocd           = 3131
    platform         = 3132
    key-rotation     = 3133
    synthetic-probe  = 3134 # #248: the probe's own way in from outside
    operator         = 3135 # #275: the operator API's break-glass reconciliation and SSO drift check
  }
  proxy_url = { for name, port in local.proxy_ports : name => "http://${local.proxy_host}:${port}" }

  # Everything reached without the proxy: cluster services, the node-local metadata and Pod Identity agents, the VPC,
  # the cluster API, and the VPC endpoints (ADR-0021). S3 is not here: pods on system nodes have no outside rule, so
  # Kyverno reads ECR's layer bucket through the proxy, which reaches S3 through the gateway endpoint.
  no_proxy = join(",", [
    "localhost", "127.0.0.1", ".svc", ".cluster.local", "169.254.169.254", "169.254.170.23",
    "10.0.0.0/8", "172.20.0.0/16", ".${var.region}.eks.amazonaws.com",
    "sts.${var.region}.amazonaws.com", "ec2.${var.region}.amazonaws.com", "sqs.${var.region}.amazonaws.com",
    "kms.${var.region}.amazonaws.com", "secretsmanager.${var.region}.amazonaws.com", "email.${var.region}.amazonaws.com",
    "api.ecr.${var.region}.amazonaws.com", ".dkr.ecr.${var.region}.amazonaws.com", "eks-auth.${var.region}.api.aws",
  ])

  proxy_env = {
    for name, url in local.proxy_url : name => [
      { name = "HTTPS_PROXY", value = url },
      { name = "https_proxy", value = url },
      { name = "NO_PROXY", value = local.no_proxy },
      { name = "no_proxy", value = local.no_proxy },
    ]
  }

  # Secrets Manager names of platform secrets (encryption 6): sft/<env>/platform/<component>/<name>.
  platform_secret_prefix = "sft/${var.environment}/platform"
}

# Platform namespaces, at Pod Security Admission restricted (ADR-0004, T-52). kube-system is EKS's.
resource "kubernetes_namespace_v1" "platform" {
  for_each = toset(["argocd", "kyverno", "karpenter", "external-secrets", "egress-proxy"])

  metadata {
    name = each.key
    labels = {
      "pod-security.kubernetes.io/enforce" = "restricted"
      "pod-security.kubernetes.io/audit"   = "restricted"
      "pod-security.kubernetes.io/warn"    = "restricted"
      "app.kubernetes.io/part-of"          = "sft-platform"
    }
  }
}
