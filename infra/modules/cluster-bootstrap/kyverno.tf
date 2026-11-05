# Kyverno (ADR-0004, ADR-0007) on the system nodes, and the policies the design names (charts/kyverno-policies):
# images only from our registry by digest, sft/ images signed by the build workflow on main, no privileged or host
# access, the system pool kept for the platform, and namespaces at Pod Security Admission restricted.
#
# The webhooks skip kube-system, karpenter, kyverno and argocd, so a cold start or a Kyverno outage never blocks what
# brings Kyverno back; every other namespace fails closed while it is down (ADR-0004). The background reports still
# check those namespaces (kube-system included, which Kyverno's default filters would skip) and alert on a violation.

locals {
  # The EKS add-ons Kyverno admits from AWS's registry, in kube-system only (ADR-0004, ADR-0007): the VPC CNI and its
  # network policy agent, kube-proxy, CoreDNS, the Pod Identity agent, the EBS CSI driver and its sidecars, the pause
  # image. The registry account is the one the network module's ECR endpoint policies allow.
  eks_addon_registry = "602401143452.dkr.ecr.${var.region}.amazonaws.com" # aws-owned-account: Amazon EKS add-ons
  eks_addon_repositories = [
    "amazon-k8s-cni", "amazon-k8s-cni-init", "amazon/aws-network-policy-agent", "eks/kube-proxy", "eks/coredns",
    "eks/eks-pod-identity-agent", "eks/aws-ebs-csi-driver", "eks/csi-provisioner", "eks/csi-attacher",
    "eks/csi-snapshotter", "eks/csi-resizer", "eks/csi-node-driver-registrar", "eks/livenessprobe", "eks/pause",
  ]

  mirror_digests = distinct(concat(
    [for i in local.images : i.digest],
    var.additional_mirror_digests,
  ))

  kyverno_component = {
    nodeSelector = local.system_scheduling.nodeSelector
    tolerations  = local.system_scheduling.tolerations
  }
}

resource "helm_release" "kyverno" {
  name             = "kyverno"
  repository       = local.charts.kyverno.repository
  chart            = local.charts.kyverno.chart
  version          = local.charts.kyverno.version
  namespace        = kubernetes_namespace_v1.platform["kyverno"].metadata[0].name
  create_namespace = false
  atomic           = true
  wait             = true
  timeout          = 900

  values = [yamlencode({
    global = {
      # Every image from our mirror; each component below names only its repository and tag.
      image        = { registry = local.registry }
      nodeSelector = local.system_scheduling.nodeSelector
      tolerations  = local.system_scheduling.tolerations
      # ECR's API is an endpoint; the layer bucket behind it is reached through the platform listener (ADR-0021).
      extraEnvVars = local.proxy_env["platform"]
    }
    crds = {
      migration = { image = { repository = local.images.kyverno_cli.repository, tag = local.image_tag["kyverno_cli"] } }
    }
    config = {
      # One object, the shape chart 3.9.2 documents: its helper applies the selector to every webhook and appends the
      # kyverno namespace (excludeKyvernoNamespace). A list would need a name per entry and renders {"<nil>": ...}.
      webhooks = {
        namespaceSelector = {
          matchExpressions = [{
            key      = "kubernetes.io/metadata.name"
            operator = "NotIn"
            values   = local.webhook_excluded_namespaces
          }]
        }
      }
      # The webhooks above keep admission out of kube-system; the background reports still check it.
      resourceFiltersExcludeNamespaces = ["kube-system"]
      webhookAnnotations               = {}
    }
    features = {
      # Policy exceptions would let any namespace owner opt out; there are none (T-70).
      policyExceptions = { enabled = false }
      registryClient   = { allowInsecure = false, credentialHelpers = ["default", "amazon"] }
    }
    admissionController = merge(local.kyverno_component, {
      replicas = local.replicas
      initContainer = {
        image = { repository = local.images.kyvernopre.repository, tag = local.image_tag["kyvernopre"] }
      }
      container = {
        image = { repository = local.images.kyverno.repository, tag = local.image_tag["kyverno"] }
        resources = {
          requests = { cpu = "100m", memory = "128Mi" }
          limits   = { memory = "512Mi" }
        }
      }
    })
    backgroundController = merge(local.kyverno_component, {
      replicas = 1
      image    = { repository = local.images.kyverno_background_controller.repository, tag = local.image_tag["kyverno_background_controller"] }
    })
    cleanupController = merge(local.kyverno_component, {
      replicas = 1
      image    = { repository = local.images.kyverno_cleanup_controller.repository, tag = local.image_tag["kyverno_cleanup_controller"] }
    })
    reportsController = merge(local.kyverno_component, {
      replicas = 1
      image    = { repository = local.images.kyverno_reports_controller.repository, tag = local.image_tag["kyverno_reports_controller"] }
    })
    # The pre-delete hooks and the Helm tests, from the mirror too. These two images default to registry ghcr.io,
    # which wins over global.image.registry in the chart's image helper, so they name the registry themselves.
    webhooksCleanup = merge(local.kyverno_component, {
      image = { registry = local.registry, repository = local.images.kyverno_readiness_checker.repository, tag = local.image_tag["kyverno_readiness_checker"] }
    })
    test = {
      image = { registry = local.registry, repository = local.images.kyverno_readiness_checker.repository, tag = local.image_tag["kyverno_readiness_checker"] }
    }
  })]

  depends_on = [helm_release.egress_proxy]
}

resource "helm_release" "kyverno_policies" {
  name             = "kyverno-policies"
  chart            = "${path.module}/charts/kyverno-policies"
  namespace        = kubernetes_namespace_v1.platform["kyverno"].metadata[0].name
  create_namespace = false
  atomic           = true
  wait             = true
  timeout          = 300

  values = [yamlencode({
    registry             = local.registry
    mirrorDigests        = local.mirror_digests
    trustedRoot          = file("${path.module}/files/sigstore-trusted-root.json")
    eksAddonRegistry     = local.eks_addon_registry
    eksAddonRepositories = local.eks_addon_repositories
    systemNamespaces     = local.system_namespaces
    hostAccessNamespaces = var.host_access_namespaces
  })]

  # default is labelled first, or the namespace policy would refuse the label's own update.
  depends_on = [helm_release.kyverno, kubernetes_labels.default_namespace]
}

# Kubernetes' own default namespace, at restricted like every other (sft-namespaces-restricted).
resource "kubernetes_labels" "default_namespace" {
  api_version = "v1"
  kind        = "Namespace"

  metadata {
    name = "default"
  }

  labels = {
    "pod-security.kubernetes.io/enforce" = "restricted"
    "pod-security.kubernetes.io/audit"   = "restricted"
    "pod-security.kubernetes.io/warn"    = "restricted"
  }
}
