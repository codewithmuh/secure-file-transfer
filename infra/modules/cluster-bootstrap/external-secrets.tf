# External Secrets (ADR-0004) and its two stores (encryption 6.4, A31), reading Secrets Manager through its endpoint.
# The controller's own role, bound to external-secrets/external-secrets by Pod Identity, reads no secret: it may only
# assume the two store roles the cluster layer creates, and each store names its own (charts/secret-stores):
#
# - platform-secrets assumes sft-<env>-external-secrets-platform, which reads only sft/<env>/platform/*, for argocd,
#   monitoring and grafana.
# - application-secrets assumes sft-<env>-external-secrets-app, which reads only the API's csrf-hmac, email-hmac and
#   this Region's idp-client (#106), for the sft namespace only.
#
# So an ExternalSecret in a platform namespace can't reach an application secret, nor one in sft a platform secret,
# whatever key it names: the namespace conditions pick the store, and the store's role decides what it can read.

locals {
  external_secrets_component = {
    nodeSelector = local.main_scheduling.nodeSelector
    tolerations  = local.main_scheduling.tolerations
    resources = {
      requests = { cpu = "10m", memory = "64Mi" }
      limits   = { memory = "256Mi" }
    }
  }

  external_secrets_image = {
    repository = local.image_repo["external_secrets"]
    tag        = local.image_tag["external_secrets"]
  }

  # With notifications on, the Argo CD notifications Secret (ADR-0005), from the platform store. The stores themselves
  # and their namespaces are in charts/secret-stores.
  external_secrets_manifests = var.github_app == null ? [] : [{
    apiVersion = "external-secrets.io/v1"
    kind       = "ExternalSecret"
    metadata   = { name = "argocd-notifications-secret", namespace = "argocd" }
    spec = {
      refreshInterval = "1h"
      secretStoreRef  = { kind = "ClusterSecretStore", name = "platform-secrets" }
      target = {
        name           = "argocd-notifications-secret"
        creationPolicy = "Owner"
        template = {
          metadata = { labels = { "app.kubernetes.io/part-of" = "argocd" } }
        }
      }
      data = [{
        secretKey = "github-privateKey"
        remoteRef = { key = "${local.platform_secret_prefix}/argocd/github-app-private-key" }
      }]
    }
  }]
}

resource "helm_release" "external_secrets" {
  name             = "external-secrets"
  repository       = local.charts.external_secrets.repository
  chart            = local.charts.external_secrets.chart
  version          = local.charts.external_secrets.version
  namespace        = kubernetes_namespace_v1.platform["external-secrets"].metadata[0].name
  create_namespace = false
  atomic           = true
  wait             = true
  timeout          = 600

  values = [yamlencode(merge(local.external_secrets_component, {
    installCRDs  = true
    replicaCount = 1
    image        = local.external_secrets_image
    serviceAccount = {
      name = "external-secrets"
    }
    # Only stores and ExternalSecrets: nothing here pushes secrets or generates credentials.
    processClusterExternalSecret = false
    processClusterPushSecret     = false
    processPushSecret            = false
    processClusterGenerator      = false
    webhook                      = merge(local.external_secrets_component, { image = local.external_secrets_image })
    certController               = merge(local.external_secrets_component, { image = local.external_secrets_image })
  }))]

  depends_on = [helm_release.karpenter_node_pools]
}

resource "helm_release" "external_secrets_store" {
  name             = "external-secrets-store"
  chart            = "${path.module}/charts/secret-stores"
  namespace        = kubernetes_namespace_v1.platform["external-secrets"].metadata[0].name
  create_namespace = false
  atomic           = true
  wait             = true
  timeout          = 300

  values = [yamlencode({
    environment = var.environment
    region      = var.region
    accountId   = var.account_id
    manifests   = local.external_secrets_manifests
  })]

  depends_on = [helm_release.external_secrets, kubernetes_namespace_v1.platform]
}
