# External Secrets (ADR-0004) and its one store, for platform components' secrets only (encryption 6, A31): it reads
# sft/<env>/platform/* through the Secrets Manager endpoint, with the role the cluster layer binds to
# external-secrets/external-secrets by Pod Identity. Application pods read their own secrets directly, so no
# application namespace may use the store.

locals {
  # Namespaces that may use the platform store: Argo CD (its notifications key) and the observability stack (ADR-0009).
  platform_secret_namespaces = ["argocd", "monitoring", "grafana"]

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

  # The store and, with notifications on, the Argo CD notifications Secret (ADR-0005).
  external_secrets_manifests = concat(
    [{
      apiVersion = "external-secrets.io/v1"
      kind       = "ClusterSecretStore"
      metadata   = { name = "platform-secrets" }
      spec = {
        conditions = [{ namespaces = local.platform_secret_namespaces }]
        provider = {
          aws = {
            service = "SecretsManager"
            region  = var.region
          }
        }
      }
    }],
    var.github_app == null ? [] : [{
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
    }],
  )
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
  chart            = "${path.module}/charts/manifests"
  namespace        = kubernetes_namespace_v1.platform["external-secrets"].metadata[0].name
  create_namespace = false
  atomic           = true
  wait             = true
  timeout          = 300

  values = [yamlencode({ manifests = local.external_secrets_manifests })]

  depends_on = [helm_release.external_secrets, kubernetes_namespace_v1.platform]
}
