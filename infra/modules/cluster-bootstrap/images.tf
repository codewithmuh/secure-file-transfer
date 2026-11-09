# Every chart and image this module installs, pinned (T-68, T-70, ADR-0007).
#
# Charts come from their vendors' repositories, by exact version, fetched by the cluster-bootstrap job on a
# GitHub-hosted runner, so no cluster ever reaches a chart repository. Each was at least 7 days old when pinned.
#
# Images run only from our registry's mirror/ repositories, by digest: the mirror workflow copies each upstream digest
# below into mirror/<upstream path>, after verifying the vendor's signature where one is published and scanning it with
# Trivy (ADR-0007). Kyverno admits a mirror/ image only with one of these digests (kyverno.tf). The digests are the
# upstream image indexes, which a copy by digest keeps.

locals {
  charts = {
    argo_cd = {
      repository = "https://argoproj.github.io/argo-helm"
      chart      = "argo-cd"
      version    = "10.11.6" # Argo CD v3.5.6
    }
    argocd_apps = {
      repository = "https://argoproj.github.io/argo-helm"
      chart      = "argocd-apps"
      version    = "2.0.7"
    }
    kyverno = {
      repository = "https://kyverno.github.io/kyverno"
      chart      = "kyverno"
      version    = "3.9.2" # Kyverno v1.19.2
    }
    karpenter_crd = {
      repository = "oci://public.ecr.aws/karpenter"
      chart      = "karpenter-crd"
      version    = "1.15.1"
    }
    karpenter = {
      repository = "oci://public.ecr.aws/karpenter"
      chart      = "karpenter"
      version    = "1.15.1"
    }
    external_secrets = {
      repository = "https://charts.external-secrets.io"
      chart      = "external-secrets"
      version    = "2.14.0"
    }
    load_balancer_controller = {
      repository = "https://aws.github.io/eks-charts"
      chart      = "aws-load-balancer-controller"
      version    = "3.6.2"
    }
    # The Prometheus Operator, its CRDs and kube-state-metrics only (observability.tf); the rest of the stack is
    # deploy/observability, from Git through Argo CD (#243).
    kube_prometheus_stack = {
      repository = "https://prometheus-community.github.io/helm-charts"
      chart      = "kube-prometheus-stack"
      version    = "92.17.0" # Prometheus Operator v0.94.2
    }
  }

  # upstream: where the mirror workflow copies from. repository: the path under our registry.
  images = {
    argocd = {
      upstream   = "quay.io/argoproj/argocd"
      repository = "mirror/argoproj/argocd"
      tag        = "v3.5.6"
      digest     = "sha256:8e5cc5bb008df8a09dba439462e58c94c55b7735888d3ebde0c25fc05e4e5335"
    }
    redis = {
      upstream   = "public.ecr.aws/docker/library/redis"
      repository = "mirror/docker/library/redis"
      tag        = "8.6.4-alpine"
      digest     = "sha256:2cc044fc5a07c9b701f8f1255a309ae9ad7856e694ac03513bf3648c01e40763"
    }
    dex = {
      upstream   = "ghcr.io/dexidp/dex"
      repository = "mirror/dexidp/dex"
      tag        = "v2.46.1"
      digest     = "sha256:65b72ca0f4b0bf6d4ada84ec21da8851782563404ac7b8f926923d27ceced9ab"
    }
    kyverno = {
      upstream   = "reg.kyverno.io/kyverno/kyverno"
      repository = "mirror/kyverno/kyverno"
      tag        = "v1.19.2"
      digest     = "sha256:c8c4dd09e720d2cd7fd24ca73ac28e46651001372f988e0cba3f2f612f04b955"
    }
    kyvernopre = {
      upstream   = "reg.kyverno.io/kyverno/kyvernopre"
      repository = "mirror/kyverno/kyvernopre"
      tag        = "v1.19.2"
      digest     = "sha256:27f3cc52e628559b56d08363b85316819802086c9808606914f7805a244148f4"
    }
    kyverno_background_controller = {
      upstream   = "reg.kyverno.io/kyverno/background-controller"
      repository = "mirror/kyverno/background-controller"
      tag        = "v1.19.2"
      digest     = "sha256:c46e124f21ef8a6bb4b48de57106808b1007edcd5ddd4ff7df5d23b9efa60ce2"
    }
    kyverno_cleanup_controller = {
      upstream   = "reg.kyverno.io/kyverno/cleanup-controller"
      repository = "mirror/kyverno/cleanup-controller"
      tag        = "v1.19.2"
      digest     = "sha256:d7340aa7c9315080c3dafa7b765d090ced37353e89e5cd7a3f9ac69e8fb532b2"
    }
    kyverno_reports_controller = {
      upstream   = "reg.kyverno.io/kyverno/reports-controller"
      repository = "mirror/kyverno/reports-controller"
      tag        = "v1.19.2"
      digest     = "sha256:5fb6d3e738050dbce84f60ecabaede7665fbe0578d07c1e8c912443b035e79c3"
    }
    kyverno_cli = {
      upstream   = "reg.kyverno.io/kyverno/kyverno-cli"
      repository = "mirror/kyverno/kyverno-cli"
      tag        = "v1.19.2"
      digest     = "sha256:322ec5044d600930cb3af0e56dc33154a2d1d1fba58f4cadad3f47be7e78b11c"
    }
    kyverno_readiness_checker = {
      upstream   = "ghcr.io/kyverno/readiness-checker"
      repository = "mirror/kyverno/readiness-checker"
      tag        = "v1.19.2"
      digest     = "sha256:02600428e7c956e222f4376413525866ed9fec28e6bcb1222774ce6bf5fc904a"
    }
    karpenter = {
      upstream   = "public.ecr.aws/karpenter/controller"
      repository = "mirror/karpenter/controller"
      tag        = "1.15.1"
      digest     = "sha256:8314ff9c6bca66372031e80532c18025bbe6d34eae2443849d9ff02796fb09c8"
    }
    external_secrets = {
      upstream   = "ghcr.io/external-secrets/external-secrets"
      repository = "mirror/external-secrets/external-secrets"
      tag        = "v2.14.0"
      digest     = "sha256:10608eb53e636e744903d5f3657a4d9c44e28d9d9c181b73e07bc7dd2e6884dc"
    }
    load_balancer_controller = {
      upstream   = "public.ecr.aws/eks/aws-load-balancer-controller"
      repository = "mirror/eks/aws-load-balancer-controller"
      tag        = "v3.6.2"
      digest     = "sha256:fd51f0ec82f8d357837aa57fdfaa4fca7137b75f25a09b421d95c425c9dc2d94"
    }
    envoy = {
      upstream   = "docker.io/envoyproxy/envoy"
      repository = "mirror/envoyproxy/envoy"
      tag        = "distroless-v1.40.2"
      digest     = "sha256:09ca6f2140a61ad8df11779a4a30d52b48433d444466328494f9188c9c35eded"
    }

    # The observability stack (ADR-0009, #243). The operator and kube-state-metrics run from this module
    # (observability.tf); the rest from deploy/observability, whose charts name the same digests (its tests check).
    prometheus_operator = {
      upstream   = "quay.io/prometheus-operator/prometheus-operator"
      repository = "mirror/prometheus-operator/prometheus-operator"
      tag        = "v0.94.2"
      digest     = "sha256:c7edf0379b7271ef1705dce258d2bb73820e299cc95559369e9f6fc3321639ec"
    }
    prometheus_config_reloader = {
      upstream   = "quay.io/prometheus-operator/prometheus-config-reloader"
      repository = "mirror/prometheus-operator/prometheus-config-reloader"
      tag        = "v0.94.2"
      digest     = "sha256:a1897c67478bc23434534e91ad3855280771196b1daf17144db9dbcb655bef71"
    }
    kube_state_metrics = {
      upstream   = "registry.k8s.io/kube-state-metrics/kube-state-metrics"
      repository = "mirror/kube-state-metrics/kube-state-metrics"
      tag        = "v2.20.0"
      digest     = "sha256:42cfe3723a5f058171c627537fb57a3ea0f26e4380fa18555a95cb1a1b4cfc5b"
    }
    prometheus = {
      upstream   = "quay.io/prometheus/prometheus"
      repository = "mirror/prometheus/prometheus"
      tag        = "v3.15.1-distroless"
      digest     = "sha256:451a845bae1d51622b41af1780eb2ad911bbb79a9855bc8e9bb67fabbc03f934"
    }
    alertmanager = {
      upstream   = "quay.io/prometheus/alertmanager"
      repository = "mirror/prometheus/alertmanager"
      tag        = "v0.34.2"
      digest     = "sha256:39d8bb3966c694a124428a3a88fbcffd40bd069129ecd47c059f8a3f17c55f3b"
    }
    pushgateway = {
      upstream   = "quay.io/prometheus/pushgateway"
      repository = "mirror/prometheus/pushgateway"
      tag        = "v1.11.4"
      digest     = "sha256:91a56b89b97dd8a5e1e4fa8b5bbbd86dd57a87a2a3cee3a3ce3368b40ef158ef"
    }
    cloudwatch_exporter = {
      upstream   = "docker.io/prom/cloudwatch-exporter"
      repository = "mirror/prom/cloudwatch-exporter"
      tag        = "v0.16.0"
      digest     = "sha256:71c2e988af061257ecec8dadf7ff1c98831bc82842e97a893b3eb7ede383b59f"
    }
    grafana = {
      upstream   = "docker.io/grafana/grafana"
      repository = "mirror/grafana/grafana"
      tag        = "13.3.0-distroless"
      digest     = "sha256:540b8afb775bf34aefce417e4329039daa5d44b6f2fbda6881397b1b247ca7df"
    }
    loki = {
      upstream   = "docker.io/grafana/loki"
      repository = "mirror/grafana/loki"
      tag        = "3.6.16"
      digest     = "sha256:79f3fbf2a3eca97dd735e2aa0871a2fc15365a81c68dea67f639b092c301f454"
    }
    tempo = {
      upstream   = "docker.io/grafana/tempo"
      repository = "mirror/grafana/tempo"
      tag        = "3.1.1"
      digest     = "sha256:64e2fbd56d9c2b3412a4b430a58ea59e91a670b1e75f920a0c702213ad145044"
    }
    otel_collector = {
      upstream   = "docker.io/otel/opentelemetry-collector-contrib"
      repository = "mirror/otel/opentelemetry-collector-contrib"
      tag        = "0.163.2"
      digest     = "sha256:7f22d2a6748110ffb6a59bc0df448bccbf501cdb667d610ede4c61d3863d5849"
    }
  }

  # The registry in this cluster's Region: Tokyo's, or its Osaka replica (ADR-0007).
  registry = "${var.shared_account_id}.dkr.ecr.${var.region}.amazonaws.com"

  # "<tag>@<digest>": charts that build "<repository>:<tag>" then pull by digest, and the tag stays readable.
  image_tag  = { for k, i in local.images : k => "${i.tag}@${i.digest}" }
  image_repo = { for k, i in local.images : k => "${local.registry}/${i.repository}" }
  image_ref  = { for k, i in local.images : k => "${local.registry}/${i.repository}:${i.tag}@${i.digest}" }
}
