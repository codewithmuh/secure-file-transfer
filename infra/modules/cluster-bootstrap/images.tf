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
  }

  # The registry in this cluster's Region: Tokyo's, or its Osaka replica (ADR-0007).
  registry = "${var.shared_account_id}.dkr.ecr.${var.region}.amazonaws.com"

  # "<tag>@<digest>": charts that build "<repository>:<tag>" then pull by digest, and the tag stays readable.
  image_tag  = { for k, i in local.images : k => "${i.tag}@${i.digest}" }
  image_repo = { for k, i in local.images : k => "${local.registry}/${i.repository}" }
  image_ref  = { for k, i in local.images : k => "${local.registry}/${i.repository}:${i.tag}@${i.digest}" }
}
