# Kubernetes RBAC for the Identity Center permission sets (ADR-0004, authn-authz 8.1, T-63). The cluster layer's
# access entries map ReadOnly to the group sft:readonly, and Operator to sft:readonly and sft:operator (#103).
#
# - sft:readonly reads workloads, events, logs and the platform's custom resources, cluster-wide. No Secrets, no
#   exec, attach or port-forward, and no write.
# - sft:portforward lets a group port-forward in one namespace, where a RoleBinding in Git grants it: the operator API's
#   sft-operator to sft:operator (#106), and Grafana's namespace to sft:readonly (ADR-0009).
# BreakGlass and the deploy role are cluster admins through their access entries.

resource "kubernetes_cluster_role_v1" "readonly" {
  metadata {
    name   = "sft:readonly"
    labels = { "app.kubernetes.io/part-of" = "sft-platform" }
  }

  rule {
    api_groups = [""]
    resources = [
      "configmaps", "endpoints", "events", "limitranges", "namespaces", "nodes", "persistentvolumeclaims",
      "persistentvolumes", "pods", "pods/log", "replicationcontrollers", "resourcequotas", "serviceaccounts",
      "services",
    ]
    verbs = ["get", "list", "watch"]
  }

  rule {
    api_groups = [
      "apps", "autoscaling", "batch", "policy", "networking.k8s.io", "discovery.k8s.io", "storage.k8s.io",
      "scheduling.k8s.io", "events.k8s.io", "coordination.k8s.io", "rbac.authorization.k8s.io",
      "admissionregistration.k8s.io", "apiextensions.k8s.io",
    ]
    resources = ["*"]
    verbs     = ["get", "list", "watch"]
  }

  # The platform's own resources: Argo CD's Applications, Karpenter's pools and claims, Kyverno's policies and
  # reports, KEDA's scalers, External Secrets' status (never the secret values, which live only in Secrets), the
  # Load Balancer Controller's bindings.
  rule {
    api_groups = [
      "argoproj.io", "karpenter.sh", "karpenter.k8s.aws", "kyverno.io", "policies.kyverno.io", "reports.kyverno.io",
      "wgpolicyk8s.io", "openreports.io", "keda.sh", "external-secrets.io", "elbv2.k8s.aws", "monitoring.coreos.com",
    ]
    resources = ["*"]
    verbs     = ["get", "list", "watch"]
  }
}

resource "kubernetes_cluster_role_binding_v1" "readonly" {
  metadata {
    name   = "sft:readonly"
    labels = { "app.kubernetes.io/part-of" = "sft-platform" }
  }

  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "ClusterRole"
    name      = kubernetes_cluster_role_v1.readonly.metadata[0].name
  }

  subject {
    api_group = "rbac.authorization.k8s.io"
    kind      = "Group"
    name      = "sft:readonly"
  }
}

resource "kubernetes_cluster_role_v1" "portforward" {
  metadata {
    name   = "sft:portforward"
    labels = { "app.kubernetes.io/part-of" = "sft-platform" }
  }

  rule {
    api_groups = [""]
    resources  = ["pods", "services"]
    verbs      = ["get", "list"]
  }

  rule {
    api_groups = [""]
    resources  = ["pods/portforward"]
    verbs      = ["create"]
  }
}
