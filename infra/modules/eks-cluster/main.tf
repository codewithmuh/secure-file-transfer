# One EKS cluster per environment and Region (ADR-0004), from the same code in Tokyo and Osaka (T-79): the cluster with
# a private API endpoint only (ADR-0021), its control-plane logs, its EKS add-ons and its access entries. The system
# node group is in node-group.tf, Karpenter's AWS side in karpenter.tf, the workload roles and their Pod Identity
# associations in workload-roles.tf and the Systems Manager session document in tunnel.tf.
#
# IAM is global, so the account's roles are created once, by the Tokyo stack (create_iam), and used by every cluster
# in the account: their trust names each cluster, and their policies the resources of each Region. Osaka's stack
# refers to them by name, the way Osaka's bootstrap stack refers to Tokyo's roles, so a failover needs no IAM change.

locals {
  cluster_name = "${var.name_prefix}-eks"

  region_short = { "ap-northeast-1" = "apne1", "ap-northeast-3" = "apne3" }

  # sft-<env>-<region-short> of every Region with a cluster, for names in the IAM policies.
  regional_prefixes = { for r in var.cluster_regions : r => "${var.global_name_prefix}-${local.region_short[r]}" }

  # Every cluster in the account, which the Pod Identity roles trust (their eks-cluster-arn session tag).
  cluster_arns = [for r, p in local.regional_prefixes : "arn:aws:eks:${r}:${var.account_id}:cluster/${p}-eks"]

  # The account's roles, all at path "/": queue, bucket and key policies in the data layer name them exactly (#101,
  # #102), and encryption 4.3 gives the workload names.
  role_names = {
    cluster          = "${var.global_name_prefix}-eks-cluster"
    system_node      = "${var.global_name_prefix}-system-node"
    karpenter_node   = "${var.global_name_prefix}-karpenter-node"
    karpenter        = "${var.global_name_prefix}-karpenter"
    vpc_cni          = "${var.global_name_prefix}-vpc-cni"
    ebs_csi          = "${var.global_name_prefix}-ebs-csi"
    lb_controller    = "${var.global_name_prefix}-lb-controller"
    external_secrets = "${var.global_name_prefix}-external-secrets"
    kyverno          = "${var.global_name_prefix}-kyverno"
    api              = "${var.global_name_prefix}-api"
    relay            = "${var.global_name_prefix}-relay"
    scan             = "${var.global_name_prefix}-scan"
    notify           = "${var.global_name_prefix}-notify"
    jobs             = "${var.global_name_prefix}-jobs"
    archive          = "${var.global_name_prefix}-archive"
    migrate          = "${var.global_name_prefix}-migrate"
    operator         = "${var.global_name_prefix}-operator"
  }
  role_arns = { for k, n in local.role_names : k => "arn:aws:iam::${var.account_id}:role/${n}" }

  # The data layer's execution role for EventBridge targets (#102, encryption 4.4), created by the Tokyo data stack.
  events_delivery_role_arn = "arn:aws:iam::${var.account_id}:role/${var.global_name_prefix}-events-delivery"

  # Every log type: the audit log records each exec and port-forward, which break-glass alerts on (authn-authz 8.3),
  # and the others are what an incident needs (capacity A19 prices all of them). SCP 3 keeps logging and the log group
  # with the apply roles.
  control_plane_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]

  # The system node group's taint and label (ADR-0004): only Karpenter, Argo CD, CoreDNS, Kyverno, the egress proxy and
  # the EKS add-ons' controllers tolerate it, and Kyverno refuses the toleration in application namespaces.
  system_pool_label = { "sft.io/pool" = "system" }
  system_toleration = { key = "sft.io/pool", operator = "Equal", value = "system", effect = "NoSchedule" }
}

# ---------------------------------------------------------------------------------------------------------------------
# Keys, by alias (encryption 4.1). The data layer creates them; ListAliases needs no key policy, so the plan role can
# read these without any use of the keys.
# ---------------------------------------------------------------------------------------------------------------------

data "aws_kms_alias" "this" {
  for_each = toset(["files", "logs", "platform", "secrets"])

  name = "${var.kms_alias_prefix}/${each.key}"
}

# ---------------------------------------------------------------------------------------------------------------------
# Control-plane logs: created before the cluster, so EKS writes into our encrypted group with our retention
# ---------------------------------------------------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "control_plane" {
  name              = "/aws/eks/${local.cluster_name}/cluster"
  retention_in_days = var.control_plane_log_retention_days
  kms_key_id        = data.aws_kms_alias.this["logs"].target_key_arn

  tags = {
    component = "eks-logs"
  }
}

# ---------------------------------------------------------------------------------------------------------------------
# The cluster role
# ---------------------------------------------------------------------------------------------------------------------

data "aws_iam_policy_document" "cluster_trust" {
  statement {
    sid     = "EksControlPlane"
    actions = ["sts:AssumeRole", "sts:TagSession"]

    principals {
      type        = "Service"
      identifiers = ["eks.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.account_id]
    }
  }
}

# Envelope encryption of Kubernetes Secrets with the secrets key (encryption 3.1). EKS uses the key through a grant it
# creates at cluster creation; the key policy names this role and the deploy role for it (#102).
data "aws_iam_policy_document" "cluster" {
  statement {
    sid       = "SecretsKeyThroughEks"
    actions   = ["kms:DescribeKey", "kms:Encrypt", "kms:Decrypt", "kms:CreateGrant"]
    resources = [for r in var.cluster_regions : "arn:aws:kms:${r}:${var.account_id}:key/*"]

    condition {
      test     = "ForAnyValue:StringEquals"
      variable = "kms:ResourceAliases"
      values   = ["${var.kms_alias_prefix}/secrets"]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = [for r in var.cluster_regions : "eks.${r}.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "cluster" {
  count = var.create_iam ? 1 : 0

  name                 = local.role_names.cluster
  description          = "EKS control planes of ${var.global_name_prefix} (ADR-0004)."
  assume_role_policy   = data.aws_iam_policy_document.cluster_trust.json
  permissions_boundary = var.permissions_boundary_arn
}

resource "aws_iam_role_policy_attachment" "cluster" {
  count = var.create_iam ? 1 : 0

  role       = aws_iam_role.cluster[0].name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}

resource "aws_iam_role_policy" "cluster" {
  count = var.create_iam ? 1 : 0

  name   = "secrets-key"
  role   = aws_iam_role.cluster[0].name
  policy = data.aws_iam_policy_document.cluster.json
}

# ---------------------------------------------------------------------------------------------------------------------
# The cluster
# ---------------------------------------------------------------------------------------------------------------------

resource "aws_eks_cluster" "this" {
  name     = local.cluster_name
  role_arn = local.role_arns.cluster
  version  = var.kubernetes_version

  # Every add-on is an EKS add-on below (ADR-0004), so EKS installs no unmanaged copies of them.
  bootstrap_self_managed_addons = false
  deletion_protection           = var.deletion_protection
  enabled_cluster_log_types     = local.control_plane_log_types

  # Access entries only, never the aws-auth ConfigMap; nobody is cluster admin by having created it (ADR-0004).
  access_config {
    authentication_mode                         = "API"
    bootstrap_cluster_creator_admin_permissions = false
  }

  # Private only (ADR-0021): the API's network interfaces sit in the endpoint subnets with the cluster_api group, and
  # people and CI reach them through the Systems Manager tunnel (tunnel.tf).
  vpc_config {
    endpoint_private_access = true
    endpoint_public_access  = false
    subnet_ids              = values(var.endpoint_subnet_ids)
    security_group_ids      = [var.security_group_ids["cluster_api"]]
  }

  kubernetes_network_config {
    ip_family = "ipv4"
  }

  encryption_config {
    resources = ["secrets"]

    provider {
      key_arn = data.aws_kms_alias.this["secrets"].target_key_arn
    }
  }

  # Standard support only: extended support costs $365 a month per cluster (capacity 7.2).
  upgrade_policy {
    support_type = "STANDARD"
  }

  # Lets an AZ's traffic be shifted away in an AZ failure (NFR-11).
  zonal_shift_config {
    enabled = true
  }

  tags = {
    component = "eks"
  }

  lifecycle {
    precondition {
      condition     = contains(var.cluster_regions, var.region)
      error_message = "cluster_regions must include this cluster's own Region, or its roles wouldn't trust it."
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.control_plane,
    aws_iam_role_policy_attachment.cluster,
    aws_iam_role_policy.cluster,
  ]
}

# ---------------------------------------------------------------------------------------------------------------------
# EKS add-ons (ADR-0004): AWS-owned images, which the endpoint policies and Kyverno allow by registry and repository.
# Each is pinned to the default version for the cluster's Kubernetes version, so an upgrade moves them with it.
# ---------------------------------------------------------------------------------------------------------------------

locals {
  # Controllers run on the system nodes, so an Osaka pilot light, which has only those, has no pending pod and
  # Karpenter launches nothing (ADR-0004). DaemonSets tolerate every taint by default.
  addons = {
    # Network policies through the VPC CNI's agent: default deny per workload (ADR-0021).
    "vpc-cni" = {
      before_nodes    = true
      service_account = "aws-node"
      role            = "vpc_cni"
      configuration   = { enableNetworkPolicy = "true" }
    }
    "kube-proxy" = {
      before_nodes    = true
      service_account = null
      role            = null
      configuration   = null
    }
    "eks-pod-identity-agent" = {
      before_nodes    = true
      service_account = null
      role            = null
      configuration   = null
    }
    "coredns" = {
      before_nodes    = false
      service_account = null
      role            = null
      configuration = {
        replicaCount = 2
        nodeSelector = local.system_pool_label
        tolerations  = [local.system_toleration]
      }
    }
    "aws-ebs-csi-driver" = {
      before_nodes    = false
      service_account = "ebs-csi-controller-sa"
      role            = "ebs_csi"
      configuration = {
        controller = {
          nodeSelector = local.system_pool_label
          tolerations  = [local.system_toleration]
        }
      }
    }
  }
}

data "aws_eks_addon_version" "this" {
  for_each = local.addons

  addon_name         = each.key
  kubernetes_version = aws_eks_cluster.this.version
}

# The CNI, kube-proxy and the Pod Identity agent go first: nodes join only once the CNI can run on them.
resource "aws_eks_addon" "before_nodes" {
  for_each = { for k, v in local.addons : k => v if v.before_nodes }

  cluster_name                = aws_eks_cluster.this.name
  addon_name                  = each.key
  addon_version               = data.aws_eks_addon_version.this[each.key].version
  configuration_values        = each.value.configuration == null ? null : jsonencode(each.value.configuration)
  resolve_conflicts_on_create = "OVERWRITE"
  resolve_conflicts_on_update = "OVERWRITE"

  dynamic "pod_identity_association" {
    for_each = each.value.role == null ? [] : [each.value]

    content {
      service_account = pod_identity_association.value.service_account
      role_arn        = local.role_arns[pod_identity_association.value.role]
    }
  }

  tags = {
    component = "eks"
  }

  depends_on = [aws_iam_role_policy_attachment.pod_identity]
}

resource "aws_eks_addon" "after_nodes" {
  for_each = { for k, v in local.addons : k => v if !v.before_nodes }

  cluster_name                = aws_eks_cluster.this.name
  addon_name                  = each.key
  addon_version               = data.aws_eks_addon_version.this[each.key].version
  configuration_values        = each.value.configuration == null ? null : jsonencode(each.value.configuration)
  resolve_conflicts_on_create = "OVERWRITE"
  resolve_conflicts_on_update = "OVERWRITE"

  dynamic "pod_identity_association" {
    for_each = each.value.role == null ? [] : [each.value]

    content {
      service_account = pod_identity_association.value.service_account
      role_arn        = local.role_arns[pod_identity_association.value.role]
    }
  }

  tags = {
    component = "eks"
  }

  depends_on = [aws_eks_node_group.system, aws_iam_role_policy_attachment.pod_identity, aws_iam_role_policy.pod_identity]
}

# ---------------------------------------------------------------------------------------------------------------------
# Access entries (ADR-0004, authn-authz 8.1). Identity Center's roles carry a random suffix, so they are read from
# IAM; a plan fails unless exactly one role matches each permission set.
# ---------------------------------------------------------------------------------------------------------------------

locals {
  # Permission set => Kubernetes groups. The cluster-bootstrap layer binds the groups (#104): sft:readonly reads
  # workloads, events and logs without Secrets and may port-forward only in grafana; sft:operator adds port-forward in
  # sft-operator. Neither may exec, attach, patch or change an Argo CD Application (T-63).
  sso_groups = {
    ReadOnly = ["sft:readonly"]
    Operator = ["sft:readonly", "sft:operator"]
  }
}

data "aws_iam_roles" "sso" {
  for_each = toset(["ReadOnly", "Operator", "BreakGlass"])

  path_prefix = "/aws-reserved/sso.amazonaws.com/"
  name_regex  = "^AWSReservedSSO_${each.key}_[0-9a-f]+$"
}

locals {
  sso_role_arns = { for set, d in data.aws_iam_roles.sso : set => one(d.arns) }
}

resource "aws_eks_access_entry" "sso_groups" {
  for_each = local.sso_groups

  cluster_name      = aws_eks_cluster.this.name
  principal_arn     = local.sso_role_arns[each.key]
  type              = "STANDARD"
  kubernetes_groups = each.value

  lifecycle {
    precondition {
      condition     = length(data.aws_iam_roles.sso[each.key].arns) == 1
      error_message = "Exactly one Identity Center role must exist for the ${each.key} permission set in this account."
    }
  }
}

# Cluster admin: BreakGlass (time-boxed, every exec alerts, authn-authz 8.3) and the deploy role, which only the
# cluster-bootstrap job on main uses, to install Argo CD (ADR-0004). No person applies manifests.
locals {
  cluster_admins = {
    break_glass = local.sso_role_arns["BreakGlass"]
    deploy      = var.deploy_role_arn
  }
}

resource "aws_eks_access_entry" "admin" {
  for_each = local.cluster_admins

  cluster_name  = aws_eks_cluster.this.name
  principal_arn = each.value
  type          = "STANDARD"

  lifecycle {
    precondition {
      condition     = each.key != "break_glass" || length(data.aws_iam_roles.sso["BreakGlass"].arns) == 1
      error_message = "Exactly one Identity Center role must exist for the BreakGlass permission set in this account."
    }
  }
}

resource "aws_eks_access_policy_association" "admin" {
  for_each = local.cluster_admins

  cluster_name  = aws_eks_cluster.this.name
  principal_arn = aws_eks_access_entry.admin[each.key].principal_arn
  policy_arn    = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"

  access_scope {
    type = "cluster"
  }
}
