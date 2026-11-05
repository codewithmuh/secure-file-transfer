# ---------------------------------------------------------------------------------------------------------------------
# Cluster-bootstrap layer (#104): what the deploy role needs to reach a cluster's private API through the Systems
# Manager tunnel (ADR-0021, modules/eks-cluster/tunnel.tf), in the Regions of var.network_regions. The stack itself
# needs nothing else from AWS: its remote state reads use the state permissions, the Operator role lookup the cluster
# layer's iam:ListRoles, and the cluster API admits the deploy role through the cluster layer's access entry.
#
# Deploy role only. The layer is planned and applied only on main (infra/README.md, "Stacks"), so pull request plans,
# and with them the plan role, never reach a cluster API.
#
# A session may start only with the cluster's tunnel document (sft-<env>-<rs>-cluster-tunnel, which forwards to the
# cluster API on 443 and nowhere else) and only on the system node group's instances, which EKS tags
# eks:nodegroup-name = sft-<env>-<rs>-system. ssm:SessionDocumentAccessCheck makes Systems Manager check the document
# too, so a StartSession without one (the default shell document) is refused. A session can be ended or resumed only
# by the role session that started it.
# ---------------------------------------------------------------------------------------------------------------------

locals {
  cluster_bootstrap_enabled = local.cluster_enabled && var.github_environment != null

  cluster_bootstrap_region_shorts = { "ap-northeast-1" = "apne1", "ap-northeast-3" = "apne3" }

  cluster_bootstrap_node_groups = [
    for r in var.network_regions : "${local.cluster_env_prefix}-${local.cluster_bootstrap_region_shorts[r]}-system"
  ]
  cluster_bootstrap_instance_arns = [for r in var.network_regions : "arn:aws:ec2:${r}:${var.account_id}:instance/*"]
}

data "aws_iam_policy_document" "cluster_bootstrap" {
  count = local.cluster_bootstrap_enabled ? 1 : 0

  # The job finds a running system node to end the tunnel on.
  statement {
    sid       = "FindSystemNodes"
    actions   = ["ec2:DescribeInstances", "ssm:DescribeInstanceInformation"]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:RequestedRegion"
      values   = var.network_regions
    }
  }

  statement {
    sid       = "TunnelOnSystemNodesOnly"
    actions   = ["ssm:StartSession"]
    resources = local.cluster_bootstrap_instance_arns

    condition {
      test     = "StringEquals"
      variable = "ssm:resourceTag/eks:nodegroup-name"
      values   = local.cluster_bootstrap_node_groups
    }

    condition {
      test     = "BoolIfExists"
      variable = "ssm:SessionDocumentAccessCheck"
      values   = ["true"]
    }
  }

  statement {
    sid       = "TunnelDocumentOnly"
    actions   = ["ssm:StartSession"]
    resources = local.cluster_document_arns
  }

  # Systems Manager tags each session with the caller's user ID, which for a role session is <role ID>:<session name>.
  statement {
    sid       = "OwnSessionsOnly"
    actions   = ["ssm:ResumeSession", "ssm:TerminateSession"]
    resources = [for r in var.network_regions : "arn:aws:ssm:${r}:${var.account_id}:session/*"]

    condition {
      test     = "StringLike"
      variable = "ssm:resourceTag/aws:ssmmessages:session-id"
      values   = ["$${aws:userid}"]
    }
  }
}

resource "aws_iam_policy" "cluster_bootstrap" {
  count = local.cluster_bootstrap_enabled ? 1 : 0

  name        = "${local.cluster_env_prefix}-terraform-cluster-bootstrap"
  path        = var.iam_path
  description = "Terraform deploy: the Systems Manager tunnel to the cluster API for cluster-bootstrap (#104)."
  policy      = data.aws_iam_policy_document.cluster_bootstrap[0].json
}

resource "aws_iam_role_policy_attachment" "deploy_cluster_bootstrap" {
  count = local.cluster_bootstrap_enabled ? 1 : 0

  role       = aws_iam_role.deploy[0].name
  policy_arn = aws_iam_policy.cluster_bootstrap[0].arn
}
