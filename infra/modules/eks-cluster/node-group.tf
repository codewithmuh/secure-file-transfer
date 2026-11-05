# The always-on system node group (ADR-0004, capacity 4.2): a small EKS managed node group of Bottlerocket nodes,
# tainted, for what Karpenter and admission depend on: Karpenter itself, CoreDNS, Argo CD, Kyverno and the egress
# proxy, and the EKS add-ons' controllers. It is also where the Systems Manager tunnel ends (ADR-0021), so it is the
# only group whose nodes run the Systems Manager agent and reach NAT (the system_nodes security group).

# ---------------------------------------------------------------------------------------------------------------------
# Node roles: one for the system group, one for Karpenter's nodes, so only the system nodes hold the agent's rights
# ---------------------------------------------------------------------------------------------------------------------

data "aws_iam_policy_document" "node_trust" {
  statement {
    sid     = "Ec2Instances"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

# Image pulls for every node: our registry in the shared account (any account of our organization, so no shared
# account ID is committed) and the AWS-owned registries of the EKS add-ons and Bottlerocket's host containers
# (ADR-0007, ADR-0021). The registry key is used only through ECR (encryption 4.4).
data "aws_iam_policy_document" "node_image_pulls" {
  statement {
    sid       = "RegistryToken"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }

  statement {
    sid       = "PullFromOurOrganization"
    actions   = ["ecr:BatchCheckLayerAvailability", "ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"]
    resources = [for r in var.cluster_regions : "arn:aws:ecr:${r}:*:repository/*"]

    condition {
      test     = "StringEquals"
      variable = "aws:ResourceOrgID"
      values   = [var.organization_id]
    }
  }

  statement {
    sid     = "PullAwsOwnedAddOnImages"
    actions = ["ecr:BatchCheckLayerAvailability", "ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"]
    resources = flatten([
      for r in var.cluster_regions : [
        "arn:aws:ecr:${r}:602401143452:repository/*", # aws-owned-account: EKS add-ons and the pause image
        "arn:aws:ecr:${r}:328549459982:repository/*", # aws-owned-account: Bottlerocket's host containers
      ]
    ])
  }

  statement {
    sid       = "RegistryKeyThroughEcr"
    actions   = ["kms:Decrypt"]
    resources = [for r in var.cluster_regions : "arn:aws:kms:${r}:*:key/*"]

    condition {
      test     = "StringEquals"
      variable = "aws:ResourceOrgID"
      values   = [var.organization_id]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = [for r in var.cluster_regions : "ecr.${r}.amazonaws.com"]
    }
  }
}

# The Systems Manager agent in Bottlerocket's control container, on system nodes only: it registers the node and
# carries port-forwarding sessions, which our session document limits to the cluster API (tunnel.tf). Narrower than
# AmazonSSMManagedInstanceCore: no Run Command documents, parameters or inventory.
data "aws_iam_policy_document" "system_node_ssm" {
  statement {
    sid       = "SessionManagerAgent"
    actions   = ["ssm:UpdateInstanceInformation"]
    resources = [for r in var.cluster_regions : "arn:aws:ec2:${r}:${var.account_id}:instance/*"]
  }

  statement {
    sid = "SessionChannels"
    actions = [
      "ec2messages:AcknowledgeMessage", "ec2messages:DeleteMessage", "ec2messages:FailMessage",
      "ec2messages:GetEndpoint", "ec2messages:GetMessages", "ec2messages:SendReply",
      "ssmmessages:CreateControlChannel", "ssmmessages:CreateDataChannel", "ssmmessages:OpenControlChannel",
      "ssmmessages:OpenDataChannel",
    ]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:RequestedRegion"
      values   = var.cluster_regions
    }
  }
}

locals {
  node_roles = {
    system_node    = "The system node group of every ${var.global_name_prefix} cluster (ADR-0004)."
    karpenter_node = "Karpenter's main and scan nodes in every ${var.global_name_prefix} cluster (ADR-0004)."
  }
}

resource "aws_iam_role" "node" {
  for_each = var.create_iam ? local.node_roles : {}

  name                 = local.role_names[each.key]
  description          = each.value
  assume_role_policy   = data.aws_iam_policy_document.node_trust.json
  permissions_boundary = var.permissions_boundary_arn
}

# AmazonEKSWorkerNodePolicy: describe calls, eks:DescribeCluster and eks-auth:AssumeRoleForPodIdentity. The CNI's
# rights are on its own Pod Identity role, never on the nodes.
resource "aws_iam_role_policy_attachment" "node" {
  for_each = var.create_iam ? local.node_roles : {}

  role       = aws_iam_role.node[each.key].name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
}

resource "aws_iam_role_policy" "node_image_pulls" {
  for_each = var.create_iam ? local.node_roles : {}

  name   = "image-pulls"
  role   = aws_iam_role.node[each.key].name
  policy = data.aws_iam_policy_document.node_image_pulls.json
}

resource "aws_iam_role_policy" "system_node_ssm" {
  count = var.create_iam ? 1 : 0

  name   = "systems-manager-agent"
  role   = aws_iam_role.node["system_node"].name
  policy = data.aws_iam_policy_document.system_node_ssm.json
}

# ---------------------------------------------------------------------------------------------------------------------
# Launch template: keeps EKS's own cluster security group, which allows all egress, off the nodes (network module)
# ---------------------------------------------------------------------------------------------------------------------

locals {
  # Bottlerocket settings, merged by EKS with its own. The control container runs the Systems Manager agent that ends
  # the tunnel; the admin container, a root shell on the host, stays off.
  system_user_data = <<-EOT
    [settings.host-containers.admin]
    enabled = false

    [settings.host-containers.control]
    enabled = true
  EOT

  # EKS tags the group's instances eks:nodegroup-name with this name, which is how the policies that may start a
  # session (cluster-bootstrap's job, #104; the ReadOnly and Operator permission sets) find the tunnel's end.
  system_node_group_name = "${var.name_prefix}-system"
}

resource "aws_launch_template" "system" {
  name        = "${var.name_prefix}-system-nodes"
  description = "System node group of ${local.cluster_name}: Bottlerocket, IMDSv2 with hop limit 1, our security groups only."

  vpc_security_group_ids = [var.security_group_ids["nodes"], var.security_group_ids["system_nodes"]]
  user_data              = base64encode(local.system_user_data)
  update_default_version = true

  # IMDSv2 only, one hop: pods can't reach the node's credentials (T-52).
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "disabled"
  }

  # Bottlerocket's data volume (containers and images). The OS volume keeps the AMI's size. Encrypted with the
  # account's default EBS key, the platform key (encryption 3.1).
  block_device_mappings {
    device_name = "/dev/xvdb"

    ebs {
      volume_size           = var.system_volume_size_gib
      volume_type           = "gp3"
      encrypted             = "true"
      delete_on_termination = "true"
    }
  }

  dynamic "tag_specifications" {
    for_each = toset(["instance", "volume", "network-interface"])

    content {
      resource_type = tag_specifications.value
      tags          = { Name = "${var.name_prefix}-system-node", component = "eks-system-nodes" }
    }
  }

  tags = {
    component = "eks-system-nodes"
  }
}

resource "aws_eks_node_group" "system" {
  cluster_name    = aws_eks_cluster.this.name
  node_group_name = local.system_node_group_name
  node_role_arn   = local.role_arns.system_node
  subnet_ids      = values(var.private_subnet_ids)

  ami_type       = "BOTTLEROCKET_ARM_64"
  capacity_type  = "ON_DEMAND"
  instance_types = [var.system_instance_type]

  scaling_config {
    desired_size = var.system_node_count
    min_size     = var.system_node_count
    max_size     = var.system_node_count + 1
  }

  update_config {
    max_unavailable = 1
  }

  node_repair_config {
    enabled = true
  }

  launch_template {
    id      = aws_launch_template.system.id
    version = aws_launch_template.system.latest_version
  }

  labels = local.system_pool_label

  taint {
    key    = local.system_toleration.key
    value  = local.system_toleration.value
    effect = "NO_SCHEDULE"
  }

  tags = {
    component = "eks-system-nodes"
  }

  # The CNI and Pod Identity agent first, or nodes never become Ready.
  depends_on = [
    aws_eks_addon.before_nodes,
    aws_iam_role_policy_attachment.node,
    aws_iam_role_policy.node_image_pulls,
  ]
}
