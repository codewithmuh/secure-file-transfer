# Karpenter's AWS side (ADR-0004, capacity 4.2): its controller role, its nodes' instance profile and access entry,
# and the interruption queue with the EventBridge rules that feed it. Karpenter itself is installed by Argo CD
# (cluster-bootstrap, #104), on the system nodes, in isolated-VPC mode (ADR-0021), with the node classes and node pools
# this file builds as data (outputs karpenter_node_classes and karpenter_node_pools).
#
# Karpenter never touches IAM: the node classes name the instance profile made here, not a role, so the controller
# has no iam:CreateInstanceProfile or similar.

locals {
  karpenter_namespace       = "karpenter"
  karpenter_service_account = "karpenter"

  interruption_queue_name = "${var.name_prefix}-karpenter-interruption"

  # Every cluster in the account, for the tag conditions on the resources Karpenter may launch, tag and terminate.
  cluster_names = [for r, p in local.regional_prefixes : "${p}-eks"]

  ec2_arns = { for t in ["fleet", "instance", "volume", "network-interface", "launch-template", "spot-instances-request"] :
    t => [for r in var.cluster_regions : "arn:aws:ec2:${r}:${var.account_id}:${t}/*"]
  }
}

# ---------------------------------------------------------------------------------------------------------------------
# Controller policy, after Karpenter's reference policy for v1: everything it launches, tags or terminates carries the
# cluster's ownership tag and a node pool tag.
# ---------------------------------------------------------------------------------------------------------------------

data "aws_iam_policy_document" "karpenter" {
  statement {
    sid     = "LaunchFromOurImagesSubnetsAndGroups"
    actions = ["ec2:RunInstances", "ec2:CreateFleet"]
    resources = flatten([
      for r in var.cluster_regions : [
        "arn:aws:ec2:${r}::image/*",
        "arn:aws:ec2:${r}::snapshot/*",
        "arn:aws:ec2:${r}:${var.account_id}:security-group/*",
        "arn:aws:ec2:${r}:${var.account_id}:subnet/*",
        "arn:aws:ec2:${r}:${var.account_id}:capacity-reservation/*",
      ]
    ])
  }

  statement {
    sid       = "LaunchFromOwnLaunchTemplates"
    actions   = ["ec2:RunInstances", "ec2:CreateFleet"]
    resources = local.ec2_arns["launch-template"]

    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/eks:eks-cluster-name"
      values   = local.cluster_names
    }

    condition {
      test     = "StringLike"
      variable = "aws:ResourceTag/karpenter.sh/nodepool"
      values   = ["*"]
    }
  }

  statement {
    sid     = "CreateTaggedResources"
    actions = ["ec2:RunInstances", "ec2:CreateFleet", "ec2:CreateLaunchTemplate"]
    resources = flatten([
      for t in ["fleet", "instance", "volume", "network-interface", "launch-template", "spot-instances-request"] :
      local.ec2_arns[t]
    ])

    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/eks:eks-cluster-name"
      values   = local.cluster_names
    }

    condition {
      test     = "StringLike"
      variable = "aws:RequestTag/karpenter.sh/nodepool"
      values   = ["*"]
    }
  }

  statement {
    sid     = "TagOnCreate"
    actions = ["ec2:CreateTags"]
    resources = flatten([
      for t in ["fleet", "instance", "volume", "network-interface", "launch-template", "spot-instances-request"] :
      local.ec2_arns[t]
    ])

    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/eks:eks-cluster-name"
      values   = local.cluster_names
    }

    condition {
      test     = "StringEquals"
      variable = "ec2:CreateAction"
      values   = ["RunInstances", "CreateFleet", "CreateLaunchTemplate"]
    }

    condition {
      test     = "StringLike"
      variable = "aws:RequestTag/karpenter.sh/nodepool"
      values   = ["*"]
    }
  }

  statement {
    sid       = "TagOwnInstances"
    actions   = ["ec2:CreateTags"]
    resources = local.ec2_arns["instance"]

    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/eks:eks-cluster-name"
      values   = local.cluster_names
    }

    condition {
      test     = "StringLike"
      variable = "aws:ResourceTag/karpenter.sh/nodepool"
      values   = ["*"]
    }

    condition {
      test     = "ForAllValues:StringEquals"
      variable = "aws:TagKeys"
      values   = ["eks:eks-cluster-name", "karpenter.sh/nodeclaim", "Name"]
    }
  }

  statement {
    sid       = "TerminateOwnInstances"
    actions   = ["ec2:TerminateInstances", "ec2:DeleteLaunchTemplate"]
    resources = concat(local.ec2_arns["instance"], local.ec2_arns["launch-template"])

    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/eks:eks-cluster-name"
      values   = local.cluster_names
    }

    condition {
      test     = "StringLike"
      variable = "aws:ResourceTag/karpenter.sh/nodepool"
      values   = ["*"]
    }
  }

  statement {
    sid = "RegionalReads"
    actions = [
      "ec2:DescribeAvailabilityZones", "ec2:DescribeCapacityReservations", "ec2:DescribeImages",
      "ec2:DescribeInstances", "ec2:DescribeInstanceTypeOfferings", "ec2:DescribeInstanceTypes",
      "ec2:DescribeLaunchTemplates", "ec2:DescribeSecurityGroups", "ec2:DescribeSpotPriceHistory",
      "ec2:DescribeSubnets",
    ]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:RequestedRegion"
      values   = var.cluster_regions
    }
  }

  # Bottlerocket's AMI IDs, from AWS's public parameters, through the proxy (ADR-0021).
  statement {
    sid       = "BottlerocketAmiParameters"
    actions   = ["ssm:GetParameter"]
    resources = [for r in var.cluster_regions : "arn:aws:ssm:${r}::parameter/aws/service/*"]
  }

  statement {
    sid       = "InterruptionQueue"
    actions   = ["sqs:DeleteMessage", "sqs:GetQueueUrl", "sqs:ReceiveMessage"]
    resources = [for r, p in local.regional_prefixes : "arn:aws:sqs:${r}:${var.account_id}:${p}-karpenter-interruption"]
  }

  # The queue is under the platform key (encryption 3.1): reading a message decrypts it through SQS.
  statement {
    sid       = "InterruptionQueueKey"
    actions   = ["kms:Decrypt"]
    resources = [for r in var.cluster_regions : "arn:aws:kms:${r}:${var.account_id}:key/*"]

    condition {
      test     = "ForAnyValue:StringEquals"
      variable = "kms:ResourceAliases"
      values   = ["${var.kms_alias_prefix}/platform"]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = [for r in var.cluster_regions : "sqs.${r}.amazonaws.com"]
    }
  }

  statement {
    sid       = "PassNodeRoleOnly"
    actions   = ["iam:PassRole"]
    resources = [local.role_arns.karpenter_node]

    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["ec2.amazonaws.com"]
    }
  }

  statement {
    sid       = "ReadNodeInstanceProfile"
    actions   = ["iam:GetInstanceProfile"]
    resources = ["arn:aws:iam::${var.account_id}:instance-profile/${local.role_names.karpenter_node}"]
  }

  statement {
    sid       = "DiscoverClusterEndpoint"
    actions   = ["eks:DescribeCluster"]
    resources = local.cluster_arns
  }

  # Node volumes (encryption 4.3, V): root volumes under the platform key, scan volumes under the files key, only
  # through EC2, grants only for AWS resources. The key policies name this role too (#102).
  statement {
    sid = "NodeVolumeKeys"
    actions = [
      "kms:DescribeKey", "kms:Decrypt", "kms:GenerateDataKeyWithoutPlaintext", "kms:ReEncryptFrom", "kms:ReEncryptTo",
    ]
    resources = [for r in var.cluster_regions : "arn:aws:kms:${r}:${var.account_id}:key/*"]

    condition {
      test     = "ForAnyValue:StringEquals"
      variable = "kms:ResourceAliases"
      values   = ["${var.kms_alias_prefix}/platform", "${var.kms_alias_prefix}/files"]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = [for r in var.cluster_regions : "ec2.${r}.amazonaws.com"]
    }
  }

  statement {
    sid       = "NodeVolumeGrants"
    actions   = ["kms:CreateGrant"]
    resources = [for r in var.cluster_regions : "arn:aws:kms:${r}:${var.account_id}:key/*"]

    condition {
      test     = "ForAnyValue:StringEquals"
      variable = "kms:ResourceAliases"
      values   = ["${var.kms_alias_prefix}/platform", "${var.kms_alias_prefix}/files"]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = [for r in var.cluster_regions : "ec2.${r}.amazonaws.com"]
    }

    condition {
      test     = "Bool"
      variable = "kms:GrantIsForAWSResource"
      values   = ["true"]
    }
  }
}

# ---------------------------------------------------------------------------------------------------------------------
# The nodes' instance profile and access entry
# ---------------------------------------------------------------------------------------------------------------------

resource "aws_iam_instance_profile" "karpenter_node" {
  count = var.create_iam ? 1 : 0

  name = local.role_names.karpenter_node
  role = aws_iam_role.node["karpenter_node"].name
}

# Managed node groups get their access entry from EKS; Karpenter's nodes need one of their own.
resource "aws_eks_access_entry" "karpenter_node" {
  cluster_name  = aws_eks_cluster.this.name
  principal_arn = local.role_arns.karpenter_node
  type          = "EC2_LINUX"

  depends_on = [aws_iam_role.node]
}

# ---------------------------------------------------------------------------------------------------------------------
# Interruption queue: AWS Health's scheduled maintenance and EC2 state changes, so Karpenter drains a node before AWS
# stops it. Both pools run on demand, so there are no Spot interruption or rebalance rules.
# ---------------------------------------------------------------------------------------------------------------------

resource "aws_sqs_queue" "interruption" {
  name                      = local.interruption_queue_name
  message_retention_seconds = 300
  kms_master_key_id         = data.aws_kms_alias.this["platform"].target_key_arn

  tags = {
    component = "karpenter"
  }
}

# EventBridge delivers through the data layer's execution role (encryption 4.4, #102), the only sender; nothing may
# use the queue without TLS.
data "aws_iam_policy_document" "interruption_queue" {
  statement {
    sid       = "EventsDeliveryRoleSends"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.interruption.arn]

    principals {
      type        = "AWS"
      identifiers = [local.events_delivery_role_arn]
    }
  }

  statement {
    sid       = "DenyWithoutTls"
    effect    = "Deny"
    actions   = ["sqs:*"]
    resources = [aws_sqs_queue.interruption.arn]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_sqs_queue_policy" "interruption" {
  queue_url = aws_sqs_queue.interruption.id
  policy    = data.aws_iam_policy_document.interruption_queue.json
}

locals {
  interruption_rules = {
    health = {
      description = "AWS Health scheduled changes to EC2 instances, for Karpenter to drain the node first"
      pattern     = { source = ["aws.health"], "detail-type" = ["AWS Health Event"] }
    }
    state-change = {
      description = "EC2 instances stopping or terminating, for Karpenter to replace the node"
      pattern     = { source = ["aws.ec2"], "detail-type" = ["EC2 Instance State-change Notification"] }
    }
  }
}

# Named sft-*, so SCP 3 keeps them with the apply roles.
resource "aws_cloudwatch_event_rule" "interruption" {
  for_each = local.interruption_rules

  name          = "${var.name_prefix}-karpenter-${each.key}"
  description   = each.value.description
  event_pattern = jsonencode(each.value.pattern)

  tags = {
    component = "karpenter"
  }
}

resource "aws_cloudwatch_event_target" "interruption" {
  for_each = local.interruption_rules

  rule     = aws_cloudwatch_event_rule.interruption[each.key].name
  arn      = aws_sqs_queue.interruption.arn
  role_arn = local.events_delivery_role_arn
}

# ---------------------------------------------------------------------------------------------------------------------
# Node classes and node pools, as data for the cluster-bootstrap layer to apply (Karpenter v1 API). Terraform owns no
# Kubernetes object (ADR-0004); these are outputs, so the AWS-side values (security groups, instance profile, keys)
# never have to be copied into Git by hand.
# ---------------------------------------------------------------------------------------------------------------------

locals {
  pool_security_groups = {
    main = [var.security_group_ids["nodes"], var.security_group_ids["main_nodes"]]
    scan = [var.security_group_ids["nodes"], var.security_group_ids["scan_nodes"]]
  }

  # Scan nodes hold hostile files in clamd's and the DLP inspector's scratch, so their volumes use the files key; the
  # main pool's use the account's default, the platform key (encryption 3.1).
  pool_volume_keys = {
    main = null
    scan = data.aws_kms_alias.this["files"].target_key_arn
  }

  # Neither Bottlerocket host container runs on Karpenter's nodes: no shell and no Systems Manager agent, which only the
  # system nodes need for the tunnel (ADR-0021).
  pool_user_data = <<-EOT
    [settings.host-containers.admin]
    enabled = false

    [settings.host-containers.control]
    enabled = false
  EOT

  karpenter_node_classes = {
    for pool in ["main", "scan"] : pool => {
      apiVersion = "karpenter.k8s.aws/v1"
      kind       = "EC2NodeClass"
      metadata   = { name = pool }
      spec = {
        amiFamily                  = "Bottlerocket"
        amiSelectorTerms           = [{ alias = var.bottlerocket_ami_alias }]
        instanceProfile            = local.role_names.karpenter_node
        subnetSelectorTerms        = [{ tags = var.karpenter_discovery_tag }]
        securityGroupSelectorTerms = [for id in local.pool_security_groups[pool] : { id = id }]
        metadataOptions = {
          httpEndpoint            = "enabled"
          httpProtocolIPv6        = "disabled"
          httpPutResponseHopLimit = 1
          httpTokens              = "required"
        }
        blockDeviceMappings = [
          {
            deviceName = "/dev/xvda"
            ebs = merge(
              { volumeSize = "4Gi", volumeType = "gp3", encrypted = true, deleteOnTermination = true },
              local.pool_volume_keys[pool] == null ? {} : { kmsKeyID = local.pool_volume_keys[pool] },
            )
          },
          {
            deviceName = "/dev/xvdb"
            ebs = merge(
              {
                volumeSize          = "${var.node_pools[pool].volume_size_gib}Gi"
                volumeType          = "gp3"
                encrypted           = true
                deleteOnTermination = true
              },
              local.pool_volume_keys[pool] == null ? {} : { kmsKeyID = local.pool_volume_keys[pool] },
            )
          },
        ]
        userData = local.pool_user_data
        tags = {
          project     = "secure-file-transfer"
          environment = var.environment
          component   = "eks-${pool}-nodes"
          managed-by  = "karpenter"
        }
      }
    }
  }

  karpenter_node_pools = {
    for pool in ["main", "scan"] : pool => {
      apiVersion = "karpenter.sh/v1"
      kind       = "NodePool"
      metadata   = { name = pool }
      spec = {
        template = {
          metadata = { labels = { "sft.io/pool" = pool } }
          spec = merge(
            {
              nodeClassRef = { group = "karpenter.k8s.aws", kind = "EC2NodeClass", name = pool }
              requirements = [
                { key = "node.kubernetes.io/instance-type", operator = "In", values = var.node_pools[pool].instance_types },
                { key = "karpenter.sh/capacity-type", operator = "In", values = ["on-demand"] },
                { key = "kubernetes.io/arch", operator = "In", values = ["arm64"] },
                { key = "topology.k8s.aws/zone-id", operator = "In", values = var.availability_zone_ids },
              ]
              # Nodes are replaced on a schedule (T-52), and drift replaces them when the AMI or node class changes.
              expireAfter = var.node_pools[pool].expire_after
              # Long downloads resume after a deploy or a node replacement (abuse 5.7); an hour bounds the drain.
              terminationGracePeriod = "1h"
            },
            # Only scan pods tolerate this, so hostile files stay off the API's nodes (#22).
            pool == "scan" ? { taints = [{ key = "sft.io/pool", value = "scan", effect = "NoSchedule" }] } : {},
          )
        }
        disruption = {
          consolidationPolicy = "WhenEmptyOrUnderutilized"
          consolidateAfter    = var.node_pools[pool].consolidate_after
          budgets             = [{ nodes = "10%" }]
        }
        limits = { cpu = tostring(var.node_pools[pool].cpu_limit) }
      }
    }
  }
}
