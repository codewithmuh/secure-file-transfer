# ---------------------------------------------------------------------------------------------------------------------
# Cluster layer (#103): what the cluster stacks (modules/eks-cluster) need, in the Regions of var.network_regions:
# every environment Region with a network has a cluster (ADR-0004). The plan role reads; the deploy role also creates,
# changes and deletes. Like everything in this module, it changes only through an Admin apply of the account's
# bootstrap stack (SCP 4).
#
# Managed policies under /sft-bootstrap/, not inline ones: the roles' inline policies share IAM's 10,240-character
# limit (infra/README.md, "Layer permissions"), and SCP 4 already keeps policies under this path with Admin.
#
# The cluster layer creates IAM roles, which is how a deploy role could widen its own reach. Three things stop that:
# it may create and change only the roles the cluster layer names (sft-<env>-<workload>, path /); every one of them must
# carry the workload permissions boundary below, which allows no IAM change, no sts:AssumeRole except into the two
# External Secrets store roles (themselves under the boundary), and only the services the workloads use; and it may
# attach only the AWS managed policies the module uses.
# ---------------------------------------------------------------------------------------------------------------------

locals {
  cluster_enabled = length(var.network_regions) > 0

  # sft-<env>, from the plan role's name (the conventions module's bootstrap_role_names).
  cluster_env_prefix = trimsuffix(var.plan_role_name, "-terraform-plan")

  # The roles modules/eks-cluster creates, by name (its locals.role_names).
  cluster_role_names = [
    for r in [
      "eks-cluster", "system-node", "karpenter-node", "karpenter", "vpc-cni", "ebs-csi", "lb-controller",
      "external-secrets", "kyverno", "api", "relay", "scan", "notify", "jobs", "archive", "migrate", "operator",
      "external-secrets-platform", "external-secrets-app",
    ] : "${local.cluster_env_prefix}-${r}"
  ]
  cluster_role_arns = [for n in local.cluster_role_names : "arn:aws:iam::${var.account_id}:role/${n}"]

  cluster_boundary_name = "${local.cluster_env_prefix}-workload-boundary"
  cluster_boundary_arn  = "arn:aws:iam::${var.account_id}:policy${var.iam_path}${local.cluster_boundary_name}"

  # The External Secrets stores' roles: the one thing a cluster-layer role may assume (encryption 6.4).
  cluster_secret_store_role_arns = [
    for r in ["external-secrets-platform", "external-secrets-app"] : "arn:aws:iam::${var.account_id}:role/${local.cluster_env_prefix}-${r}"
  ]

  cluster_managed_policy_arns = [
    "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy",
    "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
    "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
    "arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy",
  ]

  cluster_eks_arns = flatten([
    for r in var.network_regions : [
      "arn:aws:eks:${r}:${var.account_id}:cluster/${local.cluster_env_prefix}-*",
      "arn:aws:eks:${r}:${var.account_id}:nodegroup/${local.cluster_env_prefix}-*/*/*",
      "arn:aws:eks:${r}:${var.account_id}:addon/${local.cluster_env_prefix}-*/*/*",
      "arn:aws:eks:${r}:${var.account_id}:access-entry/${local.cluster_env_prefix}-*/*",
      "arn:aws:eks:${r}:${var.account_id}:podidentityassociation/${local.cluster_env_prefix}-*/*",
    ]
  ])
  cluster_eks_access_policy_arns = ["arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"]

  cluster_queue_arns     = [for r in var.network_regions : "arn:aws:sqs:${r}:${var.account_id}:${local.cluster_env_prefix}-*-karpenter-interruption"]
  cluster_rule_arns      = [for r in var.network_regions : "arn:aws:events:${r}:${var.account_id}:rule/${local.cluster_env_prefix}-*-karpenter-*"]
  cluster_log_group_arns = [for r in var.network_regions : "arn:aws:logs:${r}:${var.account_id}:log-group:/aws/eks/${local.cluster_env_prefix}-*"]
  cluster_document_arns  = [for r in var.network_regions : "arn:aws:ssm:${r}:${var.account_id}:document/${local.cluster_env_prefix}-*-cluster-tunnel"]
  cluster_launch_templates = [
    for r in var.network_regions : "arn:aws:ec2:${r}:${var.account_id}:launch-template/*"
  ]
}

# ---------------------------------------------------------------------------------------------------------------------
# Read: plan and deploy
# ---------------------------------------------------------------------------------------------------------------------

data "aws_iam_policy_document" "cluster_read" {
  count = local.cluster_enabled ? 1 : 0

  statement {
    sid = "ClusterDescribe"
    actions = [
      "eks:DescribeAccessEntry", "eks:DescribeAddon", "eks:DescribeAddonConfiguration", "eks:DescribeAddonVersions",
      "eks:DescribeCluster", "eks:DescribeNodegroup", "eks:DescribePodIdentityAssociation", "eks:DescribeUpdate",
      "eks:ListAccessEntries", "eks:ListAccessPolicies", "eks:ListAddons", "eks:ListAssociatedAccessPolicies",
      "eks:ListClusters", "eks:ListNodegroups", "eks:ListPodIdentityAssociations", "eks:ListTagsForResource",
      "eks:ListUpdates",
      "ec2:DescribeLaunchTemplates", "ec2:DescribeLaunchTemplateVersions",
      "kms:ListAliases",
      "logs:DescribeLogGroups",
      "ssm:DescribeDocument", "ssm:DescribeDocumentPermission", "ssm:GetDocument", "ssm:ListTagsForResource",
      "sqs:GetQueueAttributes", "sqs:GetQueueUrl", "sqs:ListQueueTags",
      "events:DescribeRule", "events:ListTagsForResource", "events:ListTargetsByRule",
    ]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:RequestedRegion"
      values   = var.network_regions
    }
  }

  statement {
    sid       = "LogGroupTags"
    actions   = ["logs:ListTagsForResource", "logs:ListTagsLogGroup"]
    resources = local.cluster_log_group_arns
  }

  # The cluster layer's roles and instance profile, and the Identity Center roles that access entries name.
  statement {
    sid = "IamRead"
    actions = [
      "iam:GetInstanceProfile", "iam:GetPolicy", "iam:GetPolicyVersion", "iam:GetRole", "iam:GetRolePolicy",
      "iam:ListAttachedRolePolicies", "iam:ListInstanceProfilesForRole", "iam:ListRolePolicies", "iam:ListRoles",
    ]
    resources = ["*"]
  }
}

# ---------------------------------------------------------------------------------------------------------------------
# Deploy: EKS and its supporting resources
# ---------------------------------------------------------------------------------------------------------------------

data "aws_iam_policy_document" "cluster_deploy" {
  count = local.cluster_enabled ? 1 : 0

  statement {
    sid = "EksWrite"
    actions = [
      "eks:AssociateAccessPolicy", "eks:AssociateEncryptionConfig", "eks:CreateAccessEntry", "eks:CreateAddon",
      "eks:CreateCluster", "eks:CreateNodegroup", "eks:CreatePodIdentityAssociation", "eks:DeleteAccessEntry",
      "eks:DeleteAddon", "eks:DeleteCluster", "eks:DeleteNodegroup", "eks:DeletePodIdentityAssociation",
      "eks:DisassociateAccessPolicy", "eks:TagResource", "eks:UntagResource", "eks:UpdateAccessEntry",
      "eks:UpdateAddon", "eks:UpdateClusterConfig", "eks:UpdateClusterVersion", "eks:UpdateNodegroupConfig",
      "eks:UpdateNodegroupVersion", "eks:UpdatePodIdentityAssociation",
    ]
    resources = concat(local.cluster_eks_arns, local.cluster_eks_access_policy_arns)
  }

  # The cluster's API stays private: no request may turn public access on (ADR-0021). EKS added this condition key
  # in April 2026; an SCP could hold the same line for every principal.
  statement {
    sid       = "NeverAPublicEndpoint"
    effect    = "Deny"
    actions   = ["eks:CreateCluster", "eks:UpdateClusterConfig"]
    resources = ["*"]

    condition {
      test     = "Bool"
      variable = "eks:endpointPublicAccess"
      values   = ["true"]
    }
  }

  # CreateCluster with envelope encryption creates EKS's grant on the secrets key as the caller (#102).
  statement {
    sid       = "SecretsKeyGrantThroughEks"
    actions   = ["kms:CreateGrant", "kms:DescribeKey"]
    resources = [for r in var.network_regions : "arn:aws:kms:${r}:${var.account_id}:key/*"]

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = [for r in var.network_regions : "eks.${r}.amazonaws.com"]
    }
  }

  # The system node group's launch template. Deletes only of our own, by the provider's default tags.
  statement {
    sid       = "LaunchTemplates"
    actions   = ["ec2:CreateLaunchTemplate", "ec2:CreateLaunchTemplateVersion", "ec2:CreateTags", "ec2:ModifyLaunchTemplate"]
    resources = local.cluster_launch_templates
  }

  statement {
    sid       = "DeleteOwnLaunchTemplates"
    actions   = ["ec2:DeleteLaunchTemplate", "ec2:DeleteLaunchTemplateVersions"]
    resources = local.cluster_launch_templates

    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/managed-by"
      values   = ["terraform"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/project"
      values   = ["secure-file-transfer"]
    }
  }

  statement {
    sid = "InterruptionQueue"
    actions = [
      "sqs:CreateQueue", "sqs:DeleteQueue", "sqs:SetQueueAttributes", "sqs:TagQueue", "sqs:UntagQueue",
    ]
    resources = local.cluster_queue_arns
  }

  statement {
    sid = "InterruptionRules"
    actions = [
      "events:DeleteRule", "events:PutRule", "events:PutTargets", "events:RemoveTargets", "events:TagResource",
      "events:UntagResource",
    ]
    resources = local.cluster_rule_arns
  }

  statement {
    sid = "ControlPlaneLogGroups"
    actions = [
      "logs:AssociateKmsKey", "logs:CreateLogGroup", "logs:DeleteLogGroup", "logs:PutRetentionPolicy",
      "logs:TagResource", "logs:UntagResource",
    ]
    resources = local.cluster_log_group_arns
  }

  statement {
    sid = "TunnelDocument"
    actions = [
      "ssm:AddTagsToResource", "ssm:CreateDocument", "ssm:DeleteDocument", "ssm:RemoveTagsFromResource",
      "ssm:UpdateDocument", "ssm:UpdateDocumentDefaultVersion",
    ]
    resources = local.cluster_document_arns
  }
}

# ---------------------------------------------------------------------------------------------------------------------
# Deploy: IAM for the cluster layer's roles only, each with the workload boundary
# ---------------------------------------------------------------------------------------------------------------------

data "aws_iam_policy_document" "cluster_deploy_iam" {
  count = local.cluster_enabled ? 1 : 0

  statement {
    sid       = "CreateRolesWithBoundary"
    actions   = ["iam:CreateRole", "iam:PutRolePolicy", "iam:PutRolePermissionsBoundary"]
    resources = local.cluster_role_arns

    condition {
      test     = "StringEquals"
      variable = "iam:PermissionsBoundary"
      values   = [local.cluster_boundary_arn]
    }
  }

  statement {
    sid       = "AttachOnlyTheModulesManagedPolicies"
    actions   = ["iam:AttachRolePolicy", "iam:DetachRolePolicy"]
    resources = local.cluster_role_arns

    condition {
      test     = "ArnEquals"
      variable = "iam:PolicyARN"
      values   = local.cluster_managed_policy_arns
    }

    condition {
      test     = "StringEquals"
      variable = "iam:PermissionsBoundary"
      values   = [local.cluster_boundary_arn]
    }
  }

  # Changes that grant nothing new. The boundary can't be removed: no DeleteRolePermissionsBoundary.
  statement {
    sid = "ChangeAndDeleteOwnRoles"
    actions = [
      "iam:DeleteRole", "iam:DeleteRolePolicy", "iam:TagRole", "iam:UntagRole", "iam:UpdateAssumeRolePolicy",
      "iam:UpdateRole", "iam:UpdateRoleDescription",
    ]
    resources = local.cluster_role_arns
  }

  # The deploy role writes these roles' trust, so it could name itself there; an explicit deny here wins over any
  # trust policy, so it can never act as a workload (read files, decrypt names).
  statement {
    sid       = "NeverAssumeTheRolesItWrites"
    effect    = "Deny"
    actions   = ["sts:AssumeRole", "sts:TagSession"]
    resources = local.cluster_role_arns
  }

  statement {
    sid = "KarpenterNodeInstanceProfile"
    actions = [
      "iam:AddRoleToInstanceProfile", "iam:CreateInstanceProfile", "iam:DeleteInstanceProfile",
      "iam:RemoveRoleFromInstanceProfile", "iam:TagInstanceProfile", "iam:UntagInstanceProfile",
    ]
    resources = ["arn:aws:iam::${var.account_id}:instance-profile/${local.cluster_env_prefix}-karpenter-node"]
  }

  # The cluster and node roles to EKS, the workload roles to Pod Identity, the node role into its instance profile.
  statement {
    sid       = "PassRolesToEksAndEc2"
    actions   = ["iam:PassRole"]
    resources = local.cluster_role_arns

    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["eks.amazonaws.com", "pods.eks.amazonaws.com", "ec2.amazonaws.com"]
    }
  }

  # EventBridge targets deliver through the data layer's execution role (#102).
  statement {
    sid       = "PassEventsDeliveryRole"
    actions   = ["iam:PassRole"]
    resources = ["arn:aws:iam::${var.account_id}:role/${local.cluster_env_prefix}-events-delivery"]

    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["events.amazonaws.com"]
    }
  }

  statement {
    sid       = "ServiceLinkedRoles"
    actions   = ["iam:CreateServiceLinkedRole"]
    resources = ["arn:aws:iam::${var.account_id}:role/aws-service-role/*"]

    condition {
      test     = "StringEquals"
      variable = "iam:AWSServiceName"
      values   = ["eks.amazonaws.com", "eks-nodegroup.amazonaws.com", "autoscaling.amazonaws.com", "ec2fleet.amazonaws.com"]
    }
  }
}

# ---------------------------------------------------------------------------------------------------------------------
# The workload permissions boundary: the most any cluster-layer role may ever do, whatever its own policies say
# ---------------------------------------------------------------------------------------------------------------------

data "aws_iam_policy_document" "workload_boundary" {
  count = local.cluster_enabled ? 1 : 0

  # The services the cluster, its nodes, its controllers and its workloads use (architecture 3.1, ADR-0004), and
  # sns:Publish for the data layer's EventBridge delivery role, which carries this boundary too: no IAM change, no
  # sts:AssumeRole but into the secret stores' roles, no Organizations, CloudTrail, Config or GuardDuty.
  statement {
    sid = "WorkloadServices"
    actions = [
      "autoscaling:*", "cognito-idp:*", "ec2:*", "ec2messages:*", "ecr:*", "eks:*", "eks-auth:*",
      "elasticache:Connect", "elasticloadbalancing:*", "kms:*", "rds-db:connect", "secretsmanager:*", "ses:*",
      "sns:Publish", "sqs:*", "ssm:GetParameter", "ssm:UpdateInstanceInformation", "ssmmessages:*",
      # S3 by action: only the object and listing calls the workloads make (architecture 3.1), never a bucket
      # setting, policy or ACL.
      "s3:AbortMultipartUpload", "s3:DeleteObject", "s3:DeleteObjectVersion", "s3:GetObject",
      "s3:GetObjectAttributes", "s3:GetObjectTagging", "s3:GetObjectVersion", "s3:GetObjectVersionAttributes",
      "s3:GetObjectVersionTagging", "s3:ListBucket", "s3:ListBucketMultipartUploads", "s3:ListBucketVersions",
      "s3:ListMultipartUploadParts", "s3:PutObject", "s3:PutObjectTagging", "s3:PutObjectVersionTagging",
    ]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:RequestedRegion"
      values   = var.network_regions
    }
  }

  # IAM reads and passes the cluster layer needs: the EKS cluster policy's describe calls and service-linked roles,
  # and Karpenter passing its node role.
  statement {
    sid = "IamReadsAndPasses"
    actions = [
      "iam:CreateServiceLinkedRole", "iam:GetInstanceProfile", "iam:GetRole", "iam:ListAttachedRolePolicies",
      "iam:ListInstanceProfiles", "iam:PassRole",
    ]
    resources = concat(
      ["arn:aws:iam::${var.account_id}:role/aws-service-role/*"],
      ["arn:aws:iam::${var.account_id}:role/${local.cluster_env_prefix}-karpenter-node"],
      ["arn:aws:iam::${var.account_id}:instance-profile/${local.cluster_env_prefix}-karpenter-node"],
    )
  }

  # External Secrets assumes its stores' roles, each of which reads only its own secrets (encryption 6.4). Each store
  # role trusts only the controller's role, and only the controller's own policy asks for this.
  statement {
    sid       = "AssumeOnlySecretStoreRoles"
    actions   = ["sts:AssumeRole"]
    resources = local.cluster_secret_store_role_arns
  }

  statement {
    sid           = "NeverAssumeAnyOtherRole"
    effect        = "Deny"
    actions       = ["sts:AssumeRole"]
    not_resources = local.cluster_secret_store_role_arns
  }

  # Changing IAM is not something any workload does, even if a policy above ever allowed it.
  statement {
    sid       = "NeverChangeIam"
    effect    = "Deny"
    actions   = ["iam:Add*", "iam:Attach*", "iam:Create*", "iam:Delete*", "iam:Detach*", "iam:Put*", "iam:Remove*", "iam:Set*", "iam:Tag*", "iam:Untag*", "iam:Update*"]
    resources = ["*"]

    condition {
      test     = "StringNotEquals"
      variable = "iam:AWSServiceName"
      values   = ["elasticloadbalancing.amazonaws.com", "autoscaling.amazonaws.com", "eks.amazonaws.com", "eks-nodegroup.amazonaws.com", "ec2fleet.amazonaws.com"]
    }
  }
}

resource "aws_iam_policy" "workload_boundary" {
  count = local.cluster_enabled ? 1 : 0

  name        = local.cluster_boundary_name
  path        = var.iam_path
  description = "Permissions boundary of every cluster-layer role (#103): workload services only, never an IAM change."
  policy      = data.aws_iam_policy_document.workload_boundary[0].json
}

resource "aws_iam_policy" "cluster_read" {
  count = local.cluster_enabled ? 1 : 0

  name        = "${local.cluster_env_prefix}-terraform-cluster-read"
  path        = var.iam_path
  description = "Terraform plan and deploy: read the cluster layer (#103)."
  policy      = data.aws_iam_policy_document.cluster_read[0].json
}

resource "aws_iam_policy" "cluster_deploy" {
  count = local.cluster_enabled && var.github_environment != null ? 1 : 0

  name        = "${local.cluster_env_prefix}-terraform-cluster-deploy"
  path        = var.iam_path
  description = "Terraform deploy: build the cluster layer's EKS, queue, rules, log group and tunnel document (#103)."
  policy      = data.aws_iam_policy_document.cluster_deploy[0].json
}

resource "aws_iam_policy" "cluster_deploy_iam" {
  count = local.cluster_enabled && var.github_environment != null ? 1 : 0

  name        = "${local.cluster_env_prefix}-terraform-cluster-deploy-iam"
  path        = var.iam_path
  description = "Terraform deploy: the cluster layer's roles, only with the workload boundary (#103)."
  policy      = data.aws_iam_policy_document.cluster_deploy_iam[0].json
}

resource "aws_iam_role_policy_attachment" "plan_cluster_read" {
  count = local.cluster_enabled ? 1 : 0

  role       = aws_iam_role.plan.name
  policy_arn = aws_iam_policy.cluster_read[0].arn
}

resource "aws_iam_role_policy_attachment" "deploy_cluster" {
  for_each = local.cluster_enabled && var.github_environment != null ? {
    read   = aws_iam_policy.cluster_read[0].arn
    deploy = aws_iam_policy.cluster_deploy[0].arn
    iam    = aws_iam_policy.cluster_deploy_iam[0].arn
  } : {}

  role       = aws_iam_role.deploy[0].name
  policy_arn = each.value
}
