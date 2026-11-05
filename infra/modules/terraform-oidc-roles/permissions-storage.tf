# ---------------------------------------------------------------------------------------------------------------------
# Storage and keys in the data layer (#102): the KMS keys (modules/kms-keys), the files buckets and GuardDuty Malware
# Protection (modules/files-buckets), the audit archive in dev and staging (modules/audit-archive) and EventBridge's
# delivery role (modules/events-delivery-role), in the Regions of var.network_regions: the data layer lives wherever
# the network does. The plan role reads; the deploy role also creates, changes and deletes. Like everything in this
# module, it changes only through an Admin apply of the account's bootstrap stack (SCP 4).
#
# Managed policies under /sft-bootstrap/, which SCP 4 already keeps with Admin, because the inline policies' 10,240
# characters per role can't hold every layer (infra/README.md, "Layer permissions"). Each managed policy holds at most
# 6,144, so the deploy role's are split in two.
#
# Scoped by name: buckets sft-<env>-apne?-{files,large-files,audit-archive}-<account>, keys and aliases in our Regions
# (each key policy then decides what the role may do to that key), the three roles these modules make, GuardDuty
# plans and EventBridge rules sft-<env>-*, and the account's EBS default encryption. The prod deploy role gets nothing
# on the audit archive, which is the retained stack's (SCP 5 denies it anyway), and no object deletes, which only the
# lifecycle jobs do there (ADR-0012).
# ---------------------------------------------------------------------------------------------------------------------

locals {
  storage_enabled  = local.network_enabled && var.github_environment != null
  storage_env      = coalesce(var.github_environment, "none")
  storage_teardown = local.storage_env != "prod"

  storage_region_shorts = [
    for r in var.network_regions : { "ap-northeast-1" = "apne1", "ap-northeast-3" = "apne3" }[r]
  ]

  storage_bucket_arns = flatten([
    for rs in local.storage_region_shorts : [
      for kind in concat(["files", "large-files"], local.storage_teardown ? ["audit-archive"] : []) :
      "arn:aws:s3:::sft-${local.storage_env}-${rs}-${kind}-${var.account_id}"
    ]
  ])

  storage_key_arns   = [for r in var.network_regions : "arn:aws:kms:${r}:${var.account_id}:key/*"]
  storage_alias_arns = [for r in var.network_regions : "arn:aws:kms:${r}:${var.account_id}:alias/sft/${local.storage_env}/*"]

  storage_role_arns = {
    for name in ["s3-replication", "malware-protection", "events-delivery"] :
    name => "arn:aws:iam::${var.account_id}:role/sft-${local.storage_env}-${name}"
  }

  # The service-linked roles the data stack creates for EBS volumes under the platform and files keys (4.4).
  storage_volume_service_roles = {
    "autoscaling.amazonaws.com" = "arn:aws:iam::${var.account_id}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
    "ec2fleet.amazonaws.com"    = "arn:aws:iam::${var.account_id}:role/aws-service-role/ec2fleet.amazonaws.com/AWSServiceRoleForEC2Fleet"
  }

  storage_plan_arns = [for r in var.network_regions : "arn:aws:guardduty:${r}:${var.account_id}:malware-protection-plan/*"]
  storage_rule_arns = [for r in var.network_regions : "arn:aws:events:${r}:${var.account_id}:rule/sft-${local.storage_env}-*"]
}

data "aws_iam_policy_document" "storage_read" {
  count = local.storage_enabled ? 1 : 0

  statement {
    sid = "ListKeysAndPlans"
    actions = [
      "kms:ListAliases", "kms:ListKeys", "guardduty:ListMalwareProtectionPlans",
      "ec2:GetEbsDefaultKmsKeyId", "ec2:GetEbsEncryptionByDefault",
    ]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:RequestedRegion"
      values   = var.network_regions
    }
  }

  # The key policies also let the plan role read the key (modules/kms-keys, PlanRoleReadsKeyState).
  statement {
    sid = "ReadKeys"
    actions = [
      "kms:DescribeKey", "kms:GetKeyPolicy", "kms:GetKeyRotationStatus", "kms:ListKeyRotations",
      "kms:ListResourceTags",
    ]
    resources = local.storage_key_arns
  }

  # What a refresh of the buckets reads. ListBucket is what HeadBucket needs; it lists object keys, which hold only
  # IDs (architecture 5.1), never object contents.
  statement {
    sid = "ReadBucketSettings"
    actions = [
      "s3:GetAccelerateConfiguration", "s3:GetBucketAcl", "s3:GetBucketCORS", "s3:GetBucketLocation",
      "s3:GetBucketLogging", "s3:GetBucketObjectLockConfiguration", "s3:GetBucketOwnershipControls",
      "s3:GetBucketPolicy", "s3:GetBucketPublicAccessBlock", "s3:GetBucketRequestPayment", "s3:GetBucketTagging",
      "s3:GetBucketVersioning", "s3:GetBucketWebsite", "s3:GetEncryptionConfiguration",
      "s3:GetLifecycleConfiguration", "s3:GetReplicationConfiguration", "s3:ListBucket",
    ]
    resources = local.storage_bucket_arns
  }

  statement {
    sid = "ReadStorageRoles"
    actions = [
      "iam:GetRole", "iam:GetRolePolicy", "iam:ListAttachedRolePolicies", "iam:ListRolePolicies",
    ]
    resources = concat(values(local.storage_role_arns), values(local.storage_volume_service_roles))
  }

  statement {
    sid       = "ReadMalwareProtectionPlans"
    actions   = ["guardduty:GetMalwareProtectionPlan", "guardduty:ListTagsForResource"]
    resources = local.storage_plan_arns
  }

  statement {
    sid       = "ReadRules"
    actions   = ["events:DescribeRule", "events:ListTagsForResource", "events:ListTargetsByRule"]
    resources = local.storage_rule_arns
  }
}

data "aws_iam_policy_document" "storage_kms" {
  count = local.storage_enabled ? 1 : 0

  statement {
    sid       = "CreateMultiRegionKeys"
    actions   = ["kms:CreateKey"]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:RequestedRegion"
      values   = var.network_regions
    }

    condition {
      test     = "Bool"
      variable = "kms:MultiRegion"
      values   = ["true"]
    }
  }

  # The administer actions of encryption 4.3. Each key policy repeats the rules: who else may, the deletion wait.
  statement {
    sid = "AdministerKeys"
    actions = [
      "kms:CancelKeyDeletion", "kms:DisableKey", "kms:DisableKeyRotation", "kms:EnableKey", "kms:EnableKeyRotation",
      "kms:ListGrants", "kms:PutKeyPolicy", "kms:RevokeGrant", "kms:RotateKeyOnDemand", "kms:ScheduleKeyDeletion",
      "kms:TagResource", "kms:UntagResource", "kms:UpdateKeyDescription",
    ]
    resources = local.storage_key_arns
  }

  statement {
    sid       = "ReplicateToOsakaOnly"
    actions   = ["kms:ReplicateKey"]
    resources = local.storage_key_arns

    condition {
      test     = "StringEquals"
      variable = "kms:ReplicaRegion"
      values   = ["ap-northeast-3"]
    }
  }

  statement {
    sid       = "ManageAliases"
    actions   = ["kms:CreateAlias", "kms:DeleteAlias", "kms:UpdateAlias"]
    resources = concat(local.storage_alias_arns, local.storage_key_arns)
  }

  # G in 4.3 for EKS: creating the cluster lets EKS use the secrets key for etcd through a grant (#103). The data
  # layer's own uses of the keys, grants through RDS and ElastiCache and the secrets it writes and reads back through
  # Secrets Manager, are in permissions-data.tf (UseKeysThroughDataServices); each key policy then narrows them.
  statement {
    sid       = "GrantsForEks"
    actions   = ["kms:CreateGrant"]
    resources = local.storage_key_arns

    condition {
      test     = "Bool"
      variable = "kms:GrantIsForAWSResource"
      values   = ["true"]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = [for r in var.network_regions : "eks.${r}.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "storage_write" {
  count = local.storage_enabled ? 1 : 0

  statement {
    sid = "ManageBuckets"
    actions = [
      "s3:CreateBucket", "s3:DeleteBucket", "s3:DeleteBucketPolicy", "s3:PutBucketCORS",
      "s3:PutBucketObjectLockConfiguration", "s3:PutBucketOwnershipControls", "s3:PutBucketPolicy",
      "s3:PutBucketPublicAccessBlock", "s3:PutBucketTagging", "s3:PutBucketVersioning", "s3:PutEncryptionConfiguration",
      "s3:PutLifecycleConfiguration", "s3:PutReplicationConfiguration",
    ]
    resources = local.storage_bucket_arns
  }

  # Teardown in dev and staging: empty the buckets, the archive's governance-mode records included (NFR-19).
  dynamic "statement" {
    for_each = local.storage_teardown ? [1] : []

    content {
      sid       = "EmptyBucketsAtTeardown"
      actions   = ["s3:BypassGovernanceRetention", "s3:DeleteObject", "s3:DeleteObjectVersion", "s3:ListBucketVersions"]
      resources = concat(local.storage_bucket_arns, [for b in local.storage_bucket_arns : "${b}/*"])
    }
  }

  statement {
    sid = "ManageStorageRoles"
    actions = [
      "iam:DeleteRole", "iam:DeleteRolePolicy", "iam:ListInstanceProfilesForRole", "iam:TagRole", "iam:UntagRole",
      "iam:UpdateAssumeRolePolicy", "iam:UpdateRole", "iam:UpdateRoleDescription",
    ]
    resources = values(local.storage_role_arns)
  }

  statement {
    sid       = "CreateServiceRoles"
    actions   = ["iam:CreateRole", "iam:PutRolePolicy"]
    resources = [local.storage_role_arns["s3-replication"], local.storage_role_arns["malware-protection"]]
  }

  # The EventBridge delivery role can be passed by the cluster layer too, so it carries the workload boundary
  # (permissions-cluster.tf) and is created or changed only with it. No DeleteRolePermissionsBoundary.
  statement {
    sid       = "CreateEventsDeliveryRoleWithBoundary"
    actions   = ["iam:CreateRole", "iam:PutRolePolicy", "iam:PutRolePermissionsBoundary"]
    resources = [local.storage_role_arns["events-delivery"]]

    condition {
      test     = "StringEquals"
      variable = "iam:PermissionsBoundary"
      values   = [local.cluster_boundary_arn]
    }
  }

  dynamic "statement" {
    for_each = {
      PassReplicationRoleToS3              = { role = "s3-replication", service = "s3.amazonaws.com" }
      PassMalwareProtectionRoleToGuardDuty = { role = "malware-protection", service = "malware-protection-plan.guardduty.amazonaws.com" }
      PassEventsDeliveryRoleToEventBridge  = { role = "events-delivery", service = "events.amazonaws.com" }
    }

    content {
      sid       = statement.key
      actions   = ["iam:PassRole"]
      resources = [local.storage_role_arns[statement.value.role]]

      condition {
        test     = "StringEquals"
        variable = "iam:PassedToService"
        values   = [statement.value.service]
      }
    }
  }

  # The volume service-linked roles: created before the keys whose policies name them, tagged by default_tags, and
  # deleted at teardown (AWS refuses while an Auto Scaling group or fleet still uses one).
  statement {
    sid       = "CreateVolumeServiceLinkedRoles"
    actions   = ["iam:CreateServiceLinkedRole"]
    resources = values(local.storage_volume_service_roles)

    condition {
      test     = "StringEquals"
      variable = "iam:AWSServiceName"
      values   = keys(local.storage_volume_service_roles)
    }
  }

  statement {
    sid = "ManageVolumeServiceLinkedRoles"
    actions = [
      "iam:DeleteServiceLinkedRole", "iam:GetServiceLinkedRoleDeletionStatus", "iam:TagRole", "iam:UntagRole",
      "iam:UpdateRoleDescription",
    ]
    resources = values(local.storage_volume_service_roles)
  }

  # The account's EBS encryption by default and its key, the platform key (encryption 3.1). These calls take no
  # resource. Turning it off is for teardown; SCP 3 lets only the apply roles do it.
  statement {
    sid = "EbsEncryptionByDefault"
    actions = [
      "ec2:DisableEbsEncryptionByDefault", "ec2:EnableEbsEncryptionByDefault", "ec2:ModifyEbsDefaultKmsKeyId",
      "ec2:ResetEbsDefaultKmsKeyId",
    ]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:RequestedRegion"
      values   = var.network_regions
    }
  }

  statement {
    sid = "ManageMalwareProtectionPlans"
    actions = [
      "guardduty:CreateMalwareProtectionPlan", "guardduty:DeleteMalwareProtectionPlan", "guardduty:TagResource",
      "guardduty:UntagResource", "guardduty:UpdateMalwareProtectionPlan",
    ]
    resources = local.storage_plan_arns
  }

  statement {
    sid = "ManageRules"
    actions = [
      "events:DeleteRule", "events:DisableRule", "events:EnableRule", "events:PutRule", "events:PutTargets",
      "events:RemoveTargets", "events:TagResource", "events:UntagResource",
    ]
    resources = local.storage_rule_arns
  }
}

resource "aws_iam_policy" "storage" {
  for_each = local.storage_enabled ? {
    read  = data.aws_iam_policy_document.storage_read[0].json
    kms   = data.aws_iam_policy_document.storage_kms[0].json
    write = data.aws_iam_policy_document.storage_write[0].json
  } : {}

  name        = "sft-${local.storage_env}-terraform-storage-${each.key}"
  path        = var.iam_path
  description = "Storage and keys of the data layer, ${each.key} (#102)."
  policy      = each.value
}

resource "aws_iam_role_policy_attachment" "plan_storage" {
  count = local.storage_enabled ? 1 : 0

  role       = aws_iam_role.plan.name
  policy_arn = aws_iam_policy.storage["read"].arn
}

resource "aws_iam_role_policy_attachment" "deploy_storage" {
  for_each = local.storage_enabled ? toset(["read", "kms", "write"]) : toset([])

  role       = aws_iam_role.deploy[0].name
  policy_arn = aws_iam_policy.storage[each.key].arn
}
