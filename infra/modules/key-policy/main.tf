# The common part of a key policy for a key that a stack's deploy role creates (encryption 4.4): named principals
# only, never kms:* for the account root (rule 1). Creates nothing; the caller merges its own statements, the
# services and roles that use the key, through additional_policy_documents.
#
# - The deploy role that creates the key administers it, as SCP 2 allows deploy roles to (ADR-0006).
# - The plan role reads the key's metadata and policy, which a plan refreshes.
# - The account's key-admin role only reads and puts the policy, to repair one (rule 6).
# - BreakGlass recovers, it doesn't administer or use the key (table 4.3).
# - AWS Config's rules read the key's state (encryption 9.2).

locals {
  account_root = "arn:aws:iam::${var.account_id}:root"

  key_admin_actions = [
    "kms:DescribeKey", "kms:GetKeyPolicy", "kms:GetKeyRotationStatus", "kms:ListKeyRotations",
    "kms:ListResourceTags", "kms:ListGrants", "kms:ListKeyPolicies", "kms:PutKeyPolicy", "kms:UpdateKeyDescription",
    "kms:EnableKeyRotation", "kms:DisableKeyRotation", "kms:RotateKeyOnDemand", "kms:TagResource",
    "kms:UntagResource", "kms:CreateAlias", "kms:UpdateAlias", "kms:DeleteAlias", "kms:RevokeGrant", "kms:EnableKey",
    "kms:DisableKey", "kms:ScheduleKeyDeletion", "kms:CancelKeyDeletion", "kms:GetPublicKey",
  ]
}

data "aws_iam_policy_document" "this" {
  source_policy_documents = var.additional_policy_documents

  statement {
    sid       = "DeployRoleAdministersTheKey"
    actions   = local.key_admin_actions
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [var.deploy_role_arn]
    }
  }

  # Replicas only in Osaka (rule 4).
  statement {
    sid       = "DeployRoleReplicatesToOsakaOnly"
    actions   = ["kms:ReplicateKey"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [var.deploy_role_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:ReplicaRegion"
      values   = ["ap-northeast-3"]
    }
  }

  statement {
    sid = "PlanRoleReadsTheKey"
    actions = [
      "kms:DescribeKey", "kms:GetKeyPolicy", "kms:GetKeyRotationStatus", "kms:ListKeyRotations",
      "kms:ListResourceTags", "kms:GetPublicKey",
    ]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [var.plan_role_arn]
    }
  }

  # Matched through the account principal, not named: KMS refuses a policy that names a role that doesn't exist yet.
  statement {
    sid       = "AwsConfigReadsKeyState"
    actions   = ["kms:DescribeKey", "kms:GetKeyRotationStatus"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [local.account_root]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:PrincipalArn"
      values   = ["arn:aws:iam::${var.account_id}:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig"]
    }
  }

  statement {
    sid       = "KeyAdminRepairsThePolicy"
    actions   = ["kms:GetKeyPolicy", "kms:PutKeyPolicy"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [var.key_admin_role_arn]
    }
  }

  statement {
    sid = "BreakGlassRecovers"
    actions = [
      "kms:DescribeKey", "kms:GetKeyPolicy", "kms:GetKeyRotationStatus", "kms:ListResourceTags", "kms:ListGrants",
      "kms:RevokeGrant", "kms:EnableKey", "kms:CancelKeyDeletion",
    ]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [local.account_root]
    }

    condition {
      test     = "ArnLike"
      variable = "aws:PrincipalArn"
      values   = var.break_glass_principal_arn_patterns
    }
  }
}
