# The retained stack's own deploy role (encryption 8.4, ADR-0006, #263): sft-prod-retained-terraform-deploy under
# /sft-bootstrap/. The key policies, the bucket policies and SCP 5 already name it; this makes it, so the stack can be
# applied, and its key administered, after prod's own deploy role is gone with prod's bootstrap stack.
#
# - Its trust is GitHub's OIDC provider with one subject: the `prod-retained` environment of this repository, which
#   accepts deployments from main only (a maintainer step in the repository settings, like the other environments'
#   rule in step 0 of docs/runbooks/organization-and-bootstrap.md). No pull request can obtain it.
# - It is made by the stack's first apply, which runs as Admin from local state (ADR-0005). SCP 4 keeps everything
#   under /sft-bootstrap/ with Admin, so this role can never change itself; a change to it is an Admin apply.
# - It may do exactly what this stack's resources need: the audit key and its alias in both Regions, the archive,
#   state and trail buckets, its two service roles, the alert topics and rules, the trail and the budget.
#
# The OIDC provider is prod's bootstrap stack's while prod runs. A final teardown destroys that stack, so the teardown
# apply adopts the provider here (the import below), and ops/teardown.sh removes it from the bootstrap stack's state
# before destroying it (docs/runbooks/teardown.md). The trust names the provider by its ARN, which never changes.

locals {
  oidc_host         = "token.actions.githubusercontent.com"
  oidc_provider_arn = "arn:aws:iam::${var.account_id}:oidc-provider/${local.oidc_host}"
  retained_role_arn = "arn:aws:iam::${var.account_id}:role/"

  # This stack's service roles (archive.tf, alerts.tf), at path /.
  retained_service_roles = [local.retained_replication, local.retained_events_delivery]

  retained_regions = [module.conventions.region, "ap-northeast-3"]
}

import {
  for_each = var.teardown ? toset(["github"]) : toset([])

  to = aws_iam_openid_connect_provider.github[each.key]
  id = local.oidc_provider_arn
}

# Only from the teardown apply on, adopted from prod's bootstrap stack (above).
resource "aws_iam_openid_connect_provider" "github" {
  for_each = var.teardown ? toset(["github"]) : toset([])

  url            = "https://${local.oidc_host}"
  client_id_list = ["sts.amazonaws.com"]
}

data "aws_iam_policy_document" "deploy_trust" {
  statement {
    sid     = "TheRetainedEnvironmentOfThisRepository"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [local.oidc_provider_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.oidc_host}:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.oidc_host}:sub"
      values   = ["repo:${module.conventions.github_repository}:environment:prod-retained"]
    }
  }
}

resource "aws_iam_role" "deploy" {
  name                 = "sft-prod-retained-terraform-deploy"
  path                 = module.conventions.bootstrap_iam_path
  description          = "Terraform applies of the retained stack (encryption 8.4), from the prod-retained environment of ${module.conventions.github_repository}."
  assume_role_policy   = data.aws_iam_policy_document.deploy_trust.json
  max_session_duration = 3600

  tags = { component = "retained" }

  lifecycle {
    precondition {
      condition     = "arn:aws:iam::${var.account_id}:role${module.conventions.bootstrap_iam_path}sft-prod-retained-terraform-deploy" == local.retained_deploy_role_arn
      error_message = "The role must be the one the key and bucket policies and SCP 5 name."
    }
  }
}

data "aws_iam_policy_document" "deploy" {
  # Its own state, under the audit key (state.tf).
  statement {
    sid       = "State"
    actions   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket"]
    resources = [local.state_bucket_arn, "${local.state_bucket_arn}/*"]
  }

  # The audit key and its replica: the key policy then decides, and lets this role administer, never encrypt, and use
  # the key only for its own state through S3 (modules/kms-keys).
  statement {
    sid = "AuditKey"
    actions = [
      "kms:CreateKey", "kms:ListAliases", "kms:ListKeys", "kms:DescribeKey", "kms:GetKeyPolicy",
      "kms:GetKeyRotationStatus", "kms:ListKeyRotations", "kms:ListResourceTags", "kms:PutKeyPolicy",
      "kms:EnableKeyRotation", "kms:DisableKeyRotation", "kms:UpdateKeyDescription", "kms:TagResource",
      "kms:UntagResource", "kms:ReplicateKey", "kms:CreateAlias", "kms:UpdateAlias", "kms:DeleteAlias",
      "kms:ScheduleKeyDeletion", "kms:CancelKeyDeletion", "kms:GenerateDataKey", "kms:Decrypt",
    ]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:RequestedRegion"
      values   = local.retained_regions
    }
  }

  # The archive, state and trail buckets in both Regions: their settings, never an archive object.
  statement {
    sid = "RetainedBuckets"
    actions = [
      "s3:CreateBucket", "s3:GetBucket*", "s3:GetEncryptionConfiguration", "s3:GetLifecycleConfiguration",
      "s3:GetReplicationConfiguration", "s3:GetAccelerateConfiguration", "s3:GetAnalyticsConfiguration",
      "s3:GetIntelligentTieringConfiguration", "s3:GetInventoryConfiguration", "s3:GetMetricsConfiguration",
      "s3:GetObjectLockConfiguration", "s3:ListBucket", "s3:PutBucketObjectLockConfiguration",
      "s3:PutBucketOwnershipControls", "s3:PutBucketPolicy", "s3:PutBucketPublicAccessBlock", "s3:PutBucketTagging",
      "s3:PutBucketVersioning", "s3:PutEncryptionConfiguration", "s3:PutLifecycleConfiguration",
      "s3:PutReplicationConfiguration",
    ]
    resources = [
      for name in [
        "${module.conventions.global_name_prefix}-*-audit-archive-${var.account_id}",
        "${module.conventions.global_name_prefix}-*-retained-*-${var.account_id}",
      ] : "arn:aws:s3:::${name}"
    ]
  }

  # Its service roles: the archive's replication role and the alerts' delivery role, never another.
  statement {
    sid = "ServiceRoles"
    actions = [
      "iam:CreateRole", "iam:DeleteRole", "iam:GetRole", "iam:GetRolePolicy", "iam:ListAttachedRolePolicies",
      "iam:ListInstanceProfilesForRole", "iam:ListRolePolicies", "iam:PutRolePolicy", "iam:DeleteRolePolicy",
      "iam:TagRole", "iam:UntagRole", "iam:UpdateAssumeRolePolicy", "iam:UpdateRoleDescription",
    ]
    resources = [for role in local.retained_service_roles : "${local.retained_role_arn}${role}"]
  }

  dynamic "statement" {
    for_each = {
      PassReplicationRoleToS3 = { role = local.retained_replication, service = "s3.amazonaws.com" }
      PassDeliveryRoleToRules = { role = local.retained_events_delivery, service = "events.amazonaws.com" }
    }

    content {
      sid       = statement.key
      actions   = ["iam:PassRole"]
      resources = ["${local.retained_role_arn}${statement.value.role}"]

      condition {
        test     = "StringEquals"
        variable = "iam:PassedToService"
        values   = [statement.value.service]
      }
    }
  }

  # Reading itself and the OIDC provider for plans; SCP 4 denies any change to either.
  statement {
    sid       = "ReadOwnRoleAndProvider"
    actions   = ["iam:GetRole", "iam:ListRolePolicies", "iam:GetRolePolicy", "iam:GetOpenIDConnectProvider"]
    resources = [aws_iam_role.deploy.arn, local.oidc_provider_arn]
  }

  # The alert topics, their subscriptions and the rules (alerts.tf), in both Regions.
  statement {
    sid = "AlertTopics"
    actions = [
      "sns:CreateTopic", "sns:DeleteTopic", "sns:GetTopicAttributes", "sns:SetTopicAttributes", "sns:TagResource",
      "sns:UntagResource", "sns:ListTagsForResource", "sns:Subscribe", "sns:Unsubscribe",
      "sns:GetSubscriptionAttributes", "sns:ListSubscriptionsByTopic",
    ]
    resources = [for r in local.retained_regions : "arn:aws:sns:${r}:${var.account_id}:${module.conventions.global_name_prefix}-*-retained-alerts"]
  }

  statement {
    sid = "AlertRules"
    actions = [
      "events:DeleteRule", "events:DescribeRule", "events:DisableRule", "events:EnableRule", "events:ListTagsForResource",
      "events:ListTargetsByRule", "events:PutRule", "events:PutTargets", "events:RemoveTargets", "events:TagResource",
      "events:UntagResource",
    ]
    resources = [for r in local.retained_regions : "arn:aws:events:${r}:${var.account_id}:rule/${module.conventions.global_name_prefix}-*-retained-*"]
  }

  # The trail (trail.tf).
  statement {
    sid = "Trail"
    actions = [
      "cloudtrail:AddTags", "cloudtrail:CreateTrail", "cloudtrail:DeleteTrail", "cloudtrail:DescribeTrails",
      "cloudtrail:GetEventSelectors", "cloudtrail:GetInsightSelectors", "cloudtrail:GetTrailStatus",
      "cloudtrail:ListTags", "cloudtrail:PutEventSelectors", "cloudtrail:RemoveTags", "cloudtrail:StartLogging",
      "cloudtrail:StopLogging", "cloudtrail:UpdateTrail",
    ]
    resources = [local.trail_arn]
  }

  # The NFR-19 budget (budget.tf). Budgets are global.
  statement {
    sid       = "Budget"
    actions   = ["budgets:ModifyBudget", "budgets:ViewBudget", "budgets:ListTagsForResource", "budgets:TagResource"]
    resources = ["arn:aws:budgets::${var.account_id}:budget/${module.conventions.global_name_prefix}-retained-budget"]
  }

  statement {
    sid       = "DescribeRegions"
    actions   = ["ec2:DescribeRegions", "ec2:DescribeAvailabilityZones", "sts:GetCallerIdentity"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "deploy" {
  name   = "retained-stack"
  role   = aws_iam_role.deploy.id
  policy = data.aws_iam_policy_document.deploy.json
}
