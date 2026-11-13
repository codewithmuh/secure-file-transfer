# ---------------------------------------------------------------------------------------------------------------------
# Shared stack (#105): what infra/shared needs in the shared account, when var.shared_stack is set: the registry
# (modules/registry), the zone and its environment roles (modules/dns-zone), the log archive with the organization
# trail (modules/log-archive), and the web app's bundle store with its publish role (modules/web-bundles, #283). Tokyo for everything, Osaka for the registry's replicas, us-east-1 for the
# DNSSEC key (the region guard's exception, ADR-0006). The plan role reads; the deploy role also writes.
#
# Managed policies under /sft-bootstrap/, as for the edge layer. The keys' policies, not these, give the deploy role
# the right to administer each key once it exists; these give it the right to create one. IAM is limited to roles
# under /sft-shared/, so the deploy role can never touch /sft-bootstrap/ (SCP 4 denies it too).
# ---------------------------------------------------------------------------------------------------------------------

locals {
  shared_regions = ["ap-northeast-1", "ap-northeast-3", "us-east-1"]

  shared_iam_role_arns = ["arn:aws:iam::${var.account_id}:role/sft-shared/*"]
  shared_bucket_arn    = "arn:aws:s3:::sft-shared-apne1-log-archive-${var.account_id}"
  shared_bundles_arn   = "arn:aws:s3:::sft-shared-apne1-web-bundles-${var.account_id}"
  shared_trail_arns    = ["arn:aws:cloudtrail:ap-northeast-1:*:trail/sft-organization"]
  shared_ecr_arns = [
    for region in ["ap-northeast-1", "ap-northeast-3"] : "arn:aws:ecr:${region}:${var.account_id}:*"
  ]
}

data "aws_iam_policy_document" "shared_read" {
  count = var.shared_stack ? 1 : 0

  statement {
    sid = "SharedRegionalRead"
    actions = [
      "cloudtrail:DescribeTrails",
      "cloudtrail:GetEventSelectors",
      "cloudtrail:GetInsightSelectors",
      "cloudtrail:GetTrail",
      "cloudtrail:GetTrailStatus",
      "cloudtrail:ListTags",
      "ecr:DescribeRegistry",
      "ecr:DescribeRepositories",
      "ecr:DescribeRepositoryCreationTemplates",
      "ecr:GetLifecyclePolicy",
      "ecr:GetRegistryPolicy",
      "ecr:GetRegistryScanningConfiguration",
      "ecr:GetRepositoryPolicy",
      "ecr:ListTagsForResource",
      "kms:DescribeKey",
      "kms:GetKeyPolicy",
      "kms:GetKeyRotationStatus",
      "kms:ListAliases",
      "kms:ListResourceTags",
    ]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:RequestedRegion"
      values   = local.shared_regions
    }
  }

  statement {
    sid = "SharedGlobalRead"
    actions = [
      "organizations:DescribeOrganization",
      "route53:GetChange",
      "route53:GetDNSSEC",
      "route53:GetHostedZone",
      "route53:ListHostedZones",
      "route53:ListHostedZonesByName",
      "route53:ListResourceRecordSets",
      "route53:ListTagsForResource",
    ]
    resources = ["*"]
  }

  statement {
    sid = "SharedRolesRead"
    actions = [
      "iam:GetRole",
      "iam:GetRolePolicy",
      "iam:ListAttachedRolePolicies",
      "iam:ListRolePolicies",
    ]
    resources = local.shared_iam_role_arns
  }

  statement {
    sid = "SharedBucketsRead"
    actions = [
      "s3:GetAccelerateConfiguration",
      "s3:GetBucket*",
      "s3:GetEncryptionConfiguration",
      "s3:GetLifecycleConfiguration",
      "s3:GetReplicationConfiguration",
      "s3:ListBucket", # HeadBucket, which every refresh of the bucket calls, needs it
    ]
    resources = [local.shared_bucket_arn, local.shared_bundles_arn]
  }
}

data "aws_iam_policy_document" "shared_write" {
  count = var.shared_stack ? 1 : 0

  statement {
    sid = "RegistryWrite"
    actions = [
      "ecr:CreateRepository",
      "ecr:DeleteLifecyclePolicy",
      "ecr:DeleteRepository",
      "ecr:DeleteRepositoryPolicy",
      "ecr:PutImageScanningConfiguration",
      "ecr:PutImageTagMutability",
      "ecr:PutLifecyclePolicy",
      "ecr:SetRepositoryPolicy",
      "ecr:TagResource",
      "ecr:UntagResource",
    ]
    resources = local.shared_ecr_arns
  }

  # Registry-level settings have no resource type in the Service Authorization Reference (ECR's actions table), so
  # they take "*", limited to the stack's Regions.
  statement {
    sid = "RegistrySettingsWrite"
    actions = [
      "ecr:CreateRepositoryCreationTemplate",
      "ecr:DeleteRepositoryCreationTemplate",
      "ecr:PutRegistryScanningConfiguration",
      "ecr:PutReplicationConfiguration",
      "ecr:UpdateRepositoryCreationTemplate",
    ]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:RequestedRegion"
      values   = local.shared_regions
    }
  }

  # Creating a key needs an identity permission; the key's own policy then names the deploy role as its
  # administrator (modules/key-policy). Aliases need both.
  statement {
    sid       = "CreateKeys"
    actions   = ["kms:CreateAlias", "kms:CreateKey", "kms:DeleteAlias", "kms:TagResource"]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:RequestedRegion"
      values   = local.shared_regions
    }
  }

  statement {
    sid = "ZoneWrite"
    actions = [
      "route53:ActivateKeySigningKey",
      "route53:ChangeResourceRecordSets",
      "route53:ChangeTagsForResource",
      "route53:CreateHostedZone",
      "route53:CreateKeySigningKey",
      "route53:DeactivateKeySigningKey",
      "route53:DeleteHostedZone",
      "route53:DeleteKeySigningKey",
      "route53:DisableHostedZoneDNSSEC",
      "route53:EnableHostedZoneDNSSEC",
      "route53:UpdateHostedZoneComment",
    ]
    resources = ["*"]
  }

  statement {
    sid = "SharedRolesWrite"
    actions = [
      "iam:CreateRole",
      "iam:DeleteRole",
      "iam:DeleteRolePolicy",
      "iam:PutRolePolicy",
      "iam:TagRole",
      "iam:UntagRole",
      "iam:UpdateAssumeRolePolicy",
      "iam:UpdateRole",
      "iam:UpdateRoleDescription",
    ]
    resources = local.shared_iam_role_arns
  }

  statement {
    sid = "SharedBucketsWrite"
    actions = [
      "s3:CreateBucket",
      "s3:PutBucket*",
      "s3:PutEncryptionConfiguration",
      "s3:PutLifecycleConfiguration",
    ]
    resources = [local.shared_bucket_arn, local.shared_bundles_arn]
  }

  # The bundle store, unlike the log archive, has no Object Lock: the shared stack's teardown empties and deletes it.
  statement {
    sid = "WebBundlesTeardown"
    actions = [
      "s3:DeleteBucket", "s3:DeleteBucketPolicy", "s3:DeleteObject", "s3:DeleteObjectVersion", "s3:ListBucketVersions",
    ]
    resources = [local.shared_bundles_arn, "${local.shared_bundles_arn}/*"]
  }

  # The organization trail, as CloudTrail's delegated administrator. The first one creates CloudTrail's
  # service-linked role.
  statement {
    sid = "OrganizationTrail"
    actions = [
      "cloudtrail:AddTags",
      "cloudtrail:CreateTrail",
      "cloudtrail:DeleteTrail",
      "cloudtrail:PutEventSelectors",
      "cloudtrail:RemoveTags",
      "cloudtrail:StartLogging",
      "cloudtrail:StopLogging",
      "cloudtrail:UpdateTrail",
    ]
    resources = local.shared_trail_arns
  }

  statement {
    sid = "OrganizationTrailChecks"
    actions = [
      "organizations:ListAWSServiceAccessForOrganization",
      "organizations:ListAccounts",
      "organizations:ListDelegatedAdministrators",
    ]
    resources = ["*"]
  }

  statement {
    sid       = "CloudTrailServiceLinkedRole"
    actions   = ["iam:CreateServiceLinkedRole", "iam:GetRole"]
    resources = ["arn:aws:iam::${var.account_id}:role/aws-service-role/cloudtrail.amazonaws.com/*"]

    condition {
      test     = "StringEqualsIfExists"
      variable = "iam:AWSServiceName"
      values   = ["cloudtrail.amazonaws.com"]
    }
  }
}

resource "aws_iam_policy" "shared_read" {
  count = var.shared_stack ? 1 : 0

  name        = "sft-shared-terraform-shared-read"
  path        = var.iam_path
  description = "Shared stack: read (#105)"
  policy      = data.aws_iam_policy_document.shared_read[0].json
}

resource "aws_iam_policy" "shared_write" {
  count = var.shared_stack && var.github_environment != null ? 1 : 0

  name        = "sft-shared-terraform-shared-write"
  path        = var.iam_path
  description = "Shared stack: create, change and delete (#105)"
  policy      = data.aws_iam_policy_document.shared_write[0].json
}

resource "aws_iam_role_policy_attachment" "plan_shared" {
  count = var.shared_stack ? 1 : 0

  role       = aws_iam_role.plan.name
  policy_arn = aws_iam_policy.shared_read[0].arn
}

resource "aws_iam_role_policy_attachment" "deploy_shared" {
  for_each = var.shared_stack && var.github_environment != null ? {
    read  = aws_iam_policy.shared_read[0].arn
    write = aws_iam_policy.shared_write[0].arn
  } : {}

  role       = aws_iam_role.deploy[0].name
  policy_arn = each.value
}
