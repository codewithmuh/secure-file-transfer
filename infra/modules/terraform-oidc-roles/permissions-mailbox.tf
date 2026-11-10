# ---------------------------------------------------------------------------------------------------------------------
# The probe mailbox in the identity layer (#259, modules/probe-mailbox), in the Regions of var.network_regions: the
# mailbox bucket sft-<env>-<rs>-probe-mailbox-<account>, SES's receipt rule set and rules, and in staging the load
# test's role sft-<env>-loadtest and its secret sft/<env>/loadtest/* without a value. The mailbox domains' SES
# identities are the identity policy's (SesIdentitiesAndConfigurationSets), and their records go through the DNS roles.
#
# Its own managed policies, `sft-<env>-terraform-mailbox-read` for the plan role and `-mailbox` for the deploy role,
# because the identity layer's one policy is already near IAM's 6,144 characters. That makes 15 managed policies on
# the deploy role and 8 on the plan role, inside the quota of 20 (infra/README.md, "IAM quotas").
# ---------------------------------------------------------------------------------------------------------------------

locals {
  mailbox_enabled = local.identity_enabled

  mailbox_bucket_arns = [
    for r in var.network_regions : "arn:aws:s3:::${local.cluster_env_prefix}-${var.conventions.region_shorts[r]}-probe-mailbox-${var.account_id}"
  ]
  mailbox_load_test_role = "arn:aws:iam::${var.account_id}:role/${var.conventions.workload_role_names["loadtest"]}"
  mailbox_secrets        = [for r in var.network_regions : "arn:aws:secretsmanager:${r}:${var.account_id}:secret:${local.cluster_env_prefix_path}/loadtest/*"]
}

data "aws_iam_policy_document" "mailbox_read" {
  count = local.mailbox_enabled ? 1 : 0

  statement {
    sid       = "MailboxBucketSettings"
    actions   = ["s3:GetBucket*", "s3:GetEncryptionConfiguration", "s3:GetLifecycleConfiguration", "s3:ListBucket", "s3:GetAccelerateConfiguration", "s3:GetReplicationConfiguration"]
    resources = local.mailbox_bucket_arns
  }

  # SES's receipt rules take no resource in IAM.
  statement {
    sid       = "ReceiptRulesRead"
    actions   = ["ses:DescribeActiveReceiptRuleSet", "ses:DescribeReceiptRuleSet", "ses:DescribeReceiptRule"]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:RequestedRegion"
      values   = var.network_regions
    }
  }

  statement {
    sid       = "LoadTestRoleAndSecretRead"
    actions   = ["iam:GetRole", "iam:GetRolePolicy", "iam:ListRolePolicies", "iam:ListAttachedRolePolicies", "secretsmanager:DescribeSecret", "secretsmanager:GetResourcePolicy"]
    resources = concat([local.mailbox_load_test_role], local.mailbox_secrets)
  }
}

data "aws_iam_policy_document" "mailbox" {
  count = local.mailbox_enabled && var.github_environment != null ? 1 : 0

  source_policy_documents = [data.aws_iam_policy_document.mailbox_read[0].json]

  # The bucket and its settings. Its objects are SES's and the readers'; a teardown empties it (force_destroy).
  statement {
    sid = "MailboxBucket"
    actions = [
      "s3:CreateBucket", "s3:DeleteBucket", "s3:PutBucketPolicy", "s3:DeleteBucketPolicy", "s3:PutBucketOwnershipControls",
      "s3:PutBucketPublicAccessBlock", "s3:PutBucketVersioning", "s3:PutEncryptionConfiguration",
      "s3:PutLifecycleConfiguration", "s3:PutBucketTagging", "s3:ListBucketVersions", "s3:DeleteObject",
      "s3:DeleteObjectVersion",
    ]
    resources = concat(local.mailbox_bucket_arns, [for b in local.mailbox_bucket_arns : "${b}/*"])
  }

  statement {
    sid = "ReceiptRules"
    actions = [
      "ses:CreateReceiptRuleSet", "ses:DeleteReceiptRuleSet", "ses:SetActiveReceiptRuleSet", "ses:CreateReceiptRule",
      "ses:UpdateReceiptRule", "ses:DeleteReceiptRule",
    ]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:RequestedRegion"
      values   = var.network_regions
    }
  }

  # The load test's role (staging): created and changed here, never passed; GitHub's OIDC token assumes it.
  statement {
    sid = "LoadTestRole"
    actions = [
      "iam:CreateRole", "iam:DeleteRole", "iam:UpdateRole", "iam:UpdateRoleDescription", "iam:UpdateAssumeRolePolicy",
      "iam:PutRolePolicy", "iam:DeleteRolePolicy", "iam:TagRole", "iam:UntagRole", "iam:ListInstanceProfilesForRole",
    ]
    resources = [local.mailbox_load_test_role]
  }

  statement {
    sid = "LoadTestSecretWithoutValue"
    actions = [
      "secretsmanager:CreateSecret", "secretsmanager:DeleteSecret", "secretsmanager:UpdateSecret",
      "secretsmanager:TagResource", "secretsmanager:UntagResource",
    ]
    resources = local.mailbox_secrets
  }
}

resource "aws_iam_policy" "mailbox_read" {
  count = local.mailbox_enabled ? 1 : 0

  name        = "${local.cluster_env_prefix}-terraform-mailbox-read"
  path        = var.iam_path
  description = "Terraform plan: read the probe mailbox, SES's receipt rules and the load test's role and secret (#259)."
  policy      = data.aws_iam_policy_document.mailbox_read[0].json
}

resource "aws_iam_role_policy_attachment" "plan_mailbox" {
  count = local.mailbox_enabled ? 1 : 0

  role       = aws_iam_role.plan.name
  policy_arn = aws_iam_policy.mailbox_read[0].arn
}

resource "aws_iam_policy" "mailbox" {
  count = local.mailbox_enabled && var.github_environment != null ? 1 : 0

  name        = "${local.cluster_env_prefix}-terraform-mailbox"
  path        = var.iam_path
  description = "Terraform deploy: the probe mailbox, SES's receipt rules and the load test's role and secret (#259)."
  policy      = data.aws_iam_policy_document.mailbox[0].json
}

resource "aws_iam_role_policy_attachment" "deploy_mailbox" {
  count = local.mailbox_enabled && var.github_environment != null ? 1 : 0

  role       = aws_iam_role.deploy[0].name
  policy_arn = aws_iam_policy.mailbox[0].arn
}
