# ---------------------------------------------------------------------------------------------------------------------
# Break-glass database role (#232): what modules/break-glass-role needs in the data stacks, in the Regions of
# var.network_regions. The plan role reads (`sft-<env>-terraform-break-glass-read`); the deploy role's one policy
# (`-break-glass`) holds the same reads and also creates, changes and deletes. Its EventBridge rule is a
# `sft-<env>-*` rule, which the storage layer's policies already cover (permissions-storage.tf).
#
# - IAM: the role sft-<env>-break-glass-db and its inline connect policies, by exact ARN. Never passed to a service,
#   so no iam:PassRole, and no permissions boundary: nothing assumes it but the BreakGlass permission set role.
# - SNS: the alert topics sft-<env>-<rs>-break-glass-alerts and their policy; each topic's own policy then denies
#   changes to everyone but this deploy role.
#
# A deploy role that may rewrite this role's trust could assume it. It can already read the master password at apply
# (modules/aurora), and every assumption pages, so this adds no reach (threat model T-71).
#
# The deploy role's twelfth managed policy and the plan role's sixth, within the raised quota of 20 (infra/README.md,
# "IAM quotas").
# ---------------------------------------------------------------------------------------------------------------------

locals {
  break_glass_enabled = local.cluster_enabled

  break_glass_role_arn = "arn:aws:iam::${var.account_id}:role/${local.cluster_env_prefix}-break-glass-db"
  break_glass_topics = [
    for r in var.network_regions :
    "arn:aws:sns:${r}:${var.account_id}:${local.cluster_env_prefix}-${local.identity_region_shorts[r]}-break-glass-alerts"
  ]
}

data "aws_iam_policy_document" "break_glass_read" {
  count = local.break_glass_enabled ? 1 : 0

  statement {
    sid = "BreakGlassRoleRead"
    actions = [
      "iam:GetRole", "iam:GetRolePolicy", "iam:ListAttachedRolePolicies", "iam:ListRolePolicies",
    ]
    resources = [local.break_glass_role_arn]
  }

  statement {
    sid       = "BreakGlassTopicsRead"
    actions   = ["sns:GetTopicAttributes", "sns:ListTagsForResource"]
    resources = local.break_glass_topics
  }
}

data "aws_iam_policy_document" "break_glass" {
  count = local.break_glass_enabled && var.github_environment != null ? 1 : 0

  source_policy_documents = [data.aws_iam_policy_document.break_glass_read[0].json]

  statement {
    sid = "BreakGlassRoleOnly"
    actions = [
      "iam:CreateRole", "iam:DeleteRole", "iam:DeleteRolePolicy", "iam:ListInstanceProfilesForRole",
      "iam:PutRolePolicy", "iam:TagRole", "iam:UntagRole", "iam:UpdateAssumeRolePolicy", "iam:UpdateRole",
      "iam:UpdateRoleDescription",
    ]
    resources = [local.break_glass_role_arn]
  }

  statement {
    sid = "BreakGlassTopicsOnly"
    actions = [
      "sns:CreateTopic", "sns:DeleteTopic", "sns:SetTopicAttributes", "sns:TagResource", "sns:UntagResource",
    ]
    resources = local.break_glass_topics
  }
}

resource "aws_iam_policy" "break_glass_read" {
  count = local.break_glass_enabled ? 1 : 0

  name        = "${local.cluster_env_prefix}-terraform-break-glass-read"
  path        = var.iam_path
  description = "Terraform plan: read the break-glass database role and its alert topics (#232)."
  policy      = data.aws_iam_policy_document.break_glass_read[0].json
}

resource "aws_iam_role_policy_attachment" "plan_break_glass" {
  count = local.break_glass_enabled ? 1 : 0

  role       = aws_iam_role.plan.name
  policy_arn = aws_iam_policy.break_glass_read[0].arn
}

resource "aws_iam_policy" "break_glass" {
  count = local.break_glass_enabled && var.github_environment != null ? 1 : 0

  name        = "${local.cluster_env_prefix}-terraform-break-glass"
  path        = var.iam_path
  description = "Terraform deploy: the break-glass database role and its alert topics (#232)."
  policy      = data.aws_iam_policy_document.break_glass[0].json
}

resource "aws_iam_role_policy_attachment" "deploy_break_glass" {
  count = local.break_glass_enabled && var.github_environment != null ? 1 : 0

  role       = aws_iam_role.deploy[0].name
  policy_arn = aws_iam_policy.break_glass[0].arn
}
