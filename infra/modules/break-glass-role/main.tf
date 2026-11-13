# The break-glass database role, sft-<env>-break-glass-db (FR-35, authn-authz 8.3, #232).
#
# A grant approved in the operator API lets its requester read named tenants' rows as the PostgreSQL login role
# sft_breakglass, for at most 60 minutes. This IAM role is how they sign in to it: IAM database authentication
# (rds-db:connect) as sft_breakglass and as nobody else. The database, not IAM, decides what the session reads: row-level
# security admits only the tenants of the grant named in app.break_glass_grant, and only until that grant ends.
#
# - Only the account's BreakGlass permission set role may assume it, the way the key-admin role is (encryption 4.4).
# - The assumption must carry exactly one session tag, sft-break-glass-grant, shaped like a grant ID (a UUID), so
#   CloudTrail and the alert name the grant. No other tag key is allowed.
# - Only through STS in the environment's own Regions (aws:RequestedRegion), so the call lands in a Region whose
#   EventBridge rule (alerts.tf) sees it; the global endpoint logs in us-east-1, where nothing listens.
# - Sessions last at most an hour, like BreakGlass itself; role chaining caps them at an hour anyway.
#
# IAM is global, so Tokyo's data stack creates the role (create_role) and each Region's data stack, Tokyo's and
# Osaka's, adds the inline policy for its own cluster, so the role still works on Osaka's cluster after a failover.
# Osaka's stack runs after Tokyo's (infra/README.md, "Apply order"). Every assumption pages (alerts.tf).

locals {
  region_short = var.conventions.region_shorts[var.region]

  role_name = "sft-${var.environment}-break-glass-db"
  role_arn  = "arn:aws:iam::${var.account_id}:role/${local.role_name}"

  # The session tag that names the grant, and its shape: 8-4-4-4-12 characters. IAM has no regular expressions, so
  # this checks the shape; the database checks that the grant exists and is active.
  grant_tag_key     = "sft-break-glass-grant"
  grant_tag_pattern = "????????-????-????-????-????????????"

  login_role = "sft_breakglass"
}

data "aws_iam_policy_document" "trust" {
  count = var.create_role ? 1 : 0

  statement {
    sid     = "BreakGlassWithItsGrantOnly"
    actions = ["sts:AssumeRole", "sts:TagSession"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.account_id}:root"]
    }

    condition {
      test     = "ArnLike"
      variable = "aws:PrincipalArn"
      values   = var.break_glass_principal_arn_patterns
    }

    # On sts:AssumeRole too, so an assumption without the tag is refused, not merely untagged.
    condition {
      test     = "StringLike"
      variable = "aws:RequestTag/${local.grant_tag_key}"
      values   = [local.grant_tag_pattern]
    }

    condition {
      test     = "ForAllValues:StringEquals"
      variable = "aws:TagKeys"
      values   = [local.grant_tag_key]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:RequestedRegion"
      values   = var.regions
    }
  }
}

resource "aws_iam_role" "this" {
  count = var.create_role ? 1 : 0

  name                 = local.role_name
  description          = "Signs in to the database as sft_breakglass under an approved grant (FR-35). BreakGlass only; every use pages."
  assume_role_policy   = data.aws_iam_policy_document.trust[0].json
  max_session_duration = 3600

  tags = { component = "break-glass" }
}

# This Region's cluster, as sft_breakglass only. The session must still carry the grant tag.
data "aws_iam_policy_document" "connect" {
  statement {
    sid       = "ConnectAsBreakGlassOnly"
    actions   = ["rds-db:connect"]
    resources = ["arn:aws:rds-db:${var.region}:${var.account_id}:dbuser:${var.cluster_resource_id}/${local.login_role}"]

    condition {
      test     = "StringLike"
      variable = "aws:PrincipalTag/${local.grant_tag_key}"
      values   = [local.grant_tag_pattern]
    }
  }
}

resource "aws_iam_role_policy" "connect" {
  name   = "connect-${local.region_short}"
  role   = var.create_role ? aws_iam_role.this[0].name : local.role_name
  policy = data.aws_iam_policy_document.connect.json
}
