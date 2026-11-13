# The break-glass reconciliation's read of this account (#239, authn-authz 8.3). Identity Center lives here, so its
# account assignments and the break-glass tool's removal schedules are in this account's CloudTrail, which no
# environment can read. One role per environment that runs the operator API, which only that environment's operator
# API role may assume: it may look up management events and read a user's name in the identity store, nothing else.
#
# CloudTrail's LookupEvents names no resource type and no condition key in the service authorization reference, so it
# can't be narrowed to an event name: the role reads this account's management events of the last 90 days, which
# carry no secret (request parameters of Identity Center and Scheduler calls). It changes nothing.
#
# The trust names the environment's account and matches its operator API role by aws:PrincipalArn, so the role can be
# created before the environment's cluster layer makes sft-<env>-operator, and a role re-created under another name
# never matches. The operator API role's policy and the workload boundary allow sts:AssumeRole into exactly this name
# in our organization (modules/eks-cluster, modules/terraform-oidc-roles).

locals {
  break_glass_trail_environments = var.identity_center_enabled ? toset(["dev", "staging", "prod"]) : toset([])
}

data "aws_iam_policy_document" "break_glass_trail_trust" {
  for_each = local.break_glass_trail_environments

  statement {
    sid     = "TheEnvironmentsOperatorApiOnly"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${local.account_ids[each.key]}:root"]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:PrincipalArn"
      values   = ["arn:aws:iam::${local.account_ids[each.key]}:role/sft-${each.key}-operator"]
    }
  }
}

data "aws_iam_policy_document" "break_glass_trail_read" {
  count = var.identity_center_enabled ? 1 : 0

  statement {
    sid       = "LookUpAssignmentsAndSchedules"
    actions   = ["cloudtrail:LookupEvents"]
    resources = ["*"]
  }

  statement {
    sid     = "RequesterUserNames"
    actions = ["identitystore:DescribeUser"]
    resources = [
      "arn:aws:identitystore::${var.account_id}:identitystore/${local.identity_store_id}",
      "arn:aws:identitystore:::user/*",
    ]
  }
}

resource "aws_iam_role" "break_glass_trail" {
  for_each = local.break_glass_trail_environments

  name                 = "sft-${each.key}-break-glass-trail"
  description          = "Read-only: CloudTrail lookups and identity store user names for ${each.key}'s break-glass reconciliation (#239)."
  assume_role_policy   = data.aws_iam_policy_document.break_glass_trail_trust[each.key].json
  max_session_duration = 3600
}

resource "aws_iam_role_policy" "break_glass_trail" {
  for_each = local.break_glass_trail_environments

  name   = "read-assignments"
  role   = aws_iam_role.break_glass_trail[each.key].name
  policy = data.aws_iam_policy_document.break_glass_trail_read[0].json
}
