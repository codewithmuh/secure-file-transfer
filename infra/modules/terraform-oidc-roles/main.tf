# GitHub Actions' OIDC provider and the Terraform roles for one account (ADR-0005, T-71).
#
# - The plan role trusts only pull requests from this repository. It reads state and writes lock files, nothing more
#   (the state bucket and key policies enforce that).
# - The deploy role trusts only one GitHub environment of this repository. Each environment accepts deployments from
#   main only, so no pull request job can obtain its subject.
# - Both trusts pin the audience and the exact subject with StringEquals, so a wildcard can't creep in.
# - Both roles sit under /sft-bootstrap/, which only the Admin permission set may change (ADR-0006, SCP 4), so no
#   deploy role can widen its own trust.

locals {
  oidc_host = "token.actions.githubusercontent.com"

  oidc_provider_arn = (
    var.create_oidc_provider
    ? aws_iam_openid_connect_provider.github[0].arn
    : "arn:aws:iam::${var.account_id}:oidc-provider/${local.oidc_host}"
  )
}

# AWS validates GitHub's tokens against its own trusted root CAs, so no thumbprint is needed.
resource "aws_iam_openid_connect_provider" "github" {
  count = var.create_oidc_provider ? 1 : 0

  url            = "https://${local.oidc_host}"
  client_id_list = ["sts.amazonaws.com"]
}

data "aws_iam_policy_document" "plan_trust" {
  statement {
    sid     = "PullRequestsFromThisRepository"
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
      values   = ["repo:${var.github_repository}:pull_request"]
    }
  }
}

resource "aws_iam_role" "plan" {
  name                 = var.plan_role_name
  path                 = var.iam_path
  description          = "Terraform plans from pull requests in ${var.github_repository}. Writes only lock files."
  assume_role_policy   = data.aws_iam_policy_document.plan_trust.json
  max_session_duration = 3600
}

data "aws_iam_policy_document" "deploy_trust" {
  count = var.github_environment == null ? 0 : 1

  statement {
    sid     = "OneEnvironmentOfThisRepository"
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
      values   = ["repo:${var.github_repository}:environment:${var.github_environment}"]
    }
  }
}

resource "aws_iam_role" "deploy" {
  count = var.github_environment == null ? 0 : 1

  name                 = var.deploy_role_name
  path                 = var.iam_path
  description          = "Terraform applies from the ${var.github_environment} environment of ${var.github_repository}."
  assume_role_policy   = data.aws_iam_policy_document.deploy_trust[0].json
  max_session_duration = var.deploy_max_session_seconds
}

# PLACEHOLDER (#54). Until the stacks hold resources, each role needs only its state, which the state bucket and key
# policies grant, and the account's Regions and Availability Zones, which every regional stack reads. The issues that
# build each layer replace this with the permissions that layer needs: #55 (organization), #56 (network) and the M4
# issues after them. The deploy role must never get IAM rights over /sft-bootstrap/ (SCP 4 denies them anyway).
data "aws_iam_policy_document" "placeholder" {
  statement {
    sid       = "DescribeRegionsAndZones"
    actions   = ["ec2:DescribeRegions", "ec2:DescribeAvailabilityZones"]
    resources = ["*"]
  }
}

# A caller that knows its plan role's needs replaces the placeholder with plan_policy_json: the management account
# passes read access to Organizations, Identity Center and Budgets for the organization stack (#55).
resource "aws_iam_role_policy" "plan_placeholder" {
  name   = var.plan_policy_json == null ? "placeholder" : "plan"
  role   = aws_iam_role.plan.id
  policy = coalesce(var.plan_policy_json, data.aws_iam_policy_document.placeholder.json)
}

resource "aws_iam_role_policy" "deploy_placeholder" {
  count = var.github_environment == null ? 0 : 1

  name   = "placeholder"
  role   = aws_iam_role.deploy[0].id
  policy = data.aws_iam_policy_document.placeholder.json
}
