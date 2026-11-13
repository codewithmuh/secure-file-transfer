# The web app's release role in one environment (ADR-0008, ADR-0005, #283): the only principal besides the deploy role
# that writes the environment's web buckets (modules/edge's bucket policy denies everyone else), and it does nothing
# else. The web release workflow's deploy job assumes it (.github/workflows/web-deploy.yml) to copy the version the
# environment's pointer names from the shared account's bundle store into each Region's bucket, Osaka first, and to
# write config.json and index.html last.
#
# - It trusts GitHub's OIDC provider for one subject: the GitHub environment web-<env> of this repository, which
#   accepts deployments from main only (a maintainer step). Not the environment <env>, whose subject the Terraform
#   deploy role trusts: a web job must never be able to become the deploy role (T-71).
# - It reads only bundles/ in the bundle store, by name, whose policy names it in turn (modules/web-bundles), and
#   writes objects in its own web buckets. No delete: a release only adds files and replaces config.json, index.html
#   and release.json, so a rollback finds every older version's files in place, and the bucket's lifecycle rule
#   expires replaced versions.
#
# IAM is global: Tokyo's edge stack makes it, once per account.

locals {
  role_name          = var.conventions.workload_role_names["web-release"]
  oidc_host          = "token.actions.githubusercontent.com"
  github_environment = "web-${var.environment}"

  web_buckets = {
    for r in var.regions : r => "${var.conventions.global_name_prefix}-${var.conventions.region_shorts[r]}-web-${var.account_id}"
  }

  # The shared stack's bundle store, by its fixed name (modules/web-bundles).
  store_bucket_arn = "arn:aws:s3:::sft-shared-${var.conventions.region_shorts["ap-northeast-1"]}-web-bundles-${var.shared_account_id}"
}

data "aws_iam_policy_document" "trust" {
  statement {
    sid     = "TheWebEnvironmentOfThisRepository"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = ["arn:aws:iam::${var.account_id}:oidc-provider/${local.oidc_host}"]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.oidc_host}:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.oidc_host}:sub"
      values   = ["repo:${var.conventions.github_repository}:environment:${local.github_environment}"]
    }
  }
}

resource "aws_iam_role" "release" {
  name                 = local.role_name
  description          = "The web app's release (#283): reads bundles from the shared store and writes this environment's web buckets, from the ${local.github_environment} environment."
  assume_role_policy   = data.aws_iam_policy_document.trust.json
  max_session_duration = 3600

  tags = { component = "web-release" }
}

data "aws_iam_policy_document" "release" {
  # By name only: the deploy job reads the manifest its pointer names and the files the manifest lists.
  statement {
    sid       = "ReadTheBundles"
    actions   = ["s3:GetObject"]
    resources = ["${local.store_bucket_arn}/bundles/*"]
  }

  statement {
    sid       = "WriteTheWebBuckets"
    actions   = ["s3:PutObject"]
    resources = [for b in values(local.web_buckets) : "arn:aws:s3:::${b}/*"]
  }
}

resource "aws_iam_role_policy" "release" {
  name   = "release"
  role   = aws_iam_role.release.id
  policy = data.aws_iam_policy_document.release.json
}
