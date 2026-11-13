# Staging's load test (#249, docs/operations/performance.md): the role the loadtest workflow assumes, and the secret
# that holds the load test's tenant keys. Only staging's Tokyo stack makes them (load_test); prod has neither, and
# .github/workflows/loadtest.yml can't name another environment.
#
# - sft-staging-loadtest trusts GitHub's OIDC provider for one subject: the loadtest-staging environment of this
#   repository, which accepts deployments from main only (a maintainer step in the repository settings).
# - It reads that one secret and lists, reads and deletes under loadtest/ in Tokyo's mailbox; nothing else.
# - The secret is created without a value: the maintainer stores the keys once, as the runbook says, never in Git.

locals {
  load_test       = var.load_test != null
  load_test_role  = var.conventions.workload_role_names["loadtest"]
  oidc_host       = "token.actions.githubusercontent.com"
  load_test_names = local.load_test ? { secret = "sft/${var.environment}/loadtest/api-keys" } : {}
}

resource "aws_secretsmanager_secret" "load_test_keys" {
  count = local.load_test ? 1 : 0

  name                    = local.load_test_names.secret
  description             = "The load test's tenants and API keys, [{tenant, key}] (docs/operations/performance.md). Its value is stored by hand, never in Git."
  kms_key_id              = var.load_test.secrets_key_arn
  recovery_window_in_days = 7

  tags = { component = "loadtest" }
}

data "aws_iam_policy_document" "load_test_trust" {
  count = local.load_test ? 1 : 0

  statement {
    sid     = "TheLoadTestEnvironmentOfThisRepository"
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
      values   = ["repo:${var.load_test.github_repository}:environment:loadtest-${var.environment}"]
    }
  }
}

resource "aws_iam_role" "load_test" {
  count = local.load_test ? 1 : 0

  name                 = local.load_test_role
  description          = "The load test's workflow (#249): its keys and the loadtest/ mailbox, from the loadtest-${var.environment} environment."
  assume_role_policy   = data.aws_iam_policy_document.load_test_trust[0].json
  max_session_duration = 21600 # a 5-hour window and the time to start it (docs/operations/performance.md)

  tags = { component = "loadtest" }
}

data "aws_iam_policy_document" "load_test" {
  count = local.load_test ? 1 : 0

  statement {
    sid       = "ReadTheKeys"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_secretsmanager_secret.load_test_keys[0].arn]
  }

  statement {
    sid       = "ListTheLoadTestMailbox"
    actions   = ["s3:ListBucket"]
    resources = [local.bucket_arn]

    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["loadtest/*"]
    }
  }

  statement {
    sid       = "ReadAndDeleteLoadTestMail"
    actions   = ["s3:GetObject", "s3:DeleteObject"]
    resources = ["${local.bucket_arn}/loadtest/*"]
  }

  # The secrets key for its one secret, and the platform key for its mail; both key policies repeat the conditions.
  statement {
    sid       = "SecretsKeyThroughSecretsManager"
    actions   = ["kms:Decrypt"]
    resources = [var.load_test.secrets_key_arn]

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["secretsmanager.${var.region}.amazonaws.com"]
    }
  }

  statement {
    sid       = "PlatformKeyThroughS3"
    actions   = ["kms:Decrypt"]
    resources = [var.platform_key_arn]

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${var.region}.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:EncryptionContext:aws:s3:arn"
      values   = [local.bucket_arn]
    }
  }
}

resource "aws_iam_role_policy" "load_test" {
  count = local.load_test ? 1 : 0

  name   = "load-test"
  role   = aws_iam_role.load_test[0].id
  policy = data.aws_iam_policy_document.load_test[0].json
}
