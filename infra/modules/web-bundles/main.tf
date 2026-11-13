# The web app's bundle store, in the shared account (ADR-0008, ADR-0005, #283): one versioned bundle per build of main,
# under bundles/<git-sha>/, with its manifest.json written last. An environment serves the bundle its pointer in Git
# names (deploy/environments/<env>/web.yaml: the version and the manifest's digest), as a cluster runs the image digest
# its values file names, so promotion and rollback move that pointer and nothing here.
#
# - Only the publish role writes, from the web release workflow's publish job in the registry environment (main only,
#   T-71), and only under bundles/. The build itself runs in a job with no AWS credentials.
# - Each environment's release role, sft-<env>-web-release (modules/web-release), reads bundles/ and copies a version
#   into its own web buckets. Nobody else reads: CloudFront serves the environments' buckets, never this one.
# - A bundle is never rewritten in place: the manifest pins every file's SHA-256, Git pins the manifest's, and the
#   deploy job checks both, so a changed object fails a release instead of reaching a browser. Versioning keeps what
#   anything replaced for 30 days.
# - SSE-S3: the bundle is public content, which every browser downloads (encryption 3.1), and a customer managed key
#   would have to be shared with every environment's role for nothing. Bundles stay while the shared account does
#   (a few megabytes each), so every version an environment ran can be restored.

locals {
  bucket_arn = "arn:aws:s3:::${var.bucket_name}"

  release_role_arns = [
    for env, account in var.member_account_ids : "arn:aws:iam::${account}:role/sft-${env}-web-release"
  ]
}

resource "aws_s3_bucket" "store" {
  bucket = var.bucket_name

  # The shared stack goes last of all (capacity 5.4); its teardown empties the store.
  force_destroy = true

  tags = { component = "web-bundles" }
}

resource "aws_s3_bucket_ownership_controls" "store" {
  bucket = aws_s3_bucket.store.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "store" {
  bucket                  = aws_s3_bucket.store.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "store" {
  bucket = aws_s3_bucket.store.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "store" {
  bucket = aws_s3_bucket.store.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "store" {
  bucket = aws_s3_bucket.store.id

  rule {
    id     = "expire-replaced-objects"
    status = "Enabled"

    filter {}

    noncurrent_version_expiration {
      noncurrent_days = 30
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }

  depends_on = [aws_s3_bucket_versioning.store]
}

data "aws_iam_policy_document" "store" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [local.bucket_arn, "${local.bucket_arn}/*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  # The publish role writes; the deploy role empties the store at the end. BreakGlass and every other role in this
  # account included, nobody else writes or deletes an object here.
  statement {
    sid       = "OnlyThePublishRoleWrites"
    effect    = "Deny"
    actions   = ["s3:DeleteObject", "s3:DeleteObjectVersion", "s3:PutObject", "s3:PutObjectAcl", "s3:RestoreObject"]
    resources = ["${local.bucket_arn}/*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "ArnNotEquals"
      variable = "aws:PrincipalArn"
      values   = [aws_iam_role.publish.arn, var.deploy_role_arn]
    }
  }

  # Each environment's release role, by its exact ARN in that environment's account: it reads the files its
  # pointer's manifest names, by name, and lists nothing. The accounts are the principals and the roles a condition,
  # so this policy applies before an environment's edge stack has made its role (S3 refuses a principal that doesn't
  # exist yet), and a role re-created under another name never matches.
  dynamic "statement" {
    for_each = length(local.release_role_arns) == 0 ? [] : [1]

    content {
      sid       = "ReleaseRolesReadTheBundles"
      actions   = ["s3:GetObject"]
      resources = ["${local.bucket_arn}/bundles/*"]

      principals {
        type        = "AWS"
        identifiers = [for account in values(var.member_account_ids) : "arn:aws:iam::${account}:root"]
      }

      condition {
        test     = "ArnEquals"
        variable = "aws:PrincipalArn"
        values   = local.release_role_arns
      }
    }
  }
}

resource "aws_s3_bucket_policy" "store" {
  bucket = aws_s3_bucket.store.id
  policy = data.aws_iam_policy_document.store.json

  depends_on = [aws_s3_bucket_public_access_block.store]
}

# --- Publish role ------------------------------------------------------------------------------------------------

# The web release workflow's publish job (#283) uploads a bundle through this role. It trusts only jobs in the
# registry GitHub environment, which accepts deployments from main only, like the image push role (#107, T-71).
data "aws_iam_policy_document" "publish_trust" {
  statement {
    sid     = "RegistryEnvironmentOfThisRepository"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [var.github_oidc_provider_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:${var.github_repository}:environment:${var.publish_github_environment}"]
    }
  }
}

resource "aws_iam_role" "publish" {
  name                 = var.publish_role_name
  path                 = var.iam_path
  description          = "Publishes the web app's bundles from the ${var.publish_github_environment} environment of ${var.github_repository} (#283)."
  assume_role_policy   = data.aws_iam_policy_document.publish_trust.json
  max_session_duration = 3600
}

data "aws_iam_policy_document" "publish" {
  # ListBucket so that a bundle not yet published answers 404, not 403: a re-run then finds a finished bundle, and a
  # denied call is never mistaken for "not published yet".
  statement {
    sid       = "ListTheBundles"
    actions   = ["s3:ListBucket"]
    resources = [local.bucket_arn]
  }

  statement {
    sid       = "PublishBundles"
    actions   = ["s3:GetObject", "s3:PutObject"]
    resources = ["${local.bucket_arn}/bundles/*"]
  }
}

resource "aws_iam_role_policy" "publish" {
  name   = "publish"
  role   = aws_iam_role.publish.id
  policy = data.aws_iam_policy_document.publish.json
}
