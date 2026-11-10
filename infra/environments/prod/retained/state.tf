# The retained stack's own state bucket (encryption 8.4, #263): sft-prod-apne1-retained-tfstate-<account-id>, under
# the audit key, so the stack keeps its state after prod's state bucket and tfstate key are destroyed. The stack's
# first apply runs as Admin from local state, makes the key and this bucket, then moves its state here
# (infra/README.md, "Bootstrap an account", the same steps with this bucket's name).
#
# The same guards as every state bucket (modules/tfstate-backend, T-73): TLS 1.2, versions kept 90 days and the last
# ten always, objects readable and writable only by this stack's deploy role and Admin, the bucket's settings only by
# Admin and this stack's deploy role (SCP 5 already keeps sft-prod-apne?-retained-* with those two). The audit key's
# policy lets only those two use it for this bucket (modules/kms-keys, RetainedDeployRoleUsesItsStateThroughS3).

locals {
  state_bucket_name = "${module.conventions.name_prefix}-retained-tfstate-${var.account_id}"
  state_bucket_arn  = "arn:aws:s3:::${local.state_bucket_name}"

  # Who reads and writes the state: this stack's deploy role and Admin.
  state_principal_arns = concat([local.retained_deploy_role_arn], local.admin_patterns)
}

resource "aws_s3_bucket" "state" {
  bucket = local.state_bucket_name

  tags = { component = "retained" }

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_ownership_controls" "state" {
  bucket = aws_s3_bucket.state.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "state" {
  bucket = aws_s3_bucket.state.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "state" {
  bucket = aws_s3_bucket.state.id

  versioning_configuration {
    status = "Enabled"
  }
}

# The backend sets no encryption header, so every object gets this default: the audit key's Tokyo primary.
resource "aws_s3_bucket_server_side_encryption_configuration" "state" {
  bucket = aws_s3_bucket.state.id

  rule {
    bucket_key_enabled = true

    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = module.audit_key.key_arns["audit"]
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "state" {
  bucket = aws_s3_bucket.state.id

  rule {
    id     = "expire-old-versions"
    status = "Enabled"

    filter {}

    noncurrent_version_expiration {
      noncurrent_days           = 90
      newer_noncurrent_versions = 10
    }

    expiration {
      expired_object_delete_marker = true
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  depends_on = [aws_s3_bucket_versioning.state]
}

data "aws_iam_policy_document" "state" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [local.state_bucket_arn, "${local.state_bucket_arn}/*"]

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

  statement {
    sid       = "DenyTlsBelow12"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [local.state_bucket_arn, "${local.state_bucket_arn}/*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "NumericLessThan"
      variable = "s3:TlsVersion"
      values   = ["1.2"]
    }
  }

  # T-73: the state is this stack's deploy role's and Admin's alone, BreakGlass and ReadOnly included.
  statement {
    sid    = "DenyStateAccessToEveryoneElse"
    effect = "Deny"
    actions = [
      "s3:GetObject", "s3:GetObjectVersion", "s3:GetObjectAttributes", "s3:GetObjectVersionAttributes",
      "s3:PutObject", "s3:DeleteObject", "s3:DeleteObjectVersion", "s3:RestoreObject",
      "s3:ReplicateObject", "s3:ReplicateDelete", "s3:ReplicateTags",
      "s3:ListBucket", "s3:ListBucketVersions",
    ]
    resources = [local.state_bucket_arn, "${local.state_bucket_arn}/*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "ArnNotLike"
      variable = "aws:PrincipalArn"
      values   = local.state_principal_arns
    }
  }

  # The bucket's settings, as SCP 5 says: a lifecycle rule, a suspended versioning or a new policy could erase or
  # forge the state.
  statement {
    sid    = "DenyBucketSettingsToEveryoneElse"
    effect = "Deny"
    actions = [
      "s3:DeleteBucket", "s3:PutBucketPolicy", "s3:DeleteBucketPolicy", "s3:PutBucketOwnershipControls",
      "s3:PutBucketPublicAccessBlock", "s3:PutBucketVersioning", "s3:PutEncryptionConfiguration",
      "s3:PutLifecycleConfiguration", "s3:PutReplicationConfiguration", "s3:PutInventoryConfiguration",
      "s3:PutBucketTagging",
    ]
    resources = [local.state_bucket_arn]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "ArnNotLike"
      variable = "aws:PrincipalArn"
      values   = local.state_principal_arns
    }
  }

  # Only the audit key, never another key or SSE-S3.
  statement {
    sid       = "DenyOtherEncryption"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["${local.state_bucket_arn}/*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "StringNotEqualsIfExists"
      variable = "s3:x-amz-server-side-encryption-aws-kms-key-id"
      values   = [module.audit_key.key_arns["audit"]]
    }
  }
}

resource "aws_s3_bucket_policy" "state" {
  bucket = aws_s3_bucket.state.id
  policy = data.aws_iam_policy_document.state.json

  depends_on = [aws_s3_bucket_public_access_block.state]
}
