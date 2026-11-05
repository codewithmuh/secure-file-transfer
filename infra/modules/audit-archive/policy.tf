# The archive's bucket policy (encryption 3.1 and 4.3, threat model T-51): deny statements only, matched by
# aws:PrincipalArn so it can name roles the cluster layer makes later. Writers only write, readers only read, and
# nobody shortens a record's retention or deletes it, except the deploy role at teardown in dev and staging.

locals {
  writers = concat(
    local.primary ? [local.role_arns["archive"]] : [],
    [local.role_arns["api"], local.role_arns["operator"]],
  )
  readers = concat(
    [local.role_arns["recovery"]], local.audit_reader_arn_patterns, var.break_glass_principal_arn_patterns,
  )
  settings_changers = concat([var.deploy_role_arn], var.admin_principal_arn_patterns)
}

data "aws_iam_policy_document" "bucket" {
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

  statement {
    sid       = "DenyTlsBelow12"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [local.bucket_arn, "${local.bucket_arn}/*"]

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

  statement {
    sid       = "DenyOtherEncryption"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["${local.bucket_arn}/*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "Null"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["false"]
    }

    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["aws:kms"]
    }
  }

  statement {
    sid       = "DenyOtherKeys"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["${local.bucket_arn}/*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "Null"
      variable = "s3:x-amz-server-side-encryption-aws-kms-key-id"
      values   = ["false"]
    }

    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption-aws-kms-key-id"
      values   = [var.kms_key_arn]
    }
  }

  statement {
    sid       = "DenySseC"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["${local.bucket_arn}/*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "Null"
      variable = "s3:x-amz-server-side-encryption-customer-algorithm"
      values   = ["false"]
    }
  }

  # T-51: the API's and the workers' roles can't read the archive. Readers are the recovery job, the audit reader and
  # BreakGlass (4.3).
  statement {
    sid       = "DenyReadsToEveryoneElse"
    effect    = "Deny"
    actions   = ["s3:GetObject", "s3:GetObjectVersion"]
    resources = ["${local.bucket_arn}/*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "ArnNotLike"
      variable = "aws:PrincipalArn"
      values   = local.readers
    }
  }

  # Writers: the archive job in Tokyo; the API and the operator API in both Regions (architecture 5.2).
  statement {
    sid       = "DenyWritesToEveryoneElse"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["${local.bucket_arn}/*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "ArnNotEquals"
      variable = "aws:PrincipalArn"
      values   = local.writers
    }
  }

  statement {
    sid       = "DenyReplicaWritesToEveryoneElse"
    effect    = "Deny"
    actions   = ["s3:ReplicateObject", "s3:ReplicateDelete", "s3:ReplicateTags"]
    resources = ["${local.bucket_arn}/*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "ArnNotEquals"
      variable = "aws:PrincipalArn"
      values   = [local.replication_role_arn]
    }
  }

  # Records leave only through the lifecycle rule, which no bucket policy binds. In prod nobody deletes or changes a
  # retention; compliance mode would refuse it anyway. In dev and staging the deploy role may, to tear down.
  dynamic "statement" {
    for_each = var.teardown_allowed ? [] : [1]

    content {
      sid    = "DenyDeletesAndRetentionChanges"
      effect = "Deny"
      actions = [
        "s3:DeleteObject", "s3:DeleteObjectVersion", "s3:PutObjectRetention", "s3:PutObjectLegalHold",
        "s3:BypassGovernanceRetention",
      ]
      resources = ["${local.bucket_arn}/*"]

      principals {
        type        = "AWS"
        identifiers = ["*"]
      }
    }
  }

  dynamic "statement" {
    for_each = var.teardown_allowed ? [1] : []

    content {
      sid    = "DenyDeletesAndRetentionChangesExceptTeardown"
      effect = "Deny"
      actions = [
        "s3:DeleteObject", "s3:DeleteObjectVersion", "s3:PutObjectRetention", "s3:PutObjectLegalHold",
        "s3:BypassGovernanceRetention",
      ]
      resources = ["${local.bucket_arn}/*"]

      principals {
        type        = "AWS"
        identifiers = ["*"]
      }

      condition {
        test     = "ArnNotEquals"
        variable = "aws:PrincipalArn"
        values   = [var.deploy_role_arn]
      }
    }
  }

  # Only the owning stack's deploy role and Admin change the bucket. In prod SCP 5 repeats this (encryption 8.4).
  statement {
    sid    = "DenyBucketSettingsToEveryoneElse"
    effect = "Deny"
    actions = [
      "s3:DeleteBucket", "s3:PutBucketPolicy", "s3:DeleteBucketPolicy", "s3:PutBucketOwnershipControls",
      "s3:PutBucketPublicAccessBlock", "s3:PutBucketVersioning", "s3:PutBucketObjectLockConfiguration",
      "s3:PutEncryptionConfiguration", "s3:PutLifecycleConfiguration", "s3:PutReplicationConfiguration",
      "s3:PutInventoryConfiguration", "s3:PutBucketNotification", "s3:PutBucketTagging",
    ]
    resources = [local.bucket_arn]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "ArnNotLike"
      variable = "aws:PrincipalArn"
      values   = local.settings_changers
    }
  }
}

resource "aws_s3_bucket_policy" "this" {
  bucket = var.prevent_destroy ? aws_s3_bucket.guarded[0].id : aws_s3_bucket.unguarded[0].id
  policy = data.aws_iam_policy_document.bucket.json

  depends_on = [aws_s3_bucket_public_access_block.this]
}
