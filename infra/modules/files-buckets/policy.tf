# Bucket policies (encryption 2.1 and 3.1, authn-authz 8.1, architecture 3.1, threat model T-32, T-51, T-60). Deny
# statements only: each workload's IAM policy (cluster layer) grants what it does, and these hold whatever an
# identity policy allows, BreakGlass's AdministratorAccess included. Principals are matched by aws:PrincipalArn, so
# the policy can name roles the cluster layer makes later.

locals {
  validation_object = "malware-protection-resource-validation-object"

  # Who may read object bytes. Replication reads with GetObjectVersionForReplication, which these don't cover.
  readers = {
    files         = concat([local.role_arns["api"], local.role_arns["scan"]], var.break_glass_principal_arn_patterns)
    "large-files" = concat([local.role_arns["api"], local.role_arns["malware-protection"]], var.break_glass_principal_arn_patterns)
  }

  # Who may write object bytes: the API (multipart uploads); in the large-files bucket GuardDuty also writes its
  # validation object.
  writers = {
    files         = [local.role_arns["api"]]
    "large-files" = [local.role_arns["api"], local.role_arns["malware-protection"]]
  }

  # Who may set tags: the scan worker sets the `scan` tag; GuardDuty sets its own on the large files (ADR-0019).
  taggers = {
    files         = [local.role_arns["scan"]]
    "large-files" = [local.role_arns["scan"], local.role_arns["malware-protection"]]
  }

  # Only the lifecycle jobs delete (ADR-0012). In dev and staging the deploy role too, so teardown can empty a bucket.
  deleters = concat([local.role_arns["jobs"]], var.teardown_allowed ? [var.deploy_role_arn] : [])

  settings_changers = concat([var.deploy_role_arn], var.admin_principal_arn_patterns)
}

data "aws_iam_policy_document" "bucket" {
  for_each = local.buckets

  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = ["arn:aws:s3:::${each.value}", "arn:aws:s3:::${each.value}/*"]

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
    resources = ["arn:aws:s3:::${each.value}", "arn:aws:s3:::${each.value}/*"]

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

  # A request may leave encryption to the default, which pre-signed parts do, but may not ask for anything else:
  # not SSE-S3, not DSSE, not another key and not SSE-C (T-60).
  statement {
    sid       = "DenyOtherEncryption"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["arn:aws:s3:::${each.value}/*"]

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
    resources = ["arn:aws:s3:::${each.value}/*"]

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
    resources = ["arn:aws:s3:::${each.value}/*"]

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

  # authn-authz 8.1: contents are read only by the API, the scan worker (small files), GuardDuty (large files) and
  # BreakGlass.
  statement {
    sid       = "DenyReadsToEveryoneElse"
    effect    = "Deny"
    actions   = ["s3:GetObject", "s3:GetObjectVersion"]
    resources = ["arn:aws:s3:::${each.value}/*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "ArnNotLike"
      variable = "aws:PrincipalArn"
      values   = local.readers[each.key]
    }
  }

  # FR-17: an infected file is never read again, by anyone.
  statement {
    sid       = "DenyReadsOfInfectedObjects"
    effect    = "Deny"
    actions   = ["s3:GetObject", "s3:GetObjectVersion"]
    resources = ["arn:aws:s3:::${each.value}/*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "StringEquals"
      variable = "s3:ExistingObjectTag/scan"
      values   = ["infected"]
    }
  }

  # Architecture 3.1: the API reads bytes only from objects the scan worker tagged shareable. An object without the
  # tag fails too, because a negated condition matches a missing key.
  statement {
    sid       = "DenyApiReadsOfUnshareableObjects"
    effect    = "Deny"
    actions   = ["s3:GetObject", "s3:GetObjectVersion"]
    resources = ["arn:aws:s3:::${each.value}/*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:PrincipalArn"
      values   = [local.role_arns["api"]]
    }

    condition {
      test     = "StringNotEquals"
      variable = "s3:ExistingObjectTag/scan"
      values   = ["clean", "unscannable_allowed"]
    }
  }

  # T-51: the scan worker reads only objects not yet scanned.
  statement {
    sid       = "DenyScanWorkerReadsOfScannedObjects"
    effect    = "Deny"
    actions   = ["s3:GetObject", "s3:GetObjectVersion"]
    resources = ["arn:aws:s3:::${each.value}/*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:PrincipalArn"
      values   = [local.role_arns["scan"]]
    }

    condition {
      test     = "Null"
      variable = "s3:ExistingObjectTag/scan"
      values   = ["false"]
    }
  }

  # T-32: only the API uploads, so no other principal can put new bytes under a file's key.
  statement {
    sid       = "DenyWritesToEveryoneElse"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["arn:aws:s3:::${each.value}/*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "ArnNotLike"
      variable = "aws:PrincipalArn"
      values   = local.writers[each.key]
    }
  }

  # GuardDuty's role writes only its validation object.
  dynamic "statement" {
    for_each = each.key == "large-files" ? [1] : []

    content {
      sid           = "DenyMalwareProtectionWritesExceptValidation"
      effect        = "Deny"
      actions       = ["s3:PutObject"]
      not_resources = ["arn:aws:s3:::${each.value}/${local.validation_object}"]

      principals {
        type        = "AWS"
        identifiers = ["*"]
      }

      condition {
        test     = "ArnEquals"
        variable = "aws:PrincipalArn"
        values   = [local.role_arns["malware-protection"]]
      }
    }
  }

  # The scan tag decides what the API may read, so only the scan worker (and GuardDuty, its own tag) sets tags.
  statement {
    sid    = "DenyTaggingToEveryoneElse"
    effect = "Deny"
    actions = [
      "s3:PutObjectTagging", "s3:PutObjectVersionTagging", "s3:DeleteObjectTagging", "s3:DeleteObjectVersionTagging",
    ]
    resources = ["arn:aws:s3:::${each.value}/*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "ArnNotLike"
      variable = "aws:PrincipalArn"
      values   = local.taggers[each.key]
    }
  }

  statement {
    sid       = "DenyDeletesToEveryoneElse"
    effect    = "Deny"
    actions   = ["s3:DeleteObject", "s3:DeleteObjectVersion"]
    resources = ["arn:aws:s3:::${each.value}/*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "ArnNotLike"
      variable = "aws:PrincipalArn"
      values   = local.deleters
    }
  }

  # Only the replication role writes replicas, so nobody can replicate forged versions in from a bucket of their own.
  statement {
    sid       = "DenyReplicaWritesToEveryoneElse"
    effect    = "Deny"
    actions   = ["s3:ReplicateObject", "s3:ReplicateDelete", "s3:ReplicateTags"]
    resources = ["arn:aws:s3:::${each.value}/*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "ArnNotEquals"
      variable = "aws:PrincipalArn"
      values   = [local.role_arns["s3-replication"]]
    }
  }

  # T-76: only Terraform and Admin change the bucket. Without this, BreakGlass could lift the denials above, add a
  # lifecycle rule that erases files, suspend versioning or copy everything elsewhere with replication or an inventory.
  # PutBucketNotification stays open: GuardDuty's role turns on EventBridge notifications for its plan.
  statement {
    sid    = "DenyBucketSettingsToEveryoneElse"
    effect = "Deny"
    actions = [
      "s3:DeleteBucket", "s3:PutBucketPolicy", "s3:DeleteBucketPolicy", "s3:PutBucketOwnershipControls",
      "s3:PutBucketPublicAccessBlock", "s3:PutBucketVersioning", "s3:PutBucketObjectLockConfiguration",
      "s3:PutEncryptionConfiguration", "s3:PutLifecycleConfiguration", "s3:PutReplicationConfiguration",
      "s3:PutInventoryConfiguration", "s3:PutBucketCORS", "s3:PutBucketTagging",
    ]
    resources = ["arn:aws:s3:::${each.value}"]

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
  for_each = local.buckets

  bucket = aws_s3_bucket.this[each.key].id
  policy = data.aws_iam_policy_document.bucket[each.key].json

  depends_on = [aws_s3_bucket_public_access_block.this]
}
