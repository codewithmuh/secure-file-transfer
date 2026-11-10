# The retained trail (encryption 8.4, #263): sft-prod-retained, every Region, writing to its own small bucket,
# sft-prod-apne1-retained-trail-<account-id>, with its log files encrypted under the audit key.
#
# - Always: the archive buckets' S3 data events in both Regions, so every read and write of a record is on file even
#   after the organization trail, which ends with the shared account, is gone (ADR-0006).
# - From the teardown apply on (var.teardown): the account's management events too. While prod runs the organization
#   trail logs them, the free copy, and EventBridge sees them from it; a second copy would bill (capacity A37). After
#   teardown this trail is what lets EventBridge see the calls the retained alerts watch (alerts.tf).
#
# The audit key's policy lets CloudTrail use it for this trail only (modules/kms-keys, CloudTrailWritesTheRetainedTrail).
# SCP 3 keeps trails with the apply roles, and SCP 5 the sft-prod-apne?-retained-* buckets with this stack's deploy
# role and Admin.

locals {
  trail_name       = "sft-prod-retained"
  trail_arn        = "arn:aws:cloudtrail:${module.conventions.region}:${var.account_id}:trail/${local.trail_name}"
  trail_bucket     = "${module.conventions.name_prefix}-retained-trail-${var.account_id}"
  trail_bucket_arn = "arn:aws:s3:::${local.trail_bucket}"

  archive_object_arn_prefixes = [for arn in values(local.archive_bucket_arns) : "${arn}/"]
  archive_bucket_arns = {
    "ap-northeast-1" = module.audit_archive.bucket_arn
    "ap-northeast-3" = module.audit_archive_osaka.bucket_arn
  }
}

resource "aws_s3_bucket" "trail" {
  bucket = local.trail_bucket

  tags = { component = "retained" }

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_ownership_controls" "trail" {
  bucket = aws_s3_bucket.trail.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "trail" {
  bucket = aws_s3_bucket.trail.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "trail" {
  bucket = aws_s3_bucket.trail.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id

  rule {
    bucket_key_enabled = true

    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = module.audit_key.key_arns["audit"]
    }
  }
}

# The log files are kept as long as the records they describe: the archive's 365 days, then a day.
resource "aws_s3_bucket_lifecycle_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id

  rule {
    id     = "expire-with-the-archive"
    status = "Enabled"

    filter {}

    expiration {
      days = 366
    }

    noncurrent_version_expiration {
      noncurrent_days = 1
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  depends_on = [aws_s3_bucket_versioning.trail]
}

data "aws_iam_policy_document" "trail_bucket" {
  statement {
    sid       = "CloudTrailChecksTheBucket"
    actions   = ["s3:GetBucketAcl"]
    resources = [local.trail_bucket_arn]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }

  statement {
    sid       = "CloudTrailWritesThisTrailsLogs"
    actions   = ["s3:PutObject"]
    resources = ["${local.trail_bucket_arn}/AWSLogs/${var.account_id}/*"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }

  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [local.trail_bucket_arn, "${local.trail_bucket_arn}/*"]

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

  # Nobody but this stack's deploy role and Admin deletes a log file or changes the bucket, BreakGlass included.
  statement {
    sid    = "DenyDeletesAndSettingsToEveryoneElse"
    effect = "Deny"
    actions = [
      "s3:DeleteObject", "s3:DeleteObjectVersion", "s3:DeleteBucket", "s3:PutBucketPolicy", "s3:DeleteBucketPolicy",
      "s3:PutBucketVersioning", "s3:PutLifecycleConfiguration", "s3:PutEncryptionConfiguration",
      "s3:PutReplicationConfiguration", "s3:PutBucketPublicAccessBlock", "s3:PutBucketOwnershipControls",
    ]
    resources = [local.trail_bucket_arn, "${local.trail_bucket_arn}/*"]

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
}

resource "aws_s3_bucket_policy" "trail" {
  bucket = aws_s3_bucket.trail.id
  policy = data.aws_iam_policy_document.trail_bucket.json

  depends_on = [aws_s3_bucket_public_access_block.trail]
}

resource "aws_cloudtrail" "retained" {
  name                          = local.trail_name
  s3_bucket_name                = aws_s3_bucket.trail.id
  kms_key_id                    = module.audit_key.key_arns["audit"]
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true

  advanced_event_selector {
    name = "The audit archive's object events, in both Regions"

    field_selector {
      field  = "eventCategory"
      equals = ["Data"]
    }

    field_selector {
      field  = "resources.type"
      equals = ["AWS::S3::Object"]
    }

    field_selector {
      field       = "resources.ARN"
      starts_with = local.archive_object_arn_prefixes
    }
  }

  dynamic "advanced_event_selector" {
    for_each = var.teardown ? [1] : []

    content {
      name = "Management events, once the organization trail can end (teardown)"

      field_selector {
        field  = "eventCategory"
        equals = ["Management"]
      }
    }
  }

  tags = { component = "retained" }

  depends_on = [aws_s3_bucket_policy.trail]
}
