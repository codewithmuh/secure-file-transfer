# The VPC flow log's bucket in this Region (capacity A19 and A33, encryption 3.1, T-53):
# sft-<env>-<region-short>-flow-logs-<account-id>. The network stack's flow log (modules/network, aws_flow_log.this)
# writes here from the network's second apply of a fresh build, which takes this root's flow_log_bucket_arn output as
# flow_log_destination_arn (infra/README.md, "Apply order"). Each Region's VPC logs to its own Region's bucket, and
# nothing replicates it: Osaka's flow logs stay in Osaka, like its edge's logs.
#
# - SSE-KMS with the environment's logs key (in Osaka its replica) and S3 Bucket Keys. CloudWatch Logs' delivery
#   service encrypts through the logs key's LogDeliveryWritesVendedLogs statement (modules/kms-keys), which is limited
#   by aws:SourceAccount and aws:SourceArn like the bucket policy below.
# - Private, owner-enforced and TLS only; versioning on, with a replaced version gone after a day, like the edge's log
#   buckets (modules/edge/logs.tf).
# - Kept 90 days (PRD data lifecycle, capacity A33).
# - Emptied by a destroy in dev and staging, and in prod from its teardown apply on, like the files buckets
#   (storage.tf, #263).

locals {
  flow_log_bucket         = "${var.conventions.name_prefix}-flow-logs-${var.account_id}"
  flow_log_retention_days = 90

  # The delivery service writes for flow logs in this account and Region only.
  flow_log_source_arns = ["arn:aws:logs:${local.region}:${var.account_id}:*"]
}

resource "aws_s3_bucket" "flow_logs" {
  bucket        = local.flow_log_bucket
  force_destroy = local.teardown_allowed || var.teardown

  tags = { component = "flow-logs" }
}

resource "aws_s3_bucket_ownership_controls" "flow_logs" {
  bucket = aws_s3_bucket.flow_logs.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "flow_logs" {
  bucket                  = aws_s3_bucket.flow_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "flow_logs" {
  bucket = aws_s3_bucket.flow_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "flow_logs" {
  bucket = aws_s3_bucket.flow_logs.id

  rule {
    bucket_key_enabled = true

    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = local.kms_key_arns["logs"]
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "flow_logs" {
  bucket = aws_s3_bucket.flow_logs.id

  rule {
    id     = "expire-after-retention"
    status = "Enabled"

    filter {}

    expiration {
      days = local.flow_log_retention_days
    }

    noncurrent_version_expiration {
      noncurrent_days = 1
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  depends_on = [aws_s3_bucket_versioning.flow_logs]
}

# AWS's policy for flow logs to S3 ("Amazon S3 bucket permissions for flow logs"), with the bucket check the edge's WAF
# log bucket also has (ListBucket, for the delivery service's HeadBucket). The network writes Hive-compatible
# partitions (its destination_options), so every object is under AWSLogs/aws-account-id=<account>/.
data "aws_iam_policy_document" "flow_logs" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.flow_logs.arn, "${aws_s3_bucket.flow_logs.arn}/*"]

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
    sid       = "LogDeliveryWritesFlowLogs"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.flow_logs.arn}/AWSLogs/aws-account-id=${var.account_id}/*"]

    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.account_id]
    }

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }

    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = local.flow_log_source_arns
    }
  }

  statement {
    sid       = "LogDeliveryChecksTheBucket"
    actions   = ["s3:GetBucketAcl", "s3:ListBucket"]
    resources = [aws_s3_bucket.flow_logs.arn]

    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.account_id]
    }

    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = local.flow_log_source_arns
    }
  }
}

resource "aws_s3_bucket_policy" "flow_logs" {
  bucket = aws_s3_bucket.flow_logs.id
  policy = data.aws_iam_policy_document.flow_logs.json

  depends_on = [aws_s3_bucket_public_access_block.flow_logs]
}
