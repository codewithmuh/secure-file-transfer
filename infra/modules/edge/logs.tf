# The edge's log buckets in this Region (abuse 3.4, encryption 3.1, architecture 5.5): kept 90 days.
#
# - aws-waf-logs-sft-<env>-<region-short>-<account-id>: the web ACLs' logs, which WAF writes only to a bucket named
#   aws-waf-logs-*, and in Tokyo also the CloudFront web ACL's logs and CloudFront's standard logs, delivered from
#   us-east-1. SSE-KMS with the environment's logs key.
# - sft-<env>-<region-short>-lb-logs-<account-id>: the load balancer's access logs, which support only SSE-S3, the
#   recorded exception to NFR-13 (encryption 3.1). They hold no tokens: those travel in the URL fragment.

locals {
  # Log delivery writes from this Region and, for CloudFront and its web ACL, from us-east-1.
  log_delivery_source_arns = distinct([
    "arn:aws:logs:${local.region}:${var.account_id}:*",
    "arn:aws:logs:us-east-1:${var.account_id}:*",
  ])

  log_buckets = {
    waf = local.waf_log_bucket
    lb  = local.lb_log_bucket
  }
}

resource "aws_s3_bucket" "waf_logs" {
  bucket        = local.waf_log_bucket
  force_destroy = true
}

resource "aws_s3_bucket" "lb_logs" {
  bucket        = local.lb_log_bucket
  force_destroy = true
}

locals {
  log_bucket_ids = {
    waf = aws_s3_bucket.waf_logs.id
    lb  = aws_s3_bucket.lb_logs.id
  }
}

resource "aws_s3_bucket_ownership_controls" "logs" {
  for_each = local.log_bucket_ids

  bucket = each.value

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "logs" {
  for_each = local.log_bucket_ids

  bucket                  = each.value
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "logs" {
  for_each = local.log_bucket_ids

  bucket = each.value

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "waf_logs" {
  bucket = aws_s3_bucket.waf_logs.id

  rule {
    bucket_key_enabled = true

    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = data.aws_kms_alias.logs.target_key_arn
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "lb_logs" {
  bucket = aws_s3_bucket.lb_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  for_each = local.log_bucket_ids

  bucket = each.value

  rule {
    id     = "expire-after-retention"
    status = "Enabled"

    filter {}

    expiration {
      days = var.log_retention_days
    }

    noncurrent_version_expiration {
      noncurrent_days = 1
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  depends_on = [aws_s3_bucket_versioning.logs]
}

data "aws_iam_policy_document" "deny_insecure_transport" {
  for_each = local.log_buckets

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
}

data "aws_iam_policy_document" "waf_logs" {
  source_policy_documents = [data.aws_iam_policy_document.deny_insecure_transport["waf"].json]

  statement {
    sid       = "LogDeliveryWrites"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.waf_logs.arn}/*"]

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
      values   = local.log_delivery_source_arns
    }
  }

  statement {
    sid       = "LogDeliveryChecksTheBucket"
    actions   = ["s3:GetBucketAcl", "s3:ListBucket"]
    resources = [aws_s3_bucket.waf_logs.arn]

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
      values   = local.log_delivery_source_arns
    }
  }
}

# Elastic Load Balancing writes access logs as its regional account in Regions older than its service principal,
# which Tokyo and Osaka are; the service principal is named too, for when AWS moves them over.
data "aws_iam_policy_document" "lb_logs" {
  source_policy_documents = [data.aws_iam_policy_document.deny_insecure_transport["lb"].json]

  statement {
    sid       = "LoadBalancerWritesAccessLogs"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.lb_logs.arn}/AWSLogs/${var.account_id}/*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${local.elb_log_accounts[local.region]}:root"]
    }
  }

  statement {
    sid       = "LoadBalancerServiceWritesAccessLogs"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.lb_logs.arn}/AWSLogs/${var.account_id}/*"]

    principals {
      type        = "Service"
      identifiers = ["logdelivery.elasticloadbalancing.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.account_id]
    }
  }
}

resource "aws_s3_bucket_policy" "waf_logs" {
  bucket = aws_s3_bucket.waf_logs.id
  policy = data.aws_iam_policy_document.waf_logs.json

  depends_on = [aws_s3_bucket_public_access_block.logs]
}

resource "aws_s3_bucket_policy" "lb_logs" {
  bucket = aws_s3_bucket.lb_logs.id
  policy = data.aws_iam_policy_document.lb_logs.json

  depends_on = [aws_s3_bucket_public_access_block.logs]
}
