# Loki's and Tempo's buckets in this Region (ADR-0009, encryption 3.1): sft-<env>-<region-short>-{loki,tempo}-<account>,
# SSE-KMS with the environment's logs key and its bucket key, private, TLS only. Logs and traces are customer data
# under NFR-21 and stay in this Region; nothing replicates them, and after a failover Osaka starts with empty history
# while Tokyo's stays in Tokyo's buckets (ADR-0009).
#
# Loki and Tempo delete what passes their retention themselves; the lifecycle rule removes anything that outlives it
# by a few days (a stopped compactor), and incomplete uploads. No versioning: each store writes an object once and
# deletes it at retention, and a version kept after that would keep data past its retention.

locals {
  stores = {
    loki  = { bucket = "${local.name_prefix}-loki-${var.account_id}", days = var.loki_retention_days }
    tempo = { bucket = "${local.name_prefix}-tempo-${var.account_id}", days = var.tempo_retention_days }
  }
}

resource "aws_s3_bucket" "store" {
  for_each = local.stores

  bucket = each.value.bucket
  # Derived data: an environment's teardown removes it with its contents (NFR-19).
  force_destroy = true

  tags = {
    component = "observability"
  }
}

resource "aws_s3_bucket_ownership_controls" "store" {
  for_each = local.stores

  bucket = aws_s3_bucket.store[each.key].id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "store" {
  for_each = local.stores

  bucket                  = aws_s3_bucket.store[each.key].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "store" {
  for_each = local.stores

  bucket = aws_s3_bucket.store[each.key].id

  rule {
    bucket_key_enabled = true

    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.logs_key_arn
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "store" {
  for_each = local.stores

  bucket = aws_s3_bucket.store[each.key].id

  rule {
    id     = "expire-after-retention"
    status = "Enabled"

    filter {}

    expiration {
      days = each.value.days
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }
}

# TLS only, and writes only under the logs key: a write that names another key is refused; one that names none gets the
# bucket's default, the logs key.
data "aws_iam_policy_document" "store" {
  for_each = local.stores

  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.store[each.key].arn, "${aws_s3_bucket.store[each.key].arn}/*"]

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
    sid       = "DenyOtherKeys"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.store[each.key].arn}/*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "StringNotEqualsIfExists"
      variable = "s3:x-amz-server-side-encryption-aws-kms-key-id"
      values   = [var.logs_key_arn]
    }
  }
}

resource "aws_s3_bucket_policy" "store" {
  for_each = local.stores

  bucket = aws_s3_bucket.store[each.key].id
  policy = data.aws_iam_policy_document.store[each.key].json

  depends_on = [aws_s3_bucket_public_access_block.store]
}
