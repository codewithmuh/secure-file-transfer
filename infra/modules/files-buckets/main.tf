# One Region's files buckets (ADR-0012, ADR-0019, encryption 3.1): `files` for files up to 2 GB and `large-files` for
# larger ones, with the same settings and key. Tokyo's replicate to Osaka's with RTC; Osaka's are the pilot light's
# replicas. Called once per Region with different inputs, so both come from the same code (T-79).
#
# - Versioning on (replication needs it, and a scan pins the version it checked, T-32); no Object Lock and no AWS
#   Backup plan, so nothing keeps a copy deletion can't reach (NFR-8).
# - SSE-KMS with the files key and S3 Bucket Keys as the default. The bucket policy (policy.tf) refuses other keys,
#   SSE-C and requests without TLS 1.2, and names who may read, write, tag and delete.
# - Lifecycle rules as safety nets, in each Region because they don't replicate.
# - Replication (replication.tf) and GuardDuty Malware Protection on the large-files bucket (malware-protection.tf).

data "aws_region" "current" {}

locals {
  region  = data.aws_region.current.region
  primary = local.region == "ap-northeast-1"

  region_short = {
    "ap-northeast-1" = "apne1"
    "ap-northeast-3" = "apne3"
  }[local.region]

  buckets = {
    files         = "sft-${var.environment}-${local.region_short}-files-${var.account_id}"
    "large-files" = "sft-${var.environment}-${local.region_short}-large-files-${var.account_id}"
  }

  # Osaka's buckets, the replication destinations, by name.
  osaka_buckets = { for k, name in local.buckets : k => replace(name, "-apne1-", "-apne3-") }

  role_arns = {
    for name in ["api", "scan", "jobs", "s3-replication", "malware-protection", "events-delivery"] :
    name => "arn:aws:iam::${var.account_id}:role/sft-${var.environment}-${name}"
  }
}

resource "aws_s3_bucket" "this" {
  for_each = local.buckets

  bucket        = each.value
  force_destroy = var.teardown_allowed

  tags = { component = "files" }
}

resource "aws_s3_bucket_ownership_controls" "this" {
  for_each = local.buckets

  bucket = aws_s3_bucket.this[each.key].id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "this" {
  for_each = local.buckets

  bucket = aws_s3_bucket.this[each.key].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "this" {
  for_each = local.buckets

  bucket = aws_s3_bucket.this[each.key].id

  versioning_configuration {
    status = "Enabled"
  }
}

# Pre-signed part uploads carry no encryption header, so every object gets this default (T-60).
resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  for_each = local.buckets

  bucket = aws_s3_bucket.this[each.key].id

  rule {
    bucket_key_enabled = true

    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
  }
}

# ADR-0012: noncurrent versions go after 7 days, unfinished multipart uploads after 7 days, and expired delete markers
# are removed. The deletion job deletes every version itself; these only catch what it misses (encryption 8.1).
resource "aws_s3_bucket_lifecycle_configuration" "this" {
  for_each = local.buckets

  bucket = aws_s3_bucket.this[each.key].id

  rule {
    id     = "safety-nets"
    status = "Enabled"

    filter {}

    noncurrent_version_expiration {
      noncurrent_days = 7
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }

    expiration {
      expired_object_delete_marker = true
    }
  }

  depends_on = [aws_s3_bucket_versioning.this]
}

# Browsers upload parts with pre-signed URLs and need each part's ETag back to complete the upload.
resource "aws_s3_bucket_cors_configuration" "this" {
  for_each = length(var.cors_allowed_origins) > 0 ? local.buckets : {}

  bucket = aws_s3_bucket.this[each.key].id

  cors_rule {
    allowed_methods = ["PUT"]
    allowed_origins = var.cors_allowed_origins
    allowed_headers = ["content-length", "content-md5", "content-type", "x-amz-checksum-sha256", "x-amz-sdk-checksum-algorithm"]
    expose_headers  = ["ETag"]
    max_age_seconds = 3600
  }
}
