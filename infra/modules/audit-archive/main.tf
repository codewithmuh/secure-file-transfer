# One Region's audit archive bucket (ADR-0012, encryption 3.1 and 8.4, NFR-9, NFR-15): versioned, SSE-KMS with the
# audit key and S3 Bucket Keys, Object Lock in compliance mode for 365 days in prod and governance mode for 1 day in
# dev and staging. Tokyo's replicates batches to Osaka's, without RTC; the API and the operator API also write
# security-critical records straight to both (architecture 5.2), which never depends on replication.
#
# dev and staging call it from the data layer. prod calls it from the retained stack, with prevent_destroy, its own
# deploy role and its own replication role, so no environment teardown reaches it.

data "aws_region" "current" {}

locals {
  region  = data.aws_region.current.region
  primary = local.region == "ap-northeast-1"

  prefixes = {
    for r, short in var.conventions.region_shorts : r => "${var.conventions.global_name_prefix}-${short}"
  }

  bucket_name       = "${local.prefixes[local.region]}-audit-archive-${var.account_id}"
  bucket_arn        = "arn:aws:s3:::${local.bucket_name}"
  osaka_bucket_name = "${local.prefixes["ap-northeast-3"]}-audit-archive-${var.account_id}"

  # Whichever of the two bucket resources below exists. The settings refer to it directly, with the same choice, so
  # Trivy can tie them to the bucket.
  bucket_id = one(concat(aws_s3_bucket.guarded[*].id, aws_s3_bucket.unguarded[*].id))

  # The workload roles, from their one list (modules/conventions, #172).
  role_arns = var.conventions.workload_role_arns

  replication_role_name = coalesce(var.replication_role_name, var.conventions.workload_role_names["s3-replication"])
  replication_role_arn  = "arn:aws:iam::${var.account_id}:role/${local.replication_role_name}"

  # Identity Center's role for the AuditReader permission set (infra/organization/identity-center.tf).
  audit_reader_arn_patterns = [
    "arn:aws:iam::${var.account_id}:role/aws-reserved/sso.amazonaws.com/*AWSReservedSSO_AuditReader_*",
  ]
}

# prevent_destroy can't take a variable, so the guarded and unguarded buckets are separate resources.
resource "aws_s3_bucket" "guarded" {
  count = var.prevent_destroy ? 1 : 0

  bucket              = local.bucket_name
  object_lock_enabled = true

  tags = { component = "audit-archive" }

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket" "unguarded" {
  count = var.prevent_destroy ? 0 : 1

  bucket              = local.bucket_name
  object_lock_enabled = true
  force_destroy       = var.teardown_allowed

  tags = { component = "audit-archive" }
}

resource "aws_s3_bucket_ownership_controls" "this" {
  bucket = var.prevent_destroy ? aws_s3_bucket.guarded[0].id : aws_s3_bucket.unguarded[0].id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "this" {
  bucket = var.prevent_destroy ? aws_s3_bucket.guarded[0].id : aws_s3_bucket.unguarded[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "this" {
  bucket = var.prevent_destroy ? aws_s3_bucket.guarded[0].id : aws_s3_bucket.unguarded[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "this" {
  bucket = var.prevent_destroy ? aws_s3_bucket.guarded[0].id : aws_s3_bucket.unguarded[0].id

  rule {
    default_retention {
      mode = var.object_lock_mode
      days = var.object_lock_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.this]
}

resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  bucket = var.prevent_destroy ? aws_s3_bucket.guarded[0].id : aws_s3_bucket.unguarded[0].id

  rule {
    bucket_key_enabled = true

    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
  }
}

# ADR-0012, NFR-9: a current version expires when its retention ends, which in a versioned bucket only adds a delete
# marker; the version itself goes 1 day after it becomes noncurrent, about day 366. Expired delete markers are removed.
# Lifecycle rules don't replicate, so each Region has its own.
resource "aws_s3_bucket_lifecycle_configuration" "this" {
  bucket = var.prevent_destroy ? aws_s3_bucket.guarded[0].id : aws_s3_bucket.unguarded[0].id

  rule {
    id     = "retention"
    status = "Enabled"

    filter {}

    expiration {
      days = var.expiration_days
    }

    noncurrent_version_expiration {
      noncurrent_days = 1
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  rule {
    id     = "expired-delete-markers"
    status = "Enabled"

    filter {}

    expiration {
      expired_object_delete_marker = true
    }
  }

  depends_on = [aws_s3_bucket_versioning.this]
}
