# Batches replicate from Tokyo to Osaka, without RTC (ADR-0012). Object Lock is on in both buckets, so locked objects
# replicate and replicas keep their retention. In dev and staging the role is the files buckets' sft-<env>-s3-replication,
# to which this adds its own policy; in prod it is the retained stack's own role, made here (encryption 8.4).

locals {
  replication_policy = local.primary && var.with_osaka && var.replication_role_name != null
  replicate          = local.primary && var.replicate_to_osaka
}

data "aws_iam_policy_document" "replication_trust" {
  count = local.primary && var.create_replication_role ? 1 : 0

  statement {
    sid     = "S3ForTheTokyoArchive"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["s3.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.account_id]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [local.bucket_arn]
    }
  }
}

resource "aws_iam_role" "replication" {
  count = local.primary && var.create_replication_role ? 1 : 0

  name                 = local.replication_role_name
  description          = "S3 replication of ${local.bucket_name} to Osaka (ADR-0012, encryption 8.4)."
  assume_role_policy   = data.aws_iam_policy_document.replication_trust[0].json
  max_session_duration = 3600

  tags = { component = "audit-archive" }
}

data "aws_iam_policy_document" "replication" {
  count = local.replication_policy ? 1 : 0

  statement {
    sid       = "ReadSourceConfiguration"
    actions   = ["s3:GetReplicationConfiguration", "s3:ListBucket"]
    resources = [local.bucket_arn]
  }

  statement {
    sid = "ReadSourceVersions"
    actions = [
      "s3:GetObjectVersionForReplication", "s3:GetObjectVersionAcl", "s3:GetObjectVersionTagging",
      "s3:GetObjectRetention", "s3:GetObjectLegalHold",
    ]
    resources = ["${local.bucket_arn}/*"]
  }

  statement {
    sid       = "WriteReplicas"
    actions   = ["s3:ReplicateObject", "s3:ReplicateDelete", "s3:ReplicateTags"]
    resources = ["arn:aws:s3:::${local.osaka_bucket_name}/*"]
  }

  statement {
    sid       = "DecryptInTokyo"
    actions   = ["kms:Decrypt"]
    resources = [var.kms_key_arn]

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.ap-northeast-1.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:EncryptionContext:aws:s3:arn"
      values   = [local.bucket_arn]
    }
  }

  statement {
    sid       = "EncryptInOsaka"
    actions   = ["kms:Encrypt", "kms:GenerateDataKey"]
    resources = [var.osaka_kms_key_arn]

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.ap-northeast-3.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:EncryptionContext:aws:s3:arn"
      values   = ["arn:aws:s3:::${local.osaka_bucket_name}"]
    }
  }
}

resource "aws_iam_role_policy" "replication" {
  count = local.replication_policy ? 1 : 0

  name   = "audit-archive"
  role   = var.create_replication_role ? aws_iam_role.replication[0].id : var.replication_role_name
  policy = data.aws_iam_policy_document.replication[0].json

  lifecycle {
    precondition {
      condition     = var.osaka_kms_key_arn != null
      error_message = "With with_osaka, Tokyo needs osaka_kms_key_arn for the replication role."
    }
  }
}

resource "aws_s3_bucket_replication_configuration" "this" {
  count = local.replicate ? 1 : 0

  bucket = var.prevent_destroy ? aws_s3_bucket.guarded[0].id : aws_s3_bucket.unguarded[0].id
  role   = local.replication_role_arn

  rule {
    id       = "to-osaka"
    status   = "Enabled"
    priority = 1

    filter {}

    delete_marker_replication {
      status = "Disabled"
    }

    source_selection_criteria {
      sse_kms_encrypted_objects {
        status = "Enabled"
      }
    }

    destination {
      bucket        = "arn:aws:s3:::${local.osaka_bucket_name}"
      storage_class = "STANDARD"

      encryption_configuration {
        replica_kms_key_id = var.osaka_kms_key_arn
      }
    }
  }

  depends_on = [aws_s3_bucket_versioning.this, aws_iam_role_policy.replication]
}
