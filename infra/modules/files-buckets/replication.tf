# Replication from Tokyo to Osaka with S3 Replication Time Control (ADR-0012, NFR-10, encryption 2.3).
#
# - Its own role, sft-<env>-s3-replication, made in Tokyo for both Regions. Its trust names our Tokyo buckets, which
#   also covers the audit archive in dev and staging, whose module adds its own policy to the role.
# - S3 decrypts with the Tokyo files key and re-encrypts each replica with the Osaka replica named in the rule.
# - Object tags replicate (GetObjectVersionTagging, ReplicateTags), so the `scan` tag reaches Osaka.
# - Delete marker replication stays off: nothing creates delete markers on purpose, and the deletion job deletes every
#   version in each Region itself (encryption 8.1).
# - RTC replicates 99.99 % of objects within 15 minutes, NFR-10's bound, and publishes the metrics and missed-threshold
#   events the alarms use.

locals {
  replication_role = var.create_iam_roles && var.with_osaka
  replicate        = local.primary && var.replicate_to_osaka
}

data "aws_iam_policy_document" "replication_trust" {
  count = local.replication_role ? 1 : 0

  statement {
    sid     = "S3ForOurTokyoBuckets"
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
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:aws:s3:::sft-${var.environment}-apne1-*-${var.account_id}"]
    }
  }
}

resource "aws_iam_role" "replication" {
  count = local.replication_role ? 1 : 0

  name                 = "sft-${var.environment}-s3-replication"
  description          = "S3 replication of sft-${var.environment} buckets from Tokyo to Osaka (ADR-0012)."
  assume_role_policy   = data.aws_iam_policy_document.replication_trust[0].json
  max_session_duration = 3600

  tags = { component = "files" }
}

data "aws_iam_policy_document" "replication" {
  count = local.replication_role ? 1 : 0

  statement {
    sid       = "ReadSourceConfiguration"
    actions   = ["s3:GetReplicationConfiguration", "s3:ListBucket"]
    resources = [for name in values(local.buckets) : "arn:aws:s3:::${name}"]
  }

  statement {
    sid = "ReadSourceVersions"
    actions = [
      "s3:GetObjectVersionForReplication", "s3:GetObjectVersionAcl", "s3:GetObjectVersionTagging",
    ]
    resources = [for name in values(local.buckets) : "arn:aws:s3:::${name}/*"]
  }

  statement {
    sid       = "WriteReplicas"
    actions   = ["s3:ReplicateObject", "s3:ReplicateDelete", "s3:ReplicateTags"]
    resources = [for name in values(local.osaka_buckets) : "arn:aws:s3:::${name}/*"]
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
      values   = [for name in values(local.buckets) : "arn:aws:s3:::${name}"]
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
      values   = [for name in values(local.osaka_buckets) : "arn:aws:s3:::${name}"]
    }
  }
}

resource "aws_iam_role_policy" "replication" {
  count = local.replication_role ? 1 : 0

  name   = "files-buckets"
  role   = aws_iam_role.replication[0].id
  policy = data.aws_iam_policy_document.replication[0].json

  lifecycle {
    precondition {
      condition     = var.osaka_kms_key_arn != null
      error_message = "With with_osaka, Tokyo needs osaka_kms_key_arn for the replication role."
    }
  }
}

resource "aws_s3_bucket_replication_configuration" "this" {
  for_each = local.replicate ? local.buckets : {}

  bucket = aws_s3_bucket.this[each.key].id
  role   = aws_iam_role.replication[0].arn

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
      bucket        = "arn:aws:s3:::${local.osaka_buckets[each.key]}"
      storage_class = "STANDARD"

      encryption_configuration {
        replica_kms_key_id = var.osaka_kms_key_arn
      }

      replication_time {
        status = "Enabled"

        time {
          minutes = 15
        }
      }

      metrics {
        status = "Enabled"

        event_threshold {
          minutes = 15
        }
      }
    }
  }

  depends_on = [aws_s3_bucket_versioning.this, aws_iam_role_policy.replication]
}
