# Replication between the Regions with S3 Replication Time Control (ADR-0012, NFR-10, encryption 2.3).
#
# - Its own role, sft-<env>-s3-replication, made in Tokyo for both Regions. Its trust names our buckets in both
#   Regions, which also covers the audit archive in dev and staging, whose module adds its own policy to the role.
# - Tokyo to Osaka (`to-osaka`) always, once Osaka is ready. S3 decrypts with the Tokyo files key and re-encrypts each
#   replica with the Osaka replica named in the rule.
# - Osaka to Tokyo (`to-tokyo`) only at a failback (replicate_to_tokyo, #262, #42 gap 4): the files uploaded in Osaka
#   during a failover must reach Tokyo before Tokyo serves again. S3 never replicates a replica again, so only the
#   objects created in Osaka go back. The objects created before the rule existed go by S3 Batch Replication, run by
#   the failback runbook as sft-<env>-s3-batch-replication (below). The role's permissions cover both directions all
#   the time, so the failback changes only Osaka's stack; the rule itself is what decides.
# - Object tags replicate (GetObjectVersionTagging, ReplicateTags), so the `scan` tag travels with each file.
# - Delete marker replication stays off: nothing creates delete markers on purpose, and the deletion job deletes every
#   version in each Region itself (encryption 8.1).
# - RTC replicates 99.99 % of objects within 15 minutes, NFR-10's bound, and publishes the metrics and missed-threshold
#   events the alarms use.

locals {
  replication_role  = var.create_iam_roles && var.with_osaka
  replicate         = local.primary && var.replicate_to_osaka
  replicate_reverse = !local.primary && var.replicate_to_tokyo

  # Both Regions' buckets and files keys. Osaka's files key is Tokyo's replica, so it keeps the key ID (encryption 4.2).
  files_key_arns = {
    "ap-northeast-1" = local.primary ? var.kms_key_arn : replace(var.kms_key_arn, ":ap-northeast-3:", ":ap-northeast-1:")
    "ap-northeast-3" = local.primary ? var.osaka_kms_key_arn : var.kms_key_arn
  }
  replication_directions = {
    to-osaka = { source = local.tokyo_buckets, destination = local.osaka_buckets, from = "ap-northeast-1", to = "ap-northeast-3" }
    to-tokyo = { source = local.osaka_buckets, destination = local.tokyo_buckets, from = "ap-northeast-3", to = "ap-northeast-1" }
  }
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
      values   = [for r in ["ap-northeast-1", "ap-northeast-3"] : "arn:aws:s3:::${local.prefixes[r]}-*-${var.account_id}"]
    }
  }
}

resource "aws_iam_role" "replication" {
  count = local.replication_role ? 1 : 0

  name                 = var.conventions.workload_role_names["s3-replication"]
  description          = "S3 replication of ${var.conventions.global_name_prefix} buckets between Tokyo and Osaka (ADR-0012)."
  assume_role_policy   = data.aws_iam_policy_document.replication_trust[0].json
  max_session_duration = 3600

  tags = { component = "files" }
}

data "aws_iam_policy_document" "replication" {
  count = local.replication_role ? 1 : 0

  # The same five statements for each direction: read the source's settings and versions, write the destination's
  # replicas, decrypt in the source Region and re-encrypt in the destination's.
  dynamic "statement" {
    for_each = local.replication_directions

    content {
      sid       = "ReadSourceConfiguration${replace(title(statement.key), "-", "")}"
      actions   = ["s3:GetReplicationConfiguration", "s3:ListBucket"]
      resources = [for name in values(statement.value.source) : "arn:aws:s3:::${name}"]
    }
  }

  dynamic "statement" {
    for_each = local.replication_directions

    content {
      sid = "ReadSourceVersions${replace(title(statement.key), "-", "")}"
      actions = [
        "s3:GetObjectVersionForReplication", "s3:GetObjectVersionAcl", "s3:GetObjectVersionTagging",
      ]
      resources = [for name in values(statement.value.source) : "arn:aws:s3:::${name}/*"]
    }
  }

  dynamic "statement" {
    for_each = local.replication_directions

    content {
      sid       = "WriteReplicas${replace(title(statement.key), "-", "")}"
      actions   = ["s3:ReplicateObject", "s3:ReplicateDelete", "s3:ReplicateTags"]
      resources = [for name in values(statement.value.destination) : "arn:aws:s3:::${name}/*"]
    }
  }

  dynamic "statement" {
    for_each = local.replication_directions

    content {
      sid       = "DecryptAtSource${replace(title(statement.key), "-", "")}"
      actions   = ["kms:Decrypt"]
      resources = [local.files_key_arns[statement.value.from]]

      condition {
        test     = "StringEquals"
        variable = "kms:ViaService"
        values   = ["s3.${statement.value.from}.amazonaws.com"]
      }

      condition {
        test     = "StringEquals"
        variable = "kms:EncryptionContext:aws:s3:arn"
        values   = [for name in values(statement.value.source) : "arn:aws:s3:::${name}"]
      }
    }
  }

  dynamic "statement" {
    for_each = local.replication_directions

    content {
      sid       = "EncryptAtDestination${replace(title(statement.key), "-", "")}"
      actions   = ["kms:Encrypt", "kms:GenerateDataKey"]
      resources = [local.files_key_arns[statement.value.to]]

      condition {
        test     = "StringEquals"
        variable = "kms:ViaService"
        values   = ["s3.${statement.value.to}.amazonaws.com"]
      }

      condition {
        test     = "StringEquals"
        variable = "kms:EncryptionContext:aws:s3:arn"
        values   = [for name in values(statement.value.destination) : "arn:aws:s3:::${name}"]
      }
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

# The failback's reverse rule (#262): Osaka to Tokyo, with RTC, on both buckets. Osaka's stack sets it with
# TF_VAR_replicate_to_tokyo=true from the failback's step 2 until Osaka is back in its pilot light (step 8). The role
# is Tokyo's, by name: IAM is global.
resource "aws_s3_bucket_replication_configuration" "to_tokyo" {
  for_each = local.replicate_reverse ? local.buckets : {}

  bucket = aws_s3_bucket.this[each.key].id
  role   = var.conventions.workload_role_arns["s3-replication"]

  rule {
    id       = "to-tokyo"
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
      bucket        = "arn:aws:s3:::${local.tokyo_buckets[each.key]}"
      storage_class = "STANDARD"

      encryption_configuration {
        replica_kms_key_id = local.files_key_arns["ap-northeast-1"]
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

  depends_on = [aws_s3_bucket_versioning.this]
}

# sft-<env>-s3-batch-replication: the role S3 Batch Operations runs the failback's Batch Replication jobs as (#262,
# #42 gap 4). Each job lists Osaka's bucket for objects created since the failover that are eligible for the reverse
# rule, and asks S3 to replicate each one; the replication itself then runs as sft-<env>-s3-replication, under the
# rule. So this role reads no object and holds no key: it may only start replication and generate the job's manifest
# on our files buckets. Made in Tokyo, like the other roles; the failback runbook passes it to s3control create-job.
data "aws_iam_policy_document" "batch_replication_trust" {
  count = local.replication_role ? 1 : 0

  statement {
    sid     = "S3BatchOperationsInThisAccount"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["batchoperations.s3.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.account_id]
    }
  }
}

resource "aws_iam_role" "batch_replication" {
  count = local.replication_role ? 1 : 0

  name                 = var.conventions.workload_role_names["s3-batch-replication"]
  description          = "S3 Batch Replication of ${var.conventions.global_name_prefix} files written in Osaka back to Tokyo at a failback (#262)."
  assume_role_policy   = data.aws_iam_policy_document.batch_replication_trust[0].json
  max_session_duration = 3600

  tags = { component = "files" }
}

data "aws_iam_policy_document" "batch_replication" {
  count = local.replication_role ? 1 : 0

  # The manifest generator lists the source bucket and reads its replication configuration to find the eligible
  # objects (S3JobManifestGenerator with EligibleForReplication).
  statement {
    sid = "GenerateTheManifest"
    actions = [
      "s3:ListBucket", "s3:GetReplicationConfiguration", "s3:PutInventoryConfiguration",
    ]
    resources = [for name in concat(values(local.osaka_buckets), values(local.tokyo_buckets)) : "arn:aws:s3:::${name}"]
  }

  statement {
    sid       = "StartReplication"
    actions   = ["s3:InitiateReplication"]
    resources = [for name in concat(values(local.osaka_buckets), values(local.tokyo_buckets)) : "arn:aws:s3:::${name}/*"]
  }
}

resource "aws_iam_role_policy" "batch_replication" {
  count = local.replication_role ? 1 : 0

  name   = "files-buckets"
  role   = aws_iam_role.batch_replication[0].id
  policy = data.aws_iam_policy_document.batch_replication[0].json
}
