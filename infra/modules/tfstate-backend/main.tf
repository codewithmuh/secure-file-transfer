# The Terraform state bucket and tfstate key for one account and Region (ADR-0005, T-73, encryption 4.1 and 4.4).
#
# - The bucket is versioned, blocks public access and encrypts every object with the tfstate key through S3 Bucket
#   Keys. Locking uses S3 native lock files (use_lockfile), so there is no DynamoDB table.
# - Only the Terraform roles and the bootstrap admins may read or write objects. The plan role may write and delete
#   only the .tflock lock files, and may use the key only to decrypt and generate data keys.
# - In Tokyo the key is a multi-Region primary. In Osaka (staging and prod) it is that key's replica, created here
#   from the primary's ARN, so Osaka's state never needs Tokyo once the replica exists.
#
# Access is granted by the bucket and key policies, not by identity policies, so each Region's bootstrap stack fully
# describes who can reach its state, and Osaka's needs no IAM change.

data "aws_region" "current" {}

locals {
  bucket_arn     = "arn:aws:s3:::${var.bucket_name}"
  account_root   = "arn:aws:iam::${var.account_id}:root"
  create_primary = var.primary_key_arn == null
  key_arn        = local.create_primary ? aws_kms_key.state[0].arn : aws_kms_replica_key.state[0].arn
  s3_service     = "s3.${data.aws_region.current.region}.amazonaws.com"

  # Who may touch state objects at all. Everyone else is denied, whatever their identity policies allow.
  state_principal_arns = concat(
    var.admin_principal_arn_patterns,
    compact([var.plan_role_arn, var.deploy_role_arn]),
  )

  key_admin_actions = [
    "kms:DescribeKey", "kms:GetKeyPolicy", "kms:GetKeyRotationStatus", "kms:ListKeyRotations",
    "kms:ListResourceTags", "kms:ListGrants", "kms:ListKeyPolicies", "kms:PutKeyPolicy", "kms:UpdateKeyDescription",
    "kms:EnableKeyRotation", "kms:DisableKeyRotation", "kms:RotateKeyOnDemand", "kms:TagResource",
    "kms:UntagResource", "kms:CreateAlias", "kms:UpdateAlias", "kms:DeleteAlias", "kms:RevokeGrant", "kms:EnableKey",
    "kms:DisableKey", "kms:ScheduleKeyDeletion", "kms:CancelKeyDeletion",
  ]
}

# --- Key ---------------------------------------------------------------------------------------------------------

data "aws_iam_policy_document" "key" {
  # Named principals only: no kms:* for the account root (encryption 4.4, rule 1). The bootstrap admins are matched by
  # role ARN pattern, because Identity Center adds a random suffix to each permission set's role name.
  statement {
    sid       = "BootstrapAdminsAdministerTheKey"
    actions   = local.key_admin_actions
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [local.account_root]
    }

    condition {
      test     = "ArnLike"
      variable = "aws:PrincipalArn"
      values   = var.admin_principal_arn_patterns
    }
  }

  # Replicas only in Osaka (rule 4).
  statement {
    sid       = "BootstrapAdminsReplicateToOsakaOnly"
    actions   = ["kms:ReplicateKey"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [local.account_root]
    }

    condition {
      test     = "ArnLike"
      variable = "aws:PrincipalArn"
      values   = var.admin_principal_arn_patterns
    }

    condition {
      test     = "StringEquals"
      variable = "kms:ReplicaRegion"
      values   = ["ap-northeast-3"]
    }
  }

  # The bootstrap and organization stacks keep their own state here, so the admins who apply them use the key, but
  # only through S3 and only for this bucket (rule 2's exception for state).
  statement {
    sid       = "BootstrapAdminsUseStateThroughS3"
    actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [local.account_root]
    }

    condition {
      test     = "ArnLike"
      variable = "aws:PrincipalArn"
      values   = var.admin_principal_arn_patterns
    }

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = [local.s3_service]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:EncryptionContext:aws:s3:arn"
      values   = [local.bucket_arn]
    }
  }

  # Plan and deploy roles: decrypt and generate data keys, through S3, for this bucket only. The plan role needs data
  # keys to write its lock files; the bucket policy stops it writing state.
  statement {
    sid       = "TerraformRolesUseStateThroughS3"
    actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = compact([var.plan_role_arn, var.deploy_role_arn])
    }

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = [local.s3_service]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:EncryptionContext:aws:s3:arn"
      values   = [local.bucket_arn]
    }
  }

  # The key-admin role can only read and put the key policy, to repair one (rule 6).
  dynamic "statement" {
    for_each = var.key_admin_role_arn == null ? [] : [var.key_admin_role_arn]

    content {
      sid       = "KeyAdminRepairsThePolicy"
      actions   = ["kms:GetKeyPolicy", "kms:PutKeyPolicy"]
      resources = ["*"]

      principals {
        type        = "AWS"
        identifiers = [statement.value]
      }
    }
  }

  # BreakGlass recovers, it doesn't administer or read state (rule 6, table 4.3).
  dynamic "statement" {
    for_each = length(var.break_glass_principal_arn_patterns) == 0 ? [] : [var.break_glass_principal_arn_patterns]

    content {
      sid = "BreakGlassRecovers"
      actions = [
        "kms:DescribeKey", "kms:GetKeyPolicy", "kms:GetKeyRotationStatus", "kms:ListResourceTags", "kms:ListGrants",
        "kms:RevokeGrant", "kms:EnableKey", "kms:CancelKeyDeletion",
      ]
      resources = ["*"]

      principals {
        type        = "AWS"
        identifiers = [local.account_root]
      }

      condition {
        test     = "ArnLike"
        variable = "aws:PrincipalArn"
        values   = statement.value
      }
    }
  }

  # Repeats the SCP (decision 13), so it holds even if the SCP changes: only the bootstrap admins disable or delete
  # the key, and never with a shorter wait than this environment's.
  statement {
    sid       = "DenyDisableOrDeleteExceptBootstrapAdmins"
    effect    = "Deny"
    actions   = ["kms:DisableKey", "kms:ScheduleKeyDeletion"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "ArnNotLike"
      variable = "aws:PrincipalArn"
      values   = var.admin_principal_arn_patterns
    }
  }

  statement {
    sid       = "RequireTheEnvironmentsDeletionWait"
    effect    = "Deny"
    actions   = ["kms:ScheduleKeyDeletion"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "NumericLessThan"
      variable = "kms:ScheduleKeyDeletionPendingWindowInDays"
      values   = [tostring(var.deletion_window_in_days)]
    }
  }
}

resource "aws_kms_key" "state" {
  count = local.create_primary ? 1 : 0

  description             = "Terraform state in ${var.bucket_name}"
  multi_region            = true
  enable_key_rotation     = true
  rotation_period_in_days = 365
  deletion_window_in_days = var.deletion_window_in_days
  policy                  = data.aws_iam_policy_document.key.json

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_kms_replica_key" "state" {
  count = local.create_primary ? 0 : 1

  description             = "Terraform state in ${var.bucket_name}"
  primary_key_arn         = var.primary_key_arn
  deletion_window_in_days = var.deletion_window_in_days
  policy                  = data.aws_iam_policy_document.key.json

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_kms_alias" "state" {
  name          = var.kms_alias
  target_key_id = local.key_arn
}

# --- Bucket ------------------------------------------------------------------------------------------------------

resource "aws_s3_bucket" "state" {
  bucket = var.bucket_name

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_ownership_controls" "state" {
  bucket = aws_s3_bucket.state.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "state" {
  bucket = aws_s3_bucket.state.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "state" {
  bucket = aws_s3_bucket.state.id

  versioning_configuration {
    status = "Enabled"
  }
}

# The backend sets no encryption header (encrypt is left off, because encrypt = true without kms_key_id asks for
# SSE-S3), so every object gets this default. The bucket policy refuses any other encryption.
resource "aws_s3_bucket_server_side_encryption_configuration" "state" {
  bucket = aws_s3_bucket.state.id

  rule {
    bucket_key_enabled = true

    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = local.key_arn
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "state" {
  bucket = aws_s3_bucket.state.id

  # Old state versions are the history to roll back to. Keep every version for the retention period, and the last
  # ten of each state whatever their age. Lock files leave versions and delete markers behind; this clears them too.
  rule {
    id     = "expire-old-versions"
    status = "Enabled"

    filter {}

    noncurrent_version_expiration {
      noncurrent_days           = var.noncurrent_version_retention_days
      newer_noncurrent_versions = 10
    }

    expiration {
      expired_object_delete_marker = true
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  depends_on = [aws_s3_bucket_versioning.state]
}

data "aws_iam_policy_document" "bucket" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [local.bucket_arn, "${local.bucket_arn}/*"]

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
    resources = [local.bucket_arn, "${local.bucket_arn}/*"]

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

  # T-73: state is readable only by the Terraform roles and the bootstrap admins, whatever other identity policies in
  # the account allow (BreakGlass and ReadOnly included).
  statement {
    sid    = "DenyStateAccessToEveryoneElse"
    effect = "Deny"
    actions = [
      "s3:GetObject", "s3:GetObjectVersion", "s3:GetObjectAttributes", "s3:GetObjectVersionAttributes",
      "s3:PutObject", "s3:DeleteObject", "s3:DeleteObjectVersion", "s3:RestoreObject",
      "s3:ListBucket", "s3:ListBucketVersions",
    ]
    resources = [local.bucket_arn, "${local.bucket_arn}/*"]

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

  # ADR-0005: the plan role writes and deletes only lock files, never state.
  statement {
    sid           = "DenyPlanRoleWritesExceptLockFiles"
    effect        = "Deny"
    actions       = ["s3:PutObject", "s3:DeleteObject"]
    not_resources = ["${local.bucket_arn}/*.tflock"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:PrincipalArn"
      values   = [var.plan_role_arn]
    }
  }

  statement {
    sid       = "DenyPlanRoleVersionDeletes"
    effect    = "Deny"
    actions   = ["s3:DeleteObjectVersion"]
    resources = ["${local.bucket_arn}/*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:PrincipalArn"
      values   = [var.plan_role_arn]
    }
  }

  # Objects are encrypted with the tfstate key or not written: a request may leave encryption to the bucket default,
  # but may not ask for anything else.
  statement {
    sid       = "DenyOtherEncryption"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["${local.bucket_arn}/*"]

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
    resources = ["${local.bucket_arn}/*"]

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
      values   = [local.key_arn]
    }
  }

  statement {
    sid       = "TerraformRolesListState"
    actions   = ["s3:ListBucket"]
    resources = [local.bucket_arn]

    principals {
      type        = "AWS"
      identifiers = compact([var.plan_role_arn, var.deploy_role_arn])
    }
  }

  statement {
    sid       = "TerraformRolesReadState"
    actions   = ["s3:GetObject"]
    resources = ["${local.bucket_arn}/*"]

    principals {
      type        = "AWS"
      identifiers = compact([var.plan_role_arn, var.deploy_role_arn])
    }
  }

  statement {
    sid       = "PlanRoleWritesLockFiles"
    actions   = ["s3:PutObject", "s3:DeleteObject"]
    resources = ["${local.bucket_arn}/*.tflock"]

    principals {
      type        = "AWS"
      identifiers = [var.plan_role_arn]
    }
  }

  dynamic "statement" {
    for_each = var.deploy_role_arn == null ? [] : [var.deploy_role_arn]

    content {
      sid       = "DeployRoleWritesState"
      actions   = ["s3:PutObject", "s3:DeleteObject"]
      resources = ["${local.bucket_arn}/*"]

      principals {
        type        = "AWS"
        identifiers = [statement.value]
      }
    }
  }
}

resource "aws_s3_bucket_policy" "state" {
  bucket = aws_s3_bucket.state.id
  policy = data.aws_iam_policy_document.bucket.json

  depends_on = [aws_s3_bucket_public_access_block.state]
}
