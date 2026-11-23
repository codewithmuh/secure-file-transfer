# The organization's log archive, in the shared account (ADR-0006, T-73, T-75, authn-authz 8.3,
# encryption 3.1).
#
# - The organization trail writes here: every account and Region, management events, and S3 data events on every
#   Terraform state bucket, which are the state buckets' access log instead of S3 server access logs (.trivyignore.yaml,
#   AVD-AWS-0089). The organization stack creates it in the management account (#318): one created here, as CloudTrail's
#   delegated administrator, belongs to the management account anyway, and the provider can't read it back from here.
# - The archive bucket, sft-shared-apne1-log-archive-<account-id> (the name the AuditReader permission set reads), is
#   under Object Lock in compliance mode for 90 days, so nobody, BreakGlass and the account's own administrators
#   included, can change or delete a record before then. The environments' own trails deliver their files buckets'
#   data events here too, each to its own account's prefix (authn-authz 8.3).
# - Everything is encrypted with the shared account's logs key, which CloudTrail uses only for our accounts' trails.

data "aws_region" "current" {}

data "aws_organizations_organization" "current" {
  return_organization_only = true
}

locals {
  region       = data.aws_region.current.region
  account_root = "arn:aws:iam::${var.account_id}:root"
  bucket_arn   = "arn:aws:s3:::${var.bucket_name}"
  org_id       = data.aws_organizations_organization.current.id

  # Created by a delegated administrator, an organization trail belongs to the management account, so its ARN may
  # carry either account. Both are named; nothing else can match.
  organization_trail_arns = [
    for account in [var.management_account_id, var.account_id] :
    "arn:aws:cloudtrail:${local.region}:${account}:trail/${var.trail_name}"
  ]

  # Every environment's own trails, in any of its Regions (authn-authz 8.3).
  environment_trail_patterns = [for account in values(var.member_account_ids) : "arn:aws:cloudtrail:*:${account}:trail/*"]
  all_trail_patterns         = concat(local.organization_trail_arns, local.environment_trail_patterns)

  # IAM Identity Center's role for the AuditReader permission set in this account.
  audit_reader_pattern = "arn:aws:iam::${var.account_id}:role/aws-reserved/sso.amazonaws.com/*AWSReservedSSO_AuditReader_*"

  # Who may change the archive's guards: the deploy role, which applies this stack, and Admin.
  guard_principal_patterns = concat([var.deploy_role_arn], var.admin_principal_arn_patterns)
}

# --- Logs key ----------------------------------------------------------------------------------------------------

data "aws_iam_policy_document" "key_use" {
  statement {
    sid       = "CloudTrailEncryptsOurTrails"
    actions   = ["kms:GenerateDataKey*"]
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = local.all_trail_patterns
    }

    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:cloudtrail:arn"
      values   = local.all_trail_patterns
    }
  }

  statement {
    sid       = "CloudTrailDescribesTheKey"
    actions   = ["kms:DescribeKey"]
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = local.all_trail_patterns
    }
  }

  # AuditReader reads the archive, decrypting through S3 only (encryption 8.4).
  statement {
    sid       = "AuditReaderDecryptsThroughS3"
    actions   = ["kms:Decrypt"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [local.account_root]
    }

    condition {
      test     = "ArnLike"
      variable = "aws:PrincipalArn"
      values   = [local.audit_reader_pattern]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${local.region}.amazonaws.com"]
    }
  }
}

module "key_policy" {
  source = "../key-policy"

  account_id                         = var.account_id
  deploy_role_arn                    = var.deploy_role_arn
  plan_role_arn                      = var.plan_role_arn
  key_admin_role_arn                 = var.key_admin_role_arn
  break_glass_principal_arn_patterns = var.break_glass_principal_arn_patterns
  additional_policy_documents        = [data.aws_iam_policy_document.key_use.json]
}

resource "aws_kms_key" "logs" {
  description             = "The organization's log archive (ADR-0006)"
  enable_key_rotation     = true
  rotation_period_in_days = 365
  deletion_window_in_days = 30
  policy                  = module.key_policy.json
}

resource "aws_kms_alias" "logs" {
  name          = "${var.kms_alias_prefix}/logs"
  target_key_id = aws_kms_key.logs.key_id
}

# --- Archive bucket ----------------------------------------------------------------------------------------------

resource "aws_s3_bucket" "archive" {
  bucket              = var.bucket_name
  object_lock_enabled = true
}

resource "aws_s3_bucket_ownership_controls" "archive" {
  bucket = aws_s3_bucket.archive.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "archive" {
  bucket = aws_s3_bucket.archive.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "archive" {
  bucket = aws_s3_bucket.archive.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "archive" {
  bucket = aws_s3_bucket.archive.id

  rule {
    bucket_key_enabled = true

    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.logs.arn
    }
  }
}

# Compliance mode: no principal can shorten the retention or delete a locked version before it ends (T-75). After the
# final teardown the bucket keeps billing a few cents until the last records expire (ADR-0006, NFR-19).
resource "aws_s3_bucket_object_lock_configuration" "archive" {
  bucket = aws_s3_bucket.archive.id

  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = var.retention_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.archive]
}

# Records expire once their lock ends (architecture 5.5): the current version becomes noncurrent at the retention
# period, and S3 removes it a day later, when the lock no longer holds it.
resource "aws_s3_bucket_lifecycle_configuration" "archive" {
  bucket = aws_s3_bucket.archive.id

  rule {
    id     = "expire-after-retention"
    status = "Enabled"

    filter {}

    expiration {
      days = var.retention_days
    }

    noncurrent_version_expiration {
      noncurrent_days = 1
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  rule {
    id     = "remove-expired-delete-markers"
    status = "Enabled"

    filter {}

    expiration {
      expired_object_delete_marker = true
    }
  }

  depends_on = [aws_s3_bucket_versioning.archive]
}

data "aws_iam_policy_document" "archive" {
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

  # Nobody but the deploy role and Admin changes what protects the records. No SCP covers this bucket, so its policy
  # holds the guard itself (T-75).
  statement {
    sid    = "OnlyTerraformAndAdminChangeTheGuards"
    effect = "Deny"
    actions = [
      "s3:DeleteBucket", "s3:DeleteBucketPolicy", "s3:PutBucketObjectLockConfiguration", "s3:PutBucketPolicy",
      "s3:PutBucketPublicAccessBlock", "s3:PutBucketVersioning", "s3:PutEncryptionConfiguration",
      "s3:PutLifecycleConfiguration", "s3:PutBucketOwnershipControls", "s3:PutReplicationConfiguration",
    ]
    resources = [local.bucket_arn]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "ArnNotLike"
      variable = "aws:PrincipalArn"
      values   = local.guard_principal_patterns
    }
  }

  statement {
    sid       = "CloudTrailChecksTheBucket"
    actions   = ["s3:GetBucketAcl"]
    resources = [local.bucket_arn]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = local.all_trail_patterns
    }
  }

  # The organization trail writes under the management account's prefix and the organization's.
  statement {
    sid     = "OrganizationTrailWrites"
    actions = ["s3:PutObject"]
    resources = [
      "${local.bucket_arn}/AWSLogs/${var.management_account_id}/*",
      "${local.bucket_arn}/AWSLogs/${local.org_id}/*",
    ]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = local.organization_trail_arns
    }
  }

  # Each environment's own trail writes only under its own account's prefix.
  dynamic "statement" {
    for_each = var.member_account_ids

    content {
      sid       = "${title(statement.key)}TrailWrites"
      actions   = ["s3:PutObject"]
      resources = ["${local.bucket_arn}/AWSLogs/${statement.value}/*"]

      principals {
        type        = "Service"
        identifiers = ["cloudtrail.amazonaws.com"]
      }

      condition {
        test     = "ArnLike"
        variable = "aws:SourceArn"
        values   = ["arn:aws:cloudtrail:*:${statement.value}:trail/*"]
      }
    }
  }
}

resource "aws_s3_bucket_policy" "archive" {
  bucket = aws_s3_bucket.archive.id
  policy = data.aws_iam_policy_document.archive.json

  depends_on = [aws_s3_bucket_public_access_block.archive]
}
