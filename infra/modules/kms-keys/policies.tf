# Key policies, from encryption 4.3 (who may use each key) and 4.4 (the rules and sketches). Each class has its own
# document on top of the statements every key shares. Every workload statement is limited by kms:ViaService for the
# service in this Region and by encryption context: the bucket for S3, the queue for SQS, the secret for Secrets
# Manager, the log group or trail for logs, the purpose and tenant for the fields key.

locals {
  # A: every key management action, never encrypt or decrypt (4.3).
  administer_actions = [
    "kms:DescribeKey", "kms:GetKeyPolicy", "kms:GetKeyRotationStatus", "kms:ListKeyRotations",
    "kms:ListResourceTags", "kms:ListGrants", "kms:PutKeyPolicy", "kms:UpdateKeyDescription",
    "kms:EnableKeyRotation", "kms:DisableKeyRotation", "kms:RotateKeyOnDemand", "kms:TagResource",
    "kms:UntagResource", "kms:CreateAlias", "kms:UpdateAlias", "kms:DeleteAlias", "kms:ReplicateKey",
    "kms:RevokeGrant", "kms:EnableKey", "kms:DisableKey", "kms:ScheduleKeyDeletion", "kms:CancelKeyDeletion",
  ]

  # V: EBS volumes through EC2 (4.3).
  volume_actions = [
    "kms:GenerateDataKeyWithoutPlaintext", "kms:Decrypt", "kms:DescribeKey", "kms:ReEncryptFrom", "kms:ReEncryptTo",
  ]

  # The node provisioners' IAM roles, matched by aws:PrincipalArn like every role here, which their own policies also
  # allow: Karpenter for the nodes it launches and the EBS CSI driver for the observability volumes (#103).
  root_volume_principals = [local.role_arns["karpenter"], local.role_arns["ebs-csi"]]
  scan_volume_principals = [local.role_arns["karpenter"]]

  # The service-linked roles that create the volumes: Auto Scaling for the system node group, EC2 Fleet for
  # Karpenter's launches. A service-linked role has no IAM policy that could allow KMS and can't be given one, so the
  # key policy names it as the principal, with the statements AWS documents for EBS with a customer managed key
  # ("Required AWS KMS key policy for use with encrypted volumes"). The data stack creates both roles first.
  root_volume_service_roles = [local.autoscaling_role_arn, local.ec2_fleet_role_arn]
  scan_volume_service_roles = [local.ec2_fleet_role_arn]
  service_role_volume_actions = [
    "kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:DescribeKey",
  ]

  policies = {
    files    = one(data.aws_iam_policy_document.files[*].json)
    fields   = one(data.aws_iam_policy_document.fields[*].json)
    database = one(data.aws_iam_policy_document.database[*].json)
    audit    = one(data.aws_iam_policy_document.audit[*].json)
    logs     = one(data.aws_iam_policy_document.logs[*].json)
    secrets  = one(data.aws_iam_policy_document.secrets[*].json)
    platform = one(data.aws_iam_policy_document.platform[*].json)
  }
}

# --- Every key ---------------------------------------------------------------------------------------------------

data "aws_iam_policy_document" "common" {
  # Rule 1 and 2: the owning stack's deploy role administers the key and can't use it. Rule 4: replicas only in Osaka.
  statement {
    sid       = "Administer"
    actions   = local.administer_actions
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [local.account_root]
    }

    condition {
      test     = "ArnLike"
      variable = "aws:PrincipalArn"
      values   = concat([var.deploy_role_arn], var.extra_administrator_arn_patterns)
    }

    condition {
      test     = "StringEqualsIfExists"
      variable = "kms:ReplicaRegion"
      values   = ["ap-northeast-3"]
    }
  }

  # Plans refresh the key, its policy, rotation and tags. Reading only: no use, no change (ADR-0005).
  dynamic "statement" {
    for_each = var.plan_role_arn == null ? [] : [var.plan_role_arn]

    content {
      sid = "PlanRoleReadsKeyState"
      actions = [
        "kms:DescribeKey", "kms:GetKeyPolicy", "kms:GetKeyRotationStatus", "kms:ListKeyRotations",
        "kms:ListResourceTags",
      ]
      resources = ["*"]

      principals {
        type        = "AWS"
        identifiers = [local.account_root]
      }

      condition {
        test     = "ArnEquals"
        variable = "aws:PrincipalArn"
        values   = [statement.value]
      }
    }
  }

  # AWS Config's key rules (9.2), as on the tfstate key.
  statement {
    sid       = "AwsConfigReadsKeyState"
    actions   = ["kms:DescribeKey", "kms:GetKeyRotationStatus"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [local.account_root]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:PrincipalArn"
      values   = [local.config_role_arn]
    }
  }

  # Rule 6: the key-admin role reads and puts the key policy, nothing else.
  dynamic "statement" {
    for_each = var.key_admin_role_arn == null ? [] : [var.key_admin_role_arn]

    content {
      sid       = "KeyAdminRepairsThePolicy"
      actions   = ["kms:GetKeyPolicy", "kms:PutKeyPolicy"]
      resources = ["*"]

      principals {
        type        = "AWS"
        identifiers = [local.account_root]
      }

      condition {
        test     = "ArnEquals"
        variable = "aws:PrincipalArn"
        values   = [statement.value]
      }
    }
  }

  # Rule 6: BreakGlass recovers (R in 4.3).
  statement {
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
      values   = var.break_glass_principal_arn_patterns
    }
  }

  # Rule 5 repeats the SCP, so it holds even if the SCP changes: only the deploy role disables or deletes the key.
  statement {
    sid       = "DenyDisableOrDeleteExceptDeployRole"
    effect    = "Deny"
    actions   = ["kms:DisableKey", "kms:ScheduleKeyDeletion"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "ArnNotEquals"
      variable = "aws:PrincipalArn"
      values   = [var.deploy_role_arn]
    }
  }

  # 30 days in prod, 7 in dev and staging, so they can be torn down (rule 5, 8.3).
  statement {
    sid       = "RequireTheDeletionWait"
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

# --- files: the files buckets and the scan node volumes ----------------------------------------------------------

data "aws_iam_policy_document" "files" {
  count = contains(var.classes, "files") ? 1 : 0

  source_policy_documents = [data.aws_iam_policy_document.common.json]

  statement {
    sid       = "ApiReadsAndWritesFilesThroughS3"
    actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [local.account_root]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:PrincipalArn"
      values   = [local.role_arns["api"]]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = [local.via["s3"]]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:EncryptionContext:aws:s3:arn"
      values   = [local.bucket_arns["files"], local.bucket_arns["large_files"]]
    }
  }

  # Files up to 2 GB only: larger ones are scanned by GuardDuty (ADR-0019).
  statement {
    sid       = "ScanWorkerReadsSmallFilesThroughS3"
    actions   = ["kms:Decrypt"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [local.account_root]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:PrincipalArn"
      values   = [local.role_arns["scan"]]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = [local.via["s3"]]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:EncryptionContext:aws:s3:arn"
      values   = [local.bucket_arns["files"]]
    }
  }

  # D in Tokyo, the source; E D in Osaka, where S3 re-encrypts each replica (2.3).
  statement {
    sid       = local.primary ? "ReplicationReadsThroughS3" : "ReplicationWritesThroughS3"
    actions   = local.primary ? ["kms:Decrypt"] : ["kms:Encrypt", "kms:GenerateDataKey", "kms:Decrypt"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [local.account_root]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:PrincipalArn"
      values   = [local.replication_role_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = [local.via["s3"]]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:EncryptionContext:aws:s3:arn"
      values   = [local.bucket_arns["files"], local.bucket_arns["large_files"]]
    }
  }

  # Decision 15: GuardDuty's role reads the large-file bucket only.
  statement {
    sid       = "MalwareProtectionPlanReadsThroughS3"
    actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [local.account_root]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:PrincipalArn"
      values   = [local.role_arns["malware-protection"]]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = [local.via["s3"]]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:EncryptionContext:aws:s3:arn"
      values   = [local.bucket_arns["large_files"]]
    }
  }

  statement {
    sid       = "BreakGlassReadsThroughS3"
    actions   = ["kms:Decrypt"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [local.account_root]
    }

    condition {
      test     = "ArnLike"
      variable = "aws:PrincipalArn"
      values   = var.break_glass_principal_arn_patterns
    }

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = [local.via["s3"]]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:EncryptionContext:aws:s3:arn"
      values   = [local.bucket_arns["files"], local.bucket_arns["large_files"]]
    }
  }

  # clamd's scratch holds file contents, so the scan pool's volumes use this key (3.1).
  statement {
    sid       = "NodeProvisionerUsesKeyForScanVolumes"
    actions   = local.volume_actions
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [local.account_root]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:PrincipalArn"
      values   = local.scan_volume_principals
    }

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = [local.via["ec2"]]
    }
  }

  statement {
    sid       = "NodeProvisionerGrantsForEbsOnly"
    actions   = ["kms:CreateGrant"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [local.account_root]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:PrincipalArn"
      values   = local.scan_volume_principals
    }

    condition {
      test     = "Bool"
      variable = "kms:GrantIsForAWSResource"
      values   = ["true"]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = [local.via["ec2"]]
    }
  }

  statement {
    sid       = "ServiceLinkedRolesUseKeyForScanVolumes"
    actions   = local.service_role_volume_actions
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = local.scan_volume_service_roles
    }
  }

  statement {
    sid       = "ServiceLinkedRolesGrantForScanVolumes"
    actions   = ["kms:CreateGrant"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = local.scan_volume_service_roles
    }

    condition {
      test     = "Bool"
      variable = "kms:GrantIsForAWSResource"
      values   = ["true"]
    }
  }
}

# --- fields: per-tenant data keys (3.2, 3.3) ---------------------------------------------------------------------

data "aws_iam_policy_document" "fields" {
  count = contains(var.classes, "fields") ? 1 : 0

  source_policy_documents = [data.aws_iam_policy_document.common.json]

  # Called directly, so no kms:ViaService. Both purposes, and always with the tenant in the context.
  statement {
    sid       = "ApiWrapsTenantDataKeys"
    actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [local.account_root]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:PrincipalArn"
      values   = [local.role_arns["api"]]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:EncryptionContext:purpose"
      values   = ["field-dek", "dlp-dek"]
    }

    condition {
      test     = "Null"
      variable = "kms:EncryptionContext:tenant_id"
      values   = ["false"]
    }
  }

  # dlp-dek only, so the scan worker can never unwrap a field data key (3.3).
  statement {
    sid       = "ScanWorkerWrapsDlpDataKeysOnly"
    actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [local.account_root]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:PrincipalArn"
      values   = [local.role_arns["scan"]]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:EncryptionContext:purpose"
      values   = ["dlp-dek"]
    }

    condition {
      test     = "Null"
      variable = "kms:EncryptionContext:tenant_id"
      values   = ["false"]
    }
  }
}

# --- database: Aurora, through grants ----------------------------------------------------------------------------

data "aws_iam_policy_document" "database" {
  count = contains(var.classes, "database") ? 1 : 0

  source_policy_documents = [data.aws_iam_policy_document.common.json]

  # No workload uses this key. Creating a cluster runs as the deploy role, which lets RDS use the key through a grant
  # for that cluster (G in 4.3); DescribeKey is in its administer statement.
  statement {
    sid       = "DeployRoleGrantsForRds"
    actions   = ["kms:CreateGrant"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [local.account_root]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:PrincipalArn"
      values   = [var.deploy_role_arn]
    }

    condition {
      test     = "Bool"
      variable = "kms:GrantIsForAWSResource"
      values   = ["true"]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = [local.via["rds"]]
    }
  }
}

# --- audit: the archive buckets; in prod also the retained stack's state, trail and alert topic --------------------

data "aws_iam_policy_document" "audit" {
  count = contains(var.classes, "audit") ? 1 : 0

  source_policy_documents = [data.aws_iam_policy_document.common.json]

  # Writers only generate data keys. The archive job writes batches in Tokyo; the API and the operator API write
  # security-critical records to both Regions (architecture 5.2).
  statement {
    sid       = "WritersPutArchiveObjectsThroughS3"
    actions   = ["kms:GenerateDataKey"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [local.account_root]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:PrincipalArn"
      values = concat(
        local.primary ? [local.role_arns["archive"]] : [],
        [local.role_arns["api"], local.role_arns["operator"]],
      )
    }

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = [local.via["s3"]]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:EncryptionContext:aws:s3:arn"
      values   = [local.bucket_arns["audit_archive"]]
    }
  }

  # Readers only decrypt: the recovery job, the audit reader and BreakGlass.
  statement {
    sid       = "ReadersReadArchiveThroughS3"
    actions   = ["kms:Decrypt"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [local.account_root]
    }

    condition {
      test     = "ArnLike"
      variable = "aws:PrincipalArn"
      values = concat(
        [local.role_arns["recovery"]], local.audit_reader_arn_patterns, var.break_glass_principal_arn_patterns,
      )
    }

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = [local.via["s3"]]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:EncryptionContext:aws:s3:arn"
      values   = [local.bucket_arns["audit_archive"]]
    }
  }

  statement {
    sid       = local.primary ? "ReplicationReadsThroughS3" : "ReplicationWritesThroughS3"
    actions   = local.primary ? ["kms:Decrypt"] : ["kms:Encrypt", "kms:GenerateDataKey", "kms:Decrypt"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [local.account_root]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:PrincipalArn"
      values   = [local.replication_role_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = [local.via["s3"]]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:EncryptionContext:aws:s3:arn"
      values   = [local.bucket_arns["audit_archive"]]
    }
  }

  # Rule 2's exception: the retained stack's deploy role uses its own state, through S3, that bucket only (8.4).
  dynamic "statement" {
    for_each = var.retained_stack && local.primary ? [1] : []

    content {
      sid       = "RetainedDeployRoleUsesItsStateThroughS3"
      actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
      resources = ["*"]

      principals {
        type        = "AWS"
        identifiers = [local.account_root]
      }

      condition {
        test     = "ArnEquals"
        variable = "aws:PrincipalArn"
        values   = [var.deploy_role_arn]
      }

      condition {
        test     = "StringEquals"
        variable = "kms:ViaService"
        values   = [local.via["s3"]]
      }

      condition {
        test     = "StringEquals"
        variable = "kms:EncryptionContext:aws:s3:arn"
        values   = [local.bucket_arns["retained_state"]]
      }
    }
  }

  # The retained trail writes its log files under this key: that trail only (8.4).
  dynamic "statement" {
    for_each = var.retained_stack && local.primary ? [1] : []

    content {
      sid       = "CloudTrailWritesTheRetainedTrail"
      actions   = ["kms:GenerateDataKey*"]
      resources = ["*"]

      principals {
        type        = "Service"
        identifiers = ["cloudtrail.amazonaws.com"]
      }

      condition {
        test     = "StringEquals"
        variable = "aws:SourceAccount"
        values   = [var.account_id]
      }

      condition {
        test     = "StringEquals"
        variable = "aws:SourceArn"
        values   = [local.retained_trail_arn]
      }

      condition {
        test     = "StringEquals"
        variable = "kms:EncryptionContext:aws:cloudtrail:arn"
        values   = [local.retained_trail_arn]
      }
    }
  }

  dynamic "statement" {
    for_each = var.retained_stack && local.primary ? [1] : []

    content {
      sid       = "CloudTrailDescribesTheKey"
      actions   = ["kms:DescribeKey"]
      resources = ["*"]

      principals {
        type        = "Service"
        identifiers = ["cloudtrail.amazonaws.com"]
      }

      condition {
        test     = "StringEquals"
        variable = "aws:SourceAccount"
        values   = [var.account_id]
      }

      condition {
        test     = "StringEquals"
        variable = "aws:SourceArn"
        values   = [local.retained_trail_arn]
      }
    }
  }

  # The retained stack's alert topic, in both Regions, through its own EventBridge delivery role (8.4).
  dynamic "statement" {
    for_each = var.retained_stack ? [1] : []

    content {
      sid       = "RetainedAlertsPublishThroughSns"
      actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
      resources = ["*"]

      principals {
        type        = "AWS"
        identifiers = [local.account_root]
      }

      condition {
        test     = "ArnEquals"
        variable = "aws:PrincipalArn"
        values   = [local.retained_events_delivery_role_arn]
      }

      condition {
        test     = "StringEquals"
        variable = "kms:ViaService"
        values   = [local.via["sns"]]
      }
    }
  }
}

# --- logs: log buckets, CloudWatch Logs, the log and trace stores ------------------------------------------------

data "aws_iam_policy_document" "logs" {
  count = contains(var.classes, "logs") ? 1 : 0

  source_policy_documents = [data.aws_iam_policy_document.common.json]

  # Log groups in this account and Region: EKS, Aurora and the rest.
  statement {
    sid = "CloudWatchLogsEncryptsLogGroups"
    actions = [
      "kms:Encrypt*", "kms:Decrypt*", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:Describe*",
    ]
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["logs.${local.region}.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.account_id]
    }

    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["arn:aws:logs:${local.region}:${var.account_id}:log-group:*"]
    }
  }

  statement {
    sid       = "CloudTrailEncryptsLogFiles"
    actions   = ["kms:GenerateDataKey*"]
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.account_id]
    }

    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:cloudtrail:arn"
      values   = ["arn:aws:cloudtrail:*:${var.account_id}:trail/sft-${var.environment}-*"]
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
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.account_id]
    }
  }

  # Vended logs to S3: CloudFront's standard logs, whose delivery sources are in us-east-1, and the web ACLs' (#105).
  statement {
    sid       = "LogDeliveryWritesVendedLogs"
    actions   = ["kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:DescribeKey"]
    resources = ["*"]

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
      values = [
        for region in distinct(concat([local.region], local.primary ? ["us-east-1"] : [])) :
        "arn:aws:logs:${region}:${var.account_id}:*"
      ]
    }
  }

  statement {
    sid       = "LogAndTraceStoresUseKeyThroughS3"
    actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [local.account_root]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:PrincipalArn"
      values   = [local.role_arns["loki"], local.role_arns["tempo"]]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = [local.via["s3"]]
    }
  }

  # NFR-15's daily match reads CloudTrail log files, never application logs (4.3).
  statement {
    sid       = "LifecycleJobsReadCloudTrailLogFiles"
    actions   = ["kms:Decrypt"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [local.account_root]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:PrincipalArn"
      values   = [local.role_arns["jobs"]]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = [local.via["s3"]]
    }

    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:cloudtrail:arn"
      values   = ["arn:aws:cloudtrail:*:${var.account_id}:trail/sft-${var.environment}-*"]
    }
  }

  statement {
    sid       = "AuditReaderAndBreakGlassReadLogs"
    actions   = ["kms:Decrypt"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [local.account_root]
    }

    condition {
      test     = "ArnLike"
      variable = "aws:PrincipalArn"
      values   = concat(local.audit_reader_arn_patterns, var.break_glass_principal_arn_patterns)
    }

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = [local.via["s3"], local.via["logs"]]
    }
  }
}

# --- secrets: Secrets Manager and Kubernetes Secrets (section 6) -------------------------------------------------

data "aws_iam_policy_document" "secrets" {
  count = contains(var.classes, "secrets") ? 1 : 0

  source_policy_documents = [data.aws_iam_policy_document.common.json]

  # Each reader decrypts only its own secrets (6.1, 6.4), one statement per role.
  dynamic "statement" {
    for_each = {
      ApiReadsItsSecrets = {
        roles   = [local.role_arns["api"]]
        secrets = [local.secret_arns.code_hmac, local.secret_arns.email_hmac, local.secret_arns.csrf_hmac, local.secret_arns.idp_here]
      }
      NotificationWorkerReadsItsSecrets = {
        roles   = [local.role_arns["notify"]]
        secrets = [local.secret_arns.code_hmac, local.secret_arns.email_hmac, local.secret_arns.link_hmac]
      }
      DatabaseBootstrapReadsTheMasterPassword = {
        roles   = [local.role_arns["db-bootstrap"]]
        secrets = [local.secret_arns.db_master]
      }
      # External Secrets reads through one role per store, never its controller's own (6.4).
      PlatformSecretStoreReadsPlatformSecrets = {
        roles   = [local.role_arns["external-secrets-platform"]]
        secrets = [local.secret_arns.platform]
      }
      ApplicationSecretStoreReadsApiSecrets = {
        roles   = [local.role_arns["external-secrets-app"]]
        secrets = [local.secret_arns.email_hmac, local.secret_arns.csrf_hmac, local.secret_arns.idp_here]
      }
      BreakGlassReadsTheMasterPassword = {
        roles   = var.break_glass_principal_arn_patterns
        secrets = [local.secret_arns.db_master]
      }
    }

    content {
      sid       = statement.key
      actions   = ["kms:Decrypt"]
      resources = ["*"]

      principals {
        type        = "AWS"
        identifiers = [local.account_root]
      }

      condition {
        test     = "ArnLike"
        variable = "aws:PrincipalArn"
        values   = statement.value.roles
      }

      condition {
        test     = "StringEquals"
        variable = "kms:ViaService"
        values   = [local.via["secretsmanager"]]
      }

      condition {
        test     = "StringLike"
        variable = "kms:EncryptionContext:SecretARN"
        values   = statement.value.secrets
      }
    }
  }

  # The keyrings and both identity provider client secrets, in each Region so replication can re-encrypt (6.4).
  statement {
    sid       = "KeyRotationWritesKeyringsAndClientSecrets"
    actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [local.account_root]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:PrincipalArn"
      values   = [local.role_arns["key-rotation"]]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = [local.via["secretsmanager"]]
    }

    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:SecretARN"
      values = [
        local.secret_arns.code_hmac, local.secret_arns.email_hmac, local.secret_arns.link_hmac,
        local.secret_arns.csrf_hmac, local.secret_arns.idp_all,
      ]
    }
  }

  # Rule 2's second exception: the deploy role encrypts the secrets it writes through write-only arguments, in each
  # Region, and decrypts Secrets Manager's key-access check (6.4) and, below, the master password's read-back (6.3).
  statement {
    sid       = "DeployRoleEncryptsTheSecretsItWrites"
    actions   = ["kms:GenerateDataKey"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [local.account_root]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:PrincipalArn"
      values   = [var.deploy_role_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = [local.via["secretsmanager"]]
    }

    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:SecretARN"
      values   = [local.secret_arns.db_master, local.secret_arns.platform]
    }
  }

  statement {
    sid       = "DeployRolePassesTheKeyAccessCheck"
    actions   = ["kms:Decrypt"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [local.account_root]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:PrincipalArn"
      values   = [var.deploy_role_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      # In Osaka the check for the master secret's replica may come through Tokyo's endpoint, as the replication does.
      values = distinct(concat(
        [local.via["secretsmanager"]], local.primary ? [] : ["secretsmanager.ap-northeast-1.amazonaws.com"],
      ))
    }

    condition {
      test     = "StringEquals"
      variable = "kms:EncryptionContext:SecretVersionId"
      values   = ["RequestToValidateKeyAccess"]
    }
  }

  # The master password's one source is its secret: the deploy role reads the version it just wrote back at apply and
  # gives that to the cluster (6.3, modules/aurora). The same Decrypt lets Secrets Manager decrypt the value in Tokyo
  # when it replicates it. Only where the secret is written: the Tokyo primary (dev's key too).
  dynamic "statement" {
    for_each = local.primary ? [1] : []

    content {
      sid       = "DeployRoleReadsBackTheMasterPassword"
      actions   = ["kms:Decrypt"]
      resources = ["*"]

      principals {
        type        = "AWS"
        identifiers = [local.account_root]
      }

      condition {
        test     = "ArnEquals"
        variable = "aws:PrincipalArn"
        values   = [var.deploy_role_arn]
      }

      condition {
        test     = "StringEquals"
        variable = "kms:ViaService"
        values   = [local.via["secretsmanager"]]
      }

      condition {
        test     = "StringLike"
        variable = "kms:EncryptionContext:SecretARN"
        values   = [local.secret_arns.db_master]
      }
    }
  }

  # Replicating the master secret to Osaka re-encrypts it under this replica with the caller's credentials:
  # GenerateDataKey and Encrypt ("When you replicate a secret to another Region, Secrets Manager also sends an
  # Encrypt request to AWS KMS", Secrets Manager user guide, "Secret encryption and decryption"). AWS's example of
  # that call carries the primary secret's ARN as its context, so the condition admits the master secret's ARN in
  # either Region and the call through Secrets Manager in either. The master secret only, the Osaka replica only (6.4).
  dynamic "statement" {
    for_each = local.primary ? [] : [1]

    content {
      sid       = "DeployRoleEncryptsTheMasterSecretReplica"
      actions   = ["kms:GenerateDataKey", "kms:Encrypt"]
      resources = ["*"]

      principals {
        type        = "AWS"
        identifiers = [local.account_root]
      }

      condition {
        test     = "ArnEquals"
        variable = "aws:PrincipalArn"
        values   = [var.deploy_role_arn]
      }

      condition {
        test     = "StringEquals"
        variable = "kms:ViaService"
        values   = ["secretsmanager.ap-northeast-1.amazonaws.com", "secretsmanager.ap-northeast-3.amazonaws.com"]
      }

      condition {
        test     = "StringLike"
        variable = "kms:EncryptionContext:SecretARN"
        values = [
          for region in ["ap-northeast-1", "ap-northeast-3"] :
          "arn:aws:secretsmanager:${region}:${var.account_id}:secret:sft/${var.environment}/db/master-??????"
        ]
      }
    }
  }

  # EKS envelope-encrypts etcd with this key through a grant. CreateCluster runs as the deploy role, which creates
  # the grant; the cluster role uses the key through EKS (#103).
  statement {
    sid       = "DeployRoleGrantsForEks"
    actions   = ["kms:CreateGrant"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [local.account_root]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:PrincipalArn"
      values   = [var.deploy_role_arn, local.role_arns["eks-cluster"]]
    }

    condition {
      test     = "Bool"
      variable = "kms:GrantIsForAWSResource"
      values   = ["true"]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = [local.via["eks"]]
    }
  }

  statement {
    sid       = "EksClusterEncryptsSecrets"
    actions   = ["kms:Encrypt", "kms:Decrypt", "kms:DescribeKey"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [local.account_root]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:PrincipalArn"
      values   = [local.role_arns["eks-cluster"]]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = [local.via["eks"]]
    }
  }
}

# --- platform: SQS, SNS, Valkey, EBS -----------------------------------------------------------------------------

data "aws_iam_policy_document" "platform" {
  count = contains(var.classes, "platform") ? 1 : 0

  source_policy_documents = [data.aws_iam_policy_document.common.json]

  # Producers and consumers through SQS, each for its own queues (4.3).
  dynamic "statement" {
    for_each = {
      RelaySendsToWorkQueues = {
        role    = "relay"
        actions = ["kms:GenerateDataKey", "kms:Decrypt"]
        queues  = ["scan-small", "scan-large", "notify"]
      }
      ScanWorkerReadsScanQueues = {
        role    = "scan"
        actions = ["kms:Decrypt"]
        queues  = ["scan-small", "scan-large", "guardduty-results"]
      }
      NotificationWorkerReadsItsQueues = {
        role    = "notify"
        actions = ["kms:Decrypt"]
        queues  = ["notify", "signin-events", "ses-events", "ses-tenant-status"]
      }
      KarpenterReadsItsInterruptionQueue = {
        role    = "karpenter"
        actions = ["kms:Decrypt"]
        queues  = ["karpenter-interruption"]
      }
      SignInTriggersSendSignInEvents = {
        role    = "signin-trigger"
        actions = ["kms:GenerateDataKey", "kms:Decrypt"]
        queues  = ["signin-events"]
      }
    }

    content {
      sid       = statement.key
      actions   = statement.value.actions
      resources = ["*"]

      principals {
        type        = "AWS"
        identifiers = [local.account_root]
      }

      condition {
        test     = "ArnEquals"
        variable = "aws:PrincipalArn"
        values   = [local.role_arns[statement.value.role]]
      }

      condition {
        test     = "StringEquals"
        variable = "kms:ViaService"
        values   = [local.via["sqs"]]
      }

      condition {
        test     = "StringEquals"
        variable = "kms:EncryptionContext:aws:sqs:arn"
        values   = [for q in statement.value.queues : local.queue_arns[q]]
      }
    }
  }

  statement {
    sid       = "CloudWatchAlarmsPublishToAlarmTopics"
    actions   = ["kms:GenerateDataKey*", "kms:Decrypt"]
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.account_id]
    }

    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:aws:cloudwatch:${local.region}:${var.account_id}:alarm:sft-${var.environment}-*"]
    }
  }

  statement {
    sid       = "SesPublishesSendingEventsToItsTopic"
    actions   = ["kms:GenerateDataKey*", "kms:Decrypt"]
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["ses.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.account_id]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:aws:ses:${local.region}:${var.account_id}:configuration-set/sft-${var.environment}"]
    }
  }

  statement {
    sid       = "SnsDeliversSesEventsToTheirQueue"
    actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["sns.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.account_id]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = ["arn:aws:sns:${local.region}:${var.account_id}:${local.name_prefix}-ses-events"]
    }
  }

  # EventBridge delivers through its own role, so the key names a role, not every rule (4.4).
  statement {
    sid       = "EventBridgeDeliversThroughItsRole"
    actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [local.account_root]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:PrincipalArn"
      values   = [local.role_arns["events-delivery"]]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = [local.via["sqs"], local.via["sns"]]
    }
  }

  statement {
    sid       = "NodeProvisionerUsesKeyForRootVolumes"
    actions   = local.volume_actions
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [local.account_root]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:PrincipalArn"
      values   = local.root_volume_principals
    }

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = [local.via["ec2"]]
    }
  }

  statement {
    sid       = "ServiceLinkedRolesUseKeyForRootVolumes"
    actions   = local.service_role_volume_actions
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = local.root_volume_service_roles
    }
  }

  statement {
    sid       = "ServiceLinkedRolesGrantForRootVolumes"
    actions   = ["kms:CreateGrant"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = local.root_volume_service_roles
    }

    condition {
      test     = "Bool"
      variable = "kms:GrantIsForAWSResource"
      values   = ["true"]
    }
  }

  statement {
    sid       = "NodeProvisionerGrantsForEbsOnly"
    actions   = ["kms:CreateGrant"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [local.account_root]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:PrincipalArn"
      values   = local.root_volume_principals
    }

    condition {
      test     = "Bool"
      variable = "kms:GrantIsForAWSResource"
      values   = ["true"]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = [local.via["ec2"]]
    }
  }

  # CreateServerlessCache runs as the deploy role, which lets ElastiCache use the key through a grant (4.3, #101).
  statement {
    sid       = "DeployRoleGrantsForElastiCache"
    actions   = ["kms:CreateGrant"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [local.account_root]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:PrincipalArn"
      values   = [var.deploy_role_arn]
    }

    condition {
      test     = "Bool"
      variable = "kms:GrantIsForAWSResource"
      values   = ["true"]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = [local.via["elasticache"]]
    }
  }
}
