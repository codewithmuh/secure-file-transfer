# The environment's customer managed keys, one per data class (ADR-0017, encryption 4.1 to 4.4).
#
# - In Tokyo each key is a multi-Region primary with yearly rotation. In Osaka (staging and prod) the same module makes
#   each key's replica from the primary's ARN, with a policy built from the same template and Osaka's values, so the two
#   Regions can't drift apart (T-79). dev runs in Tokyo only: multi-Region keys without a replica.
# - The policies are in policies.tf, one document per class on top of the statements every key shares.
# - Roles are matched by aws:PrincipalArn through the account principal, never named as the principal. KMS refuses a
#   policy that names a role that doesn't exist yet, and the workload roles arrive with the cluster layer, after this
#   one. The account principal with an exact ARN condition gives nothing to anyone else: there is no kms:* for the
#   account, and each role still needs its own IAM policy too. It also means a re-created role still matches.

data "aws_region" "current" {}

locals {
  region  = data.aws_region.current.region
  primary = length(var.primary_key_arns) == 0

  region_short = {
    "ap-northeast-1" = "apne1"
    "ap-northeast-3" = "apne3"
  }[local.region]

  name_prefix  = "sft-${var.environment}-${local.region_short}"
  account_root = "arn:aws:iam::${var.account_id}:root"
  alias_prefix = "alias/sft/${var.environment}"

  # Workload roles of authn-authz and encryption 4.3, created by the cluster layer: sft-<env>-<name>, path /.
  role_arns = {
    for name in [
      "api", "scan", "notify", "relay", "jobs", "archive", "operator", "recovery", "key-rotation", "db-bootstrap",
      "s3-replication", "malware-protection", "events-delivery", "signin-trigger", "karpenter", "ebs-csi",
      "external-secrets", "eks-cluster", "loki", "tempo",
    ] :
    name => "arn:aws:iam::${var.account_id}:role/sft-${var.environment}-${name}"
  }

  replication_role_arn = (
    var.replication_role_name == null
    ? local.role_arns["s3-replication"]
    : "arn:aws:iam::${var.account_id}:role/${var.replication_role_name}"
  )

  # Service-linked roles: the node provisioners for EBS volumes (4.4) and AWS Config for its key rules (9.2).
  ec2_fleet_role_arn = try(
    var.volume_service_linked_role_arns.ec2_fleet,
    "arn:aws:iam::${var.account_id}:role/aws-service-role/ec2fleet.amazonaws.com/AWSServiceRoleForEC2Fleet",
  )
  autoscaling_role_arn = try(
    var.volume_service_linked_role_arns.autoscaling,
    "arn:aws:iam::${var.account_id}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling",
  )
  config_role_arn = "arn:aws:iam::${var.account_id}:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig"

  # Identity Center's role for the AuditReader permission set (infra/organization/identity-center.tf), whose name ends
  # in a random suffix.
  audit_reader_arn_patterns = [
    "arn:aws:iam::${var.account_id}:role/aws-reserved/sso.amazonaws.com/*AWSReservedSSO_AuditReader_*",
  ]

  # Buckets in this Region, by the names in infra/README.md: the key policies name them before they exist.
  bucket_arns = {
    files         = "arn:aws:s3:::${local.name_prefix}-files-${var.account_id}"
    large_files   = "arn:aws:s3:::${local.name_prefix}-large-files-${var.account_id}"
    audit_archive = "arn:aws:s3:::${local.name_prefix}-audit-archive-${var.account_id}"
    # The retained stack's own state bucket, Tokyo only (encryption 8.4).
    retained_state = "arn:aws:s3:::sft-prod-apne1-retained-tfstate-${var.account_id}"
  }

  via = {
    for service in ["s3", "sqs", "sns", "ec2", "rds", "elasticache", "secretsmanager", "eks", "logs"] :
    service => "${service}.${local.region}.amazonaws.com"
  }

  # Queues of ADR-0013 (#101) and Karpenter's interruption queue (#103): sft-<env>-<region-short>-<queue>.
  queue_arns = {
    for queue in [
      "scan-small", "scan-large", "notify", "signin-events", "ses-events", "guardduty-results", "ses-tenant-status",
      "karpenter-interruption",
    ] :
    queue => "arn:aws:sqs:${local.region}:${var.account_id}:${local.name_prefix}-${queue}"
  }

  # Secrets of encryption 6.1. Secrets Manager adds a six-character suffix to every secret's ARN.
  secret_arn_prefix = "arn:aws:secretsmanager:${local.region}:${var.account_id}:secret:sft/${var.environment}/"
  secret_arns = {
    code_hmac  = "${local.secret_arn_prefix}app/code-hmac-??????"
    email_hmac = "${local.secret_arn_prefix}app/email-hmac-??????"
    link_hmac  = "${local.secret_arn_prefix}app/link-hmac-??????"
    csrf_hmac  = "${local.secret_arn_prefix}app/csrf-hmac-??????"
    idp_here   = "${local.secret_arn_prefix}app/idp-client/${local.region}-??????"
    idp_all    = "${local.secret_arn_prefix}app/idp-client/ap-northeast-?-??????"
    db_master  = "${local.secret_arn_prefix}db/master-??????"
    platform   = "${local.secret_arn_prefix}platform/*"
  }

  # The retained stack's trail and alert delivery role (encryption 8.4), named here for the issue that builds them.
  retained_trail_arn                = "arn:aws:cloudtrail:ap-northeast-1:${var.account_id}:trail/sft-prod-retained"
  retained_events_delivery_role_arn = "arn:aws:iam::${var.account_id}:role/sft-prod-retained-events-delivery"

  # prevent_destroy can't take a variable, so guarded and unguarded keys are separate resources.
  primary_guarded   = local.primary && var.prevent_destroy ? var.classes : toset([])
  primary_unguarded = local.primary && !var.prevent_destroy ? var.classes : toset([])
  replica_guarded   = !local.primary && var.prevent_destroy ? var.classes : toset([])
  replica_unguarded = !local.primary && !var.prevent_destroy ? var.classes : toset([])

  key_arns = merge(
    { for c, k in aws_kms_key.guarded : c => k.arn },
    { for c, k in aws_kms_key.unguarded : c => k.arn },
    { for c, k in aws_kms_replica_key.guarded : c => k.arn },
    { for c, k in aws_kms_replica_key.unguarded : c => k.arn },
  )

  descriptions = {
    files    = "File contents: the files buckets and the scan node volumes"
    fields   = "Per-tenant data keys for file names, messages and DLP details"
    database = "Aurora storage, backups, snapshots and Performance Insights"
    audit    = "The audit archive"
    logs     = "Log buckets, CloudWatch Logs and the log and trace stores"
    secrets  = "Secrets Manager and Kubernetes Secrets"
    platform = "SQS, SNS, Valkey and EBS"
  }
}

resource "aws_kms_key" "guarded" {
  for_each = local.primary_guarded

  description             = "sft ${var.environment} ${each.key}: ${local.descriptions[each.key]} (encryption 4.1)"
  multi_region            = true
  enable_key_rotation     = true
  rotation_period_in_days = 365
  deletion_window_in_days = var.deletion_window_in_days
  policy                  = local.policies[each.key]

  tags = { component = "kms" }

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_kms_key" "unguarded" {
  for_each = local.primary_unguarded

  description             = "sft ${var.environment} ${each.key}: ${local.descriptions[each.key]} (encryption 4.1)"
  multi_region            = true
  enable_key_rotation     = true
  rotation_period_in_days = 365
  deletion_window_in_days = var.deletion_window_in_days
  policy                  = local.policies[each.key]

  tags = { component = "kms" }
}

# A replica rotates with its primary: KMS copies new key material to it before using it (encryption 7.1).
resource "aws_kms_replica_key" "guarded" {
  for_each = local.replica_guarded

  description             = "sft ${var.environment} ${each.key}: ${local.descriptions[each.key]} (encryption 4.1)"
  primary_key_arn         = var.primary_key_arns[each.key]
  deletion_window_in_days = var.deletion_window_in_days
  policy                  = local.policies[each.key]

  tags = { component = "kms" }

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_kms_replica_key" "unguarded" {
  for_each = local.replica_unguarded

  description             = "sft ${var.environment} ${each.key}: ${local.descriptions[each.key]} (encryption 4.1)"
  primary_key_arn         = var.primary_key_arns[each.key]
  deletion_window_in_days = var.deletion_window_in_days
  policy                  = local.policies[each.key]

  tags = { component = "kms" }
}

# Aliases are per Region, so both Regions get the same one (4.1).
resource "aws_kms_alias" "this" {
  for_each = var.classes

  name          = "${local.alias_prefix}/${each.key}"
  target_key_id = local.key_arns[each.key]
}
