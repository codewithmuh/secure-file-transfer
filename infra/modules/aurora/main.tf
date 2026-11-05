# One Region's Aurora PostgreSQL cluster (ADR-0011): standalone in dev, the primary of the global database in Tokyo,
# its secondary in Osaka. Encrypted with the Region's database key, reachable only from the node groups the caller
# names, IAM database authentication for every workload, TLS only, and the master password set through write-only
# arguments into Secrets Manager, so it never reaches the plan or the state (encryption 6.3).

locals {
  engine             = "aurora-postgresql"
  cluster_identifier = "${var.name_prefix}-aurora"

  standalone = var.cluster_role == "standalone"
  primary    = var.cluster_role == "primary"
  secondary  = var.cluster_role == "secondary"
  has_master = !local.secondary

  writer_availability_zone_id  = var.instance_availability_zone_ids[0]
  reader_availability_zone_ids = toset(slice(var.instance_availability_zone_ids, 1, length(var.instance_availability_zone_ids)))

  # The cluster's two forms (below) are one cluster: whichever exists.
  cluster = one(concat(aws_rds_cluster.standalone[*], aws_rds_cluster.global_member[*]))

  log_group_name = "/aws/rds/cluster/${local.cluster_identifier}/postgresql"

  # Encryption 2.2 and 3.1: TLS 1.2 or later only, and no values in the log. Statements are parameterized, so their
  # text holds placeholders; bound values, DETAIL lines and logged statements are off, and pgaudit decides what is
  # audited. The connection log is the record of IAM sign-ins, which CloudTrail doesn't log (ADR-0011).
  cluster_parameters = {
    "rds.force_ssl"                     = { value = "1" }
    "ssl_min_protocol_version"          = { value = "TLSv1.2" }
    "log_connections"                   = { value = "1" }
    "log_disconnections"                = { value = "1" }
    "log_statement"                     = { value = "none" }
    "log_error_verbosity"               = { value = "terse" }
    "log_parameter_max_length"          = { value = "0" }
    "log_parameter_max_length_on_error" = { value = "0" }
    "shared_preload_libraries"          = { value = "pg_stat_statements,pgaudit", apply_method = "pending-reboot" }
    "pgaudit.log"                       = { value = var.pgaudit_log }
    "pgaudit.log_parameter"             = { value = "0" }
  }
}

# AZ IDs name the same physical zones in every account; RDS takes names.
data "aws_availability_zone" "instance" {
  for_each = toset(var.instance_availability_zone_ids)

  zone_id = each.value
}

# ---------------------------------------------------------------------------------------------------------------------
# Network access: 5432 from the named security groups only. No egress rules: the database starts no connections.
# ---------------------------------------------------------------------------------------------------------------------

resource "aws_security_group" "this" {
  name        = "${var.name_prefix}-aurora"
  description = "Aurora PostgreSQL: 5432 from the main and scan node groups only (ADR-0011, ADR-0021)"
  vpc_id      = var.vpc_id

  tags = {
    Name = "${var.name_prefix}-aurora"
  }
}

resource "aws_vpc_security_group_ingress_rule" "clients" {
  for_each = var.client_security_group_ids

  security_group_id            = aws_security_group.this.id
  description                  = "PostgreSQL from ${each.key}; network policies narrow it to the workloads that use it"
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
  referenced_security_group_id = each.value
}

resource "aws_db_subnet_group" "this" {
  name        = local.cluster_identifier
  description = "Isolated subnets, no route out (ADR-0021)"
  subnet_ids  = var.subnet_ids
}

resource "aws_rds_cluster_parameter_group" "this" {
  name_prefix = "${local.cluster_identifier}-"
  family      = "aurora-postgresql${split(".", var.engine_version)[0]}"
  description = "TLS only, no values in the log, pgaudit (encryption 2.2, 3.1)"

  dynamic "parameter" {
    for_each = local.cluster_parameters

    content {
      name         = parameter.key
      value        = parameter.value.value
      apply_method = lookup(parameter.value, "apply_method", "immediate")
    }
  }

  # A new major version needs a new family, so the new group exists before the cluster moves to it.
  lifecycle {
    create_before_destroy = true
  }
}

# Created before the cluster so that RDS writes into a log group under the logs key, with a retention, rather than
# creating its own (encryption 3.1).
resource "aws_cloudwatch_log_group" "postgresql" {
  name              = local.log_group_name
  retention_in_days = var.log_retention_days
  kms_key_id        = var.logs_kms_key_arn
}

# Masks any email address that still gets into the log, such as the quoted value of an input-syntax error (encryption
# 3.1, residual risk 9.1).
resource "aws_cloudwatch_log_data_protection_policy" "postgresql" {
  log_group_name = aws_cloudwatch_log_group.postgresql.name

  policy_document = jsonencode({
    Name    = "${local.cluster_identifier}-mask-email"
    Version = "2021-06-01"
    Statement = [
      {
        Sid            = "AuditEmailAddresses"
        DataIdentifier = ["arn:aws:dataprotection::aws:data-identifier/EmailAddress"]
        Operation      = { Audit = { FindingsDestination = {} } }
      },
      {
        Sid            = "MaskEmailAddresses"
        DataIdentifier = ["arn:aws:dataprotection::aws:data-identifier/EmailAddress"]
        Operation      = { Deidentify = { MaskConfig = {} } }
      },
    ]
  })
}

# ---------------------------------------------------------------------------------------------------------------------
# The master password: generated for this run only, sent to the cluster and the secret through write-only arguments.
# It changes only when master_password_version does.
# ---------------------------------------------------------------------------------------------------------------------

ephemeral "aws_secretsmanager_random_password" "master" {
  count = local.has_master ? 1 : 0

  password_length     = 40
  exclude_punctuation = true
}

# ---------------------------------------------------------------------------------------------------------------------
# The global database (primary only) and the cluster
# ---------------------------------------------------------------------------------------------------------------------

resource "aws_rds_global_cluster" "this" {
  count = local.primary ? 1 : 0

  global_cluster_identifier = var.global_cluster_identifier
  engine                    = local.engine
  engine_version            = var.engine_version
  database_name             = var.database_name
  storage_encrypted         = true
  deletion_protection       = var.deletion_protection
}

# Two resource blocks for one cluster, because ignore_changes can't depend on a variable: in a global database the
# global cluster upgrades its members, so they must ignore engine_version (the provider's documented pattern), while
# dev's standalone cluster upgrades itself. Every other argument is the same in both.
resource "aws_rds_cluster" "standalone" {
  count = local.standalone ? 1 : 0

  cluster_identifier = local.cluster_identifier
  engine             = local.engine
  engine_version     = var.engine_version
  database_name      = var.database_name

  master_username            = var.master_username
  master_password_wo         = ephemeral.aws_secretsmanager_random_password.master[0].random_password
  master_password_wo_version = var.master_password_version

  iam_database_authentication_enabled = true
  storage_encrypted                   = true
  kms_key_id                          = var.kms_key_arn

  db_subnet_group_name            = aws_db_subnet_group.this.name
  vpc_security_group_ids          = [aws_security_group.this.id]
  db_cluster_parameter_group_name = aws_rds_cluster_parameter_group.this.name
  network_type                    = "IPV4"
  port                            = 5432

  backup_retention_period      = var.backup_retention_days
  preferred_backup_window      = var.preferred_backup_window
  preferred_maintenance_window = var.preferred_maintenance_window
  copy_tags_to_snapshot        = true
  deletion_protection          = var.deletion_protection
  skip_final_snapshot          = var.skip_final_snapshot
  final_snapshot_identifier    = var.skip_final_snapshot ? null : "${local.cluster_identifier}-final"

  enabled_cloudwatch_logs_exports = ["postgresql"]

  dynamic "serverlessv2_scaling_configuration" {
    for_each = var.serverless_capacity == null ? [] : [var.serverless_capacity]

    content {
      min_capacity = serverlessv2_scaling_configuration.value.min
      max_capacity = serverlessv2_scaling_configuration.value.max
    }
  }

  depends_on = [aws_cloudwatch_log_group.postgresql]

  lifecycle {
    precondition {
      condition     = var.global_cluster_identifier == null && var.master_secret != null
      error_message = "A standalone cluster has no global_cluster_identifier and needs master_secret."
    }

    precondition {
      condition     = (var.instance_class == "db.serverless") == (var.serverless_capacity != null)
      error_message = "serverless_capacity must be set exactly when instance_class is db.serverless."
    }
  }
}

resource "aws_rds_cluster" "global_member" {
  count = local.standalone ? 0 : 1

  cluster_identifier        = local.cluster_identifier
  engine                    = local.engine
  engine_version            = var.engine_version
  global_cluster_identifier = local.primary ? aws_rds_global_cluster.this[0].id : var.global_cluster_identifier

  # The secondary takes its database and its master user from the primary.
  database_name              = local.primary ? var.database_name : null
  master_username            = local.primary ? var.master_username : null
  master_password_wo         = local.primary ? ephemeral.aws_secretsmanager_random_password.master[0].random_password : null
  master_password_wo_version = local.primary ? var.master_password_version : null

  iam_database_authentication_enabled = true
  storage_encrypted                   = true
  kms_key_id                          = var.kms_key_arn

  db_subnet_group_name            = aws_db_subnet_group.this.name
  vpc_security_group_ids          = [aws_security_group.this.id]
  db_cluster_parameter_group_name = aws_rds_cluster_parameter_group.this.name
  network_type                    = "IPV4"
  port                            = 5432

  backup_retention_period      = var.backup_retention_days
  preferred_backup_window      = var.preferred_backup_window
  preferred_maintenance_window = var.preferred_maintenance_window
  copy_tags_to_snapshot        = true
  deletion_protection          = var.deletion_protection
  skip_final_snapshot          = var.skip_final_snapshot
  final_snapshot_identifier    = var.skip_final_snapshot ? null : "${local.cluster_identifier}-final"

  enabled_cloudwatch_logs_exports = ["postgresql"]

  dynamic "serverlessv2_scaling_configuration" {
    for_each = var.serverless_capacity == null ? [] : [var.serverless_capacity]

    content {
      min_capacity = serverlessv2_scaling_configuration.value.min
      max_capacity = serverlessv2_scaling_configuration.value.max
    }
  }

  depends_on = [aws_cloudwatch_log_group.postgresql]

  lifecycle {
    # engine_version: the global cluster upgrades its members. replication_source_identifier: set by RDS on the
    # secondary, and swapped by a managed failover or switchover.
    ignore_changes = [engine_version, replication_source_identifier]

    precondition {
      condition     = var.global_cluster_identifier != null
      error_message = "A primary or secondary cluster needs global_cluster_identifier."
    }

    precondition {
      condition     = local.primary == (var.master_secret != null)
      error_message = "master_secret must be set for the primary and null for the secondary."
    }

    precondition {
      condition     = (var.instance_class == "db.serverless") == (var.serverless_capacity != null)
      error_message = "serverless_capacity must be set exactly when instance_class is db.serverless."
    }
  }
}

# ---------------------------------------------------------------------------------------------------------------------
# Instances: the writer first, then a reader in each further AZ. A failover can swap the roles; the names stay.
# ---------------------------------------------------------------------------------------------------------------------

resource "aws_rds_cluster_instance" "writer" {
  identifier         = "${local.cluster_identifier}-${local.writer_availability_zone_id}"
  cluster_identifier = local.cluster.id
  engine             = local.engine
  instance_class     = var.instance_class
  availability_zone  = data.aws_availability_zone.instance[local.writer_availability_zone_id].name
  promotion_tier     = 0

  db_subnet_group_name = aws_db_subnet_group.this.name
  publicly_accessible  = false
  # Clients verify the server with sslmode=verify-full and the RDS bundle (encryption 2.2).
  ca_cert_identifier = "rds-ca-ecc384-g1"

  # Upgrades are reviewed changes, rehearsed in staging first (ADR-0011).
  auto_minor_version_upgrade   = false
  preferred_maintenance_window = var.preferred_maintenance_window
  copy_tags_to_snapshot        = true

  performance_insights_enabled          = true
  performance_insights_kms_key_id       = var.kms_key_arn
  performance_insights_retention_period = 7
}

resource "aws_rds_cluster_instance" "reader" {
  for_each = local.reader_availability_zone_ids

  identifier         = "${local.cluster_identifier}-${each.value}"
  cluster_identifier = local.cluster.id
  engine             = local.engine
  instance_class     = var.instance_class
  availability_zone  = data.aws_availability_zone.instance[each.value].name
  promotion_tier     = 1

  db_subnet_group_name = aws_db_subnet_group.this.name
  publicly_accessible  = false
  ca_cert_identifier   = "rds-ca-ecc384-g1"

  auto_minor_version_upgrade   = false
  preferred_maintenance_window = var.preferred_maintenance_window
  copy_tags_to_snapshot        = true

  performance_insights_enabled          = true
  performance_insights_kms_key_id       = var.kms_key_arn
  performance_insights_retention_period = 7

  # The first instance becomes the writer, so readers wait for it.
  depends_on = [aws_rds_cluster_instance.writer]
}

# ---------------------------------------------------------------------------------------------------------------------
# The master password's secret (encryption 6.1, 6.3): standalone and primary only. Osaka gets a read-only replica
# under its own secrets key.
# ---------------------------------------------------------------------------------------------------------------------

resource "aws_secretsmanager_secret" "master" {
  count = var.master_secret == null ? 0 : 1

  name                    = var.master_secret.name
  description             = "Aurora master password of ${local.cluster_identifier}: the database bootstrap job, then BreakGlass only (encryption 6.3)"
  kms_key_id              = var.master_secret.kms_key_arn
  recovery_window_in_days = var.master_secret.recovery_window_in_days

  dynamic "replica" {
    for_each = var.master_secret.replica_kms_key_arn == null ? [] : [1]

    content {
      region     = var.master_secret.replica_region
      kms_key_id = var.master_secret.replica_kms_key_arn
    }
  }
}

# Identity policies alone would let any role with secretsmanager:GetSecretValue on * read it. This denies reading to
# everyone but the bootstrap job and BreakGlass, and writing to everyone but the deploy role (encryption 6.4).
data "aws_iam_policy_document" "master_secret" {
  count = var.master_secret == null ? 0 : 1

  statement {
    sid       = "ReadOnlyByBootstrapJobAndBreakGlass"
    effect    = "Deny"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = ["*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "ArnNotEquals"
      variable = "aws:PrincipalArn"
      values   = [var.master_secret.reader_role_arn]
    }

    condition {
      test     = "ArnNotLike"
      variable = "aws:PrincipalArn"
      values   = [var.master_secret.break_glass_arn_like]
    }
  }

  statement {
    sid    = "WrittenOnlyByDeployRole"
    effect = "Deny"
    actions = [
      "secretsmanager:CancelRotateSecret",
      "secretsmanager:PutSecretValue",
      "secretsmanager:RotateSecret",
      "secretsmanager:UpdateSecret",
      "secretsmanager:UpdateSecretVersionStage",
    ]
    resources = ["*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "ArnNotEquals"
      variable = "aws:PrincipalArn"
      values   = [var.master_secret.writer_role_arn]
    }
  }
}

resource "aws_secretsmanager_secret_policy" "master" {
  count = var.master_secret == null ? 0 : 1

  secret_arn          = aws_secretsmanager_secret.master[0].arn
  policy              = data.aws_iam_policy_document.master_secret[0].json
  block_public_policy = true
}

resource "aws_secretsmanager_secret_version" "master" {
  count = var.master_secret == null ? 0 : 1

  secret_id = aws_secretsmanager_secret.master[0].id
  secret_string_wo = jsonencode({
    username = var.master_username
    password = ephemeral.aws_secretsmanager_random_password.master[0].random_password
  })
  secret_string_wo_version = var.master_password_version
}
