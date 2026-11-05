variable "name_prefix" {
  description = "Prefix for resource names, from the caller's conventions module: sft-<env>-<region-short>."
  type        = string

  validation {
    condition     = can(regex("^sft-(dev|staging|prod)-apne[13]$", var.name_prefix))
    error_message = "name_prefix must be sft-<dev|staging|prod>-<apne1|apne3>, the conventions module's name_prefix."
  }
}

variable "cluster_role" {
  description = <<-EOT
    What this Region's cluster is (ADR-0011): standalone (dev, no global database), primary (Tokyo in staging and
    prod: it creates the global database and holds the master password) or secondary (Osaka: it joins the global
    database and has no master password of its own).
  EOT
  type        = string

  validation {
    condition     = contains(["standalone", "primary", "secondary"], var.cluster_role)
    error_message = "cluster_role must be standalone, primary or secondary."
  }
}

variable "global_cluster_identifier" {
  description = "Name of the Aurora global database, sft-<env>-aurora: created by the primary, joined by the secondary. Null for standalone."
  type        = string
  default     = null

  validation {
    condition     = var.global_cluster_identifier == null || can(regex("^sft-(staging|prod)-aurora$", var.global_cluster_identifier))
    error_message = "global_cluster_identifier must be sft-<staging|prod>-aurora, or null."
  }
}

variable "engine_version" {
  description = "Aurora PostgreSQL version, 17 or later (ADR-0011, data model 2.5). Both Regions run the same one; upgrades are rehearsed in staging first."
  type        = string

  validation {
    condition     = can(regex("^(1[7-9]|[2-9][0-9])\\.[0-9]+$", var.engine_version))
    error_message = "engine_version must be an Aurora PostgreSQL version of 17 or later, such as 17.10."
  }
}

variable "instance_class" {
  description = "Instance class: db.r8g.large in staging and prod, db.t4g.medium in dev, db.serverless for Aurora Serverless v2 (capacity 4.1, 4.5)."
  type        = string

  validation {
    condition     = can(regex("^db\\.(serverless|[a-z0-9]+\\.[a-z0-9]+)$", var.instance_class))
    error_message = "instance_class must be an RDS instance class such as db.r8g.large, or db.serverless."
  }
}

variable "serverless_capacity" {
  description = "ACU range for Aurora Serverless v2, required when instance_class is db.serverless (staging's Osaka secondary, capacity 4.5). Null otherwise."
  type = object({
    min = number
    max = number
  })
  default = null

  validation {
    condition = var.serverless_capacity == null ? true : (
      var.serverless_capacity.min >= 0.5 && var.serverless_capacity.max <= 256 &&
      var.serverless_capacity.min <= var.serverless_capacity.max
    )
    error_message = "serverless_capacity must have 0.5 <= min <= max <= 256."
  }
}

variable "instance_availability_zone_ids" {
  description = "One instance per AZ ID, in order: the first is created first and is the writer, the rest are readers in their own AZs (ADR-0011)."
  type        = list(string)

  validation {
    condition = (
      length(var.instance_availability_zone_ids) >= 1 &&
      length(distinct(var.instance_availability_zone_ids)) == length(var.instance_availability_zone_ids) &&
      alltrue([for id in var.instance_availability_zone_ids : can(regex("^apne[13]-az[1-4]$", id))])
    )
    error_message = "instance_availability_zone_ids must hold one or more distinct AZ IDs such as apne1-az1."
  }
}

variable "vpc_id" {
  description = "The VPC, from the network stack."
  type        = string
}

variable "subnet_ids" {
  description = "The isolated subnets, with no route out, from the network stack (ADR-0021). At least two AZs, as RDS requires."
  type        = list(string)

  validation {
    condition     = length(var.subnet_ids) >= 2
    error_message = "subnet_ids must name at least two subnets in different AZs."
  }
}

variable "client_security_group_ids" {
  description = "Security groups admitted on 5432, by role: the network module's main_nodes and scan_nodes (ADR-0021). Nothing else reaches the database."
  type        = map(string)

  validation {
    condition     = length(var.client_security_group_ids) > 0
    error_message = "client_security_group_ids must name at least one security group."
  }
}

variable "kms_key_arn" {
  description = "This Region's database key (alias/sft/<env>/database): storage, backups, snapshots and Performance Insights (encryption 3.1)."
  type        = string

  validation {
    condition     = can(regex("^arn:aws:kms:ap-northeast-[13]:[0-9]{12}:key/", var.kms_key_arn))
    error_message = "kms_key_arn must be a KMS key ARN in Tokyo or Osaka."
  }
}

variable "logs_kms_key_arn" {
  description = "This Region's logs key (alias/sft/<env>/logs), for the cluster's CloudWatch log group (encryption 3.1)."
  type        = string

  validation {
    condition     = can(regex("^arn:aws:kms:ap-northeast-[13]:[0-9]{12}:key/", var.logs_kms_key_arn))
    error_message = "logs_kms_key_arn must be a KMS key ARN in Tokyo or Osaka."
  }
}

variable "log_retention_days" {
  description = "Days the PostgreSQL log is kept in CloudWatch Logs. 90, like the other logs (ADR-0009)."
  type        = number
  default     = 90
}

variable "database_name" {
  description = "Name of the application database. Standalone and primary only; the secondary inherits it."
  type        = string
  default     = "sft"
}

variable "master_username" {
  description = "Aurora master user. Only the database bootstrap job and BreakGlass ever sign in with it (encryption 6.3)."
  type        = string
  default     = "sft_master"
}

variable "master_password_version" {
  description = <<-EOT
    Version of the master password. Raising it in a reviewed change sends a new random password to the cluster and
    the secret through write-only arguments, so it never reaches the plan or the state; the runbook does that after
    every use and every 90 days (encryption 6.3). Ignored by the secondary.
  EOT
  type        = number
  default     = 1

  validation {
    condition     = var.master_password_version >= 1 && floor(var.master_password_version) == var.master_password_version
    error_message = "master_password_version must be a whole number, 1 or more."
  }
}

variable "master_secret" {
  description = <<-EOT
    The master password's secret, sft/<env>/db/master (encryption 6.1), for the standalone and primary clusters; null
    for the secondary. kms_key_arn is the secrets key; replica_kms_key_arn is the Osaka copy of it for the read-only
    replica, or null for none (dev, or a fresh build before Osaka's keys exist). Only the database bootstrap job and
    BreakGlass may read it, and only the deploy role may write it.
  EOT
  type = object({
    name                    = string
    kms_key_arn             = string
    replica_region          = optional(string, "ap-northeast-3")
    replica_kms_key_arn     = optional(string)
    reader_role_arn         = string
    break_glass_arn_like    = string
    writer_role_arn         = string
    recovery_window_in_days = number
  })
  default = null

  validation {
    condition     = var.master_secret == null || can(regex("^sft/(dev|staging|prod)/db/master$", var.master_secret.name))
    error_message = "master_secret.name must be sft/<env>/db/master."
  }

  validation {
    condition     = var.master_secret == null || contains([0, 7, 14, 30], try(var.master_secret.recovery_window_in_days, -1))
    error_message = "master_secret.recovery_window_in_days must be 0 (teardown), 7, 14 or 30."
  }
}

variable "backup_retention_days" {
  description = "Days of point-in-time recovery: 14 in staging and prod (NFR-11), in both Regions (#42 is open on Osaka's)."
  type        = number

  validation {
    condition     = var.backup_retention_days >= 1 && var.backup_retention_days <= 35
    error_message = "backup_retention_days must be between 1 and 35."
  }
}

variable "preferred_backup_window" {
  description = "Daily backup window in UTC, outside the maintenance window. 18:00-18:30 UTC is 03:00 in Japan."
  type        = string
  default     = "18:00-18:30"
}

variable "preferred_maintenance_window" {
  description = "Weekly maintenance window in UTC. Sunday 19:00-20:00 UTC is Monday 04:00 in Japan."
  type        = string
  default     = "sun:19:00-sun:20:00"
}

variable "deletion_protection" {
  description = "Refuse to delete the cluster. True except in the teardown apply that comes before a destroy (infra/README.md)."
  type        = bool
  default     = true
}

variable "skip_final_snapshot" {
  description = <<-EOT
    Destroy without a final snapshot. Only the teardown apply sets it: a snapshot would outlive the environment under a
    key that is being deleted, so it could never be restored (encryption 8.4).
  EOT
  type        = bool
  default     = false
}

variable "pgaudit_log" {
  description = <<-EOT
    pgaudit.log for every session: the statement classes audited by default. DDL and role changes, so migrations and
    grants are on record without auditing every workload query. The master user's sessions are audited in full by a
    role setting (ALTER ROLE ... SET pgaudit.log = 'all'), which the database bootstrap job sets (authn-authz 8.3).
  EOT
  type        = string
  default     = "ddl,role"
}
