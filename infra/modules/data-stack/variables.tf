variable "account_id" {
  description = "ID of the environment's AWS account, from the root's account_id."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "account_id must be a 12-digit AWS account ID."
  }
}

variable "conventions" {
  description = "The root's conventions module (pass module.conventions): names, the state bucket and the roles."
  type = object({
    region                = string
    name_prefix           = string
    global_name_prefix    = string
    state_bucket_name     = string
    sso_role_arn_patterns = object({ break_glass = string })
    bootstrap_role_arns   = object({ terraform_deploy = string })
  })

  validation {
    condition     = contains(["ap-northeast-1", "ap-northeast-3"], var.conventions.region)
    error_message = "The data layer exists only in Tokyo and Osaka."
  }

  validation {
    condition     = can(regex("^sft-(dev|staging|prod)$", var.conventions.global_name_prefix))
    error_message = "The data layer exists only in dev, staging and prod."
  }
}

variable "kms_key_arns" {
  description = <<-EOT
    This Region's keys by class (encryption 4.1): database (Aurora), logs (its log group), platform (queues and the
    counter store) and, where the master secret lives (standalone and primary), secrets. Each is a multi-Region key; in
    Osaka, the replica. Until #102 merges, each root takes them as a variable; then the keys module provides them.
  EOT
  type = object({
    database = string
    logs     = string
    platform = string
    secrets  = optional(string)
  })

  validation {
    condition = alltrue([
      for arn in values(var.kms_key_arns) :
      arn == null || can(regex("^arn:aws:kms:${var.conventions.region}:[0-9]{12}:key/mrk-[0-9a-f]{32}$", arn))
    ])
    error_message = "Each key must be a multi-Region key ARN in this stack's Region."
  }

  validation {
    condition     = (var.aurora.cluster_role == "secondary") == (var.kms_key_arns.secrets == null)
    error_message = "kms_key_arns.secrets is the master secret's key: set it for a standalone or primary cluster only."
  }
}

variable "aurora" {
  description = <<-EOT
    What differs between the data roots' clusters (ADR-0011, capacity 4.1, 4.5, 5.2, 5.3): the cluster's role, its
    instance class (db.serverless with serverless_capacity for Serverless v2), how many instances (one per AZ, the
    first the writer), the backup retention, and the master secret's recovery window outside teardown.
  EOT
  type = object({
    cluster_role                       = string
    engine_version                     = optional(string, "17.10")
    instance_class                     = string
    serverless_capacity                = optional(object({ min = number, max = number }))
    instance_count                     = optional(number, 1)
    backup_retention_days              = number
    master_secret_recovery_window_days = optional(number, 7)
  })

  validation {
    condition     = contains(["standalone", "primary", "secondary"], var.aurora.cluster_role)
    error_message = "aurora.cluster_role must be standalone, primary or secondary."
  }

  validation {
    condition     = contains([1, 2, 3], var.aurora.instance_count)
    error_message = "aurora.instance_count must be 1, 2 or 3: at most one instance per AZ."
  }
}

variable "master_secret_replica_kms_key_arn" {
  description = <<-EOT
    Osaka's replica of the secrets key, for the master secret's Osaka replica: staging and prod Tokyo only, null
    elsewhere and for the first Tokyo apply of a fresh build (infra/README.md, "Apply order"). A multi-Region replica
    has its primary's key ID, so it must be kms_key_arns.secrets's key in ap-northeast-3 (encryption 4.2).
  EOT
  type        = string
  default     = null

  validation {
    condition = var.master_secret_replica_kms_key_arn == null || (
      var.aurora.cluster_role == "primary" &&
      can(regex("^arn:aws:kms:ap-northeast-3:[0-9]{12}:key/mrk-[0-9a-f]{32}$", var.master_secret_replica_kms_key_arn)) &&
      try(split("/", var.master_secret_replica_kms_key_arn)[1] == split("/", var.kms_key_arns.secrets)[1], false)
    )
    error_message = "master_secret_replica_kms_key_arn is for a primary only, and must be the Osaka replica of kms_key_arns.secrets (same mrk- key ID, ap-northeast-3)."
  }
}

variable "master_password_version" {
  description = "Version of the master password (modules/aurora, encryption 6.3). Ignored by the secondary."
  type        = number
  default     = 1
}

variable "teardown" {
  description = <<-EOT
    True only for the apply that comes before destroying the stack: it turns deletion protection off, skips the final
    snapshot and lets the master secret go without a recovery window (infra/README.md, "Apply order").
  EOT
  type        = bool
  default     = false
}
