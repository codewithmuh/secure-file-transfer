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
    bootstrap_iam_path    = string
    sso_role_arn_patterns = object({ admin = string, break_glass = string })
    bootstrap_role_arns   = object({ terraform_deploy = string, terraform_plan = string, key_admin = string })
    region_shorts         = map(string)
    workload_role_names   = map(string)
    workload_role_arns    = map(string)
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

variable "aurora" {
  description = <<-EOT
    What differs between the data roots' clusters (ADR-0011, capacity 4.1, 4.5, 5.2, 5.3): the cluster's role, its
    instance class (db.serverless with serverless_capacity for Serverless v2), how many instances (one per AZ, the
    first the writer), the backup retention, the master secret's recovery window outside teardown, and the global
    database's generation: 1 (sft-<env>-aurora) until a failback after a detach makes a new one from Osaka's cluster
    (#261, docs/runbooks/regional-failback.md).
  EOT
  type = object({
    cluster_role                       = string
    engine_version                     = optional(string, "17.10")
    instance_class                     = string
    serverless_capacity                = optional(object({ min = number, max = number }))
    instance_count                     = optional(number, 1)
    backup_retention_days              = number
    master_secret_recovery_window_days = optional(number, 7)
    global_generation                  = optional(number, 1)
  })

  validation {
    condition     = contains(["standalone", "primary", "secondary"], var.aurora.cluster_role)
    error_message = "aurora.cluster_role must be standalone, primary or secondary."
  }

  validation {
    condition     = var.aurora.global_generation >= 1 && var.aurora.global_generation <= 9 && floor(var.aurora.global_generation) == var.aurora.global_generation
    error_message = "aurora.global_generation must be a whole number from 1 to 9."
  }

  validation {
    condition     = contains([1, 2, 3], var.aurora.instance_count)
    error_message = "aurora.instance_count must be 1, 2 or 3: at most one instance per AZ."
  }
}

variable "primary_key_arns" {
  description = <<-EOT
    Osaka only: the Tokyo data stack's kms_key_arns output, the primary of each class, which this stack replicates
    (TF_VAR_primary_key_arns, never committed). Empty in Tokyo, where the keys module makes the primaries.
  EOT
  type        = map(string)
  default     = {}

  validation {
    condition     = (var.conventions.region == "ap-northeast-3") == (length(var.primary_key_arns) > 0)
    error_message = "primary_key_arns is required in Osaka and must be empty in Tokyo."
  }
}

variable "osaka_ready" {
  description = <<-EOT
    Tokyo in staging and prod: true once Osaka's data stack has made its buckets and key replicas. It turns on S3
    replication to them and the master secret's Osaka replica. False only for the first Tokyo apply of a fresh build
    (infra/README.md, "Apply order"). Ignored in dev and in Osaka.
  EOT
  type        = bool
  default     = true
}

variable "osaka_malware_protection_enabled" {
  description = "Osaka only: turn on GuardDuty Malware Protection for the large-files bucket. Off in the pilot light, with no plan at all; the failover runbook's apply creates it (ADR-0019). Tokyo always has it."
  type        = bool
  default     = false

  validation {
    condition     = !var.osaka_malware_protection_enabled || var.conventions.region == "ap-northeast-3"
    error_message = "osaka_malware_protection_enabled is for Osaka only; Tokyo always has Malware Protection."
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

variable "replicate_to_tokyo" {
  description = <<-EOT
    Osaka only, at a failback: replicate Osaka's files buckets back to Tokyo's (rule to-tokyo, with RTC), so the files
    uploaded during a failover reach Tokyo (#262, #42 gap 4). Set by the failback runbook's step 2
    (TF_VAR_replicate_to_tokyo=true) and cleared in its step 8. Ignored in Tokyo.
  EOT
  type        = bool
  default     = false
}
