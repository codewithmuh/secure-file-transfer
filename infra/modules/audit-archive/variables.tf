variable "account_id" {
  description = "ID of the account that owns the archive. The bucket name ends in it."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "account_id must be a 12-digit AWS account ID."
  }
}

variable "kms_key_arn" {
  description = "The audit key in this Region (the replica in Osaka): the default encryption and the only key the bucket policy accepts."
  type        = string

  validation {
    condition     = can(regex("^arn:aws:kms:ap-northeast-[13]:[0-9]{12}:key/mrk-[0-9a-f]{32}$", var.kms_key_arn))
    error_message = "kms_key_arn must be the ARN of a multi-Region key in Tokyo or Osaka."
  }
}

variable "object_lock_mode" {
  description = "COMPLIANCE in prod, GOVERNANCE in dev and staging so they can be torn down (encryption 3.1, NFR-15)."
  type        = string

  validation {
    condition     = contains(["COMPLIANCE", "GOVERNANCE"], var.object_lock_mode)
    error_message = "object_lock_mode must be COMPLIANCE or GOVERNANCE."
  }
}

variable "object_lock_days" {
  description = "Default retention: 365 days in prod, 1 day in dev and staging."
  type        = number

  validation {
    condition     = var.object_lock_days >= 1 && var.object_lock_days <= 365
    error_message = "object_lock_days must be between 1 and 365."
  }
}

variable "expiration_days" {
  description = "Days after which the lifecycle rule expires a record, when its retention has ended (NFR-9, ADR-0012)."
  type        = number
  default     = 365

  validation {
    condition     = var.expiration_days >= var.object_lock_days
    error_message = "A record can't expire before its Object Lock retention ends."
  }
}

variable "deploy_role_arn" {
  description = "Deploy role of the stack that owns the archive: the environment's in dev and staging, the retained stack's in prod."
  type        = string
}

variable "admin_principal_arn_patterns" {
  description = "ArnLike patterns for the Admin permission set, which may also change the bucket's settings (in prod, SCP 5 repeats it)."
  type        = list(string)
}

variable "break_glass_principal_arn_patterns" {
  description = "ArnLike patterns for BreakGlass, which may read records (table 4.3) but not change the bucket."
  type        = list(string)

  validation {
    condition     = length(var.break_glass_principal_arn_patterns) > 0
    error_message = "Name the BreakGlass role."
  }
}

variable "with_osaka" {
  description = "True where the environment has an Osaka archive (staging and prod): Tokyo's replication role then covers it."
  type        = bool
}

variable "osaka_kms_key_arn" {
  description = "Tokyo only, with with_osaka: the Osaka replica's ARN of the audit key."
  type        = string
  default     = null
}

variable "replicate_to_osaka" {
  description = "Tokyo only: replicate batches to the Osaka archive, without RTC (ADR-0012). The destination must exist first."
  type        = bool
  default     = false

  validation {
    condition     = !var.replicate_to_osaka || (var.with_osaka && var.osaka_kms_key_arn != null && var.replication_role_name != null)
    error_message = "replicate_to_osaka is for Tokyo with with_osaka, osaka_kms_key_arn and replication_role_name set."
  }
}

variable "replication_role_name" {
  description = "Tokyo, with with_osaka: the replication role. In dev and staging the files buckets' role, which this module adds a policy to; in prod the retained stack's own, which this module makes."
  type        = string
  default     = null
}

variable "create_replication_role" {
  description = "True in prod's retained stack: make replication_role_name here. False where the files-buckets module made it."
  type        = bool
  default     = false
}

variable "teardown_allowed" {
  description = "dev and staging: the deploy role may delete records once their governance-mode retention has passed, so the environment tears down. False in prod."
  type        = bool
}

variable "prevent_destroy" {
  description = "Guard the bucket with prevent_destroy: true in prod's retained stack (encryption 8.4)."
  type        = bool
  default     = false
}

variable "environment_retired" {
  description = "True once the environment is torn down (prod's retained stack, from its teardown apply on, encryption 8.4): the environment's workload roles leave the bucket policy, so nobody writes and only the audit reader and BreakGlass read (#263)."
  type        = bool
  default     = false
}

variable "conventions" {
  description = "The caller's conventions module (pass module.conventions): names the buckets, and the roles its policies name, from their one definition (#172)."
  type = object({
    global_name_prefix  = string
    region_shorts       = map(string)
    workload_role_names = map(string)
    workload_role_arns  = map(string)
  })
}
