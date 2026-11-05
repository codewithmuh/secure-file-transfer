variable "account_id" {
  description = "ID of the shared account, which holds the archive."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "account_id must be a 12-digit AWS account ID."
  }
}

variable "management_account_id" {
  description = "ID of the management account, which owns the organization trail. Never committed."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.management_account_id))
    error_message = "management_account_id must be a 12-digit AWS account ID."
  }
}

variable "member_account_ids" {
  description = "Account IDs of the environments whose own trails deliver here, by environment. Never committed."
  type        = map(string)
  default     = {}

  validation {
    condition = alltrue([
      for env, id in var.member_account_ids : contains(["dev", "staging", "prod"], env) && can(regex("^[0-9]{12}$", id))
    ])
    error_message = "member_account_ids maps dev, staging or prod to a 12-digit account ID."
  }
}

variable "bucket_name" {
  description = "The archive bucket: sft-shared-apne1-log-archive-<account-id>, the name AuditReader expects."
  type        = string

  validation {
    condition     = can(regex("^sft-shared-apne1-log-archive-[0-9]{12}$", var.bucket_name))
    error_message = "bucket_name must be sft-shared-apne1-log-archive-<account-id>."
  }
}

variable "trail_name" {
  description = "Name of the organization trail."
  type        = string
  default     = "sft-organization"
}

variable "retention_days" {
  description = "Object Lock retention, and when records expire (T-75, architecture 5.5)."
  type        = number
  default     = 90

  validation {
    condition     = var.retention_days >= 90
    error_message = "retention_days must be at least 90 (T-75)."
  }
}

variable "kms_alias_prefix" {
  description = "Prefix for the logs key's alias, from the conventions module: alias/sft/shared."
  type        = string
}

variable "deploy_role_arn" {
  description = "ARN of the shared account's Terraform deploy role."
  type        = string
}

variable "plan_role_arn" {
  description = "ARN of the shared account's Terraform plan role."
  type        = string
}

variable "key_admin_role_arn" {
  description = "ARN of the shared account's key-admin role."
  type        = string
}

variable "admin_principal_arn_patterns" {
  description = "ArnLike patterns for the Admin permission set's role in the shared account."
  type        = list(string)
}

variable "break_glass_principal_arn_patterns" {
  description = "ArnLike patterns for the BreakGlass permission set's role in the shared account."
  type        = list(string)
}
