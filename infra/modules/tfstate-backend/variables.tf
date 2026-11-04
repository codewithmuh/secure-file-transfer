variable "account_id" {
  description = "ID of the account that owns the bucket and key."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "account_id must be a 12-digit AWS account ID."
  }
}

variable "bucket_name" {
  description = "Name of the state bucket, from the conventions module's state_bucket_name."
  type        = string

  validation {
    condition     = can(regex("^sft-[a-z]+-apne[13]-tfstate-[0-9]{12}$", var.bucket_name))
    error_message = "bucket_name must follow sft-<env>-<region-short>-tfstate-<account-id>."
  }
}

variable "kms_alias" {
  description = "Alias of the tfstate key, alias/sft/<env>/tfstate (encryption 4.1)."
  type        = string

  validation {
    condition     = can(regex("^alias/sft/[a-z]+/tfstate$", var.kms_alias))
    error_message = "kms_alias must be alias/sft/<env>/tfstate."
  }
}

variable "primary_key_arn" {
  description = "ARN of the Tokyo tfstate key. Set it in Osaka to create that key's replica; leave it null in Tokyo."
  type        = string
  default     = null

  validation {
    condition = (
      var.primary_key_arn == null
      || can(regex("^arn:aws:kms:ap-northeast-1:[0-9]{12}:key/mrk-[0-9a-f]{32}$", var.primary_key_arn))
    )
    error_message = "primary_key_arn must be the ARN of a multi-Region key in ap-northeast-1."
  }
}

variable "deletion_window_in_days" {
  description = "Days KMS waits before deleting the key, and the least the key policy allows (encryption 8.3)."
  type        = number

  validation {
    condition     = var.deletion_window_in_days >= 7 && var.deletion_window_in_days <= 30
    error_message = "deletion_window_in_days must be between 7 and 30."
  }
}

variable "admin_principal_arn_patterns" {
  description = "ArnLike patterns for the principals that apply the bootstrap stack: the Admin permission set (ADR-0006)."
  type        = list(string)

  validation {
    condition     = length(var.admin_principal_arn_patterns) > 0
    error_message = "At least one admin principal is needed, or nobody could manage the key."
  }
}

variable "break_glass_principal_arn_patterns" {
  description = "ArnLike patterns for BreakGlass, which may recover the key but not use it. Empty for none."
  type        = list(string)
  default     = []
}

variable "plan_role_arn" {
  description = "ARN of the Terraform plan role, which reads state and writes only lock files."
  type        = string
}

variable "deploy_role_arn" {
  description = "ARN of the deploy role, which reads and writes state. Null where CI never applies (management)."
  type        = string
  default     = null
}

variable "key_admin_role_arn" {
  description = "ARN of the key-admin role, which may read and put the key policy. Null where the account has none."
  type        = string
  default     = null
}

variable "noncurrent_version_retention_days" {
  description = "Days to keep a replaced state version. The last ten of each state are kept regardless."
  type        = number
  default     = 90

  validation {
    condition     = var.noncurrent_version_retention_days >= 30
    error_message = "Keep replaced state versions for at least 30 days."
  }
}
