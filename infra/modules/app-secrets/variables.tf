variable "environment" {
  description = "dev, staging or prod."
  type        = string

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be dev, staging or prod."
  }
}

variable "region" {
  description = "ap-northeast-1 or ap-northeast-3: names this Region's idp-client secret."
  type        = string
}

variable "primary_region" {
  description = "True in Tokyo, which holds the four keyrings; Osaka holds only its idp-client."
  type        = bool
}

variable "kms_alias_prefix" {
  description = "alias/sft/<env>, from the conventions module; the secrets key encrypts them."
  type        = string
}

variable "replica_region" {
  description = "ap-northeast-3 for Tokyo's keyrings in staging and prod; null in dev and in Osaka."
  type        = string
  default     = null
}

variable "replica_kms_key_arn" {
  description = "Osaka's secrets key, which encrypts each replica (the data layer's kms_osaka_key_arns[\"secrets\"])."
  type        = string
  default     = null

  validation {
    condition     = var.replica_region == null || var.replica_kms_key_arn != null
    error_message = "a replica needs Osaka's secrets key."
  }
}

variable "recovery_window_in_days" {
  description = "How long a deleted secret can be restored: 30 in prod, 7 elsewhere."
  type        = number
}
