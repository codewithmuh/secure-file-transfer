variable "account_id" {
  description = "ID of the shared account, which holds the zone."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "account_id must be a 12-digit AWS account ID."
  }
}

variable "domain" {
  description = "The maintainer's domain (PRD open question 5); the zone is sft.<domain>. Supplied at plan time, never committed."
  type        = string

  validation {
    condition     = can(regex("^([a-z0-9]([a-z0-9-]*[a-z0-9])?\\.)+[a-z]{2,}$", var.domain))
    error_message = "domain must be a lower-case domain name without a trailing dot."
  }
}

variable "member_account_ids" {
  description = "Account IDs of the environments that write records, by environment (dev, staging, prod). Never committed."
  type        = map(string)

  validation {
    condition = alltrue([
      for env, id in var.member_account_ids : contains(["dev", "staging", "prod"], env) && can(regex("^[0-9]{12}$", id))
    ])
    error_message = "member_account_ids maps dev, staging or prod to a 12-digit account ID."
  }
}

variable "record_labels" {
  description = "The labels each environment may write under its own domain, and anything below them."
  type        = list(string)
  default     = ["app", "api", "api-apne1", "api-apne3", "auth", "mail"]

  validation {
    condition     = alltrue([for label in var.record_labels : can(regex("^[a-z0-9]([a-z0-9-]*[a-z0-9])?$", label))])
    error_message = "Each label must be one lower-case DNS label."
  }
}

variable "record_types" {
  description = "Record types the environment roles may change. Never NS or DS: the zone delegates nothing (T-01)."
  type        = list(string)
  default     = ["A", "AAAA", "CNAME", "MX", "TXT"]

  validation {
    condition     = length(setintersection(var.record_types, ["NS", "DS", "SOA"])) == 0
    error_message = "record_types can't include NS, DS or SOA."
  }
}

variable "kms_alias_prefix" {
  description = "Prefix for the DNSSEC key's alias, from the conventions module: alias/sft/shared."
  type        = string
}

variable "bootstrap_iam_path" {
  description = "IAM path of the environments' Terraform roles, from the conventions module (/sft-bootstrap/)."
  type        = string
}

variable "iam_path" {
  description = "IAM path for the environment roles. Not /sft-bootstrap/: the deploy role must be able to change them (SCP 4)."
  type        = string

  validation {
    condition     = var.iam_path != "/sft-bootstrap/" && can(regex("^/([A-Za-z0-9-]+/)*$", var.iam_path))
    error_message = "iam_path must be an IAM path other than /sft-bootstrap/."
  }
}

variable "deploy_role_arn" {
  description = "ARN of the shared account's Terraform deploy role, which administers the DNSSEC key."
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

variable "break_glass_principal_arn_patterns" {
  description = "ArnLike patterns for the BreakGlass permission set's role in the shared account."
  type        = list(string)
}
