variable "account_id" {
  description = "ID of the account the roles live in."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "account_id must be a 12-digit AWS account ID."
  }
}

variable "github_repository" {
  description = "owner/name of the repository whose workflows may assume the roles. No wildcards (T-71)."
  type        = string

  validation {
    condition     = can(regex("^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", var.github_repository))
    error_message = "github_repository must be owner/name, without wildcards."
  }
}

variable "github_environment" {
  description = "GitHub environment the deploy role trusts, for example prod. Null for no deploy role (ADR-0006)."
  type        = string
  default     = null

  validation {
    condition     = var.github_environment == null || can(regex("^[A-Za-z0-9_-]+$", var.github_environment))
    error_message = "github_environment must be a plain environment name, without wildcards."
  }
}

variable "network_regions" {
  description = "Regions where this account has network stacks (#56): the roles get that layer's permissions there. Empty for none."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for r in var.network_regions : contains(["ap-northeast-1", "ap-northeast-3"], r)])
    error_message = "network_regions may hold only ap-northeast-1 and ap-northeast-3 (NFR-21)."
  }
}

variable "create_oidc_provider" {
  description = "Create the GitHub OIDC provider. False only if another stack owns it: an account has one per issuer."
  type        = bool
  default     = true
}

variable "iam_path" {
  description = "IAM path for the roles, from the conventions module (/sft-bootstrap/)."
  type        = string
}

variable "plan_role_name" {
  description = "Name of the plan role, from the conventions module."
  type        = string
}

variable "deploy_role_name" {
  description = "Name of the deploy role, from the conventions module."
  type        = string
}

variable "deploy_max_session_seconds" {
  description = "Longest deploy session. Two hours covers a full rebuild (NFR-19's 2-hour target)."
  type        = number
  default     = 7200

  validation {
    condition     = var.deploy_max_session_seconds >= 3600 && var.deploy_max_session_seconds <= 43200
    error_message = "deploy_max_session_seconds must be between 3600 and 43200."
  }
}
