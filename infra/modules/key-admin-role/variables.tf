variable "account_id" {
  description = "ID of the account the role lives in."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "account_id must be a 12-digit AWS account ID."
  }
}

variable "role_name" {
  description = "Name of the role, from the conventions module (sft-<env>-keyadmin)."
  type        = string
}

variable "iam_path" {
  description = "IAM path for the role, from the conventions module (/sft-bootstrap/)."
  type        = string
}

variable "break_glass_principal_arn_patterns" {
  description = "ArnLike patterns for the BreakGlass permission set's role, the only principal that may assume it."
  type        = list(string)

  validation {
    condition     = length(var.break_glass_principal_arn_patterns) > 0
    error_message = "Name at least one BreakGlass principal, or nobody could use the role."
  }
}
