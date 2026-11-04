variable "account_id" {
  description = "ID of the management AWS account. Supplied at plan time (TF_VAR_account_id), never committed."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "account_id must be a 12-digit AWS account ID."
  }
}

variable "admin_principal_arn_patterns" {
  description = "ArnLike patterns for the principals that apply this account's stacks. No default: Identity Center may not exist yet."
  type        = list(string)

  validation {
    condition     = length(var.admin_principal_arn_patterns) > 0
    error_message = "Name at least one admin principal, or nobody could manage the state key."
  }
}
