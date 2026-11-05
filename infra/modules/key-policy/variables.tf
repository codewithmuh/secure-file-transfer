variable "account_id" {
  description = "ID of the account the key lives in."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "account_id must be a 12-digit AWS account ID."
  }
}

variable "deploy_role_arn" {
  description = "ARN of the stack's Terraform deploy role, which creates and administers the key."
  type        = string
}

variable "plan_role_arn" {
  description = "ARN of the stack's Terraform plan role, which reads the key's metadata and policy."
  type        = string
}

variable "key_admin_role_arn" {
  description = "ARN of the account's key-admin role (sft-<env>-keyadmin), which may only read and put the policy."
  type        = string
}

variable "break_glass_principal_arn_patterns" {
  description = "ArnLike patterns for the BreakGlass permission set's role in this account."
  type        = list(string)

  validation {
    condition     = length(var.break_glass_principal_arn_patterns) > 0
    error_message = "break_glass_principal_arn_patterns needs at least one pattern."
  }
}

variable "additional_policy_documents" {
  description = "JSON policy documents with the statements for the services and roles that use the key."
  type        = list(string)
  default     = []
}
