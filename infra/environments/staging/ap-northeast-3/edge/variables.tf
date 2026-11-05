variable "account_id" {
  description = "ID of the staging AWS account. Supplied at plan time (TF_VAR_account_id), never committed."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "account_id must be a 12-digit AWS account ID."
  }
}

variable "shared_account_id" {
  description = "ID of the shared account, which holds the DNS zone. TF_VAR_shared_account_id, never committed."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.shared_account_id))
    error_message = "shared_account_id must be a 12-digit AWS account ID."
  }
}

variable "domain" {
  description = "The maintainer's domain; the shared zone is sft.<domain> (PRD open question 5). TF_VAR_domain, never committed."
  type        = string
}

variable "terraform_role" {
  description = "Which DNS role to assume in the shared account: plan (read) for plans, deploy (write) for applies."
  type        = string
  default     = "plan"

  validation {
    condition     = contains(["plan", "deploy"], var.terraform_role)
    error_message = "terraform_role must be plan or deploy."
  }
}

variable "web_distribution_arn" {
  description = "The Tokyo edge stack's web_distribution_arn output: the web bucket's only reader. Null until Tokyo has applied."
  type        = string
  default     = null
}
