variable "account_id" {
  description = "ID of the prod AWS account. Supplied at plan time (TF_VAR_account_id), never committed."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "account_id must be a 12-digit AWS account ID."
  }
}

variable "teardown" {
  description = <<-EOT
    True only for the apply that comes before prod's teardown (architecture 3.4 step 1, encryption 8.4,
    docs/runbooks/teardown.md): the key-admin role, which the bootstrap stack's destroy removes, leaves the audit key's
    policy, and the $7 NFR-19 budget is created. Once true, it stays true: the stack outlives the environment.
  EOT
  type        = bool
  default     = false
}

variable "budget_email" {
  description = "The address the NFR-19 budget emails (teardown only). Supplied at apply time, never committed."
  type        = string
  default     = null

  validation {
    condition     = var.budget_email == null || can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", var.budget_email))
    error_message = "budget_email must be an email address."
  }

  validation {
    condition     = !var.teardown || var.budget_email != null
    error_message = "The teardown apply creates the NFR-19 budget: name the address it emails (TF_VAR_budget_email)."
  }
}
