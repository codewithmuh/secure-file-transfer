variable "account_id" {
  description = "ID of the prod AWS account. Supplied at plan time (TF_VAR_account_id), never committed."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "account_id must be a 12-digit AWS account ID."
  }
}

variable "teardown" {
  description = "True only for the apply that comes before destroying this stack (ops/teardown.sh, docs/runbooks/teardown.md): it turns the EKS cluster's deletion protection off, so the destroy can run (NFR-19, #263)."
  type        = bool
  default     = false
}
