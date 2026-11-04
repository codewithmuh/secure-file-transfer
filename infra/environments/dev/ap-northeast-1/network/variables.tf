variable "account_id" {
  description = "ID of the dev AWS account. Supplied at plan time (TF_VAR_account_id), never committed."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "account_id must be a 12-digit AWS account ID."
  }
}

variable "flow_log_destination_arn" {
  description = "The environment's log bucket ARN, optionally with /prefix/, for the VPC flow log. Null until data creates it."
  type        = string
  default     = null
}
