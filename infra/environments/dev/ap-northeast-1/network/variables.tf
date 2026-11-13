variable "account_id" {
  description = "ID of the dev AWS account. Supplied at plan time (TF_VAR_account_id), never committed."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "account_id must be a 12-digit AWS account ID."
  }
}

variable "flow_log_destination_arn" {
  description = "The VPC flow log's bucket ARN: the data root's flow_log_bucket_arn output (TF_VAR_flow_log_destination_arn). Null until data creates it."
  type        = string
  default     = null
}

variable "domain" {
  description = "The maintainer's domain; the shared zone is sft.<domain> (PRD open question 5). DNS Firewall answers the API's and the web app's names under it (#259). TF_VAR_domain, never committed."
  type        = string
}
