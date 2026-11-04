variable "account_id" {
  description = "ID of the staging AWS account. Supplied at plan time (TF_VAR_account_id), never committed."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "account_id must be a 12-digit AWS account ID."
  }
}

variable "tfstate_primary_key_arn" {
  description = "ARN of this account's tfstate key in Tokyo: the tfstate_key_arn output of the Tokyo bootstrap stack."
  type        = string

  validation {
    condition     = can(regex("^arn:aws:kms:ap-northeast-1:[0-9]{12}:key/mrk-[0-9a-f]{32}$", var.tfstate_primary_key_arn))
    error_message = "tfstate_primary_key_arn must be the ARN of the multi-Region tfstate key in ap-northeast-1."
  }
}
