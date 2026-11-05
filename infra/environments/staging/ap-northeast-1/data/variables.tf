variable "account_id" {
  description = "ID of the staging AWS account. Supplied at plan time (TF_VAR_account_id), never committed."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "account_id must be a 12-digit AWS account ID."
  }
}

variable "kms_key_arns" {
  description = <<-EOT
    This Region's keys by class (encryption 4.1), until #102 merges and module.kms.key_arns replaces this variable:
    database (Aurora), logs (its log group), secrets (the master password) and platform (queues and the counter
    store). Each is a multi-Region key in ap-northeast-1; modules/data-stack checks them.
  EOT
  type = object({
    database = string
    logs     = string
    secrets  = string
    platform = string
  })
}

variable "teardown" {
  description = <<-EOT
    True only for the apply that comes before destroying this stack: it turns deletion protection off, skips the
    final snapshot and lets the master secret go without a recovery window (infra/README.md, "Apply order").
  EOT
  type        = bool
  default     = false
}

variable "master_password_version" {
  description = "Version of the Aurora master password. Raise it in a reviewed change to set a new one, after every use and every 90 days (encryption 6.3)."
  type        = number
  default     = 1
}

variable "replicate_master_secret" {
  description = <<-EOT
    Replicate the master secret to Osaka under Osaka's secrets key. On a fresh build that key replica doesn't exist
    until Osaka's data stack is applied, so the first apply here sets this to false and the second, after Osaka's,
    leaves it true (infra/README.md, "Apply order").
  EOT
  type        = bool
  default     = true
}

variable "master_secret_replica_kms_key_arn" {
  description = <<-EOT
    Osaka's replica of the secrets key (alias/sft/<env>/secrets in ap-northeast-3), for the master secret's Osaka
    replica, until #102 merges and its keys module provides it. A multi-Region replica keeps its primary's key ID, so
    it is kms_key_arns.secrets's key ID in ap-northeast-3; modules/data-stack checks that (encryption 4.2).
  EOT
  type        = string
}
