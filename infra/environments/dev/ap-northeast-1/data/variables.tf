variable "account_id" {
  description = "ID of the dev AWS account. Supplied at plan time (TF_VAR_account_id), never committed."
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
