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
    database (Aurora), logs (its log group) and platform (queues and the counter store). Each is the Osaka replica of
    a multi-Region key; modules/data-stack checks them. Osaka has no master secret of its own, so no secrets key here:
    Tokyo's data stack replicates the secret under it (master_secret_replica_kms_key_arn).
  EOT
  type = object({
    database = string
    logs     = string
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
