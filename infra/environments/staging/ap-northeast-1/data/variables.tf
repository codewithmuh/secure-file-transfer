variable "account_id" {
  description = "ID of the staging AWS account. Supplied at plan time (TF_VAR_account_id), never committed."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "account_id must be a 12-digit AWS account ID."
  }
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

variable "osaka_ready" {
  description = <<-EOT
    True once Osaka's data stack has made its buckets and key replicas: replication to them and the master secret's
    Osaka replica are on. Set it to false only for the first apply of a fresh build, before Osaka's data stack
    exists (infra/README.md, "Apply order"), so a later apply can't turn replication off by forgetting it.
  EOT
  type        = bool
  default     = true
}
