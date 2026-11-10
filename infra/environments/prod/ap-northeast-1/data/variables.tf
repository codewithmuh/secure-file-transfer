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

variable "aurora_role" {
  description = <<-EOT
    What Tokyo's Aurora cluster is in the global database: primary from the build on. A failback after a detach sets
    secondary (TF_VAR_aurora_role=secondary): Tokyo's old cluster goes, with its final snapshot, and a new one joins
    Osaka's global database as its secondary; the switchover then makes it the writer, and the input stays secondary
    until the next rebuild, because changing it replaces the cluster (docs/runbooks/regional-failback.md, #261).
  EOT
  type        = string
  default     = "primary"

  validation {
    condition     = contains(["primary", "secondary"], var.aurora_role)
    error_message = "aurora_role must be primary or secondary."
  }
}

variable "aurora_global_generation" {
  description = <<-EOT
    The global database's generation: 1 (sft-<env>-aurora) from the build on. A failback after a detach makes a new
    global database from Osaka's cluster, sft-<env>-aurora-2, and both data roots take 2 from then on
    (docs/runbooks/regional-failback.md, #261).
  EOT
  type        = number
  default     = 1
}
