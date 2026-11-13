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

variable "primary_key_arns" {
  description = "The Tokyo data stack's kms_key_arns output: the primary of each class, which this stack replicates. Supplied at plan time (TF_VAR_primary_key_arns), never committed."
  type        = map(string)

  validation {
    condition = alltrue([
      for arn in values(var.primary_key_arns) :
      can(regex("^arn:aws:kms:ap-northeast-1:[0-9]{12}:key/mrk-[0-9a-f]{32}$", arn))
    ])
    error_message = "Each value must be the ARN of a multi-Region key in ap-northeast-1."
  }
}

variable "malware_protection_enabled" {
  description = "Turn on GuardDuty Malware Protection for Osaka's large-files bucket. Off in the pilot light, with no plan at all; the failover runbook's apply creates it (ADR-0019)."
  type        = bool
  default     = false
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

variable "replicate_to_tokyo" {
  description = "At a failback only: replicate Osaka's files buckets back to Tokyo's (rule to-tokyo, with RTC), from the failback's step 2 until Osaka is back in its pilot light in step 8 (docs/runbooks/regional-failback.md, #262)."
  type        = bool
  default     = false
}
