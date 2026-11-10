variable "account_id" {
  description = "ID of the prod AWS account. Supplied at plan time (TF_VAR_account_id), never committed."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "account_id must be a 12-digit AWS account ID."
  }
}

variable "alert_emails" {
  description = "Who the alerts reach: the pager's and every operator's address. TF_VAR_alert_emails, as a JSON list, at apply time; never committed."
  type        = list(string)
}

variable "heartbeat_enabled" {
  description = "Whether the heartbeat alarm notifies. False during the pilot light, where no observability stack runs; the failover runbook sets it true (ADR-0009)."
  type        = bool
  default     = false
}

variable "pilot_light" {
  description = "True while Osaka waits (architecture 3.2): the API target alarm doesn't notify. The failover runbook sets it false."
  type        = bool
  default     = true
}

variable "probe_enabled" {
  description = "Whether the synthetic probe runs here (probe.enabled in deploy/environments, #248): creates its CloudWatch alarm. False until the probe's AWS side exists."
  type        = bool
  default     = false
}

variable "database_role" {
  description = "What Osaka's cluster is for the database alarms (modules/alarms): secondary in the pilot light; the failover runbook applies it as primary (TF_VAR_database_role=primary), so the writer's CPU and memory alarms watch Osaka, and the failback back to secondary (#261)."
  type        = string
  default     = "secondary"

  validation {
    condition     = contains(["primary", "secondary"], var.database_role)
    error_message = "database_role must be primary or secondary."
  }
}
