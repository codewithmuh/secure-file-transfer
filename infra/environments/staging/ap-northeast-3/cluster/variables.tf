variable "account_id" {
  description = "ID of the staging AWS account. Supplied at plan time (TF_VAR_account_id), never committed."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "account_id must be a 12-digit AWS account ID."
  }
}

variable "system_node_count" {
  description = "Osaka's system nodes: 1 in the pilot light (ADR-0004); the failover runbook applies 2 (TF_VAR_system_node_count=2) and the failback 1 again, so Git and the node group agree (#261)."
  type        = number
  default     = 1

  validation {
    condition     = contains([1, 2], var.system_node_count)
    error_message = "system_node_count is 1 in the pilot light and 2 after a failover."
  }
}
