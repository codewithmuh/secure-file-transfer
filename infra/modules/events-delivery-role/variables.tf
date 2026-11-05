variable "environment" {
  description = "The environment: dev, staging or prod. The role is sft-<env>-events-delivery."
  type        = string

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be dev, staging or prod."
  }
}

variable "account_id" {
  description = "ID of the account the role lives in."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "account_id must be a 12-digit AWS account ID."
  }
}

variable "regions" {
  description = "Regions whose rules may deliver through the role: Tokyo in dev, Tokyo and Osaka in staging and prod."
  type        = list(string)

  validation {
    condition = length(var.regions) > 0 && alltrue([
      for r in var.regions : contains(["ap-northeast-1", "ap-northeast-3"], r)
    ])
    error_message = "regions may hold only ap-northeast-1 and ap-northeast-3 (NFR-21)."
  }
}

variable "queue_names" {
  description = "Short names of the queues the role delivers to, from the queues module's queue_names_by_sender_role for this role: the same in each Region."
  type        = list(string)

  validation {
    condition     = length(var.queue_names) > 0 && alltrue([for q in var.queue_names : can(regex("^[a-z0-9-]+$", q))])
    error_message = "Name at least one queue, by its short name (guardduty-results, not an ARN)."
  }
}

variable "platform_key_arns" {
  description = "The platform key in each of those Regions (the Osaka one is the replica's ARN)."
  type        = list(string)

  validation {
    condition     = length(var.platform_key_arns) > 0
    error_message = "Name the platform key: the queues and topics are encrypted with it."
  }
}

variable "permissions_boundary_arn" {
  description = "The account's workload permissions boundary, sft-<env>-workload-boundary under /sft-bootstrap/, which the bootstrap stack makes (terraform-oidc-roles)."
  type        = string

  validation {
    condition     = can(regex("^arn:aws:iam::[0-9]{12}:policy/sft-bootstrap/sft-(dev|staging|prod)-workload-boundary$", var.permissions_boundary_arn))
    error_message = "permissions_boundary_arn must be sft-<env>-workload-boundary under /sft-bootstrap/."
  }
}
