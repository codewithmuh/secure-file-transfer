variable "name_prefix" {
  description = "Prefix for queue names, from the caller's conventions module: sft-<env>-<region-short>."
  type        = string

  validation {
    condition     = can(regex("^sft-(dev|staging|prod)-apne[13]$", var.name_prefix))
    error_message = "name_prefix must be sft-<dev|staging|prod>-<apne1|apne3>, the conventions module's name_prefix."
  }
}

variable "senders" {
  description = <<-EOT
    The one principal that may send to each kind of queue (ADR-0013, T-50), by exact ARN, never a pattern: the outbox
    relay's role (the work queues), the sign-in triggers' role (signin-events), the EventBridge delivery role
    (guardduty-results, ses-tenant-status) and the SES events topic (ses-events). The roles may not exist yet: the
    queue policies match them by aws:PrincipalArn, which needs no existing principal.
  EOT
  type = object({
    relay_role_arn           = string
    signin_trigger_role_arn  = string
    events_delivery_role_arn = string
    ses_events_topic_arn     = string
  })

  validation {
    condition = alltrue([
      for arn in [var.senders.relay_role_arn, var.senders.signin_trigger_role_arn, var.senders.events_delivery_role_arn] :
      can(regex("^arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]+$", arn))
    ])
    error_message = "Each sender role must be an IAM role ARN without wildcards."
  }

  validation {
    condition     = can(regex("^arn:aws:sns:ap-northeast-[13]:[0-9]{12}:[A-Za-z0-9_-]+$", var.senders.ses_events_topic_arn))
    error_message = "ses_events_topic_arn must be an SNS topic ARN in Tokyo or Osaka, without wildcards."
  }
}

variable "kms_key_arn" {
  description = "This Region's platform key (alias/sft/<env>/platform), for SSE-KMS on every queue (encryption 3.1)."
  type        = string

  validation {
    condition     = can(regex("^arn:aws:kms:ap-northeast-[13]:[0-9]{12}:key/", var.kms_key_arn))
    error_message = "kms_key_arn must be a KMS key ARN in Tokyo or Osaka."
  }
}

variable "message_retention_seconds" {
  description = "How long a queue keeps a message: 4 days (architecture 5.6)."
  type        = number
  default     = 345600
}

variable "dead_letter_retention_seconds" {
  description = "How long a dead-letter queue keeps a message: 14 days, the longest SQS allows (architecture 5.6)."
  type        = number
  default     = 1209600
}

variable "max_receive_count" {
  description = "Receives before a message moves to its dead-letter queue: 5 to start with (ADR-0013)."
  type        = number
  default     = 5

  validation {
    condition     = var.max_receive_count >= 1 && var.max_receive_count <= 1000
    error_message = "max_receive_count must be between 1 and 1000."
  }
}
