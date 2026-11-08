variable "environment" {
  description = "dev, staging or prod."
  type        = string

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be dev, staging or prod."
  }
}

variable "account_id" {
  description = "This environment's account, for the source conditions of the topic and identity policies."
  type        = string
}

variable "region" {
  description = "This stack's Region: ap-northeast-1 or ap-northeast-3 (NFR-21)."
  type        = string

  validation {
    condition     = contains(["ap-northeast-1", "ap-northeast-3"], var.region)
    error_message = "region must be ap-northeast-1 or ap-northeast-3."
  }
}

variable "region_short" {
  description = "apne1 or apne3, from the conventions module: the MAIL FROM subdomain's label."
  type        = string
}

variable "name_prefix" {
  description = "sft-<env>-<region-short>, from the conventions module: the topic is <prefix>-ses-events, the name the queue's and the platform key's policies expect."
  type        = string
}

variable "kms_alias_prefix" {
  description = "alias/sft/<env>, from the conventions module; the topic uses the platform key."
  type        = string
}

variable "domain" {
  description = "The maintainer's domain; the shared zone is sft.<domain>. Never committed."
  type        = string
}

variable "primary_region" {
  description = "True in Tokyo, which writes the sending subdomain's one DMARC record."
  type        = bool
}

variable "events_queue_arn" {
  description = "The ses-events queue (the data layer's queue_arns[\"ses-events\"]), whose policy admits only this topic."
  type        = string
}

variable "dmarc_report_address" {
  description = "Where DMARC aggregate reports go: a mailbox the maintainer reads (ADR-0015). Never committed."
  type        = string

  validation {
    condition     = can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", var.dmarc_report_address))
    error_message = "dmarc_report_address must be an email address."
  }
}
