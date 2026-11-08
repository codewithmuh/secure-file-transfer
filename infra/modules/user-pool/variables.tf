variable "environment" {
  description = "dev, staging or prod."
  type        = string

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be dev, staging or prod."
  }
}

variable "account_id" {
  description = "This environment's account; only its hash goes into the managed login prefix."
  type        = string
}

variable "region" {
  description = "ap-northeast-1 or ap-northeast-3 (NFR-21)."
  type        = string

  validation {
    condition     = contains(["ap-northeast-1", "ap-northeast-3"], var.region)
    error_message = "region must be ap-northeast-1 or ap-northeast-3."
  }
}

variable "region_short" {
  description = "apne1 or apne3, from the conventions module."
  type        = string
}

variable "name_prefix" {
  description = "sft-<env>-<region-short>, from the conventions module."
  type        = string
}

variable "domain" {
  description = "The maintainer's domain; the service is api.<service domain>. Never committed."
  type        = string
}

variable "ses_identity_arn" {
  description = "This Region's SES identity mail.<service domain> (modules/ses), which Cognito sends as."
  type        = string
}

variable "from_address" {
  description = "no-reply@mail.<service domain> (modules/ses)."
  type        = string
}

variable "ses_configuration_set" {
  description = "This Region's configuration set, sft-<env> (modules/ses)."
  type        = string
}

variable "sign_in_web_acl_arn" {
  description = "The edge stack's sign-in web ACL (abuse 3), or null before the edge exists."
  type        = string
  default     = null
}

variable "deletion_protection" {
  description = "True in prod: the pool holds every local member's credentials, which can't be exported (ADR-0016)."
  type        = bool
}
