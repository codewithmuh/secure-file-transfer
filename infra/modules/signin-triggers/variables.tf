variable "environment" {
  description = "dev, staging or prod."
  type        = string

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be dev, staging or prod."
  }
}

variable "account_id" {
  description = "ID of the environment's account."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "account_id must be a 12-digit AWS account ID."
  }
}

variable "region" {
  description = "This stack's Region: ap-northeast-1 or ap-northeast-3."
  type        = string

  validation {
    condition     = contains(["ap-northeast-1", "ap-northeast-3"], var.region)
    error_message = "region must be ap-northeast-1 or ap-northeast-3."
  }
}

variable "name_prefix" {
  description = "Regional name prefix from the conventions module: sft-<env>-<region-short>."
  type        = string

  validation {
    condition     = can(regex("^sft-(dev|staging|prod)-apne[13]$", var.name_prefix))
    error_message = "name_prefix must be sft-<dev|staging|prod>-<apne1|apne3>."
  }
}

variable "kms_alias_prefix" {
  description = "KMS alias prefix from the conventions module; the function's log group uses <prefix>/logs."
  type        = string
}

variable "create_role" {
  description = <<-EOT
    True in Tokyo: IAM is global, so Tokyo's stack makes the role sft-<env>-signin-trigger for both Regions, which
    the queues' policies, the platform key's policy and the Valkey users already name. Osaka's stack uses it.
  EOT
  type        = bool
}

variable "regions" {
  description = "Every Region of the environment, for the role's resources: Tokyo, and Osaka in staging and prod."
  type        = list(string)

  validation {
    condition     = length(var.regions) > 0 && alltrue([for r in var.regions : contains(["ap-northeast-1", "ap-northeast-3"], r)])
    error_message = "regions lists ap-northeast-1 and, where there is one, ap-northeast-3."
  }
}

variable "image_uri" {
  description = <<-EOT
    The API image, by digest, in the shared registry: <registry>/sft/app@sha256:<digest>. The deploy supplies the
    digest it promotes; the function runs it as python -m sft.workers.signin_trigger.
  EOT
  type        = string

  validation {
    condition     = can(regex("^[0-9a-z.-]+/sft/app@sha256:[0-9a-f]{64}$", var.image_uri))
    error_message = "image_uri must name sft/app by digest: <registry>/sft/app@sha256:<64 hex digits>."
  }
}

variable "user_pool_arn" {
  description = "The user pool whose triggers these are: only it may invoke the function."
  type        = string
}

variable "valkey" {
  description = "The counter store, from the data layer: its cache ARN, endpoint and security group."
  type = object({
    cache_arn         = string
    address           = string
    port              = number
    security_group_id = string
  })
}

variable "log_retention_days" {
  description = "How long the function's logs are kept (PRD data lifecycle: operational logs 90 days)."
  type        = number
  default     = 90
}

variable "conventions" {
  description = "The caller's conventions module (pass module.conventions): names the role and every Region's resources it reaches, from their one definition (#172)."
  type = object({
    region_shorts       = map(string)
    workload_role_names = map(string)
  })
}
