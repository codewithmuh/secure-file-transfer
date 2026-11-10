variable "environment" {
  description = "The environment: dev, staging or prod. Names the service domain and the load test's secret."
  type        = string

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be dev, staging or prod."
  }
}

variable "account_id" {
  description = "ID of the environment's account. Bucket names end in it."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "account_id must be a 12-digit AWS account ID."
  }
}

variable "region" {
  description = "This stack's Region: its SES receives here and writes to its own bucket."
  type        = string

  validation {
    condition     = contains(["ap-northeast-1", "ap-northeast-3"], var.region)
    error_message = "region must be ap-northeast-1 or ap-northeast-3, both of which receive email."
  }
}

variable "domain" {
  description = "The maintainer's domain; the zone is sft.<domain> and the mailboxes probe. and loadtest. under the service domain. Never committed."
  type        = string
}

variable "mailboxes" {
  description = "The mailboxes this Region receives for: probe everywhere, loadtest in staging (docs/operations/performance.md)."
  type        = set(string)

  validation {
    condition     = contains(var.mailboxes, "probe") && length(setsubtract(var.mailboxes, ["probe", "loadtest"])) == 0
    error_message = "mailboxes holds probe, and loadtest where the load test runs."
  }
}

variable "mx_regions" {
  description = "Tokyo's stack only: the Regions the MX records name, preferred first (Tokyo, then Osaka in staging and prod). Empty in Osaka, whose records Tokyo's stack writes."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for r in var.mx_regions : contains(["ap-northeast-1", "ap-northeast-3"], r)])
    error_message = "mx_regions may name only ap-northeast-1 and ap-northeast-3."
  }
}

variable "platform_key_arn" {
  description = "This Region's platform key (data stack's kms_key_arns[\"platform\"]): the bucket's default encryption, whose policy admits SES and the readers (modules/kms-keys)."
  type        = string
}

variable "deploy_role_arn" {
  description = "The environment's Terraform deploy role: with Admin, the only principal that may change the bucket."
  type        = string
}

variable "admin_principal_arn_patterns" {
  description = "ArnLike patterns for the Admin permission set, which may also change the bucket and empty it."
  type        = list(string)
}

variable "load_test" {
  description = "staging's Tokyo stack only: the secrets key (data stack's kms_key_arns[\"secrets\"]) and the repository the load test's role trusts. Null elsewhere."
  type = object({
    secrets_key_arn   = string
    github_repository = string
  })
  default = null
}

variable "conventions" {
  description = "The caller's conventions module (pass module.conventions): names the bucket and the roles, from their one definition (#172)."
  type = object({
    global_name_prefix  = string
    region_shorts       = map(string)
    workload_role_names = map(string)
    workload_role_arns  = map(string)
  })
}
