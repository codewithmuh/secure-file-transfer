variable "conventions" {
  description = "The caller's conventions module (pass module.conventions): names the role and the buckets, from their one definition (#172)."
  type = object({
    global_name_prefix  = string
    region_shorts       = map(string)
    github_repository   = string
    workload_role_names = map(string)
  })
}

variable "environment" {
  description = "The environment: dev, staging or prod."
  type        = string

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be dev, staging or prod."
  }
}

variable "account_id" {
  description = "ID of this environment's account, which holds the web buckets."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "account_id must be a 12-digit AWS account ID."
  }
}

variable "shared_account_id" {
  description = "ID of the shared account, whose bundle store (infra/shared, modules/web-bundles) the role reads."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.shared_account_id))
    error_message = "shared_account_id must be a 12-digit AWS account ID."
  }
}

variable "regions" {
  description = "The Regions with a web bucket (modules/edge): Tokyo, and Osaka in staging and prod."
  type        = list(string)

  validation {
    condition     = length(var.regions) > 0 && alltrue([for r in var.regions : contains(["ap-northeast-1", "ap-northeast-3"], r)])
    error_message = "regions must name ap-northeast-1 and, outside dev, ap-northeast-3."
  }
}
