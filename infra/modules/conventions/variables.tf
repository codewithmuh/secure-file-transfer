variable "environment" {
  description = "The account the stack runs in: management, shared, dev, staging or prod (ADR-0006)."
  type        = string

  validation {
    condition     = contains(["management", "shared", "dev", "staging", "prod"], var.environment)
    error_message = "environment must be one of management, shared, dev, staging or prod."
  }
}

variable "region" {
  description = "The stack's home Region: Tokyo or Osaka (NFR-21). Providers for us-east-1 override the region tag."
  type        = string

  validation {
    condition     = contains(["ap-northeast-1", "ap-northeast-3"], var.region)
    error_message = "region must be ap-northeast-1 or ap-northeast-3."
  }
}

variable "account_id" {
  description = "ID of the AWS account the stack runs in. Supplied at plan time, never committed."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "account_id must be a 12-digit AWS account ID."
  }
}

variable "stack" {
  description = "The root module's directory under infra/, which is also its state key without /terraform.tfstate."
  type        = string

  validation {
    condition     = can(regex("^(bootstrap|organization|shared|environments)(/[a-z0-9-]+)*$", var.stack))
    error_message = "stack must be the root's path under infra/, for example environments/prod/ap-northeast-1/network."
  }
}

variable "component" {
  description = "Cost line the stack's resources belong to (capacity 7.3). Modules may override it per resource."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,31}$", var.component))
    error_message = "component must be lowercase letters, digits and hyphens, at most 32 characters."
  }
}

variable "extra_tags" {
  description = "Tags added to the standard set, for example retention = audit-archive on the retained stack."
  type        = map(string)
  default     = {}

  validation {
    condition = length(setintersection(
      keys(var.extra_tags),
      ["project", "environment", "region", "stack", "component", "managed-by", "repository"],
    )) == 0
    error_message = "extra_tags can't replace a standard tag."
  }
}
