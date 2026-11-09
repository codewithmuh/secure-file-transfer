variable "environment" {
  description = "The environment: dev, staging or prod. The role is sft-<env>-break-glass-db."
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
  description = "This stack's Region: its cluster gets the connect policy, and its rule and topic carry the alert."
  type        = string

  validation {
    condition     = contains(["ap-northeast-1", "ap-northeast-3"], var.region)
    error_message = "region must be ap-northeast-1 or ap-northeast-3."
  }
}

variable "regions" {
  description = "The environment's Regions (dev: Tokyo; staging and prod: Tokyo and Osaka). The trust admits STS calls in these only, each of which has the alert rule. Used where create_role is true."
  type        = list(string)

  validation {
    condition     = length(var.regions) > 0 && alltrue([for r in var.regions : contains(["ap-northeast-1", "ap-northeast-3"], r)])
    error_message = "regions must name Tokyo, Osaka or both."
  }
}

variable "create_role" {
  description = "True in Tokyo, whose data stack creates the role; Osaka's adds its connect policy to it by name. IAM is global."
  type        = bool
}

variable "break_glass_principal_arn_patterns" {
  description = "ArnLike patterns for the BreakGlass permission set's role (modules/conventions), the only principal that may assume the role."
  type        = list(string)

  validation {
    condition     = length(var.break_glass_principal_arn_patterns) > 0
    error_message = "Name at least one BreakGlass principal, or nobody could use the role."
  }
}

variable "cluster_resource_id" {
  description = "Resource ID of this Region's Aurora cluster (modules/aurora, cluster_resource_id), which the rds-db:connect ARN names."
  type        = string

  validation {
    condition     = can(regex("^cluster-[A-Z0-9]+$", var.cluster_resource_id))
    error_message = "cluster_resource_id must be an Aurora cluster resource ID, cluster-<letters and digits>."
  }
}

variable "platform_key_arn" {
  description = "ARN of this Region's platform key, which encrypts the alert topic (encryption 3.1); its policy lets the delivery role use it through SNS."
  type        = string
}

variable "events_delivery_role_arn" {
  description = "ARN of sft-<env>-events-delivery, the role the rule delivers through and the only publisher to the topic (encryption 4.4)."
  type        = string
}

variable "deploy_role_arn" {
  description = "ARN of the Terraform deploy role, the only principal that may change or delete the alert topic."
  type        = string
}
