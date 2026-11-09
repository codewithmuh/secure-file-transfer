variable "environment" {
  description = "The environment: dev, staging or prod."
  type        = string

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be dev, staging or prod."
  }
}

variable "region" {
  description = "This stack's Region: its Loki and Tempo buckets and its cluster's Pod Identity associations."
  type        = string

  validation {
    condition     = contains(["ap-northeast-1", "ap-northeast-3"], var.region)
    error_message = "region must be ap-northeast-1 or ap-northeast-3."
  }
}

variable "regions" {
  description = "The environment's Regions with a cluster (dev: Tokyo; staging and prod: Tokyo and Osaka). The roles admit every one of their clusters, so Osaka's stack works after a failover with no IAM change."
  type        = list(string)

  validation {
    condition     = length(var.regions) > 0 && alltrue([for r in var.regions : contains(["ap-northeast-1", "ap-northeast-3"], r)])
    error_message = "regions must name Tokyo, Osaka or both."
  }
}

variable "account_id" {
  description = "ID of the environment's account. The buckets' names end in it."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "account_id must be a 12-digit AWS account ID."
  }
}

variable "cluster_name" {
  description = "This Region's cluster (sft-<env>-<region-short>-eks), from the cluster layer: the Pod Identity associations' cluster."
  type        = string

  validation {
    condition     = can(regex("^sft-(dev|staging|prod)-apne[13]-eks$", var.cluster_name))
    error_message = "cluster_name must be sft-<env>-<region-short>-eks."
  }
}

variable "create_iam" {
  description = "Create the account's observability roles. True in Tokyo only: the roles are account-wide and Osaka's stack refers to them by name, like the cluster layer's (modules/eks-cluster)."
  type        = bool
}

variable "logs_key_arn" {
  description = "This Region's logs key (alias/sft/<env>/logs), from the data layer: the Loki and Tempo buckets' default encryption (encryption 3.1). Its key policy already admits sft-<env>-loki and sft-<env>-tempo through S3."
  type        = string

  validation {
    condition     = can(regex("^arn:aws:kms:ap-northeast-[13]:[0-9]{12}:key/mrk-[0-9a-f]{32}$", var.logs_key_arn))
    error_message = "logs_key_arn must be a multi-Region KMS key ARN in Tokyo or Osaka."
  }
}

variable "permissions_boundary_arn" {
  description = "The observability roles' permissions boundary, sft-<env>-observability-boundary, which the account's bootstrap stack makes (modules/terraform-oidc-roles, permissions-observability.tf)."
  type        = string

  validation {
    condition     = can(regex("^arn:aws:iam::[0-9]{12}:policy/.+-observability-boundary$", var.permissions_boundary_arn))
    error_message = "permissions_boundary_arn must be the observability boundary policy's ARN."
  }
}

variable "loki_retention_days" {
  description = "Loki deletes logs after its own retention (deploy/observability/environments); the bucket's lifecycle rule removes anything older a few days later, as a safety net. 90 days of logs in prod (PRD data lifecycle)."
  type        = number
  default     = 95

  validation {
    condition     = var.loki_retention_days >= 7
    error_message = "loki_retention_days must be at least 7."
  }
}

variable "tempo_retention_days" {
  description = "Tempo's retention is 14 days in prod (capacity A33); the bucket's safety net a few days after it."
  type        = number
  default     = 17

  validation {
    condition     = var.tempo_retention_days >= 3
    error_message = "tempo_retention_days must be at least 3."
  }
}
