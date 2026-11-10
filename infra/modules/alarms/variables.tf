variable "environment" {
  description = "The environment: dev, staging or prod. Every alarm is sft-<env>-<region-short>-<what>."
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
  description = "This stack's Region, where its alarms, topics and the metrics they read live."
  type        = string

  validation {
    condition     = contains(["ap-northeast-1", "ap-northeast-3"], var.region)
    error_message = "region must be ap-northeast-1 or ap-northeast-3."
  }
}

variable "name_prefix" {
  description = "sft-<env>-<region-short>, from the conventions module."
  type        = string
}

variable "kms_alias_prefix" {
  description = "alias/sft/<env>, from the conventions module: the us-east-1 key's alias is <prefix>/alarms."
  type        = string
}

variable "platform_key_arn" {
  description = "This Region's platform key (data stack's kms_key_arns[\"platform\"]): the topics' encryption (encryption 3.1)."
  type        = string
}

variable "deploy_role_arn" {
  description = "The environment's Terraform deploy role: the only principal that may change or delete the topics."
  type        = string
}

variable "alert_emails" {
  description = "Who the page and ticket topics and the break-glass topic reach: the pager's and every operator's address. Supplied at apply time (TF_VAR_alert_emails), never committed. Each must confirm its subscription."
  type        = list(string)

  validation {
    condition     = length(var.alert_emails) > 0 && alltrue([for e in var.alert_emails : can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", e))])
    error_message = "alert_emails needs at least one plain email address."
  }
}

variable "heartbeat_enabled" {
  description = "Whether the heartbeat alarm notifies. False in Osaka during the pilot light, where no observability stack runs (ADR-0009); the failover runbook sets it true."
  type        = bool
  default     = true
}

variable "probe_enabled" {
  description = "Whether the synthetic probe runs in this environment (probe.enabled in the cluster's values file, #248). Creates its CloudWatch alarm, which treats missing data as breaching."
  type        = bool
  default     = false
}

variable "pilot_light" {
  description = "True in Osaka while it waits (architecture 3.2): alarms on what only runs after a failover, such as the API's targets, don't notify."
  type        = bool
  default     = false
}

variable "database" {
  description = <<-EOT
    This Region's Aurora cluster (modules/aurora): its identifier, sft-<env>-<region-short>-aurora; its role,
    standalone (dev), primary (Tokyo) or secondary (Osaka); and the FreeableMemory, in bytes, below which the writer
    raises a ticket (about a tenth of its instance's memory).
  EOT
  type = object({
    cluster_identifier          = string
    role                        = string
    freeable_memory_alarm_bytes = number
  })

  validation {
    condition     = contains(["standalone", "primary", "secondary"], var.database.role)
    error_message = "database.role must be standalone, primary or secondary."
  }
}

variable "load_balancer_arn" {
  description = "The API's load balancer (edge stack's load_balancer.arn)."
  type        = string
}

variable "api_target_group_arn" {
  description = "The API's target group (edge stack's api_target_group_arn)."
  type        = string
}

variable "vpc_id" {
  description = "This Region's VPC (network stack's vpc_id): its NAT gateways get the NAT alarms."
  type        = string
}

variable "replicated_buckets" {
  description = "Tokyo's buckets that replicate to Osaka with Replication Time Control, by kind, with their Osaka destination. Empty where nothing replicates with RTC (dev, Osaka)."
  type = map(object({
    source      = string
    destination = string
  }))
  default = {}
}

variable "region_health" {
  description = <<-EOT
    Tokyo's stack only: the Route 53 health checks to alarm on, by Region (each edge stack's health_check_id), and
    what the us-east-1 key needs (modules/key-policy). Null in Osaka, whose health check Tokyo's stack watches.
  EOT
  type = object({
    health_checks                      = map(string)
    plan_role_arn                      = string
    key_admin_role_arn                 = string
    break_glass_principal_arn_patterns = list(string)
    key_deletion_window_days           = number
  })
  default = null

  validation {
    condition = var.region_health == null || alltrue([
      for r in keys(try(var.region_health.health_checks, {})) : contains(["ap-northeast-1", "ap-northeast-3"], r)
    ])
    error_message = "region_health.health_checks is keyed by ap-northeast-1 or ap-northeast-3."
  }
}

variable "conventions" {
  description = "The caller's conventions module (pass module.conventions): names the Regions' health check alarms, Alertmanager's and the delivery role, and the roles and users the security alerts watch (#256), from their one definition (#172)."
  type = object({
    region_shorts         = map(string)
    workload_role_arns    = map(string)
    bootstrap_iam_path    = string
    bootstrap_role_arns   = object({ terraform_deploy = string, terraform_plan = string, key_admin = string })
    emergency_user        = object({ name = string, path = string, arn = string })
    sso_role_arn_patterns = object({ admin = string, break_glass = string })
  })
}
