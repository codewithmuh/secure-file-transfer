variable "environment" {
  description = "dev, staging or prod: names the environment's own domain in the shared zone."
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

variable "name_prefix" {
  description = "Regional name prefix from the conventions module: sft-<env>-<region-short>."
  type        = string
}

variable "region_short" {
  description = "Short Region code from the conventions module: apne1 or apne3."
  type        = string

  validation {
    condition     = contains(["apne1", "apne3"], var.region_short)
    error_message = "region_short must be apne1 or apne3."
  }
}

variable "kms_alias_prefix" {
  description = "KMS alias prefix from the conventions module; the data layer's logs key is <prefix>/logs."
  type        = string
}

variable "domain" {
  description = "The maintainer's domain; the shared zone is sft.<domain>. Supplied at plan time, never committed."
  type        = string

  validation {
    condition     = can(regex("^([a-z0-9]([a-z0-9-]*[a-z0-9])?\\.)+[a-z]{2,}$", var.domain))
    error_message = "domain must be a lower-case domain name without a trailing dot."
  }
}

variable "primary_region" {
  description = "True in Tokyo: this stack owns the API's name and its certificate validation record."
  type        = bool
}

variable "api_alias_target" {
  description = "Where the API's name points, if not this Region's load balancer: Osaka's, during a failover (T-78)."
  type = object({
    dns_name = string
    zone_id  = string
  })
  default = null
}

variable "api_public_port" {
  description = "The API pods' public port (sft.core.settings public_port)."
  type        = number
  default     = 8000
}

variable "api_internal_port" {
  description = "The API pods' internal port for probes, which no listener routes (sft.core.settings internal_port)."
  type        = number
  default     = 8001
}

variable "tls_policy" {
  description = "The listener's TLS policy (encryption 2.1)."
  type        = string
  default     = "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09"
}

variable "health_check_path" {
  description = "Path the load balancer answers itself for the Route 53 health check."
  type        = string
  default     = "/edge-health"

  validation {
    condition     = can(regex("^/[a-z0-9-]+$", var.health_check_path)) && !startswith(var.health_check_path, "/v1")
    error_message = "health_check_path must be one path segment outside the API's /v1 routes."
  }
}

variable "health_check_body" {
  description = "The fixed body the health check's string match looks for."
  type        = string
  default     = "sft-edge-ok"
}

variable "deletion_protection" {
  description = "Deletion protection on the load balancer. A teardown turns it off first (NFR-19)."
  type        = bool
  default     = false
}

variable "managed_rules_in_count" {
  description = "Managed rules and the sign-in rate rules count instead of block: the two-week rollout (abuse 3.2)."
  type        = bool
  default     = false
}

variable "attack_mode_links" {
  description = "Block link calls from anonymous and hosting-provider addresses: a runbook lever (abuse 3.2, rule 9)."
  type        = bool
  default     = false
}

variable "blocked_countries" {
  description = "ISO country codes the API web ACL blocks: a runbook lever, empty by default (abuse 3.2, rule 10)."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for code in var.blocked_countries : can(regex("^[A-Z]{2}$", code))])
    error_message = "blocked_countries must be ISO 3166-1 alpha-2 codes."
  }
}

variable "log_retention_days" {
  description = "How long the edge's logs are kept (PRD data lifecycle, abuse 3.4)."
  type        = number
  default     = 90
}

variable "web_bucket" {
  description = "Create this Region's web bundle bucket (ADR-0008): Tokyo always, Osaka in staging and prod."
  type        = bool
  default     = true
}

variable "web_distribution_arn" {
  description = "ARN of the environment's CloudFront distribution, the web bucket's only reader. Null until it exists."
  type        = string
  default     = null
}

variable "web_writer_arns" {
  description = "The only principals that may write or delete the web bucket's objects (ADR-0008, #283): the environment's release role, sft-<env>-web-release (modules/web-release), and the Terraform deploy role, which empties the bucket at teardown."
  type        = list(string)

  validation {
    condition     = length(var.web_writer_arns) > 0 && alltrue([for a in var.web_writer_arns : can(regex("^arn:aws:iam::[0-9]{12}:role/", a))])
    error_message = "web_writer_arns must name the release role and the deploy role by role ARN."
  }
}
