variable "name_prefix" {
  description = "Regional name prefix from the conventions module: sft-<env>-apne1."
  type        = string
}

variable "service_domain" {
  description = "The environment's own domain in the shared zone, from the edge module."
  type        = string
}

variable "zone_id" {
  description = "ID of the shared zone, as the DNS role sees it, from the edge module."
  type        = string
}

variable "primary_bucket" {
  description = "Tokyo's web bundle bucket: its region_short and regional_domain_name."
  type = object({
    region_short         = string
    regional_domain_name = string
  })
}

variable "failover_bucket" {
  description = "Osaka's web bundle bucket, the failover origin (staging and prod). Null for none (dev)."
  type = object({
    region_short         = string
    regional_domain_name = string
  })
  default = null
}

variable "upload_origins" {
  description = "The files buckets' upload endpoints, which the CSP's connect-src allows (ADR-0008)."
  type        = list(string)

  validation {
    condition     = alltrue([for origin in var.upload_origins : can(regex("^https://[a-z0-9.-]+\\.amazonaws\\.com$", origin))])
    error_message = "Each upload origin must be an https:// S3 endpoint origin, without a path."
  }
}

variable "log_bucket_arn" {
  description = "ARN of the Tokyo aws-waf-logs-* bucket, for the web ACL's logs and CloudFront's standard logs."
  type        = string
}

variable "link_page_paths" {
  description = "Paths of the recipient and uploader pages, whose bursts get a Challenge (abuse 3.2)."
  type        = list(string)
  default     = ["/t"]
}

variable "managed_rules_in_count" {
  description = "Managed rules count instead of block: the two-week rollout (abuse 3.2)."
  type        = bool
  default     = false
}

variable "price_class" {
  description = "CloudFront price class. PriceClass_200 includes Japan and most of the world."
  type        = string
  default     = "PriceClass_200"
}

variable "minimum_protocol_version" {
  description = "The viewer TLS policy (encryption 2.1)."
  type        = string
  default     = "TLSv1.2_2025"
}
