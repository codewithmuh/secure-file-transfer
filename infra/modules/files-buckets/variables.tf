variable "environment" {
  description = "The environment: dev, staging or prod. Names the buckets and the roles the policies name."
  type        = string

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be dev, staging or prod."
  }
}

variable "account_id" {
  description = "ID of the account that owns the buckets. Bucket names end in it (infra/README.md, Names)."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "account_id must be a 12-digit AWS account ID."
  }
}

variable "kms_key_arn" {
  description = "The files key in this Region (the replica in Osaka), every object's default encryption and the only key the bucket policy accepts."
  type        = string

  validation {
    condition     = can(regex("^arn:aws:kms:ap-northeast-[13]:[0-9]{12}:key/mrk-[0-9a-f]{32}$", var.kms_key_arn))
    error_message = "kms_key_arn must be the ARN of a multi-Region key in Tokyo or Osaka."
  }
}

variable "with_osaka" {
  description = "True where the environment has Osaka buckets (staging and prod): Tokyo's roles then cover both Regions."
  type        = bool
}

variable "osaka_kms_key_arn" {
  description = "Tokyo only, with with_osaka: the Osaka replica's ARN of the files key, from the kms-keys module's osaka_key_arns."
  type        = string
  default     = null
}

variable "replicate_to_osaka" {
  description = "Tokyo only: turn on replication with RTC to the Osaka buckets. S3 needs the destination to exist, so a fresh build applies Tokyo, then Osaka, then Tokyo again with this on."
  type        = bool
  default     = false

  validation {
    condition     = !var.replicate_to_osaka || (var.with_osaka && var.create_iam_roles && var.osaka_kms_key_arn != null)
    error_message = "replicate_to_osaka is for Tokyo with with_osaka, create_iam_roles and osaka_kms_key_arn set."
  }
}

variable "replicate_to_tokyo" {
  description = "Osaka only, at a failback: replicate Osaka's buckets back to Tokyo's with RTC (rule to-tokyo, #262, #42 gap 4), so files uploaded during a failover reach Tokyo. Off in the pilot light; the failback runbook sets it in step 2 and clears it in step 8."
  type        = bool
  default     = false
}

variable "create_iam_roles" {
  description = "True in Tokyo: make the replication role (where with_osaka) and GuardDuty's role. IAM is global, so Osaka uses Tokyo's."
  type        = bool
}

variable "malware_protection_enabled" {
  description = "Protect the large-files bucket with a GuardDuty Malware Protection plan and route its results to the scan worker. On in Tokyo; in Osaka false means no plan at all, and the failover runbook's apply creates it (ADR-0019)."
  type        = bool
}

variable "deploy_role_arn" {
  description = "The environment's Terraform deploy role: with the bootstrap admins, the only principal that may change the buckets' settings."
  type        = string
}

variable "admin_principal_arn_patterns" {
  description = "ArnLike patterns for the Admin permission set, which may also change the buckets' settings."
  type        = list(string)
}

variable "break_glass_principal_arn_patterns" {
  description = "ArnLike patterns for BreakGlass, which may read objects (authn-authz 8.1) but not change the buckets."
  type        = list(string)

  validation {
    condition     = length(var.break_glass_principal_arn_patterns) > 0
    error_message = "Name the BreakGlass role."
  }
}

variable "cors_allowed_origins" {
  description = "Origins of the web app, whose browsers upload parts straight to the buckets with pre-signed URLs (architecture 4.1). Empty until the domain is chosen (open question 5)."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for o in var.cors_allowed_origins : can(regex("^https://[a-z0-9.-]+$", o))])
    error_message = "Each origin must be https://<host>, without a path or a wildcard."
  }
}

variable "teardown_allowed" {
  description = "The deploy role and Admin (which runs ops/teardown.sh) may delete objects and destroy non-empty buckets, so the environment tears down (NFR-19): always in dev and staging; in prod only from the teardown apply on (#263, #42 gap 11). Otherwise only the lifecycle jobs delete (ADR-0012)."
  type        = bool
}

variable "conventions" {
  description = "The caller's conventions module (pass module.conventions): names the buckets, and the roles it makes or its policies name, from their one definition (#172)."
  type = object({
    global_name_prefix  = string
    region_shorts       = map(string)
    workload_role_names = map(string)
    workload_role_arns  = map(string)
  })
}
