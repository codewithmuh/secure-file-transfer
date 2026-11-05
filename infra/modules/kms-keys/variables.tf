variable "environment" {
  description = "The environment the keys belong to: dev, staging or prod. Names every role and bucket the policies name."
  type        = string

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be dev, staging or prod."
  }
}

variable "account_id" {
  description = "ID of the account that owns the keys."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "account_id must be a 12-digit AWS account ID."
  }
}

variable "classes" {
  description = "Data classes to make a key for (encryption 4.1). The data roots make all but tfstate; prod's retained stack makes audit."
  type        = set(string)

  validation {
    condition = length(var.classes) > 0 && alltrue([
      for c in var.classes : contains(["files", "fields", "database", "audit", "logs", "secrets", "platform"], c)
    ])
    error_message = "classes may hold files, fields, database, audit, logs, secrets and platform. tfstate belongs to the bootstrap stack."
  }
}

variable "primary_key_arns" {
  description = "Osaka only: the Tokyo primary of each class, from the Tokyo stack's key_arns output. Empty in Tokyo, where the module makes the primaries."
  type        = map(string)
  default     = {}

  validation {
    condition = alltrue([
      for arn in values(var.primary_key_arns) :
      can(regex("^arn:aws:kms:ap-northeast-1:[0-9]{12}:key/mrk-[0-9a-f]{32}$", arn))
    ])
    error_message = "Each primary_key_arns value must be the ARN of a multi-Region key in ap-northeast-1."
  }
}

variable "osaka_replicas" {
  description = "Tokyo only: true where the Osaka stack replicates these keys (staging and prod), so osaka_key_arns is filled in."
  type        = bool
  default     = false
}

variable "deletion_window_in_days" {
  description = "Days KMS waits before deleting a key, and the least the key policy allows: 30 in prod, 7 in dev and staging (encryption 8.3)."
  type        = number

  validation {
    condition     = var.deletion_window_in_days >= 7 && var.deletion_window_in_days <= 30
    error_message = "deletion_window_in_days must be between 7 and 30."
  }
}

variable "deploy_role_arn" {
  description = "The Terraform deploy role of the stack that owns the keys: it administers them, and only it may disable or delete them (rule 5)."
  type        = string

  validation {
    condition     = can(regex("^arn:aws:iam::[0-9]{12}:role/sft-bootstrap/sft-[a-z]+(-retained)?-terraform-deploy$", var.deploy_role_arn))
    error_message = "deploy_role_arn must be a deploy role under /sft-bootstrap/."
  }
}

variable "extra_administrator_arn_patterns" {
  description = "ArnLike patterns that administer the keys besides the deploy role, never disable or delete them: Admin for the retained stack, whose first apply runs with it (ADR-0005). Empty elsewhere."
  type        = list(string)
  default     = []
}

variable "plan_role_arn" {
  description = "The Terraform plan role, which may read each key's state and policy for plans, never use it. Null for none."
  type        = string
  default     = null
}

variable "key_admin_role_arn" {
  description = "The key-admin role sft-<env>-keyadmin, which may read and put the key policy (rule 6). Null to leave it out, as the audit key's policy does from prod's teardown on (encryption 8.4)."
  type        = string
  default     = null
}

variable "break_glass_principal_arn_patterns" {
  description = "ArnLike patterns for the BreakGlass permission set's role, which recovers keys and reads some (table 4.3)."
  type        = list(string)

  validation {
    condition     = length(var.break_glass_principal_arn_patterns) > 0
    error_message = "Name the BreakGlass role: without it nobody could cancel a pending deletion."
  }
}

variable "replication_role_name" {
  description = "Name of the S3 replication role the files and audit keys name. Null for sft-<env>-s3-replication; prod's retained stack passes its own role."
  type        = string
  default     = null
}

variable "retained_stack" {
  description = "True in prod's retained stack: the audit key also covers that stack's state bucket, trail and alert topic (encryption 8.4)."
  type        = bool
  default     = false
}

variable "prevent_destroy" {
  description = "Guard the keys with prevent_destroy: true for the retained stack's audit key (encryption 8.4), false where teardown removes them."
  type        = bool
  default     = false
}

variable "volume_service_linked_role_arns" {
  description = <<-EOT
    The service-linked roles that create EBS volumes under the platform and files keys: Auto Scaling (the system node
    group) and EC2 Fleet (Karpenter's launches). The key policies name them as principals, because a service-linked
    role has no IAM policy of its own to allow KMS (encryption 4.4), so they must exist before the keys' policies.
    Tokyo's data stack passes the roles it creates, which orders them first; null builds the ARNs from the names, for
    Osaka, whose stack runs after Tokyo's.
  EOT
  type = object({
    autoscaling = string
    ec2_fleet   = string
  })
  default = null
}
