variable "account_id" {
  description = "ID of the shared account, which holds the registry."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "account_id must be a 12-digit AWS account ID."
  }
}

variable "member_account_ids" {
  description = "Account IDs of the environments whose node roles pull, by environment (dev, staging, prod). Never committed."
  type        = map(string)
  default     = {}

  validation {
    condition = alltrue([
      for env, id in var.member_account_ids : contains(["dev", "staging", "prod"], env) && can(regex("^[0-9]{12}$", id))
    ])
    error_message = "member_account_ids maps dev, staging or prod to a 12-digit account ID."
  }
}

variable "app_repository" {
  description = "Repository of the one application image (architecture 2)."
  type        = string
  default     = "sft/app"

  validation {
    condition     = can(regex("^sft/[a-z0-9-]+$", var.app_repository))
    error_message = "app_repository must be under sft/, the only prefix the push role may write."
  }
}

variable "mirror_repositories" {
  description = "Third-party images mirrored by digest, each created as mirror/<name> (ADR-0007, T-70)."
  type        = list(string)

  validation {
    condition     = alltrue([for name in var.mirror_repositories : can(regex("^[a-z0-9]+([._/-][a-z0-9]+)*$", name))])
    error_message = "Each mirror repository must be a lowercase ECR repository name, without the mirror/ prefix."
  }
}

variable "undeployed_images_kept" {
  description = "How many images never tagged deployed-* the application repository keeps (capacity A40)."
  type        = number
  default     = 30
}

variable "replicate_to_osaka" {
  description = "Replicate every repository to Osaka with the key's Osaka replica. On once staging exists (capacity 5.4)."
  type        = bool
  default     = false
}

variable "kms_alias_prefix" {
  description = "Prefix for the key's alias, from the conventions module: alias/sft/shared."
  type        = string
}

variable "deploy_role_arn" {
  description = "ARN of the shared account's Terraform deploy role, which administers the registry key."
  type        = string
}

variable "plan_role_arn" {
  description = "ARN of the shared account's Terraform plan role."
  type        = string
}

variable "key_admin_role_arn" {
  description = "ARN of the shared account's key-admin role."
  type        = string
}

variable "break_glass_principal_arn_patterns" {
  description = "ArnLike patterns for the BreakGlass permission set's role in the shared account."
  type        = list(string)
}

variable "github_oidc_provider_arn" {
  description = "ARN of the shared account's GitHub OIDC provider, made by its bootstrap stack."
  type        = string
}

variable "github_repository" {
  description = "owner/name of the repository whose build workflow pushes. No wildcards (T-71)."
  type        = string

  validation {
    condition     = can(regex("^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", var.github_repository))
    error_message = "github_repository must be owner/name, without wildcards."
  }
}

variable "push_github_environment" {
  description = "GitHub environment whose jobs may push (#107). It must accept deployments from main only."
  type        = string
  default     = "registry"

  validation {
    condition     = can(regex("^[A-Za-z0-9_-]+$", var.push_github_environment))
    error_message = "push_github_environment must be a plain environment name, without wildcards."
  }
}

variable "push_role_name" {
  description = "Name of the push role."
  type        = string
}

variable "iam_path" {
  description = "IAM path for the push role. Not /sft-bootstrap/: the deploy role must be able to change it (SCP 4)."
  type        = string

  validation {
    condition     = var.iam_path != "/sft-bootstrap/" && can(regex("^/([A-Za-z0-9-]+/)*$", var.iam_path))
    error_message = "iam_path must be an IAM path other than /sft-bootstrap/."
  }
}
