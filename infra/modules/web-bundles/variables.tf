variable "bucket_name" {
  description = "The store's bucket: sft-shared-apne1-web-bundles-<account-id>, the name each environment's release role reads (modules/web-release)."
  type        = string

  validation {
    condition     = can(regex("^sft-shared-apne1-web-bundles-[0-9]{12}$", var.bucket_name))
    error_message = "bucket_name must be sft-shared-apne1-web-bundles-<account-id>."
  }
}

variable "member_account_ids" {
  description = "dev, staging and prod account IDs by environment, as they come to exist: each one's release role, sft-<env>-web-release, may read the bundles."
  type        = map(string)
  default     = {}

  validation {
    condition     = length(setsubtract(keys(var.member_account_ids), ["dev", "staging", "prod"])) == 0
    error_message = "member_account_ids takes dev, staging and prod only."
  }
}

variable "deploy_role_arn" {
  description = "The shared stack's Terraform deploy role, which alone changes the bucket and empties it at the end (capacity 5.4)."
  type        = string
}

variable "github_oidc_provider_arn" {
  description = "The shared account's GitHub OIDC provider, made by its bootstrap stack."
  type        = string
}

variable "github_repository" {
  description = "The repository whose workflow publishes bundles (T-71)."
  type        = string
}

variable "publish_github_environment" {
  description = "The GitHub environment whose jobs may publish, as for images (#107). It must accept deployments from main only."
  type        = string
  default     = "registry"

  validation {
    condition     = can(regex("^[A-Za-z0-9_-]+$", var.publish_github_environment))
    error_message = "publish_github_environment must be a plain environment name, without wildcards."
  }
}

variable "publish_role_name" {
  description = "Name of the publish role."
  type        = string
}

variable "iam_path" {
  description = "IAM path for the publish role. Not /sft-bootstrap/: the deploy role must be able to change it (SCP 4)."
  type        = string

  validation {
    condition     = var.iam_path != "/sft-bootstrap/" && can(regex("^/([A-Za-z0-9-]+/)*$", var.iam_path))
    error_message = "iam_path must be an IAM path other than /sft-bootstrap/."
  }
}
