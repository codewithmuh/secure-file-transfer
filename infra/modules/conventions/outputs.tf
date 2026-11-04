output "region" {
  description = "The stack's home Region."
  value       = var.region
}

output "region_short" {
  description = "Short Region code used in names: apne1 (Tokyo) or apne3 (Osaka)."
  value       = local.region_short
}

output "name_prefix" {
  description = "Prefix for regional resource names: sft-<env>-<region-short>."
  value       = local.name_prefix
}

output "global_name_prefix" {
  description = "Prefix for global resource names such as IAM roles: sft-<env>."
  value       = local.global_name_prefix
}

output "kms_alias_prefix" {
  description = "Prefix for KMS aliases: alias/sft/<env> (encryption 4.1)."
  value       = "alias/sft/${var.environment}"
}

output "state_bucket_name" {
  description = "The Terraform state bucket for this account and Region: sft-<env>-<region-short>-tfstate-<account-id>."
  value       = "${local.name_prefix}-tfstate-${var.account_id}"
}

output "tags" {
  description = "Tags for the AWS provider's default_tags."
  value       = local.tags
}

output "github_repository" {
  description = "The repository whose workflows may assume the Terraform roles (T-71)."
  value       = local.github_repository
}

output "bootstrap_iam_path" {
  description = "IAM path of the roles the bootstrap stacks create."
  value       = local.bootstrap_iam_path
}

output "bootstrap_role_names" {
  description = "Names of the roles the bootstrap stacks create: terraform_plan, terraform_deploy and key_admin."
  value       = local.bootstrap_role_names
}

output "bootstrap_role_arns" {
  description = "ARNs of the roles the bootstrap stacks create, built from their names so other stacks need no lookup."
  value = {
    for role, name in local.bootstrap_role_names :
    role => "arn:aws:iam::${var.account_id}:role${local.bootstrap_iam_path}${name}"
  }
}

output "sso_role_arn_patterns" {
  description = "ArnLike patterns for the Identity Center permission set roles in this account: admin and break_glass."
  value = {
    admin       = "${local.sso_role_arn_prefix}*AWSReservedSSO_Admin_*"
    break_glass = "${local.sso_role_arn_prefix}*AWSReservedSSO_BreakGlass_*"
  }
}
