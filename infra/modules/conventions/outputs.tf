output "region" {
  description = "The stack's home Region."
  value       = var.region
}

output "region_short" {
  description = "Short Region code used in names: apne1 (Tokyo) or apne3 (Osaka)."
  value       = local.region_short
}

output "region_shorts" {
  description = "Short Region code of every Region the service runs in, by Region: the one definition modules use (#172)."
  value       = local.region_shorts
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

output "emergency_user" {
  description = "Name, path and ARN of the account's emergency IAM user (authn-authz 8.4): sft-<env>-emergency."
  value = merge(local.emergency_user, {
    arn = "arn:aws:iam::${var.account_id}:user${local.emergency_user.path}${local.emergency_user.name}"
  })
}

output "sso_role_arn_patterns" {
  description = "ArnLike patterns for the Identity Center permission set roles in this account: admin and break_glass."
  value = {
    admin       = "${local.sso_role_arn_prefix}*AWSReservedSSO_Admin_*"
    break_glass = "${local.sso_role_arn_prefix}*AWSReservedSSO_BreakGlass_*"
  }
}

output "workload_roles" {
  description = "The environment's workload role short names, by the layer that makes them: cluster, data, identity, cluster_bootstrap and edge (#172)."
  value       = local.workload_roles
}

output "workload_role_names" {
  description = "Every workload role's name, sft-<env>-<name>, by short name (#172)."
  value       = local.workload_role_names
}

output "workload_role_arns" {
  description = "Every workload role's ARN at path /, by short name, built from the name so policies can name a role before it exists (#172)."
  value       = { for name, role in local.workload_role_names : name => "arn:aws:iam::${var.account_id}:role/${role}" }
}
