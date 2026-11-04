output "state_bucket_name" {
  description = "State bucket for this account in Tokyo, for -backend-config=bucket=... ."
  value       = module.state.bucket_name
}

output "tfstate_key_arn" {
  description = "ARN of the Tokyo tfstate key. Osaka's bootstrap stack, where there is one, replicates it."
  value       = module.state.kms_key_arn
}

output "oidc_provider_arn" {
  description = "ARN of the account's GitHub OIDC provider."
  value       = module.terraform_roles.oidc_provider_arn
}

output "plan_role_arn" {
  description = "ARN of the Terraform plan role, for pull request plans."
  value       = module.terraform_roles.plan_role_arn
}
