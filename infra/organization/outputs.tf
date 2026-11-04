output "organization_id" {
  description = "ID of the organization, for aws:PrincipalOrgID conditions in endpoint, bucket and key policies (ADR-0021)."
  value       = aws_organizations_organization.this.id
}

output "root_id" {
  description = "ID of the organization's root, where SCPs 1 to 4 are attached."
  value       = local.root_id
}

output "organizational_unit_ids" {
  description = "IDs of the prod, nonprod and shared OUs."
  value       = { for name, ou in aws_organizations_organizational_unit.this : name => ou.id }
}

output "account_ids" {
  description = "Account ID of each environment, management included: the TF_VAR_account_id of every other stack."
  value       = local.account_ids
}

output "scp_ids" {
  description = "IDs of the SCPs, by name."
  value       = { for name, policy in aws_organizations_policy.scp : name => policy.id }
}

output "sso_instance_arn" {
  description = "ARN of the IAM Identity Center instance, or null before it is enabled."
  value       = local.sso_instance_arn
}

output "identity_store_id" {
  description = "ID of Identity Center's identity store, or null before it is enabled."
  value       = local.identity_store_id
}

output "permission_set_arns" {
  description = "ARN of each permission set, for the break-glass assignment commands (runbook) and the break-glass tool."
  value       = { for name, set in aws_ssoadmin_permission_set.this : name => set.arn }
}

output "budget_names" {
  description = "Names of the monthly budgets."
  value       = { for name, budget in aws_budgets_budget.monthly : name => budget.name }
}
