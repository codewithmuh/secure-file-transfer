output "function_arn" {
  description = "The trigger function, for the user pool's pre- and post-authentication triggers."
  value       = aws_lambda_function.this.arn
}

output "role_arn" {
  description = "The function's role, sft-<env>-signin-trigger."
  value       = local.role_arn
}

output "security_group_id" {
  description = "The function's security group, admitted to the counter store."
  value       = aws_security_group.this.id
}
