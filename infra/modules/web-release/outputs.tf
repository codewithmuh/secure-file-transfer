output "role_arn" {
  description = "The release role, which the web release workflow's deploy job assumes from the GitHub environment web-<env>."
  value       = aws_iam_role.release.arn
}

output "github_environment" {
  description = "The GitHub environment the role trusts; it must accept deployments from main only."
  value       = local.github_environment
}

output "bucket_names" {
  description = "The web buckets the role writes, by Region."
  value       = local.web_buckets
}
