# Read by the cluster-bootstrap layer and the chart (#106), the failover runbook and Osaka's edge stack.

output "api_name" {
  description = "The API's name."
  value       = module.edge.api_name
}

output "app_name" {
  description = "The web app's name."
  value       = module.web_cdn.app_name
}

output "load_balancer" {
  description = "The API load balancer's ARN, DNS name and zone ID."
  value       = module.edge.load_balancer
}

output "api_target_group_arn" {
  description = "The API target group, which the chart's TargetGroupBinding finds by name (#106)."
  value       = module.edge.api_target_group_arn
}

output "load_balancer_security_group_id" {
  description = "The load balancer's security group, which the main nodes admit on the API's ports."
  value       = module.edge.load_balancer_security_group_id
}

output "sign_in_web_acl_arn" {
  description = "The sign-in web ACL, which the user pool's stack associates."
  value       = module.edge.sign_in_web_acl_arn
}

output "health_check_id" {
  description = "This Region's Route 53 health check, for its alarm."
  value       = module.edge.health_check_id
}

output "web_bucket_name" {
  description = "Tokyo's web bundle bucket, which the release pipeline writes."
  value       = module.edge.web_bucket.name
}

output "web_distribution_arn" {
  description = "The distribution's ARN: TF_VAR_web_distribution_arn for Osaka's edge stack."
  value       = module.web_cdn.distribution_arn
}

output "web_distribution_id" {
  description = "The distribution's ID."
  value       = module.web_cdn.distribution_id
}

output "web_release_role_arn" {
  description = "The web app's release role, which the web-deploy workflow assumes from the GitHub environment web-<env> (#283)."
  value       = module.web_release.role_arn
}
