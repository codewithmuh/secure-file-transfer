# Read by the cluster-bootstrap layer and the chart (#106) and by the failover runbook.

output "regional_api_name" {
  description = "This Region's own API name."
  value       = module.edge.regional_api_name
}

output "load_balancer" {
  description = "The API load balancer's ARN, DNS name and zone ID: TF_VAR_api_alias_target for Tokyo's stack in a failover."
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
  description = "Osaka's web bundle bucket, which the release pipeline writes first."
  value       = module.edge.web_bucket.name
}
