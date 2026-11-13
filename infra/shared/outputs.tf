output "registry_host" {
  description = "The registry's host, for the ECR_REGISTRY repository variable (#107)."
  value       = module.registry.registry_host
}

output "repository_urls" {
  description = "ECR repository URLs by name."
  value       = module.registry.repository_urls
}

output "image_push_role_arn" {
  description = "The build workflow's push role, for the ECR_PUSH_ROLE_ARN repository variable (#107)."
  value       = module.registry.push_role_arn
}

output "registry_key_arn" {
  description = "ARN of the registry key."
  value       = module.registry.registry_key_arn
}

output "zone_id" {
  description = "ID of the sft.<domain> zone, which the edge stacks look up through their DNS role."
  value       = module.dns_zone.zone_id
}

output "zone_name_servers" {
  description = "Name servers for the one NS delegation at the maintainer's DNS host."
  value       = module.dns_zone.name_servers
}

output "zone_ds_record" {
  description = "The DS record to publish at the parent once the zone is signed."
  value       = module.dns_zone.ds_record
}

output "dns_role_arns" {
  description = "The environments' DNS roles, by <env>-plan and <env>-deploy."
  value       = module.dns_zone.environment_role_arns
}

output "log_archive_bucket_arn" {
  description = "ARN of the organization's log archive, for the environments' trails."
  value       = module.log_archive.bucket_arn
}

output "log_archive_key_arn" {
  description = "ARN of the logs key the environments' trails encrypt with."
  value       = module.log_archive.logs_key_arn
}

output "organization_trail_arn" {
  description = "ARN of the organization trail."
  value       = module.log_archive.trail_arn
}

output "web_bundle_bucket" {
  description = "The web app's bundle store, for the WEB_BUNDLE_BUCKET repository variable (#283)."
  value       = module.web_bundles.bucket_name
}

output "web_publish_role_arn" {
  description = "The web release workflow's publish role, for the WEB_PUBLISH_ROLE_ARN repository variable (#283)."
  value       = module.web_bundles.publish_role_arn
}
