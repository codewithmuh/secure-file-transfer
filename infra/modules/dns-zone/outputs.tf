output "zone_id" {
  description = "ID of the sft.<domain> zone."
  value       = aws_route53_zone.this.zone_id
}

output "zone_name" {
  description = "The zone's name, sft.<domain>."
  value       = aws_route53_zone.this.name
}

output "name_servers" {
  description = "The zone's name servers, for the one NS delegation at the maintainer's DNS host."
  value       = aws_route53_zone.this.name_servers
}

output "ds_record" {
  description = "The DS record to publish at the parent once signing is on (ADR-0021, T-01)."
  value       = aws_route53_key_signing_key.this.ds_record
}

output "environment_domains" {
  description = "Each environment's own domain in the zone."
  value       = local.environment_domains
}

output "environment_role_arns" {
  description = "ARNs of the environment roles, by <env>-plan and <env>-deploy."
  value       = { for key, role in aws_iam_role.environment : key => role.arn }
}
