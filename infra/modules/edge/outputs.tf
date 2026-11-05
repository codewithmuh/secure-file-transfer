output "service_domain" {
  description = "The environment's own domain in the shared zone: sft.<domain> in prod, <env>.sft.<domain> otherwise."
  value       = local.service_domain
}

output "zone_id" {
  description = "ID of the shared zone, as the DNS role sees it."
  value       = data.aws_route53_zone.this.zone_id
}

output "api_name" {
  description = "The API's name."
  value       = local.api_name
}

output "regional_api_name" {
  description = "This Region's own API name, which the health check probes."
  value       = local.regional_api_name
}

output "load_balancer" {
  description = "The API load balancer's ARN, DNS name and zone ID: what a failover points the API's name at."
  value = {
    arn      = aws_lb.api.arn
    dns_name = aws_lb.api.dns_name
    zone_id  = aws_lb.api.zone_id
  }
}

output "load_balancer_security_group_id" {
  description = "ID of the load balancer's security group."
  value       = aws_security_group.load_balancer.id
}

output "api_target_group_arn" {
  description = "The API target group, which the chart's TargetGroupBinding finds by its name, sft-<env>-<region-short>-api (#106)."
  value       = aws_lb_target_group.api.arn
}

output "api_web_acl_arn" {
  description = "ARN of the API web ACL."
  value       = aws_wafv2_web_acl.api.arn
}

output "sign_in_web_acl_arn" {
  description = "ARN of the sign-in web ACL, which the user pool's stack associates (abuse 3.1)."
  value       = aws_wafv2_web_acl.sign_in.arn
}

output "block_list_ip_set_arn" {
  description = "ARN of the operators' block list (abuse 8.3)."
  value       = aws_wafv2_ip_set.block_list.arn
}

output "health_check_id" {
  description = "ID of this Region's Route 53 health check, for its alarm in us-east-1."
  value       = aws_route53_health_check.edge.id
}

output "waf_log_bucket_arn" {
  description = "ARN of this Region's WAF and CloudFront log bucket, once its policy lets log delivery write."
  value       = aws_s3_bucket.waf_logs.arn

  depends_on = [aws_s3_bucket_policy.waf_logs]
}

output "web_bucket" {
  description = "This Region's web bundle bucket: name, ARN and regional domain name. Null where there is none."
  value = var.web_bucket ? {
    name                 = aws_s3_bucket.web[0].id
    arn                  = aws_s3_bucket.web[0].arn
    regional_domain_name = aws_s3_bucket.web[0].bucket_regional_domain_name
  } : null
}
