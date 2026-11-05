output "distribution_arn" {
  description = "ARN of the distribution, the web buckets' only reader: Osaka's edge stack takes it as web_distribution_arn."
  value       = aws_cloudfront_distribution.web.arn
}

output "distribution_id" {
  description = "ID of the distribution."
  value       = aws_cloudfront_distribution.web.id
}

output "app_name" {
  description = "The web app's name."
  value       = local.app_name
}

output "web_acl_arn" {
  description = "ARN of the CloudFront web ACL."
  value       = aws_wafv2_web_acl.web.arn
}
