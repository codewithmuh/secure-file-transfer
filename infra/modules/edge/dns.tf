# The load balancer's certificate and the environment's API records in the shared zone, written through the
# environment's DNS role in the shared account (aws.dns, ADR-0021). Every record is in Terraform (T-01).

resource "aws_acm_certificate" "api" {
  domain_name               = local.api_name
  subject_alternative_names = [local.regional_api_name]
  validation_method         = "DNS"

  lifecycle {
    create_before_destroy = true
  }
}

locals {
  api_validation = {
    for option in aws_acm_certificate.api.domain_validation_options : option.domain_name => {
      name   = option.resource_record_name
      type   = option.resource_record_type
      record = option.resource_record_value
    }
  }

  # ACM's validation record for a name is the same in every Region of an account, so the API's name has one record,
  # owned by the primary Region's stack. The other Region writes only its own name's record and waits for both.
  api_validation_owned = {
    for name, record in local.api_validation : name => record if var.primary_region || name != local.api_name
  }
}

resource "aws_route53_record" "api_validation" {
  for_each = local.api_validation_owned
  provider = aws.dns

  zone_id = data.aws_route53_zone.this.zone_id
  name    = each.value.name
  type    = each.value.type
  ttl     = 300
  records = [each.value.record]
}

resource "aws_acm_certificate_validation" "api" {
  certificate_arn         = aws_acm_certificate.api.arn
  validation_record_fqdns = [for record in local.api_validation : trimsuffix(record.name, ".")]

  depends_on = [aws_route53_record.api_validation]
}

# This Region's own name, always on its own load balancer: the health check and the drills use it.
resource "aws_route53_record" "regional_api" {
  provider = aws.dns

  zone_id = data.aws_route53_zone.this.zone_id
  name    = local.regional_api_name
  type    = "A"

  alias {
    name                   = aws_lb.api.dns_name
    zone_id                = aws_lb.api.zone_id
    evaluate_target_health = false
  }
}

# The API's name, owned by the primary Region's stack. It aliases Tokyo's load balancer; the failover runbook points
# it at Osaka's by setting api_alias_target (T-78). Never by a health check (ADR-0021).
resource "aws_route53_record" "api" {
  count    = var.primary_region ? 1 : 0
  provider = aws.dns

  zone_id = data.aws_route53_zone.this.zone_id
  name    = local.api_name
  type    = "A"

  alias {
    name                   = coalesce(try(var.api_alias_target.dns_name, null), aws_lb.api.dns_name)
    zone_id                = coalesce(try(var.api_alias_target.zone_id, null), aws_lb.api.zone_id)
    evaluate_target_health = false
  }
}
