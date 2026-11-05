# The environment's one CloudFront distribution, which serves only the web bundle (ADR-0008, abuse 3.2, encryption
# 2.1): origin access control to the private bundle buckets, an origin group that fails over from Tokyo to Osaka,
# the security headers, the route rewrite, its certificate and web ACL in us-east-1, its logs to Tokyo, and the app's
# record in the shared zone.
#
# No cache behavior routes to the API or the files buckets, so file contents never reach an edge. The CI check of
# ADR-0008 fails a distribution with any other origin.

locals {
  app_name = "app.${var.service_domain}"

  primary_origin  = "web-${var.primary_bucket.region_short}"
  failover_origin = var.failover_bucket == null ? null : "web-${var.failover_bucket.region_short}"
  target_origin   = var.failover_bucket == null ? local.primary_origin : "web"

  origins = merge(
    { (local.primary_origin) = var.primary_bucket.regional_domain_name },
    var.failover_bucket == null ? {} : { (local.failover_origin) = var.failover_bucket.regional_domain_name },
  )

  # ADR-0008's Content-Security-Policy: 'self' for the bundle and config.json, the API, and the files buckets' upload
  # endpoints. No inline script and no third-party origin (T-02).
  content_security_policy = join("; ", [
    "default-src 'self'",
    "script-src 'self'",
    "connect-src ${join(" ", concat(["'self'", "https://api.${var.service_domain}"], var.upload_origins))}",
    "frame-ancestors 'none'",
    "base-uri 'none'",
    "object-src 'none'",
  ])
}

# --- Certificate -------------------------------------------------------------------------------------------------

# CloudFront takes certificates from us-east-1 only (NFR-21's exception).
resource "aws_acm_certificate" "app" {
  provider = aws.us_east_1

  domain_name       = local.app_name
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_route53_record" "app_validation" {
  for_each = {
    for option in aws_acm_certificate.app.domain_validation_options : option.domain_name => option
  }
  provider = aws.dns

  zone_id = var.zone_id
  name    = each.value.resource_record_name
  type    = each.value.resource_record_type
  ttl     = 300
  records = [each.value.resource_record_value]
}

resource "aws_acm_certificate_validation" "app" {
  provider = aws.us_east_1

  certificate_arn         = aws_acm_certificate.app.arn
  validation_record_fqdns = [for record in aws_route53_record.app_validation : record.fqdn]
}

# --- Distribution ------------------------------------------------------------------------------------------------

resource "aws_cloudfront_origin_access_control" "web" {
  name                              = "${var.name_prefix}-web"
  description                       = "The web bundle buckets, read only by this distribution (ADR-0008)"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

# App routes, paths without a file extension, serve /index.html, so error responses never route and a missing asset
# stays a 404 (ADR-0008).
resource "aws_cloudfront_function" "routes" {
  name    = "${var.name_prefix}-web-routes"
  comment = "App routes to /index.html"
  runtime = "cloudfront-js-2.0"
  publish = true
  code    = file("${path.module}/routes.js")
}

data "aws_cloudfront_cache_policy" "optimized" {
  name = "Managed-CachingOptimized"
}

resource "aws_cloudfront_response_headers_policy" "web" {
  name    = "${var.name_prefix}-web"
  comment = "Security headers for the web app (ADR-0008, encryption 2.1)"

  security_headers_config {
    content_security_policy {
      content_security_policy = local.content_security_policy
      override                = true
    }

    strict_transport_security {
      access_control_max_age_sec = 63072000
      include_subdomains         = true
      preload                    = false
      override                   = true
    }

    referrer_policy {
      referrer_policy = "no-referrer"
      override        = true
    }

    content_type_options {
      override = true
    }

    frame_options {
      frame_option = "DENY"
      override     = true
    }
  }
}

resource "aws_cloudfront_distribution" "web" {
  comment             = "${var.name_prefix}: the web bundle only (ADR-0008)"
  enabled             = true
  aliases             = [local.app_name]
  default_root_object = "index.html"
  http_version        = "http2and3"
  price_class         = var.price_class
  web_acl_id          = aws_wafv2_web_acl.web.arn

  # IPv4 only, like the API: WAF rate rules key each IPv6 address separately (abuse 2.1).
  is_ipv6_enabled = false

  dynamic "origin" {
    for_each = local.origins

    content {
      origin_id                = origin.key
      domain_name              = origin.value
      origin_access_control_id = aws_cloudfront_origin_access_control.web.id
    }
  }

  # Fails over on 5xx and connection errors, for GET and HEAD (ADR-0008). Only where Osaka has a copy.
  dynamic "origin_group" {
    for_each = var.failover_bucket == null ? [] : [1]

    content {
      origin_id = "web"

      failover_criteria {
        status_codes = [500, 502, 503, 504]
      }

      member {
        origin_id = local.primary_origin
      }

      member {
        origin_id = local.failover_origin
      }
    }
  }

  default_cache_behavior {
    target_origin_id           = local.target_origin
    viewer_protocol_policy     = "redirect-to-https"
    allowed_methods            = ["GET", "HEAD"]
    cached_methods             = ["GET", "HEAD"]
    compress                   = true
    cache_policy_id            = data.aws_cloudfront_cache_policy.optimized.id
    response_headers_policy_id = aws_cloudfront_response_headers_policy.web.id

    function_association {
      event_type   = "viewer-request"
      function_arn = aws_cloudfront_function.routes.arn
    }
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
      locations        = []
    }
  }

  viewer_certificate {
    acm_certificate_arn      = aws_acm_certificate_validation.app.certificate_arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = var.minimum_protocol_version
  }
}

resource "aws_route53_record" "app" {
  provider = aws.dns

  zone_id = var.zone_id
  name    = local.app_name
  type    = "A"

  alias {
    name                   = aws_cloudfront_distribution.web.domain_name
    zone_id                = aws_cloudfront_distribution.web.hosted_zone_id
    evaluate_target_health = false
  }
}

# --- Standard logs -----------------------------------------------------------------------------------------------

# CloudFront's standard logs, through CloudWatch Logs delivery configured in us-east-1 (the region guard allows it,
# ADR-0006), into the Tokyo log bucket under AWSLogs/<account-id>/CloudFront/, beside WAF's WAFLogs/; no log group
# anywhere (architecture 5.5).
resource "aws_cloudwatch_log_delivery_source" "web" {
  provider = aws.us_east_1

  name         = "${var.name_prefix}-cloudfront"
  log_type     = "ACCESS_LOGS"
  resource_arn = aws_cloudfront_distribution.web.arn
}

resource "aws_cloudwatch_log_delivery_destination" "web" {
  provider = aws.us_east_1

  name          = "${var.name_prefix}-cloudfront"
  output_format = "json"

  delivery_destination_configuration {
    destination_resource_arn = var.log_bucket_arn
  }
}

resource "aws_cloudwatch_log_delivery" "web" {
  provider = aws.us_east_1

  delivery_source_name     = aws_cloudwatch_log_delivery_source.web.name
  delivery_destination_arn = aws_cloudwatch_log_delivery_destination.web.arn
}
