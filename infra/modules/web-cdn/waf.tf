# The CloudFront web ACL (abuse 3.2), in us-east-1: rules 0, 1 and 4 of the API web ACL, a per-IP rate rule, and a
# Challenge on bursts of link page loads. The link pages read the token from the fragment, which a challenge keeps,
# and load no WAF script (T-02).

resource "aws_wafv2_ip_set" "block_list" {
  provider = aws.us_east_1

  name               = "${var.name_prefix}-web-block-list"
  description        = "Addresses operators block during an incident, abuse 8.3"
  scope              = "CLOUDFRONT"
  ip_address_version = "IPV4"
  addresses          = []

  # Operators maintain it; Terraform only creates it.
  lifecycle {
    ignore_changes = [addresses]
  }
}

resource "aws_wafv2_web_acl" "web" {
  provider = aws.us_east_1

  name        = "${var.name_prefix}-web"
  description = "The web app CloudFront distribution, abuse 3.2"
  scope       = "CLOUDFRONT"

  default_action {
    allow {}
  }

  rule {
    name     = "block-list"
    priority = 0

    action {
      block {}
    }

    statement {
      ip_set_reference_statement {
        arn = aws_wafv2_ip_set.block_list.arn
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "block-list"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "ip-reputation"
    priority = 1

    override_action {
      dynamic "count" {
        for_each = var.managed_rules_in_count ? [1] : []
        content {}
      }
      dynamic "none" {
        for_each = var.managed_rules_in_count ? [] : [1]
        content {}
      }
    }

    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesAmazonIpReputationList"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "ip-reputation"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "core-rule-set"
    priority = 2

    override_action {
      dynamic "count" {
        for_each = var.managed_rules_in_count ? [1] : []
        content {}
      }
      dynamic "none" {
        for_each = var.managed_rules_in_count ? [] : [1]
        content {}
      }
    }

    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesCommonRuleSet"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "core-rule-set"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "rate-web-ip"
    priority = 3

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit                 = 2000
        evaluation_window_sec = 300
        aggregate_key_type    = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "rate-web-ip"
      sampled_requests_enabled   = true
    }
  }

  # Above 30 navigations to a link page per IP in 5 minutes, each one gets a Challenge, which a browser solves
  # silently. A script that calls the API directly never meets it; the API's limits stop that.
  rule {
    name     = "challenge-link-pages"
    priority = 4

    action {
      challenge {}
    }

    statement {
      rate_based_statement {
        limit                 = 30
        evaluation_window_sec = 300
        aggregate_key_type    = "IP"

        scope_down_statement {
          or_statement {
            dynamic "statement" {
              for_each = toset(var.link_page_paths)

              content {
                byte_match_statement {
                  positional_constraint = "EXACTLY"
                  search_string         = statement.value

                  field_to_match {
                    uri_path {}
                  }

                  text_transformation {
                    priority = 0
                    type     = "NONE"
                  }
                }
              }
            }
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "challenge-link-pages"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.name_prefix}-web"
    sampled_requests_enabled   = true
  }
}

# To the Tokyo log bucket, through the log delivery that WAF configures in us-east-1 (ADR-0008, abuse 3.4).
resource "aws_wafv2_web_acl_logging_configuration" "web" {
  provider = aws.us_east_1

  resource_arn            = aws_wafv2_web_acl.web.arn
  log_destination_configs = [var.log_bucket_arn]

  redacted_fields {
    single_header {
      name = "authorization"
    }
  }

  redacted_fields {
    single_header {
      name = "cookie"
    }
  }

  logging_filter {
    default_behavior = "DROP"

    filter {
      behavior    = "KEEP"
      requirement = "MEETS_ANY"

      dynamic "condition" {
        for_each = ["BLOCK", "CAPTCHA", "CHALLENGE", "COUNT", "EXCLUDED_AS_COUNT"]

        content {
          action_condition {
            action = condition.value
          }
        }
      }
    }
  }
}
