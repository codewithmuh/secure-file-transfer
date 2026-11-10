# The Region's two web ACLs (abuse 3.1 to 3.4): the API's, on the load balancer, and the sign-in one, which the
# stack that creates the Cognito user pool associates with it. The API isn't behind CloudFront, so the source IP is
# the client's own.
#
# Rollout (abuse 3.2): managed rules and the sign-in rate rules start in Count where managed_rules_in_count is set,
# for two weeks in staging and then in prod, and move to Block one by one. The application enforces every limit
# itself; these rules keep floods off the pods.

locals {
  # The rollout mode, decided here once for every rule that rolls out (#186). Each such rule has one dynamic block per
  # action, iterating over one of these two lists, so exactly one of the pair is present: Count during the rollout;
  # after it, a managed rule group's own actions (override_action none) or a rate rule's Block.
  rollout_count   = var.managed_rules_in_count ? [1] : []
  rollout_enforce = var.managed_rules_in_count ? [] : [1]

  # The managed rule groups (abuse 3.2, rules 1 to 4), by rule name: the web ACLs that run each, its priority there,
  # whether it only labels (Count always, outside the rollout), and the group's own rules that only count.
  managed_rule_groups = {
    "ip-reputation" = {
      web_acls    = ["api", "sign_in"]
      priority    = 1
      group       = "AWSManagedRulesAmazonIpReputationList"
      labels_only = false
      count_rules = []
    }
    # Labels only: corporate recipients often reach the internet through cloud proxies.
    "anonymous-ip" = {
      web_acls    = ["api"]
      priority    = 2
      group       = "AWSManagedRulesAnonymousIpList"
      labels_only = true
      count_rules = []
    }
    "known-bad-inputs" = {
      web_acls    = ["api"]
      priority    = 3
      group       = "AWSManagedRulesKnownBadInputsRuleSet"
      labels_only = false
      count_rules = []
    }
    # Its 8 KB body rule only labels; rule 5 decides.
    "core-rule-set" = {
      web_acls    = ["api"]
      priority    = 4
      group       = "AWSManagedRulesCommonRuleSet"
      labels_only = false
      count_rules = ["SizeRestrictions_BODY"]
    }
  }

  # Rule 5's exceptions: the three routes whose bodies may exceed 8 KB. WAF allows only two levels of and, or and
  # not, so the rule matches the path alone; the API answers any other method on these paths with 405 unread.
  large_body_path_regex = "^/v1/(transfers|upload-requests|tenant/policy)$"

  links_prefix = "/v1/links/"
  token_paths  = ["/oauth2/token", "/oauth2/revoke"]

  # Labels the anonymous IP list adds, for the attack-mode lever (rule 9).
  anonymous_labels = [
    "awswaf:managed:aws:anonymous-ip-list:AnonymousIPList",
    "awswaf:managed:aws:anonymous-ip-list:HostingProviderIPList",
  ]
}

resource "aws_wafv2_ip_set" "block_list" {
  name               = "${var.name_prefix}-block-list"
  description        = "Addresses operators block during an incident, abuse 8.3"
  scope              = "REGIONAL"
  ip_address_version = "IPV4"
  addresses          = []

  # Operators maintain it (abuse 3.2, rule 0); Terraform only creates it.
  lifecycle {
    ignore_changes = [addresses]
  }
}

resource "aws_wafv2_ip_set" "nat" {
  name               = "${var.name_prefix}-nat"
  description        = "NAT gateway addresses of this Region, the only source of Cognito code exchanges"
  scope              = "REGIONAL"
  ip_address_version = "IPV4"
  addresses          = [for ip in data.aws_eips.nat.public_ips : "${ip}/32"]
}

# --- API web ACL -------------------------------------------------------------------------------------------------

resource "aws_wafv2_web_acl" "api" {
  name        = "${var.name_prefix}-api"
  description = "The API load balancer, abuse 3.2"
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  # 429 with a fixed Retry-After equal to the rule's window (abuse 2.2).
  custom_response_body {
    key          = "rate-limited"
    content_type = "APPLICATION_JSON"
    content      = jsonencode({ type = "about:blank", title = "Too many requests", status = 429 })
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

  # Rules 1 to 4: the managed rule groups this web ACL runs, in the rollout mode unless they only label.
  dynamic "rule" {
    for_each = { for name, g in local.managed_rule_groups : name => g if contains(g.web_acls, "api") }

    content {
      name     = rule.key
      priority = rule.value.priority

      override_action {
        dynamic "count" {
          for_each = rule.value.labels_only ? [1] : local.rollout_count
          content {}
        }
        dynamic "none" {
          for_each = rule.value.labels_only ? [] : local.rollout_enforce
          content {}
        }
      }

      statement {
        managed_rule_group_statement {
          vendor_name = "AWS"
          name        = rule.value.group

          dynamic "rule_action_override" {
            for_each = rule.value.count_rules

            content {
              name = rule_action_override.value

              action_to_use {
                count {}
              }
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = rule.key
        sampled_requests_enabled   = true
      }
    }
  }

  rule {
    name     = "body-size"
    priority = 5

    action {
      block {}
    }

    statement {
      and_statement {
        statement {
          label_match_statement {
            scope = "LABEL"
            key   = "awswaf:managed:aws:core-rule-set:SizeRestrictions_Body"
          }
        }

        statement {
          not_statement {
            statement {
              regex_match_statement {
                regex_string = local.large_body_path_regex

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

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "body-size"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "rate-links-ip"
    priority = 6

    action {
      block {
        custom_response {
          response_code            = 429
          custom_response_body_key = "rate-limited"

          response_header {
            name  = "Retry-After"
            value = "60"
          }
        }
      }
    }

    statement {
      rate_based_statement {
        limit                 = 100
        evaluation_window_sec = 60
        aggregate_key_type    = "IP"

        scope_down_statement {
          byte_match_statement {
            positional_constraint = "STARTS_WITH"
            search_string         = local.links_prefix

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

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "rate-links-ip"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "rate-api-ip"
    priority = 7

    action {
      block {
        custom_response {
          response_code            = 429
          custom_response_body_key = "rate-limited"

          response_header {
            name  = "Retry-After"
            value = "300"
          }
        }
      }
    }

    statement {
      rate_based_statement {
        limit                 = 6000
        evaluation_window_sec = 300
        aggregate_key_type    = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "rate-api-ip"
      sampled_requests_enabled   = true
    }
  }

  # Shows distributed guessing from one network.
  rule {
    name     = "rate-links-asn"
    priority = 8

    action {
      count {}
    }

    statement {
      rate_based_statement {
        limit                 = 3000
        evaluation_window_sec = 300
        aggregate_key_type    = "CUSTOM_KEYS"

        custom_key {
          asn {}
        }

        scope_down_statement {
          byte_match_statement {
            positional_constraint = "STARTS_WITH"
            search_string         = local.links_prefix

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

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "rate-links-asn"
      sampled_requests_enabled   = true
    }
  }

  # A runbook lever during AB-1, AB-2 or AB-3: off unless attack_mode_links is set.
  dynamic "rule" {
    for_each = var.attack_mode_links ? [1] : []

    content {
      name     = "attack-mode-links"
      priority = 9

      action {
        block {}
      }

      statement {
        and_statement {
          statement {
            byte_match_statement {
              positional_constraint = "STARTS_WITH"
              search_string         = local.links_prefix

              field_to_match {
                uri_path {}
              }

              text_transformation {
                priority = 0
                type     = "NONE"
              }
            }
          }

          statement {
            or_statement {
              dynamic "statement" {
                for_each = local.anonymous_labels

                content {
                  label_match_statement {
                    scope = "LABEL"
                    key   = statement.value
                  }
                }
              }
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "attack-mode-links"
        sampled_requests_enabled   = true
      }
    }
  }

  # A runbook lever, empty by default: NFR-21 limits where data is stored, not who may connect.
  dynamic "rule" {
    for_each = length(var.blocked_countries) > 0 ? [1] : []

    content {
      name     = "geo-block"
      priority = 10

      action {
        block {}
      }

      statement {
        geo_match_statement {
          country_codes = var.blocked_countries
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "geo-block"
        sampled_requests_enabled   = true
      }
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.name_prefix}-api"
    sampled_requests_enabled   = true
  }
}

resource "aws_wafv2_web_acl_association" "api" {
  resource_arn = aws_lb.api.arn
  web_acl_arn  = aws_wafv2_web_acl.api.arn
}

# --- Sign-in web ACL ---------------------------------------------------------------------------------------------

# Cognito allows Count, Allow, Block and CAPTCHA, and answers a block with its own 403 (abuse 3.2).
resource "aws_wafv2_web_acl" "sign_in" {
  name        = "${var.name_prefix}-sign-in"
  description = "The Cognito user pool managed login and OAuth endpoints, abuse 3.2"
  scope       = "REGIONAL"

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

  # Rule 1: the managed rule groups this web ACL runs, in the rollout mode unless they only label.
  dynamic "rule" {
    for_each = { for name, g in local.managed_rule_groups : name => g if contains(g.web_acls, "sign_in") }

    content {
      name     = rule.key
      priority = rule.value.priority

      override_action {
        dynamic "count" {
          for_each = rule.value.labels_only ? [1] : local.rollout_count
          content {}
        }
        dynamic "none" {
          for_each = rule.value.labels_only ? [] : local.rollout_enforce
          content {}
        }
      }

      statement {
        managed_rule_group_statement {
          vendor_name = "AWS"
          name        = rule.value.group

          dynamic "rule_action_override" {
            for_each = rule.value.count_rules

            content {
              name = rule_action_override.value

              action_to_use {
                count {}
              }
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = rule.key
        sampled_requests_enabled   = true
      }
    }
  }

  # Only our API, through its proxy listener and the NAT gateways, exchanges codes and revokes tokens (ADR-0021).
  rule {
    name     = "token-nat-only"
    priority = 2

    action {
      block {}
    }

    statement {
      and_statement {
        statement {
          or_statement {
            dynamic "statement" {
              for_each = local.token_paths

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

        statement {
          not_statement {
            statement {
              ip_set_reference_statement {
                arn = aws_wafv2_ip_set.nat.arn
              }
            }
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "token-nat-only"
      sampled_requests_enabled   = true
    }
  }

  # Stops a runaway loop in our own code, far above the need.
  rule {
    name     = "rate-token-nat"
    priority = 3

    action {
      dynamic "count" {
        for_each = local.rollout_count
        content {}
      }
      dynamic "block" {
        for_each = local.rollout_enforce
        content {}
      }
    }

    statement {
      rate_based_statement {
        limit                 = 10000
        evaluation_window_sec = 300
        aggregate_key_type    = "IP"

        scope_down_statement {
          ip_set_reference_statement {
            arn = aws_wafv2_ip_set.nat.arn
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "rate-token-nat"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "rate-signin-ip"
    priority = 4

    action {
      dynamic "count" {
        for_each = local.rollout_count
        content {}
      }
      dynamic "block" {
        for_each = local.rollout_enforce
        content {}
      }
    }

    statement {
      rate_based_statement {
        limit                 = 2000
        evaluation_window_sec = 300
        aggregate_key_type    = "IP"

        scope_down_statement {
          not_statement {
            statement {
              ip_set_reference_statement {
                arn = aws_wafv2_ip_set.nat.arn
              }
            }
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "rate-signin-ip"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "rate-signin-post-ip"
    priority = 5

    action {
      dynamic "count" {
        for_each = local.rollout_count
        content {}
      }
      dynamic "block" {
        for_each = local.rollout_enforce
        content {}
      }
    }

    statement {
      rate_based_statement {
        limit                 = 500
        evaluation_window_sec = 300
        aggregate_key_type    = "IP"

        scope_down_statement {
          and_statement {
            statement {
              byte_match_statement {
                positional_constraint = "EXACTLY"
                search_string         = "POST"

                field_to_match {
                  method {}
                }

                text_transformation {
                  priority = 0
                  type     = "NONE"
                }
              }
            }

            statement {
              not_statement {
                statement {
                  ip_set_reference_statement {
                    arn = aws_wafv2_ip_set.nat.arn
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
      metric_name                = "rate-signin-post-ip"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.name_prefix}-sign-in"
    sampled_requests_enabled   = true
  }
}

# --- Logging -----------------------------------------------------------------------------------------------------

# Blocks, CAPTCHAs, Challenges and Count matches are kept; sampled requests cover the allowed ones (capacity A19).
# The authorization and cookie headers are redacted. Tokens are never in URLs, so paths and queries are safe to keep.
resource "aws_wafv2_web_acl_logging_configuration" "this" {
  for_each = {
    api     = aws_wafv2_web_acl.api.arn
    sign_in = aws_wafv2_web_acl.sign_in.arn
  }

  resource_arn            = each.value
  log_destination_configs = [aws_s3_bucket.waf_logs.arn]

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

  depends_on = [aws_s3_bucket_policy.waf_logs]
}
