# The web app's CloudFront web ACL as abuse and rate limits 3.2 and 3.4 define it (#235): rules 0, 1 and 4 of the API
# web ACL, the per-IP rate rule, the Challenge on bursts of link page loads, and the logging filter and redaction.
# Plans only, against a mocked AWS provider (infra/scripts/check.sh test). The live check, a browser matrix through
# the challenge in staging (abuse 9.2), is pending the AWS run.

mock_provider "aws" {}

mock_provider "aws" {
  alias = "us_east_1"
}

mock_provider "aws" {
  alias = "dns"
}

# The certificate's validation records name the for_each keys of their records, so they are known at plan here.
override_resource {
  target          = aws_acm_certificate.app
  override_during = plan
  values = {
    arn = "arn:aws:acm:us-east-1:aws:certificate/test-only" # a placeholder, no account ID
    domain_validation_options = [{
      domain_name           = "app.dev.sft.example.com"
      resource_record_name  = "_test.app.dev.sft.example.com."
      resource_record_type  = "CNAME"
      resource_record_value = "_test.acm-validations.aws."
    }]
  }
}

variables {
  name_prefix    = "sft-dev-apne1"
  service_domain = "dev.sft.example.com"
  zone_id        = "Z0TESTONLY"
  primary_bucket = {
    region_short         = "apne1"
    regional_domain_name = "sft-dev-apne1-web.s3.ap-northeast-1.amazonaws.com"
  }
  upload_origins = ["https://s3.ap-northeast-1.amazonaws.com"]
  log_bucket_arn = "arn:aws:s3:::aws-waf-logs-sft-dev-apne1-test-only"
}

run "web_acl" {
  command = plan

  assert {
    condition = { for r in aws_wafv2_web_acl.web.rule : r.name => r.priority } == {
      "block-list"           = 0
      "ip-reputation"        = 1
      "core-rule-set"        = 2
      "rate-web-ip"          = 3
      "challenge-link-pages" = 4
    }
    error_message = "The web app's web ACL has the five rules of abuse 3.2."
  }

  assert {
    condition     = aws_wafv2_web_acl.web.scope == "CLOUDFRONT"
    error_message = "The web app's web ACL is CloudFront's, in us-east-1."
  }

  assert {
    condition = [
      for r in aws_wafv2_web_acl.web.rule : [
        r.statement[0].rate_based_statement[0].limit,
        r.statement[0].rate_based_statement[0].evaluation_window_sec,
        length(r.action[0].block),
      ] if r.name == "rate-web-ip"
    ] == [[2000, 300, 1]]
    error_message = "rate-web-ip: 2,000 requests per IP in 300 s, blocked."
  }

  # Above 30 link page loads per IP in 5 minutes, each gets a Challenge, which keeps the URL fragment.
  # Compared as JSON: the rule mixes numbers, strings and a list.
  assert {
    condition = jsonencode([
      for r in aws_wafv2_web_acl.web.rule : [
        r.statement[0].rate_based_statement[0].limit,
        r.statement[0].rate_based_statement[0].evaluation_window_sec,
        r.statement[0].rate_based_statement[0].aggregate_key_type,
        length(r.action[0].challenge),
        sort([
          for s in r.statement[0].rate_based_statement[0].scope_down_statement[0].or_statement[0].statement :
          s.byte_match_statement[0].search_string
        ]),
      ] if r.name == "challenge-link-pages"
    ]) == jsonencode([[30, 300, "IP", 1, ["/t"]]])
    error_message = "challenge-link-pages: a Challenge above 30 link page loads per IP in 300 s."
  }

  assert {
    condition = { for r in aws_wafv2_web_acl.web.rule : r.name => length(r.override_action[0].none) if length(r.override_action) > 0 } == {
      "ip-reputation" = 1
      "core-rule-set" = 1
    }
    error_message = "Managed rules block once the rollout ends."
  }
}

run "rollout_and_link_pages" {
  command = plan

  variables {
    managed_rules_in_count = true
    link_page_paths        = ["/t", "/u"]
  }

  assert {
    condition = alltrue([
      for r in aws_wafv2_web_acl.web.rule : length(r.override_action[0].count) == 1 if length(r.override_action) > 0
    ])
    error_message = "During the rollout the managed rule groups only count."
  }

  assert {
    condition = jsonencode([
      for r in aws_wafv2_web_acl.web.rule : sort([
        for s in r.statement[0].rate_based_statement[0].scope_down_statement[0].or_statement[0].statement :
        s.byte_match_statement[0].search_string
      ]) if r.name == "challenge-link-pages"
    ]) == jsonencode([["/t", "/u"]])
    error_message = "Every link page path is challenged."
  }
}

run "logging" {
  command = plan

  assert {
    condition     = toset(aws_wafv2_web_acl_logging_configuration.web.log_destination_configs) == toset(["arn:aws:s3:::aws-waf-logs-sft-dev-apne1-test-only"])
    error_message = "The CloudFront web ACL logs to the Tokyo aws-waf-logs- bucket (abuse 3.4)."
  }

  assert {
    condition = toset([
      for f in aws_wafv2_web_acl_logging_configuration.web.redacted_fields : f.single_header[0].name
    ]) == toset(["authorization", "cookie"])
    error_message = "Logs redact the authorization and cookie headers."
  }

  assert {
    condition = (
      aws_wafv2_web_acl_logging_configuration.web.logging_filter[0].default_behavior == "DROP" &&
      toset([
        for k in one(aws_wafv2_web_acl_logging_configuration.web.logging_filter[0].filter).condition :
        one(k.action_condition).action
      ]) == toset(["BLOCK", "CAPTCHA", "CHALLENGE", "COUNT", "EXCLUDED_AS_COUNT"])
    )
    error_message = "Logs keep blocks, CAPTCHAs, challenges and counts."
  }
}
