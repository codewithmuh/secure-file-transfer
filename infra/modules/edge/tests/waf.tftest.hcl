# The API and sign-in web ACLs as abuse and rate limits 3.2 to 3.4 define them (#235): each rule's name, priority,
# action, limit and window, the levers off by default, the rollout switch, and the logging filter and redaction.
# Plans only, against a mocked AWS provider: nothing reaches AWS (infra/scripts/check.sh test). The live WAF test,
# k6 against staging (abuse 9.2), is pending the AWS run.

mock_provider "aws" {
  # Policy documents must be JSON for the bucket policies that take them.
  mock_data "aws_iam_policy_document" {
    defaults = { json = "{}" }
  }
  mock_data "aws_region" {
    defaults = { region = "ap-northeast-1", name = "ap-northeast-1" }
  }
  mock_data "aws_eips" {
    defaults = { public_ips = ["192.0.2.10", "192.0.2.11"] }
  }
}

mock_provider "aws" {
  alias = "dns"
}

# The certificate's validation records name the for_each keys of their records, so they are known at plan here.
override_resource {
  target          = aws_acm_certificate.api
  override_during = plan
  values = {
    arn = "arn:aws:acm:ap-northeast-1:aws:certificate/test-only" # a placeholder, no account ID
    domain_validation_options = [
      for name in ["api.dev.sft.example.com", "api-apne1.dev.sft.example.com"] : {
        domain_name           = name
        resource_record_name  = "_test.${name}."
        resource_record_type  = "CNAME"
        resource_record_value = "_test.acm-validations.aws."
      }
    ]
  }
}

variables {
  environment      = "dev"
  account_id       = format("%012d", 1) # a placeholder account, never a real one
  name_prefix      = "sft-dev-apne1"
  region_short     = "apne1"
  kms_alias_prefix = "alias/sft-dev"
  domain           = "example.com"
  primary_region   = true
}

run "api_web_acl" {
  command = plan

  assert {
    condition = { for r in aws_wafv2_web_acl.api.rule : r.name => r.priority } == {
      "block-list"       = 0
      "ip-reputation"    = 1
      "anonymous-ip"     = 2
      "known-bad-inputs" = 3
      "core-rule-set"    = 4
      "body-size"        = 5
      "rate-links-ip"    = 6
      "rate-api-ip"      = 7
      "rate-links-asn"   = 8
    }
    error_message = "The API web ACL has rules 0 to 8 of abuse 3.2; the two levers stay off by default."
  }

  assert {
    condition = [
      for r in aws_wafv2_web_acl.api.rule : [
        r.statement[0].rate_based_statement[0].limit,
        r.statement[0].rate_based_statement[0].evaluation_window_sec,
        r.statement[0].rate_based_statement[0].aggregate_key_type,
      ] if r.name == "rate-links-ip"
    ] == [[100, 60, "IP"]]
    error_message = "rate-links-ip: 100 link requests per IP in 60 s (above the app's 60 a minute, NFR-14)."
  }

  assert {
    condition = [
      for r in aws_wafv2_web_acl.api.rule : [
        r.statement[0].rate_based_statement[0].limit,
        r.statement[0].rate_based_statement[0].evaluation_window_sec,
      ] if r.name == "rate-api-ip"
    ] == [[6000, 300]]
    error_message = "rate-api-ip: 6,000 requests per IP in 300 s."
  }

  assert {
    condition = [
      for r in aws_wafv2_web_acl.api.rule : [
        r.statement[0].rate_based_statement[0].limit,
        r.statement[0].rate_based_statement[0].evaluation_window_sec,
        length(r.action[0].count),
      ] if r.name == "rate-links-asn"
    ] == [[3000, 300, 1]]
    error_message = "rate-links-asn: 3,000 link requests per ASN in 300 s, counted only."
  }

  # The rate rules answer 429 with a fixed Retry-After equal to their window (abuse 2.2, 2.4).
  assert {
    condition = { for r in aws_wafv2_web_acl.api.rule : r.name => [
      r.action[0].block[0].custom_response[0].response_code,
      r.action[0].block[0].custom_response[0].custom_response_body_key,
      one(r.action[0].block[0].custom_response[0].response_header[*].name),
      one(r.action[0].block[0].custom_response[0].response_header[*].value),
      ] if contains(["rate-links-ip", "rate-api-ip"], r.name) } == {
      "rate-links-ip" = [429, "rate-limited", "Retry-After", "60"]
      "rate-api-ip"   = [429, "rate-limited", "Retry-After", "300"]
    }
    error_message = "The API's rate rules block with 429 and Retry-After 60 or 300."
  }

  assert {
    condition     = [for b in aws_wafv2_web_acl.api.custom_response_body : b.content_type if b.key == "rate-limited"] == ["APPLICATION_JSON"]
    error_message = "The 429 body is JSON with the problem fields."
  }

  # Rule 5 blocks bodies over 8 KB except on the three routes whose bodies may be larger (abuse 3.3).
  assert {
    condition = [
      for r in aws_wafv2_web_acl.api.rule :
      r.statement[0].and_statement[0].statement[1].not_statement[0].statement[0].regex_match_statement[0].regex_string
      if r.name == "body-size"
    ] == ["^/v1/(transfers|upload-requests|tenant/policy)$"]
    error_message = "body-size exempts only /v1/transfers, /v1/upload-requests and /v1/tenant/policy."
  }

  # Managed rule groups block once the rollout ends; the anonymous IP list only labels.
  assert {
    condition = { for r in aws_wafv2_web_acl.api.rule : r.name => [length(r.override_action[0].none), length(r.override_action[0].count)] if length(r.override_action) > 0 } == {
      "ip-reputation"    = [1, 0]
      "anonymous-ip"     = [0, 1]
      "known-bad-inputs" = [1, 0]
      "core-rule-set"    = [1, 0]
    }
    error_message = "Managed rules block, except the anonymous IP list, which only labels."
  }

  assert {
    condition = [
      for r in aws_wafv2_web_acl.api.rule : r.statement[0].managed_rule_group_statement[0].rule_action_override[0].name
      if r.name == "core-rule-set"
    ] == ["SizeRestrictions_BODY"]
    error_message = "The core rule set's own 8 KB body rule only counts; rule 5 decides."
  }

  assert {
    condition     = length(aws_wafv2_web_acl.api.default_action[0].allow) == 1
    error_message = "The API web ACL allows by default."
  }
}

run "api_web_acl_levers_and_rollout" {
  command = plan

  variables {
    attack_mode_links      = true
    blocked_countries      = ["KP"]
    managed_rules_in_count = true
  }

  assert {
    condition = { for r in aws_wafv2_web_acl.api.rule : r.name => r.priority if r.priority >= 9 } == {
      "attack-mode-links" = 9
      "geo-block"         = 10
    }
    error_message = "The runbook levers are rules 9 and 10 when turned on."
  }

  assert {
    condition = alltrue([
      for r in aws_wafv2_web_acl.api.rule : length(r.override_action[0].count) == 1 if length(r.override_action) > 0
    ])
    error_message = "During the rollout every managed rule group only counts."
  }

  assert {
    condition = alltrue([
      for r in aws_wafv2_web_acl.sign_in.rule : length(r.action[0].count) == 1 if startswith(r.name, "rate-")
    ])
    error_message = "During the rollout the sign-in rate rules only count."
  }
}

run "sign_in_web_acl" {
  command = plan

  assert {
    condition = { for r in aws_wafv2_web_acl.sign_in.rule : r.name => r.priority } == {
      "block-list"          = 0
      "ip-reputation"       = 1
      "token-nat-only"      = 2
      "rate-token-nat"      = 3
      "rate-signin-ip"      = 4
      "rate-signin-post-ip" = 5
    }
    error_message = "The sign-in web ACL has the six rules of abuse 3.2."
  }

  assert {
    condition = { for r in aws_wafv2_web_acl.sign_in.rule : r.name => [
      r.statement[0].rate_based_statement[0].limit,
      r.statement[0].rate_based_statement[0].evaluation_window_sec,
      length(r.action[0].block),
      ] if startswith(r.name, "rate-") } == {
      "rate-token-nat"      = [10000, 300, 1]
      "rate-signin-ip"      = [2000, 300, 1]
      "rate-signin-post-ip" = [500, 300, 1]
    }
    error_message = "Sign-in rate rules: 10,000 from the NAT gateways, 2,000 and 500 form posts per other IP, in 5 minutes."
  }

  assert {
    condition     = toset(aws_wafv2_ip_set.nat.addresses) == toset(["192.0.2.10/32", "192.0.2.11/32"])
    error_message = "The NAT IP set holds the Region's NAT gateway addresses, each a /32."
  }
}

run "logging" {
  command = plan

  assert {
    condition     = toset(keys(aws_wafv2_web_acl_logging_configuration.this)) == toset(["api", "sign_in"])
    error_message = "Both regional web ACLs log (NFR-21, abuse 3.4)."
  }

  assert {
    condition = alltrue([
      for c in aws_wafv2_web_acl_logging_configuration.this :
      toset([for f in c.redacted_fields : f.single_header[0].name]) == toset(["authorization", "cookie"])
    ])
    error_message = "Logs redact the authorization and cookie headers."
  }

  assert {
    condition = alltrue([
      for c in aws_wafv2_web_acl_logging_configuration.this :
      c.logging_filter[0].default_behavior == "DROP" &&
      one(c.logging_filter[0].filter).behavior == "KEEP" &&
      toset([for k in one(c.logging_filter[0].filter).condition : one(k.action_condition).action]) ==
      toset(["BLOCK", "CAPTCHA", "CHALLENGE", "COUNT", "EXCLUDED_AS_COUNT"])
    ])
    error_message = "Logs keep blocks, CAPTCHAs, challenges and counts; sampled requests cover the rest."
  }

  assert {
    condition     = startswith(aws_s3_bucket.waf_logs.bucket, "aws-waf-logs-")
    error_message = "WAF logs go to an aws-waf-logs- bucket in the Region."
  }
}
