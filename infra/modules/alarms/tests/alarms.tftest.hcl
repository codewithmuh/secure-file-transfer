# The alarms layer (#246), planned against a mocked AWS provider (infra/scripts/check.sh test). Whether each alarm
# fires on the real metric is pending the AWS run.

mock_provider "aws" {
  mock_data "aws_iam_policy_document" {
    defaults = { json = "{}" }
  }
  mock_data "aws_nat_gateways" {
    defaults = { ids = ["nat-0testa", "nat-0testb", "nat-0testc"] }
  }
}

mock_provider "aws" {
  alias = "us_east_1"

  mock_data "aws_iam_policy_document" {
    defaults = { json = "{}" }
  }
}

variables {
  environment      = "staging"
  account_id       = format("%012d", 1) # a placeholder account, never a real one
  region           = "ap-northeast-1"
  name_prefix      = "sft-staging-apne1"
  kms_alias_prefix = "alias/sft/staging"
  platform_key_arn = "arn:aws:kms:ap-northeast-1:aws:key/test-only"
  deploy_role_arn  = "arn:aws:iam::aws:role/sft-bootstrap/sft-staging-terraform-deploy"
  alert_emails     = ["oncall@example.com", "ops@example.com"]

  # What the root passes as module.conventions (modules/conventions), for a placeholder account.
  conventions = {
    region_shorts = { "ap-northeast-1" = "apne1", "ap-northeast-3" = "apne3" }
    workload_role_arns = {
      alertmanager      = "arn:aws:iam::aws:role/sft-staging-alertmanager"
      "events-delivery" = "arn:aws:iam::aws:role/sft-staging-events-delivery"
    }
    bootstrap_iam_path = "/sft-bootstrap/"
    bootstrap_role_arns = {
      terraform_deploy = "arn:aws:iam::aws:role/sft-bootstrap/sft-staging-terraform-deploy"
      terraform_plan   = "arn:aws:iam::aws:role/sft-bootstrap/sft-staging-terraform-plan"
      key_admin        = "arn:aws:iam::aws:role/sft-bootstrap/sft-staging-keyadmin"
    }
    emergency_user = {
      name = "sft-staging-emergency"
      path = "/sft-emergency/"
      arn  = "arn:aws:iam::aws:user/sft-emergency/sft-staging-emergency"
    }
    sso_role_arn_patterns = {
      admin       = "arn:aws:iam::aws:role/aws-reserved/sso.amazonaws.com/*AWSReservedSSO_Admin_*"
      break_glass = "arn:aws:iam::aws:role/aws-reserved/sso.amazonaws.com/*AWSReservedSSO_BreakGlass_*"
    }
  }

  database = {
    cluster_identifier          = "sft-staging-apne1-aurora"
    role                        = "primary"
    freeable_memory_alarm_bytes = 1610612736
  }

  load_balancer_arn    = "arn:aws:elasticloadbalancing:ap-northeast-1:aws:loadbalancer/app/sft-staging-apne1-api/0123456789abcdef"
  api_target_group_arn = "arn:aws:elasticloadbalancing:ap-northeast-1:aws:targetgroup/sft-staging-apne1-api/fedcba9876543210"
  vpc_id               = "vpc-0testonly"

  replicated_buckets = {
    files = {
      source      = "sft-staging-apne1-files-test"
      destination = "sft-staging-apne3-files-test"
    }
  }

  region_health = {
    health_checks = {
      "ap-northeast-1" = "hc-tokyo"
      "ap-northeast-3" = "hc-osaka"
    }
    plan_role_arn                      = "arn:aws:iam::aws:role/sft-bootstrap/sft-staging-terraform-plan"
    key_admin_role_arn                 = "arn:aws:iam::aws:role/sft-bootstrap/sft-staging-keyadmin"
    break_glass_principal_arn_patterns = ["arn:aws:iam::aws:role/aws-reserved/sso.amazonaws.com/*AWSReservedSSO_BreakGlass_*"]
    key_deletion_window_days           = 7
  }
}

run "tokyo" {
  command = plan

  assert {
    condition = (
      aws_cloudwatch_metric_alarm.heartbeat_missing.treat_missing_data == "breaching" &&
      aws_cloudwatch_metric_alarm.heartbeat_missing.actions_enabled &&
      aws_cloudwatch_metric_alarm.heartbeat_missing.evaluation_periods == 5
    )
    error_message = "The heartbeat alarm pages after 5 minutes without a heartbeat, missing data included (ADR-0009)."
  }

  assert {
    condition     = length(aws_cloudwatch_metric_alarm.database_rpo_lag) == 0 && length(aws_cloudwatch_metric_alarm.database_cpu) == 1
    error_message = "Tokyo's primary gets the writer's alarms; only Osaka's secondary has a recovery point to watch."
  }

  assert {
    condition     = toset(keys(aws_cloudwatch_metric_alarm.dead_letter)) == toset(["notify", "signin-events", "ses-events", "ses-tenant-status"])
    error_message = "The dead-letter queues ScanFailed doesn't already page on, and no others."
  }

  assert {
    condition     = aws_cloudwatch_metric_alarm.queue_age["signin-events"].threshold == 30
    error_message = "A sign-in event older than 30 seconds alarms (authn-authz 2.4)."
  }

  assert {
    condition     = length(aws_cloudwatch_metric_alarm.nat_packet_drops) == 3 && length(aws_cloudwatch_metric_alarm.replication_latency) == 1
    error_message = "One pair of NAT alarms per gateway, and the replication alarms per replicated bucket."
  }

  assert {
    condition = (
      aws_cloudwatch_metric_alarm.load_balancer_5xx.dimensions["LoadBalancer"] == "app/sft-staging-apne1-api/0123456789abcdef" &&
      aws_cloudwatch_metric_alarm.api_targets.dimensions["TargetGroup"] == "targetgroup/sft-staging-apne1-api/fedcba9876543210" &&
      aws_cloudwatch_metric_alarm.api_targets.actions_enabled
    )
    error_message = "The load balancer alarms use the ARNs' suffixes, and notify outside the pilot light."
  }

  assert {
    condition     = length(aws_cloudwatch_metric_alarm.region_health) == 2 && length(aws_kms_key.region_health) == 1
    error_message = "Tokyo's stack watches both Regions' health checks from us-east-1, with a key there for their topics."
  }

  assert {
    condition     = length(aws_sns_topic_subscription.email) == 6 && length(aws_sns_topic_subscription.region_health_email) == 4
    error_message = "Every address subscribes to the page, ticket and break-glass topics here, and to both us-east-1 topics."
  }

  assert {
    condition     = length(aws_cloudwatch_metric_alarm.probe_failing) == 0
    error_message = "No probe alarm until the environment's probe runs: missing data would page for good."
  }

  assert {
    condition = alltrue([
      for a in concat(
        [aws_cloudwatch_metric_alarm.heartbeat_missing.alarm_name, aws_cloudwatch_metric_alarm.kms_quota.alarm_name],
        [for x in aws_cloudwatch_metric_alarm.queue_age : x.alarm_name],
        [for x in aws_cloudwatch_metric_alarm.region_health : x.alarm_name],
      ) : startswith(a, "sft-staging-")
    ])
    error_message = "Every alarm is sft-<env>-*, which the keys' policies and SCP 3 match."
  }
}

run "security_events_tokyo" {
  command = plan

  assert {
    condition     = toset(keys(aws_cloudwatch_event_rule.security)) == toset(["kms-key-changed", "key-admin-used", "human-sign-in", "security-service-off", "alerting-or-endpoint-changed"])
    error_message = "Each Region pages on KMS changes, the key-admin role, privileged sign-ins and security services turned off (#256); the prod-only rule is prod's."
  }

  assert {
    condition = alltrue([
      for t in aws_cloudwatch_event_target.security : t.role_arn == "arn:aws:iam::aws:role/sft-staging-events-delivery" && t.target_id == "alerts-page"
    ])
    error_message = "Every security rule pages through the environment's delivery role (encryption 4.4)."
  }

  assert {
    condition = alltrue([
      for t in aws_cloudwatch_event_target.security :
      fileexists("../../../docs/runbooks/${regex("docs/runbooks/([a-z0-9-]+)\\.md", t.input_transformer[0].input_template)[0]}.md")
    ])
    error_message = "Every security rule names a runbook that exists in docs/runbooks (NFR-17)."
  }

  assert {
    condition = alltrue([
      for t in aws_cloudwatch_event_target.security :
      alltrue([for p in values(t.input_transformer[0].input_paths) : !strcontains(p, "requestParameters") && !strcontains(p, "responseElements")])
    ])
    error_message = "No alert carries requestParameters or responseElements, where policies, access key IDs and tokens can be."
  }

  assert {
    condition     = length(aws_cloudwatch_event_rule.global_events) == 1 && aws_cloudwatch_event_target.global_events[0].arn == "arn:aws:events:ap-northeast-1:${var.account_id}:event-bus/default"
    error_message = "Tokyo forwards the us-east-1 sign-in and STS events to its own bus."
  }

  assert {
    condition     = !strcontains(aws_cloudwatch_event_rule.security["human-sign-in"].event_pattern, "\"region\"")
    error_message = "Tokyo's rules see the forwarded us-east-1 events too."
  }
}

run "security_events_prod_osaka_failover" {
  command = plan

  variables {
    environment        = "prod"
    region             = "ap-northeast-3"
    name_prefix        = "sft-prod-apne3"
    platform_key_arn   = "arn:aws:kms:ap-northeast-3:aws:key/test-only"
    pilot_light        = false
    replicated_buckets = {}
    region_health      = null
  }

  assert {
    condition     = alltrue([for r in aws_cloudwatch_event_rule.security : length(r.event_pattern) <= 4096])
    error_message = "Each pattern fits EventBridge's 4,096 characters, prod's longer deploy role list included."
  }

  assert {
    condition     = contains(keys(aws_cloudwatch_event_rule.security), "kms-key-destroyed")
    error_message = "In prod a deploy role disabling or deleting a key pages too (encryption 4.4 rule 7)."
  }

  assert {
    condition     = length(aws_cloudwatch_event_rule.global_events) == 1 && aws_cloudwatch_event_target.global_events[0].arn == "arn:aws:events:ap-northeast-3:${var.account_id}:event-bus/default"
    error_message = "Out of the pilot light, Osaka forwards the us-east-1 events to its own bus, so a failover keeps them."
  }
}

run "osaka_pilot_light" {
  command = plan

  variables {
    region             = "ap-northeast-3"
    name_prefix        = "sft-staging-apne3"
    platform_key_arn   = "arn:aws:kms:ap-northeast-3:aws:key/test-only"
    heartbeat_enabled  = false
    pilot_light        = true
    replicated_buckets = {}
    region_health      = null

    database = {
      cluster_identifier          = "sft-staging-apne3-aurora"
      role                        = "secondary"
      freeable_memory_alarm_bytes = 1610612736
    }
  }

  assert {
    condition     = !aws_cloudwatch_metric_alarm.heartbeat_missing.actions_enabled && !aws_cloudwatch_metric_alarm.api_targets.actions_enabled
    error_message = "In the pilot light, the heartbeat and API target alarms exist but don't notify (ADR-0009, architecture 3.2)."
  }

  assert {
    condition     = aws_cloudwatch_metric_alarm.load_balancer_5xx.actions_enabled != false && aws_cloudwatch_metric_alarm.dead_letter["notify"].actions_enabled != false
    error_message = "Everything else in Osaka notifies during the pilot light."
  }

  assert {
    condition     = length(aws_cloudwatch_metric_alarm.database_rpo_lag) == 1 && length(aws_cloudwatch_metric_alarm.database_cpu) == 0
    error_message = "Osaka's secondary watches its recovery point (ADR-0011), not a writer it doesn't have."
  }

  assert {
    condition     = length(aws_cloudwatch_metric_alarm.region_health) == 0 && length(aws_kms_key.region_health) == 0 && length(aws_cloudwatch_event_rule.global_events) == 0
    error_message = "Osaka makes nothing in us-east-1 in the pilot light: Tokyo's stack watches its health check and forwards the global events."
  }

  assert {
    condition = alltrue([
      for r in aws_cloudwatch_event_rule.security : jsondecode(r.event_pattern).region == ["ap-northeast-3"]
    ])
    error_message = "In the pilot light Osaka's security rules look at Osaka's own events only, so nothing pages twice."
  }
}

run "probe_running" {
  command = plan

  variables {
    probe_enabled = true
  }

  assert {
    condition = (
      aws_cloudwatch_metric_alarm.probe_failing[0].namespace == "SecureFileTransfer/Probe" &&
      aws_cloudwatch_metric_alarm.probe_failing[0].dimensions["Environment"] == "staging" &&
      aws_cloudwatch_metric_alarm.probe_failing[0].treat_missing_data == "breaching" &&
      aws_cloudwatch_metric_alarm.probe_failing[0].actions_enabled
    )
    error_message = "Once the probe runs, two 5-minute periods without a pass page, missing data included (#248, NFR-1)."
  }
}

run "no_addresses" {
  command = plan

  variables {
    alert_emails = []
  }

  expect_failures = [var.alert_emails]
}
