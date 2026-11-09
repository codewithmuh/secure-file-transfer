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
    condition     = length(aws_cloudwatch_metric_alarm.region_health) == 0 && length(aws_kms_key.region_health) == 0
    error_message = "Osaka makes nothing in us-east-1: Tokyo's stack watches its health check."
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
