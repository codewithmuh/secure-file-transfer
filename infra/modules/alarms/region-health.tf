# Region health (architecture 6, "Tokyo region lost"; modules/edge). Each Region's edge has a Route 53 health check on
# a fixed response its load balancer answers itself, so it passes in Osaka's pilot light too (ADR-0021). Route 53
# publishes health check metrics only in us-east-1, so these alarms, their topics and the key for the topics live
# there, the exception NFR-21 makes for exactly this; none of them holds file contents. Tokyo's stack makes them for
# both Regions.
#
# Tokyo failing its check pages: it starts the failover decision (architecture 7), which an operator takes; nothing
# moves traffic on its own (T-78). Osaka failing raises a ticket: the service is fine, but the standby isn't.
#
# The topics need a key CloudWatch may use, and the Regions' platform keys can't leave Japan (encryption 4.4, rule 4),
# so us-east-1 has its own small key, alias/sft/<env>/alarms, for these two topics only.

locals {
  region_health = var.region_health == null ? {} : var.region_health.health_checks

  region_health_severity = { "ap-northeast-1" = "page", "ap-northeast-3" = "ticket" }
  region_health_short    = { "ap-northeast-1" = "apne1", "ap-northeast-3" = "apne3" }

  region_health_topics = var.region_health == null ? {} : {
    page   = "arn:aws:sns:us-east-1:${var.account_id}:${var.name_prefix}-region-health-page"
    ticket = "arn:aws:sns:us-east-1:${var.account_id}:${var.name_prefix}-region-health-ticket"
  }

  region_health_subscriptions = merge([
    for severity, _ in local.region_health_topics : {
      for email in var.alert_emails : "${severity}/${email}" => { severity = severity, email = email }
    }
  ]...)
}

data "aws_iam_policy_document" "region_health_key_use" {
  count = var.region_health == null ? 0 : 1

  statement {
    sid       = "CloudWatchAlarmsPublishToAlarmTopics"
    actions   = ["kms:GenerateDataKey*", "kms:Decrypt"]
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.account_id]
    }

    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:aws:cloudwatch:us-east-1:${var.account_id}:alarm:sft-${var.environment}-*"]
    }
  }
}

module "region_health_key_policy" {
  source = "../key-policy"
  count  = var.region_health == null ? 0 : 1

  account_id                         = var.account_id
  deploy_role_arn                    = var.deploy_role_arn
  plan_role_arn                      = var.region_health.plan_role_arn
  key_admin_role_arn                 = var.region_health.key_admin_role_arn
  break_glass_principal_arn_patterns = var.region_health.break_glass_principal_arn_patterns
  additional_policy_documents        = [data.aws_iam_policy_document.region_health_key_use[0].json]
}

resource "aws_kms_key" "region_health" {
  provider = aws.us_east_1
  count    = var.region_health == null ? 0 : 1

  description             = "Encrypts the Route 53 health check alarms' topics in us-east-1 (architecture 6, NFR-21)"
  enable_key_rotation     = true
  deletion_window_in_days = var.region_health.key_deletion_window_days
  policy                  = module.region_health_key_policy[0].json

  tags = { component = "alarms" }
}

resource "aws_kms_alias" "region_health" {
  provider = aws.us_east_1
  count    = var.region_health == null ? 0 : 1

  name          = "${var.kms_alias_prefix}/alarms"
  target_key_id = aws_kms_key.region_health[0].key_id
}

resource "aws_sns_topic" "region_health" {
  provider = aws.us_east_1
  for_each = local.region_health_topics

  name              = "${var.name_prefix}-region-health-${each.key}"
  kms_master_key_id = aws_kms_key.region_health[0].arn

  tags = { component = "alarms" }
}

data "aws_iam_policy_document" "region_health_topic" {
  for_each = local.region_health_topics

  statement {
    sid       = "CloudWatchAlarmsPublish"
    actions   = ["sns:Publish"]
    resources = [each.value]

    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.account_id]
    }

    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:aws:cloudwatch:us-east-1:${var.account_id}:alarm:sft-${var.environment}-*"]
    }
  }

  statement {
    sid       = "NobodyElsePublishes"
    effect    = "Deny"
    actions   = ["sns:Publish"]
    resources = [each.value]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "StringNotEquals"
      variable = "aws:PrincipalServiceName"
      values   = ["cloudwatch.amazonaws.com"]
    }
  }

  statement {
    sid    = "OnlyTheDeployRoleChangesTheTopic"
    effect = "Deny"
    actions = [
      "sns:AddPermission", "sns:DeleteTopic", "sns:PutDataProtectionPolicy", "sns:RemovePermission",
      "sns:SetTopicAttributes",
    ]
    resources = [each.value]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "ArnNotEquals"
      variable = "aws:PrincipalArn"
      values   = [var.deploy_role_arn]
    }
  }
}

resource "aws_sns_topic_policy" "region_health" {
  provider = aws.us_east_1
  for_each = local.region_health_topics

  arn    = aws_sns_topic.region_health[each.key].arn
  policy = data.aws_iam_policy_document.region_health_topic[each.key].json
}

resource "aws_sns_topic_subscription" "region_health_email" {
  provider = aws.us_east_1
  for_each = local.region_health_subscriptions

  topic_arn = aws_sns_topic.region_health[each.value.severity].arn
  protocol  = "email"
  endpoint  = each.value.email
}

resource "aws_cloudwatch_metric_alarm" "region_health" {
  provider = aws.us_east_1
  for_each = local.region_health

  alarm_name        = "sft-${var.environment}-${local.region_health_short[each.key]}-region-health"
  alarm_description = "The Route 53 health check of ${each.key}'s edge has failed for 3 minutes: the Region may be down; Tokyo's pages for the failover decision, Osaka's raises a ticket (architecture 6, 7). Severity: ${local.region_health_severity[each.key]}. Runbook: https://github.com/codewithmuh/secure-file-transfer/blob/main/docs/runbooks/region-health.md"

  namespace   = "AWS/Route53"
  metric_name = "HealthCheckStatus"
  dimensions  = { HealthCheckId = each.value }
  statistic   = "Minimum"
  period      = 60

  comparison_operator = "LessThanThreshold"
  threshold           = 1
  evaluation_periods  = 3
  datapoints_to_alarm = 3
  treat_missing_data  = "breaching"

  alarm_actions = [aws_sns_topic.region_health[local.region_health_severity[each.key]].arn]
  ok_actions    = [aws_sns_topic.region_health[local.region_health_severity[each.key]].arn]

  tags = { component = "alarms" }
}
