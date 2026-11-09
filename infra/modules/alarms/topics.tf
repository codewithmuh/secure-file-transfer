# The Region's alert topics, under its platform key (encryption 3.1):
# - sft-<env>-<rs>-alerts-page and -alerts-ticket: CloudWatch alarms here and Alertmanager publish; the operators'
#   addresses subscribe.
# - sft-<env>-<rs>-heartbeat: only Alertmanager publishes, once a minute, for the always-firing Watchdog alert; nobody
#   subscribes. The heartbeat-missing alarm counts its messages (heartbeat.tf).
# Only the deploy role may change or delete them: BreakGlass holds AdministratorAccess, and SCP 4 guards alarms but not
# topics, so each topic guards itself, as the break-glass topic does (modules/break-glass-role).

locals {
  topics = {
    "alerts-page"   = { cloudwatch = true }
    "alerts-ticket" = { cloudwatch = true }
    "heartbeat"     = { cloudwatch = false }
  }

  topic_arns = { for t, _ in local.topics : t => "arn:aws:sns:${var.region}:${var.account_id}:${var.name_prefix}-${t}" }

  # The break-glass alert topic of this Region (modules/break-glass-role), whose subscribers come from here.
  break_glass_topic_arn = "arn:aws:sns:${var.region}:${var.account_id}:${var.name_prefix}-break-glass-alerts"

  subscriptions = merge([
    for topic, arn in merge(
      { for t, v in local.topics : t => aws_sns_topic.this[t].arn if v.cloudwatch },
      { "break-glass-alerts" = local.break_glass_topic_arn },
      ) : {
      for email in var.alert_emails : "${topic}/${email}" => { topic_arn = arn, email = email }
    }
  ]...)
}

resource "aws_sns_topic" "this" {
  for_each = local.topics

  name              = "${var.name_prefix}-${each.key}"
  kms_master_key_id = var.platform_key_arn

  tags = { component = "alarms" }
}

data "aws_iam_policy_document" "topic" {
  for_each = local.topics

  dynamic "statement" {
    for_each = each.value.cloudwatch ? [1] : []

    content {
      sid       = "CloudWatchAlarmsPublish"
      actions   = ["sns:Publish"]
      resources = [local.topic_arns[each.key]]

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
        values   = ["arn:aws:cloudwatch:${var.region}:${var.account_id}:alarm:sft-${var.environment}-*"]
      }
    }
  }

  # Alertmanager's own identity policy allows its publish; this keeps everyone else out. A service principal has no
  # aws:PrincipalArn, so CloudWatch passes by its service name, and only on the topics it may use.
  statement {
    sid       = "NobodyElsePublishes"
    effect    = "Deny"
    actions   = ["sns:Publish"]
    resources = [local.topic_arns[each.key]]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "ArnNotEquals"
      variable = "aws:PrincipalArn"
      values   = [local.alertmanager_role_arn]
    }

    dynamic "condition" {
      for_each = each.value.cloudwatch ? [1] : []

      content {
        test     = "StringNotEquals"
        variable = "aws:PrincipalServiceName"
        values   = ["cloudwatch.amazonaws.com"]
      }
    }
  }

  statement {
    sid    = "OnlyTheDeployRoleChangesTheTopic"
    effect = "Deny"
    actions = [
      "sns:AddPermission", "sns:DeleteTopic", "sns:PutDataProtectionPolicy", "sns:RemovePermission",
      "sns:SetTopicAttributes",
    ]
    resources = [local.topic_arns[each.key]]

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

resource "aws_sns_topic_policy" "this" {
  for_each = local.topics

  arn    = aws_sns_topic.this[each.key].arn
  policy = data.aws_iam_policy_document.topic[each.key].json
}

# Email subscriptions: each address confirms once, from the message SNS sends it. Until then the topic holds the
# subscription as pending and delivers nothing to it.
resource "aws_sns_topic_subscription" "email" {
  for_each = local.subscriptions

  topic_arn = each.value.topic_arn
  protocol  = "email"
  endpoint  = each.value.email
}
