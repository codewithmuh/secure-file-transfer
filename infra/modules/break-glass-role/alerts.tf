# Every assumption of sft-<env>-break-glass-db pages (authn-authz 8.3, "Alerts"): an EventBridge rule on CloudTrail's
# AssumeRole event for the role, in this Region, into this Region's break-glass alert topic, through the
# environment's EventBridge delivery role (encryption 4.4, modules/events-delivery-role). A refused attempt matches
# too: CloudTrail records it with its errorCode, and an attempt is worth a page as much as a use.
#
# The topic is sft-<env>-<region-short>-break-glass-alerts under the platform key, like the other alarm topics
# (encryption 3.1). Only the delivery role may publish to it, and only the deploy role may change or delete it. SCP 4
# already keeps rules named sft-* with the apply roles, so BreakGlass can't switch the rule off first.
#
# Who the topic reaches, the pager and every operator's address, comes with M7's alerting as code (ADR-0009); until
# then nothing subscribes, and the alert is pending both M7 and the AWS run. CloudTrail delivers management events to
# EventBridge through the organization trail (ADR-0006), with up to a few minutes' delay.

locals {
  topic_name = "sft-${var.environment}-${local.region_short}-break-glass-alerts"
  topic_arn  = "arn:aws:sns:${var.region}:${var.account_id}:${local.topic_name}"
  rule_name  = "sft-${var.environment}-${local.region_short}-break-glass-db-assumed"

  runbook_url = "https://github.com/codewithmuh/secure-file-transfer/blob/main/docs/runbooks/break-glass.md"
}

resource "aws_sns_topic" "alerts" {
  name              = local.topic_name
  kms_master_key_id = var.platform_key_arn

  tags = { component = "break-glass" }
}

data "aws_iam_policy_document" "topic" {
  statement {
    sid       = "EventBridgeDeliveryRolePublishes"
    actions   = ["sns:Publish"]
    resources = [local.topic_arn]

    principals {
      type        = "AWS"
      identifiers = [var.events_delivery_role_arn]
    }
  }

  statement {
    sid       = "NobodyElsePublishes"
    effect    = "Deny"
    actions   = ["sns:Publish"]
    resources = [local.topic_arn]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "ArnNotEquals"
      variable = "aws:PrincipalArn"
      values   = [var.events_delivery_role_arn]
    }
  }

  # BreakGlass holds AdministratorAccess, and SCP 4 guards rules but not topics, so the topic guards itself.
  statement {
    sid    = "OnlyTheDeployRoleChangesTheTopic"
    effect = "Deny"
    actions = [
      "sns:AddPermission", "sns:DeleteTopic", "sns:PutDataProtectionPolicy", "sns:RemovePermission",
      "sns:SetTopicAttributes",
    ]
    resources = [local.topic_arn]

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

resource "aws_sns_topic_policy" "alerts" {
  arn    = aws_sns_topic.alerts.arn
  policy = data.aws_iam_policy_document.topic.json
}

resource "aws_cloudwatch_event_rule" "assumed" {
  name        = local.rule_name
  description = "Any AssumeRole of ${local.role_name} in ${var.region}, granted or refused: pages (FR-35, authn-authz 8.3)."

  event_pattern = jsonencode({
    source        = ["aws.sts"]
    "detail-type" = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["sts.amazonaws.com"]
      eventName   = ["AssumeRole"]
      requestParameters = {
        roleArn = [local.role_arn]
      }
    }
  })

  tags = { component = "break-glass" }
}

resource "aws_cloudwatch_event_target" "assumed" {
  rule      = aws_cloudwatch_event_rule.assumed.name
  target_id = "break-glass-alerts-topic"
  arn       = aws_sns_topic.alerts.arn
  role_arn  = var.events_delivery_role_arn

  # Who, from where, and the request, whose tags name the grant. Never the response, which holds the session's
  # access key ID. Each path is in every AssumeRole event that matches the pattern.
  input_transformer {
    input_paths = {
      time      = "$.time"
      region    = "$.region"
      caller    = "$.detail.userIdentity.arn"
      source_ip = "$.detail.sourceIPAddress"
      request   = "$.detail.requestParameters"
      event_id  = "$.detail.eventID"
    }
    input_template = <<-EOT
      {
        "alert": "BreakGlassDatabaseRoleAssumed",
        "severity": "page",
        "summary": "Someone assumed, or tried to assume, ${local.role_name}; the request's tag names the grant (FR-35).",
        "runbook_url": "${local.runbook_url}",
        "time": <time>,
        "region": <region>,
        "caller": <caller>,
        "source_ip": <source_ip>,
        "request": <request>,
        "cloudtrail_event_id": <event_id>
      }
    EOT
  }

  # A day of retries, like the environment's other rules: a page delivered late is better than none.
  retry_policy {
    maximum_event_age_in_seconds = 86400
    maximum_retry_attempts       = 185
  }
}
