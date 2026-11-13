# The alert on any SCP change (#277; encryption 8.4, ADR-0006). The SCPs are what bind every role in the member
# accounts, and Organizations records its calls only in this account, in us-east-1, where no environment's rule and no
# retained-stack rule can see them. So this account has its own rule there, on every call that changes what an SCP
# allows or where it applies: AttachPolicy, DetachPolicy, UpdatePolicy, DeletePolicy, EnablePolicyType and
# DisablePolicyType, successful or refused, by anyone, the maintainer's own applies of this stack included (the runbook
# says how to tell those apart). It publishes to a topic the maintainer's addresses subscribe to (var.alert_emails).
#
# EventBridge sees these events through the organization trail, which logs every account's management events in every
# Region, global services included (the shared stack, modules/log-archive). Until the shared stack has made that trail,
# the rule exists and sees nothing.
#
# The message carries who, what, where and when, never requestParameters or responseElements: an UpdatePolicy's
# request holds the whole policy. The CloudTrail event ID finds the rest. NFR-21 keeps data in Japan; this account
# holds none, and Organizations' events exist only in us-east-1, the exception SCP 1 also makes for EventBridge, SNS
# and KMS there.

locals {
  scp_change_events = ["AttachPolicy", "DetachPolicy", "UpdatePolicy", "DeletePolicy", "EnablePolicyType", "DisablePolicyType"]

  scp_alerts_name  = "${module.conventions.global_name_prefix}-scp-alerts"
  scp_alerts_topic = "arn:aws:sns:us-east-1:${var.account_id}:${local.scp_alerts_name}"
  scp_change_rule  = "arn:aws:events:us-east-1:${var.account_id}:rule/${module.conventions.global_name_prefix}-scp-changed"
}

# The topic's key. A topic EventBridge publishes to needs a key whose policy lets EventBridge use it; an AWS managed
# key can't. Administered through IAM, by this account's administrators: SCPs don't bind them here, so a key-admin
# role (which exists elsewhere only so a key policy can be repaired past the SCPs) would add nothing.
data "aws_iam_policy_document" "scp_alerts_key" {
  statement {
    sid       = "TheAccountsAdministratorsThroughIam"
    actions   = ["kms:*"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.account_id}:root"]
    }
  }

  # For SNS's encryption of this one topic's messages, which EventBridge's publish asks for.
  statement {
    sid       = "EventBridgePublishesToTheScpAlertsTopic"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey"]
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:EncryptionContext:aws:sns:topicArn"
      values   = [local.scp_alerts_topic]
    }
  }
}

resource "aws_kms_key" "scp_alerts" {
  provider = aws.us_east_1

  description             = "Encrypts the SCP change alerts' topic in us-east-1 (#277, encryption 8.4)"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.scp_alerts_key.json

  tags = { component = "scp-alerts" }
}

resource "aws_kms_alias" "scp_alerts" {
  provider = aws.us_east_1

  name          = "${module.conventions.kms_alias_prefix}/alerts"
  target_key_id = aws_kms_key.scp_alerts.key_id
}

resource "aws_sns_topic" "scp_alerts" {
  provider = aws.us_east_1

  name              = local.scp_alerts_name
  kms_master_key_id = aws_kms_key.scp_alerts.arn

  tags = { component = "scp-alerts" }
}

# Only the rule publishes; nobody else does, even with sns:Publish in an identity policy.
data "aws_iam_policy_document" "scp_alerts_topic" {
  statement {
    sid       = "TheScpRulePublishes"
    actions   = ["sns:Publish"]
    resources = [local.scp_alerts_topic]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [local.scp_change_rule]
    }
  }

  statement {
    sid       = "NobodyElsePublishes"
    effect    = "Deny"
    actions   = ["sns:Publish"]
    resources = [local.scp_alerts_topic]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "StringNotEquals"
      variable = "aws:PrincipalServiceName"
      values   = ["events.amazonaws.com"]
    }
  }
}

resource "aws_sns_topic_policy" "scp_alerts" {
  provider = aws.us_east_1

  arn    = aws_sns_topic.scp_alerts.arn
  policy = data.aws_iam_policy_document.scp_alerts_topic.json
}

# Each address confirms once, from the message SNS sends it; until then it receives nothing.
resource "aws_sns_topic_subscription" "scp_alerts" {
  provider = aws.us_east_1
  for_each = toset(var.alert_emails)

  topic_arn = aws_sns_topic.scp_alerts.arn
  protocol  = "email"
  endpoint  = each.value
}

resource "aws_cloudwatch_event_rule" "scp_changed" {
  provider = aws.us_east_1

  name        = "${module.conventions.global_name_prefix}-scp-changed"
  description = "Any call that changes an SCP or where it applies, successful or refused (#277, encryption 8.4): pages."

  event_pattern = jsonencode({
    source        = ["aws.organizations"]
    "detail-type" = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["organizations.amazonaws.com"]
      eventName   = local.scp_change_events
    }
  })

  tags = { component = "scp-alerts" }
}

resource "aws_cloudwatch_event_target" "scp_changed" {
  provider = aws.us_east_1

  rule      = aws_cloudwatch_event_rule.scp_changed.name
  target_id = "scp-alerts"
  arn       = aws_sns_topic.scp_alerts.arn

  input_transformer {
    input_paths = {
      time        = "$.time"
      account     = "$.account"
      event_name  = "$.detail.eventName"
      caller      = "$.detail.userIdentity.arn"
      caller_type = "$.detail.userIdentity.type"
      source_ip   = "$.detail.sourceIPAddress"
      error_code  = "$.detail.errorCode"
      event_id    = "$.detail.eventID"
    }
    input_template = <<-EOT
      {
        "alert": "ScpChanged",
        "severity": "page",
        "summary": "An SCP, or where one applies, was changed in the organization, or someone tried (encryption 8.4, ADR-0006).",
        "runbook_url": "https://github.com/codewithmuh/secure-file-transfer/blob/main/docs/runbooks/scp-change.md",
        "time": <time>,
        "account": <account>,
        "event_name": <event_name>,
        "caller": <caller>,
        "caller_type": <caller_type>,
        "source_ip": <source_ip>,
        "error_code": <error_code>,
        "cloudtrail_event_id": <event_id>
      }
    EOT
  }

  # A day of retries, like the environments' security rules: a page delivered late is better than none.
  retry_policy {
    maximum_event_age_in_seconds = 86400
    maximum_retry_attempts       = 185
  }

  depends_on = [aws_sns_topic_policy.scp_alerts]
}
