# The Cognito sign-in triggers (modules/signin-triggers; threat model T-89, architecture 6). A trigger that errors or
# is throttled denies the sign-in, so members can't sign in while it lasts: both page.

locals {
  signin_trigger = "${var.name_prefix}-signin-trigger"
}

resource "aws_cloudwatch_metric_alarm" "signin_trigger_errors" {
  alarm_name        = "${var.name_prefix}-signin-trigger-errors"
  alarm_description = "The sign-in trigger ${local.signin_trigger} failed more than 5 times in 5 minutes; members' sign-ins are being denied (T-89). Severity: page. Runbook: https://github.com/codewithmuh/secure-file-transfer/blob/main/docs/runbooks/signin-trigger.md"

  namespace   = "AWS/Lambda"
  metric_name = "Errors"
  dimensions  = { FunctionName = local.signin_trigger }
  statistic   = "Sum"
  period      = 300

  comparison_operator = "GreaterThanThreshold"
  threshold           = 5
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions = local.notify.page
  ok_actions    = local.notify.page

  tags = { component = "alarms" }
}

resource "aws_cloudwatch_metric_alarm" "signin_trigger_throttles" {
  alarm_name        = "${var.name_prefix}-signin-trigger-throttles"
  alarm_description = "The sign-in trigger ${local.signin_trigger} was throttled; those sign-ins were denied (T-89). Severity: page. Runbook: https://github.com/codewithmuh/secure-file-transfer/blob/main/docs/runbooks/signin-trigger.md"

  namespace   = "AWS/Lambda"
  metric_name = "Throttles"
  dimensions  = { FunctionName = local.signin_trigger }
  statistic   = "Sum"
  period      = 300

  comparison_operator = "GreaterThanThreshold"
  threshold           = 0
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions = local.notify.page
  ok_actions    = local.notify.page

  tags = { component = "alarms" }
}
