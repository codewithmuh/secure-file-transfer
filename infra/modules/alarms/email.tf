# SesReputation (abuse 7.3 and 8.2, ADR-0015): the account's bounce rate at 2 % or its complaint rate at 0.05 %, for
# 3 hours in a row, pages, well before SES's own review thresholds (5 % and 0.1 %). Reputation is per account and
# Region, so each Region alarms on its own; Osaka's is quiet until it sends.

resource "aws_cloudwatch_metric_alarm" "ses_reputation" {
  alarm_name        = "${var.name_prefix}-ses-reputation"
  alarm_description = "SesReputation: SES bounce rate at least 2 % or complaint rate at least 0.05 % for 3 hours; SES may pause sending for every tenant (abuse 8.2). Severity: page. Runbook: https://github.com/codewithmuh/secure-file-transfer/blob/main/docs/runbooks/ses-reputation.md"

  comparison_operator = "GreaterThanOrEqualToThreshold"
  threshold           = 1
  evaluation_periods  = 3
  datapoints_to_alarm = 3
  treat_missing_data  = "notBreaching"

  # Each rate against its own threshold: 1 or more means at least one is at its threshold.
  metric_query {
    id          = "reputation"
    expression  = "MAX([bounce / 0.02, complaint / 0.0005])"
    label       = "SES reputation against its thresholds"
    return_data = true
  }

  dynamic "metric_query" {
    for_each = { bounce = "Reputation.BounceRate", complaint = "Reputation.ComplaintRate" }

    content {
      id = metric_query.key

      metric {
        namespace   = "AWS/SES"
        metric_name = metric_query.value
        stat        = "Maximum"
        period      = 3600
      }
    }
  }

  alarm_actions = local.notify.page
  ok_actions    = local.notify.page

  tags = { component = "alarms" }
}
