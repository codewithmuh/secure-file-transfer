# KMS throttling. Every upload, download, queue message and sealed field uses the Region's keys (encryption 4), and
# the symmetric cryptographic operations share one request quota per account and Region. KMS publishes no throttle
# count of its own, so this watches usage against the quota (AWS/Usage and SERVICE_QUOTA): above 80 % for 5 minutes is
# a ticket, before requests are throttled and retried.

resource "aws_cloudwatch_metric_alarm" "kms_quota" {
  alarm_name        = "${var.name_prefix}-kms-quota"
  alarm_description = "KMS symmetric requests have used more than 80 % of the account's quota in this Region for 5 minutes; throttling is next (encryption 4). Severity: ticket. Runbook: https://github.com/codewithmuh/secure-file-transfer/blob/main/docs/runbooks/kms-throttling.md"

  comparison_operator = "GreaterThanThreshold"
  threshold           = 80
  evaluation_periods  = 5
  datapoints_to_alarm = 5
  treat_missing_data  = "notBreaching"

  metric_query {
    id          = "usage"
    expression  = "100 * calls / PERIOD(calls) / SERVICE_QUOTA(calls)"
    label       = "KMS symmetric requests (% of quota)"
    return_data = true
  }

  metric_query {
    id = "calls"

    metric {
      namespace   = "AWS/Usage"
      metric_name = "CallCount"
      dimensions = {
        Service  = "KMS"
        Type     = "API"
        Resource = "CryptographicOperationsSymmetric"
        Class    = "None"
      }
      stat   = "Sum"
      period = 60
    }
  }

  alarm_actions = local.notify.ticket
  ok_actions    = local.notify.ticket

  tags = { component = "alarms" }
}
