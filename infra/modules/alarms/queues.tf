# SQS (ADR-0013, "Alerts"): any message in a dead-letter queue, and the age of the oldest message per queue.
#
# The scan-small, scan-large and guardduty-results dead-letter queues are left to the in-cluster ScanFailed alert
# (deploy/alerts/scanning.rules.yaml), which already pages on them through the CloudWatch exporter; alarming here too
# would page twice. If the cluster is dead, the heartbeat alarm pages instead.
#
# Osaka's queues are idle during the pilot light: SQS publishes no metrics for an idle queue, and missing data doesn't
# breach, so they stay quiet until a failover uses them. A message in an Osaka dead-letter queue is still a page.

locals {
  dead_letter_alarm_queues = toset(["notify", "signin-events", "ses-events", "ses-tenant-status"])

  # The oldest message's age, in seconds, past which a queue's consumer is behind, held for `minutes`:
  # - signin-events: authentication 2.4, "an alarm fires when a queued event is more than 30 seconds old" (NFR-15's
  #   60 seconds to the audit log).
  # - notify: NFR-7 hands emails to SES within 10 s at p95; a minute-old message means codes are late for everyone.
  # - scan-small: NFR-5's 2 minutes for files up to 100 MB; 5 minutes waiting means the target is lost.
  # - scan-large: NFR-5's 15 minutes for the largest transfers; a ticket, since one large scan can hold the queue.
  # - ses-events, guardduty-results: bounces and large-file results that wait 10 minutes are late, not lost.
  # ses-tenant-status has no consumer yet (abuse 7.3), so its age would always breach; its dead-letter queue is enough.
  queue_age = {
    "signin-events"     = { seconds = 30, minutes = 3, severity = "page" }
    "notify"            = { seconds = 60, minutes = 5, severity = "page" }
    "scan-small"        = { seconds = 300, minutes = 10, severity = "page" }
    "scan-large"        = { seconds = 900, minutes = 15, severity = "ticket" }
    "ses-events"        = { seconds = 600, minutes = 15, severity = "ticket" }
    "guardduty-results" = { seconds = 600, minutes = 15, severity = "ticket" }
  }
}

resource "aws_cloudwatch_metric_alarm" "dead_letter" {
  for_each = local.dead_letter_alarm_queues

  alarm_name        = "${var.name_prefix}-${each.key}-dlq"
  alarm_description = "A message is in ${var.name_prefix}-${each.key}-dlq: its consumer failed it on every attempt (ADR-0013). Severity: page. Runbook: https://github.com/codewithmuh/secure-file-transfer/blob/main/docs/runbooks/dead-letter-queue.md"

  namespace   = "AWS/SQS"
  metric_name = "ApproximateNumberOfMessagesVisible"
  dimensions  = { QueueName = "${var.name_prefix}-${each.key}-dlq" }
  statistic   = "Maximum"
  period      = 300

  comparison_operator = "GreaterThanThreshold"
  threshold           = 0
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions = local.notify.page
  ok_actions    = local.notify.page

  tags = { component = "alarms" }
}

resource "aws_cloudwatch_metric_alarm" "queue_age" {
  for_each = local.queue_age

  alarm_name        = "${var.name_prefix}-${each.key}-age"
  alarm_description = "The oldest message in ${var.name_prefix}-${each.key} is over ${each.value.seconds} s old for ${each.value.minutes} minutes: its consumer is behind (ADR-0013). Severity: ${each.value.severity}. Runbook: https://github.com/codewithmuh/secure-file-transfer/blob/main/docs/runbooks/queue-backlog.md"

  namespace   = "AWS/SQS"
  metric_name = "ApproximateAgeOfOldestMessage"
  dimensions  = { QueueName = "${var.name_prefix}-${each.key}" }
  statistic   = "Maximum"
  period      = 60

  comparison_operator = "GreaterThanThreshold"
  threshold           = each.value.seconds
  evaluation_periods  = each.value.minutes
  datapoints_to_alarm = each.value.minutes
  treat_missing_data  = "notBreaching"

  alarm_actions = local.notify[each.value.severity]
  ok_actions    = local.notify[each.value.severity]

  tags = { component = "alarms" }
}
