# The AWS-side alarms of ADR-0009 (A34): what CloudWatch watches so that a dead cluster, or a fault in an AWS service
# that Prometheus can't see well, still pages. Prometheus's rules (deploy/alerts) watch the application; these watch
# the AWS services under it, the out-of-cluster watchdog and the Regions' health. One stack per Region, the `alarms`
# layer, applied last (infra/README.md).
#
# Every alarm is sft-<env>-<region-short>-<what>, which the platform key's policy and SCP 3 both match, and names its
# runbook in its description as a literal URL, which deploy/tests/test_runbooks.py checks (NFR-17). Pages go to the
# Region's page topic, tickets to its ticket topic; both notify again when the alarm clears.

locals {
  # Alertmanager's Pod Identity role (deploy/observability, #243), which publishes the in-cluster alerts and the
  # heartbeat (ADR-0009). Matched by name, since it may not exist when this stack is applied.
  alertmanager_role_arn = "arn:aws:iam::${var.account_id}:role/sft-${var.environment}-alertmanager"

  # Notification targets by severity.
  notify = {
    page   = [aws_sns_topic.this["alerts-page"].arn]
    ticket = [aws_sns_topic.this["alerts-ticket"].arn]
  }
}
