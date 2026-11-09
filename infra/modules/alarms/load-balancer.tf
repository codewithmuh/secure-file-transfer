# The API's load balancer (modules/edge). The application's own error and latency budgets are Prometheus's burn-rate
# alerts (deploy/alerts); these catch what never reaches a pod: the load balancer answering 5xx itself, and no healthy
# target behind it.
#
# In Osaka's pilot light the target group is empty by design, so the target alarm exists but doesn't notify until the
# failover applies this stack with TF_VAR_pilot_light=false. The load balancer still answers its fixed health-check
# response there (ADR-0021), so its own 5xx alarm stays on.

locals {
  # CloudWatch's dimensions are the ARNs' suffixes: app/<name>/<id> and targetgroup/<name>/<id>.
  load_balancer_dimension = element(split(":loadbalancer/", var.load_balancer_arn), 1)
  target_group_dimension  = "targetgroup/${element(split(":targetgroup/", var.api_target_group_arn), 1)}"
}

resource "aws_cloudwatch_metric_alarm" "load_balancer_5xx" {
  alarm_name        = "${var.name_prefix}-api-lb-5xx"
  alarm_description = "The API's load balancer answered more than 10 5xx of its own a minute for 5 minutes: requests aren't reaching the API (NFR-1). Severity: page. Runbook: https://github.com/codewithmuh/secure-file-transfer/blob/main/docs/runbooks/service-unavailable.md"

  namespace   = "AWS/ApplicationELB"
  metric_name = "HTTPCode_ELB_5XX_Count"
  dimensions  = { LoadBalancer = local.load_balancer_dimension }
  statistic   = "Sum"
  period      = 60

  comparison_operator = "GreaterThanThreshold"
  threshold           = 10
  evaluation_periods  = 5
  datapoints_to_alarm = 5
  treat_missing_data  = "notBreaching"

  alarm_actions = local.notify.page
  ok_actions    = local.notify.page

  tags = { component = "alarms" }
}

resource "aws_cloudwatch_metric_alarm" "api_targets" {
  alarm_name        = "${var.name_prefix}-api-no-healthy-targets"
  alarm_description = "The API's target group has had no healthy target for 3 minutes: the API is down in this Region (NFR-1). Severity: page. Runbook: https://github.com/codewithmuh/secure-file-transfer/blob/main/docs/runbooks/service-unavailable.md"

  namespace   = "AWS/ApplicationELB"
  metric_name = "HealthyHostCount"
  dimensions = {
    LoadBalancer = local.load_balancer_dimension
    TargetGroup  = local.target_group_dimension
  }
  statistic = "Minimum"
  period    = 60

  comparison_operator = "LessThanThreshold"
  threshold           = 1
  evaluation_periods  = 3
  datapoints_to_alarm = 3
  # No data at all means no targets were ever registered, which is the same outage.
  treat_missing_data = "breaching"

  actions_enabled = !var.pilot_light
  alarm_actions   = local.notify.page
  ok_actions      = local.notify.page

  tags = { component = "alarms" }
}
