# The synthetic probe's watchdog (NFR-1, #248). The probe (sft.probe, a CronJob every 5 minutes) puts ProbeSuccess, 1 or
# 0, in SecureFileTransfer/Probe with the dimension Environment, in the Region it runs in. Two 5-minute periods without
# a 1 page: a failed journey, and a probe that stopped running (missing data breaches), look the same. The in-cluster
# SyntheticProbeFailing and SyntheticProbeStale alerts say the same from Prometheus; this one still fires when the
# cluster's own alerting is down.
#
# Created only once the environment's probe runs (probe_enabled, with probe.enabled in the cluster's values file):
# before that, missing data would page for good. Silent in Osaka during the pilot light, where the probe is suspended.

resource "aws_cloudwatch_metric_alarm" "probe_failing" {
  count = var.probe_enabled ? 1 : 0

  alarm_name        = "${var.name_prefix}-probe-failing"
  alarm_description = "The synthetic probe's send, verify and download journey hasn't passed for 10 minutes, or the probe isn't running (NFR-1). Severity: page. Runbook: https://github.com/codewithmuh/secure-file-transfer/blob/main/docs/runbooks/synthetic-probe.md"

  namespace   = "SecureFileTransfer/Probe"
  metric_name = "ProbeSuccess"
  dimensions  = { Environment = var.environment }
  statistic   = "Minimum"
  period      = 300

  comparison_operator = "LessThanThreshold"
  threshold           = 1
  evaluation_periods  = 2
  datapoints_to_alarm = 2
  treat_missing_data  = "breaching"

  actions_enabled = !var.pilot_light
  alarm_actions   = local.notify.page
  ok_actions      = local.notify.page

  tags = { component = "alarms" }
}
