# The NAT gateways under the egress proxy (ADR-0021). Only the `system` nodes route to them, so their faults show as
# sign-in code exchanges, Cognito admin calls, Argo CD syncs and signature updates failing. The proxy's own health is
# Prometheus's (deploy/alerts). Tickets: what goes out through NAT retries, and nothing user-facing but sign-in depends
# on it.

data "aws_nat_gateways" "this" {
  vpc_id = var.vpc_id

  filter {
    name   = "state"
    values = ["available"]
  }
}

resource "aws_cloudwatch_metric_alarm" "nat_port_allocation" {
  for_each = toset(data.aws_nat_gateways.this.ids)

  alarm_name        = "${var.name_prefix}-nat-${each.key}-port-allocation"
  alarm_description = "NAT gateway ${each.key} couldn't allocate a source port: outbound connections through the egress proxy are failing (ADR-0021). Severity: ticket. Runbook: https://github.com/codewithmuh/secure-file-transfer/blob/main/docs/runbooks/nat-gateway.md"

  namespace   = "AWS/NATGateway"
  metric_name = "ErrorPortAllocation"
  dimensions  = { NatGatewayId = each.key }
  statistic   = "Sum"
  period      = 300

  comparison_operator = "GreaterThanThreshold"
  threshold           = 0
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions = local.notify.ticket
  ok_actions    = local.notify.ticket

  tags = { component = "alarms" }
}

# AWS's recommended alarm: drops above 0.01 % of the gateway's packets.
resource "aws_cloudwatch_metric_alarm" "nat_packet_drops" {
  for_each = toset(data.aws_nat_gateways.this.ids)

  alarm_name        = "${var.name_prefix}-nat-${each.key}-packet-drops"
  alarm_description = "NAT gateway ${each.key} dropped more than 0.01 % of its packets for 15 minutes (ADR-0021). Severity: ticket. Runbook: https://github.com/codewithmuh/secure-file-transfer/blob/main/docs/runbooks/nat-gateway.md"

  comparison_operator = "GreaterThanThreshold"
  threshold           = 0.01
  evaluation_periods  = 3
  datapoints_to_alarm = 3
  treat_missing_data  = "notBreaching"

  metric_query {
    id          = "drops"
    expression  = "100 * dropped / (from_source + from_destination)"
    label       = "Dropped packets (%)"
    return_data = true
  }

  dynamic "metric_query" {
    for_each = {
      dropped          = "PacketsDropCount"
      from_source      = "PacketsInFromSource"
      from_destination = "PacketsInFromDestination"
    }

    content {
      id = metric_query.key

      metric {
        namespace   = "AWS/NATGateway"
        metric_name = metric_query.value
        dimensions  = { NatGatewayId = each.key }
        stat        = "Sum"
        period      = 300
      }
    }
  }

  alarm_actions = local.notify.ticket
  ok_actions    = local.notify.ticket

  tags = { component = "alarms" }
}
