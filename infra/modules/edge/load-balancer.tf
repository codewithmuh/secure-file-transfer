# The API's load balancer (encryption 2.1, abuse 2.1 and 3.3, architecture 8).

resource "aws_security_group" "load_balancer" {
  name        = "${var.name_prefix}-api-lb"
  description = "API load balancer: HTTPS from anywhere, out only to the API pods on the main nodes"
  vpc_id      = data.aws_vpc.this.id

  tags = {
    Name = "${var.name_prefix}-api-lb"
  }
}

# The API is public: recipients and uploaders may be anywhere (abuse 3.2, rule 10). The web ACL, not the security
# group, decides who gets through.
resource "aws_vpc_security_group_ingress_rule" "load_balancer_https" {
  security_group_id = aws_security_group.load_balancer.id
  description       = "HTTPS from the internet: the API's one listener"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_vpc_security_group_egress_rule" "load_balancer_to_api" {
  for_each = { public = var.api_public_port, internal = var.api_internal_port }

  security_group_id            = aws_security_group.load_balancer.id
  description                  = "To the API pods on the main nodes: the ${each.key} port"
  ip_protocol                  = "tcp"
  from_port                    = each.value
  to_port                      = each.value
  referenced_security_group_id = data.aws_security_group.main_nodes.id
}

# The rule the network module leaves to this stack: the load balancer reaches the main nodes' pods, and only on the
# API's two ports. Never the scan nodes, which hold hostile files (ADR-0021).
resource "aws_vpc_security_group_ingress_rule" "main_nodes_from_load_balancer" {
  for_each = { public = var.api_public_port, internal = var.api_internal_port }

  security_group_id            = data.aws_security_group.main_nodes.id
  description                  = "From the API load balancer: the API's ${each.key} port"
  ip_protocol                  = "tcp"
  from_port                    = each.value
  to_port                      = each.value
  referenced_security_group_id = aws_security_group.load_balancer.id
}

resource "aws_lb" "api" {
  name               = "${var.name_prefix}-api"
  load_balancer_type = "application"
  internal           = false
  ip_address_type    = "ipv4"
  subnets            = data.aws_subnets.public.ids
  security_groups    = [aws_security_group.load_balancer.id]

  # 60 s closes a download stream that sends nothing (abuse 5.7). Invalid header fields are dropped and HTTP desync
  # mitigation runs in its strictest mode (abuse 3.3). If WAF can't be reached, requests fail rather than pass.
  idle_timeout               = 60
  drop_invalid_header_fields = true
  desync_mitigation_mode     = "strictest"
  enable_waf_fail_open       = false
  xff_header_processing_mode = "append"
  enable_deletion_protection = var.deletion_protection

  access_logs {
    bucket  = aws_s3_bucket.lb_logs.id
    enabled = true
  }

  depends_on = [aws_s3_bucket_policy.lb_logs]
}

# IP targets: the controller registers API pods directly (#106). The public port serves TLS with a certificate each
# pod makes at start, so the hop is encrypted (encryption 2.1). The health check uses /readyz on the internal port,
# which no listener routes; it carries no customer data, so it is plain HTTP inside the VPC.
resource "aws_lb_target_group" "api" {
  name        = "${var.name_prefix}-api"
  target_type = "ip"
  protocol    = "HTTPS"
  port        = var.api_public_port
  vpc_id      = data.aws_vpc.this.id

  # Longer than the 120 s stream drain, inside the pods' 150 s grace period (architecture 8, abuse 5.7).
  deregistration_delay = 130

  health_check {
    protocol            = "HTTP"
    port                = tostring(var.api_internal_port)
    path                = "/readyz"
    matcher             = "200"
    interval            = 10
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.api.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = var.tls_policy
  certificate_arn   = aws_acm_certificate_validation.api.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.api.arn
  }
}

# Answered by the load balancer itself, with no targets: the health checks' probe (ADR-0021). The API has no public
# health route.
resource "aws_lb_listener_rule" "edge_health" {
  listener_arn = aws_lb_listener.https.arn
  priority     = 1

  condition {
    path_pattern {
      values = [var.health_check_path]
    }
  }

  action {
    type = "fixed-response"

    fixed_response {
      content_type = "text/plain"
      message_body = var.health_check_body
      status_code  = "200"
    }
  }
}

resource "aws_route53_health_check" "edge" {
  fqdn              = local.regional_api_name
  type              = "HTTPS_STR_MATCH"
  port              = 443
  resource_path     = var.health_check_path
  search_string     = var.health_check_body
  enable_sni        = true
  request_interval  = 30
  failure_threshold = 3
  measure_latency   = false

  tags = {
    Name = "${var.name_prefix}-edge"
  }

  depends_on = [aws_route53_record.regional_api]
}
