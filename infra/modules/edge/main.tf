# One environment's edge in one Region (ADR-0021, ADR-0008, abuse 2 and 3, encryption 2.1): what the internet reaches
# first. The same module builds Tokyo and Osaka (T-79).
#
# - The API's Application Load Balancer, IPv4 only, with one HTTPS listener. The AWS Load Balancer Controller
#   registers the API pods in its target group through a TargetGroupBinding (#106); Terraform, not the controller,
#   owns the load balancer, so its records, web ACL and teardown stay in this stack.
# - The listener answers a fixed health response itself, with no targets, for the Route 53 health check, which is for
#   alarms only: it shows whether this Region's edge answers, and Osaka's passes during the pilot light.
# - The API and sign-in web ACLs (abuse 3.1, 3.2) and their logs.
# - The load balancer's certificate and its records in the shared zone, written through the environment's DNS role.
# - Where asked, this Region's web bundle bucket, which only the CloudFront distribution reads.

data "aws_region" "current" {}

locals {
  region             = data.aws_region.current.region
  bucket_name_format = "${var.name_prefix}-%s-${var.account_id}"

  zone_name      = "sft.${var.domain}"
  service_domain = var.environment == "prod" ? local.zone_name : "${var.environment}.${local.zone_name}"

  # The API's name, which the failover runbook moves (T-78), and this Region's own name, which the health check and
  # drills use. Both are on the certificate, so either Region can take the API's name.
  api_name          = "api.${local.service_domain}"
  regional_api_name = "api-${var.region_short}.${local.service_domain}"

  waf_log_bucket = "aws-waf-logs-${var.name_prefix}-${var.account_id}"
  lb_log_bucket  = format(local.bucket_name_format, "lb-logs")
  web_bucket     = format(local.bucket_name_format, "web")

  # The legacy Elastic Load Balancing account of each Region that predates the service principal; both are named.
  elb_log_accounts = {
    "ap-northeast-1" = "582318560864" # aws-owned-account: Elastic Load Balancing, Tokyo
    "ap-northeast-3" = "383597477331" # aws-owned-account: Elastic Load Balancing, Osaka
  }
}

# --- What other layers made --------------------------------------------------------------------------------------

data "aws_vpc" "this" {
  tags = {
    Name = "${var.name_prefix}-vpc"
  }
}

data "aws_subnets" "public" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.this.id]
  }

  tags = {
    tier = "public"
  }
}

data "aws_security_group" "main_nodes" {
  vpc_id = data.aws_vpc.this.id
  name   = "${var.name_prefix}-main-nodes"
}

# The NAT gateways' addresses, for the sign-in web ACL's token rule (abuse 3.2).
data "aws_eips" "nat" {
  filter {
    name   = "tag:Name"
    values = ["${var.name_prefix}-nat-*"]
  }
}

data "aws_kms_alias" "logs" {
  name = "${var.kms_alias_prefix}/logs"
}

data "aws_route53_zone" "this" {
  provider = aws.dns

  name         = local.zone_name
  private_zone = false
}
