# Route 53 Resolver DNS Firewall (ADR-0021, T-53): the VPC's resolver answers only allowed names and returns NXDOMAIN
# for everything else, which also stops DNS tunnelling. If DNS Firewall itself fails, queries fail too (fail closed).
#
# Every query from the VPC reaches the resolver: CoreDNS forwards to it, and no node or pod can send DNS anywhere
# else (security-groups.tf: only the system nodes leave the VPC, and only on 443). The allowed names are the VPC
# endpoints' own (endpoints.tf), S3 in this Region (gateway endpoint), and var.dns_firewall_allowed_domains: the cluster
# API, EC2 host names, and what the egress proxy and the system nodes' host processes reach through NAT; and the API's
# and the web app's own names, which the synthetic probe calls from inside (#259). The proxy's per-workload allowlists
# are narrower still.

locals {
  dns_allowed_domains = sort(distinct(concat(
    flatten([for e in local.interface_endpoints : e.dns_names]),
    # S3 in this Region, through the gateway endpoint: path-style and virtual-hosted names, ECR's layer bucket included.
    ["s3.${var.region}.amazonaws.com", "*.s3.${var.region}.amazonaws.com"],
    [
      for d in concat(var.dns_firewall_allowed_domains, var.dns_firewall_additional_domains) :
      replace(d, "{region}", var.region)
    ],
    # The synthetic probe reaches the API and the web app by their public names, through the egress proxy (#248, #259).
    var.service_domain == null ? [] : ["api.${var.service_domain}", "app.${var.service_domain}"],
  )))
}

resource "aws_route53_resolver_firewall_domain_list" "allowed" {
  name    = "${var.name_prefix}-dns-allowed"
  domains = local.dns_allowed_domains

  tags = {
    Name      = "${var.name_prefix}-dns-allowed"
    component = "dns-firewall"
  }
}

resource "aws_route53_resolver_firewall_domain_list" "everything" {
  name    = "${var.name_prefix}-dns-everything"
  domains = ["*"]

  tags = {
    Name      = "${var.name_prefix}-dns-everything"
    component = "dns-firewall"
  }
}

resource "aws_route53_resolver_firewall_rule_group" "allowlist" {
  name = "${var.name_prefix}-dns-allowlist"

  tags = {
    Name      = "${var.name_prefix}-dns-allowlist"
    component = "dns-firewall"
  }
}

# Allowed names, and the CNAME and DNAME targets they lead to. The owner of an allowed name (AWS, GitHub, ClamAV's CDN)
# chooses its targets, which change without notice (database.clamav.net and S3's bucket names are CNAMEs), so they
# are trusted rather than listed; a pod still can't choose them.
resource "aws_route53_resolver_firewall_rule" "allow" {
  name                               = "allow-listed-names"
  firewall_rule_group_id             = aws_route53_resolver_firewall_rule_group.allowlist.id
  firewall_domain_list_id            = aws_route53_resolver_firewall_domain_list.allowed.id
  priority                           = 100
  action                             = "ALLOW"
  firewall_domain_redirection_action = "TRUST_REDIRECTION_DOMAIN"
}

resource "aws_route53_resolver_firewall_rule" "block_everything_else" {
  name                    = "block-everything-else"
  firewall_rule_group_id  = aws_route53_resolver_firewall_rule_group.allowlist.id
  firewall_domain_list_id = aws_route53_resolver_firewall_domain_list.everything.id
  priority                = 200
  action                  = "BLOCK"
  block_response          = "NXDOMAIN"
}

resource "aws_route53_resolver_firewall_rule_group_association" "this" {
  name                   = "${var.name_prefix}-dns-allowlist"
  firewall_rule_group_id = aws_route53_resolver_firewall_rule_group.allowlist.id
  vpc_id                 = aws_vpc.this.id
  priority               = 101

  tags = {
    Name      = "${var.name_prefix}-dns-allowlist"
    component = "dns-firewall"
  }

  # Both rules first, so the VPC never has the group without its block rule.
  depends_on = [
    aws_route53_resolver_firewall_rule.allow,
    aws_route53_resolver_firewall_rule.block_everything_else,
  ]
}

resource "aws_route53_resolver_firewall_config" "this" {
  resource_id        = aws_vpc.this.id
  firewall_fail_open = "DISABLED"
}
