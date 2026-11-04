# One VPC per account and Region (ADR-0021), from the same code in Tokyo and Osaka (T-79): subnets, route tables, the
# internet and NAT gateways, and the VPC flow log. The VPC endpoints are in endpoints.tf, the security groups in
# security-groups.tf and Route 53 Resolver DNS Firewall in dns-firewall.tf.
#
# Per AZ (ADR-0021):
#   public    /24  the load balancer and the NAT gateway; routes to the internet gateway
#   private   /19  nodes, pods and the Cognito trigger functions; routes to the NAT gateway and the S3 gateway endpoint,
#                  but only the system nodes' security group lets anything out to NAT (security-groups.tf)
#   endpoints /26  only the interface endpoints and the cluster API's network interfaces; no route out
#   isolated  /24  Aurora and Valkey; no route out
#
# Each subnet's range follows from its AZ ID's number, not its place in the list, so dev's two AZs have the same ranges
# as the same AZs in a three-AZ VPC, and adding or removing an AZ moves no other subnet. With N = AZ number - 1:
#   private   10.x.(32 * N).0/19   N = 0..3 fills 10.x.0.0/17; the rest of the /16 holds everything else
#   public    10.x.(128 + N).0/24
#   isolated  10.x.(136 + N).0/24
#   endpoints 10.x.144.(64 * N)/26, so all of them sit in 10.x.144.0/24

locals {
  az_ids = toset(var.availability_zone_ids)

  # apne1-az4 -> 3: the subnet number inside each tier's block.
  az_number = { for id in var.availability_zone_ids : id => tonumber(regex("-az([0-9]+)$", id)[0]) - 1 }

  private_cidrs  = { for id, n in local.az_number : id => cidrsubnet(var.vpc_cidr_block, 3, n) }
  public_cidrs   = { for id, n in local.az_number : id => cidrsubnet(var.vpc_cidr_block, 8, 128 + n) }
  isolated_cidrs = { for id, n in local.az_number : id => cidrsubnet(var.vpc_cidr_block, 8, 136 + n) }
  endpoint_cidrs = { for id, n in local.az_number : id => cidrsubnet(var.vpc_cidr_block, 10, 576 + n) }

  # dev: one NAT gateway, whose AZ every private subnet uses (capacity 5.3). Elsewhere one per AZ, each used by its own
  # AZ, so losing an AZ never cuts another AZ's egress (NFR-11).
  nat_az_ids = toset(coalesce(var.nat_gateway_availability_zone_ids, var.availability_zone_ids))
  nat_for_az = {
    for id in var.availability_zone_ids :
    id => contains(local.nat_az_ids, id) ? id : sort(local.nat_az_ids)[0]
  }

  # VPC flow log records with the fields that show where traffic really went (T-53): the address behind NAT
  # (pkt-srcaddr, pkt-dstaddr), the path out (traffic-path: 8 = internet gateway, through NAT) and the AWS service.
  flow_log_format = join(" ", [for f in [
    "version", "account-id", "vpc-id", "subnet-id", "instance-id", "interface-id", "az-id", "flow-direction",
    "srcaddr", "dstaddr", "srcport", "dstport", "protocol", "pkt-srcaddr", "pkt-dstaddr", "pkt-src-aws-service",
    "pkt-dst-aws-service", "traffic-path", "packets", "bytes", "start", "end", "action", "tcp-flags", "log-status",
  ] : "$${${f}}"])
}

resource "aws_vpc" "this" {
  cidr_block = var.vpc_cidr_block

  # Both are needed for the interface endpoints' private DNS and the cluster's private API endpoint.
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "${var.name_prefix}-vpc"
  }
}

# The VPC's default security group, route table and network ACL exist whatever we do. The first two are adopted and
# emptied, so anything created without naming its own gets no traffic and no route out. The default network ACL stays
# open: security groups and routes do the filtering (ADR-0021), and a stateless ACL would add rules to keep in step.
# AWS creates them untagged; their tags, with the provider's default tags (managed-by, project), mark them on the
# first apply. The deploy role changes them only with actions that need no tag, and never deletes them
# (terraform-oidc-roles).
resource "aws_default_security_group" "this" {
  vpc_id = aws_vpc.this.id

  tags = {
    Name = "${var.name_prefix}-default-unused"
  }
}

resource "aws_default_route_table" "this" {
  default_route_table_id = aws_vpc.this.default_route_table_id
  route                  = []

  tags = {
    Name = "${var.name_prefix}-default-unused"
  }
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id

  tags = {
    Name = "${var.name_prefix}-igw"
  }
}

# ---------------------------------------------------------------------------------------------------------------------
# Subnets
# ---------------------------------------------------------------------------------------------------------------------

resource "aws_subnet" "public" {
  for_each = local.az_ids

  vpc_id               = aws_vpc.this.id
  availability_zone_id = each.key
  cidr_block           = local.public_cidrs[each.key]

  # Nothing here needs an address at launch: the NAT gateways have Elastic IPs and the load balancer its own.
  map_public_ip_on_launch = false

  tags = {
    Name = "${var.name_prefix}-public-${each.key}"
    tier = "public"
    # The AWS Load Balancer Controller finds internet-facing subnets by this tag.
    "kubernetes.io/role/elb" = "1"
  }
}

resource "aws_subnet" "private" {
  for_each = local.az_ids

  vpc_id               = aws_vpc.this.id
  availability_zone_id = each.key
  cidr_block           = local.private_cidrs[each.key]

  tags = {
    Name = "${var.name_prefix}-private-${each.key}"
    tier = "private"
    # Karpenter's EC2NodeClass selects node subnets by this tag. The value is the VPC's name prefix, not the cluster's
    # name, so this stack doesn't fix a name the cluster stack owns; there is one cluster per VPC.
    "karpenter.sh/discovery" = var.name_prefix
  }
}

resource "aws_subnet" "endpoints" {
  for_each = local.az_ids

  vpc_id               = aws_vpc.this.id
  availability_zone_id = each.key
  cidr_block           = local.endpoint_cidrs[each.key]

  tags = {
    Name = "${var.name_prefix}-endpoints-${each.key}"
    tier = "endpoints"
  }
}

resource "aws_subnet" "isolated" {
  for_each = local.az_ids

  vpc_id               = aws_vpc.this.id
  availability_zone_id = each.key
  cidr_block           = local.isolated_cidrs[each.key]

  tags = {
    Name = "${var.name_prefix}-isolated-${each.key}"
    tier = "isolated"
  }
}

# ---------------------------------------------------------------------------------------------------------------------
# NAT gateways: reached only by the egress proxy and the system nodes' host processes (ADR-0021)
# ---------------------------------------------------------------------------------------------------------------------

resource "aws_eip" "nat" {
  for_each = local.nat_az_ids

  domain = "vpc"

  tags = {
    Name      = "${var.name_prefix}-nat-${each.key}"
    component = "nat"
  }

  depends_on = [aws_internet_gateway.this]
}

resource "aws_nat_gateway" "this" {
  for_each = local.nat_az_ids

  connectivity_type = "public"
  allocation_id     = aws_eip.nat[each.key].allocation_id
  subnet_id         = aws_subnet.public[each.key].id

  tags = {
    Name      = "${var.name_prefix}-nat-${each.key}"
    component = "nat"
  }

  depends_on = [aws_internet_gateway.this]
}

# ---------------------------------------------------------------------------------------------------------------------
# Route tables. Routes are separate resources, never inline blocks, so they don't fight the S3 gateway endpoint's
# managed routes.
# ---------------------------------------------------------------------------------------------------------------------

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id

  tags = {
    Name = "${var.name_prefix}-public"
    tier = "public"
  }
}

resource "aws_route" "public_internet" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.this.id
}

resource "aws_route_table_association" "public" {
  for_each = aws_subnet.public

  subnet_id      = each.value.id
  route_table_id = aws_route_table.public.id
}

# One per AZ, so each AZ uses its own NAT gateway. The S3 gateway endpoint adds its prefix-list route (endpoints.tf).
resource "aws_route_table" "private" {
  for_each = local.az_ids

  vpc_id = aws_vpc.this.id

  tags = {
    Name = "${var.name_prefix}-private-${each.key}"
    tier = "private"
  }
}

resource "aws_route" "private_nat" {
  for_each = aws_route_table.private

  route_table_id         = each.value.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.this[local.nat_for_az[each.key]].id
}

resource "aws_route_table_association" "private" {
  for_each = aws_subnet.private

  subnet_id      = each.value.id
  route_table_id = aws_route_table.private[each.key].id
}

# The endpoint and isolated subnets have only the VPC's local route: nothing in them starts a connection outside the
# VPC. Each has its own table, so a route added to one tier can't reach the other.
resource "aws_route_table" "endpoints" {
  vpc_id = aws_vpc.this.id

  tags = {
    Name = "${var.name_prefix}-endpoints"
    tier = "endpoints"
  }
}

resource "aws_route_table_association" "endpoints" {
  for_each = aws_subnet.endpoints

  subnet_id      = each.value.id
  route_table_id = aws_route_table.endpoints.id
}

resource "aws_route_table" "isolated" {
  vpc_id = aws_vpc.this.id

  tags = {
    Name = "${var.name_prefix}-isolated"
    tier = "isolated"
  }
}

resource "aws_route_table_association" "isolated" {
  for_each = aws_subnet.isolated

  subnet_id      = each.value.id
  route_table_id = aws_route_table.isolated.id
}

# ---------------------------------------------------------------------------------------------------------------------
# VPC flow log: all traffic to the environment's log bucket (capacity A19, T-53)
# ---------------------------------------------------------------------------------------------------------------------

# The bucket and its logs key belong to the data layer, which is applied after this one, so the flow log starts with
# the second network apply of a fresh build (infra/README.md, "Apply order"). The bucket policy must let
# delivery.logs.amazonaws.com write under <prefix>/AWSLogs/aws-account-id=<account>/ for this account, and the logs key
# must let it encrypt (encryption 3.1).
resource "aws_flow_log" "this" {
  count = var.flow_log_destination_arn == null ? 0 : 1

  vpc_id               = aws_vpc.this.id
  traffic_type         = "ALL"
  log_destination_type = "s3"
  log_destination      = var.flow_log_destination_arn
  log_format           = local.flow_log_format

  destination_options {
    file_format                = "parquet"
    hive_compatible_partitions = true
    per_hour_partition         = true
  }

  tags = {
    Name      = "${var.name_prefix}-flow-log"
    component = "flow-logs"
  }
}
