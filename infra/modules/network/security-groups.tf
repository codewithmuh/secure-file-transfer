# Security groups that make the network's perimeter (ADR-0021). They live here, not with the cluster, because the
# perimeter is the network's design, and because the data layer, applied before the cluster, admits the node groups to
# Aurora and Valkey by these groups. The cluster stack attaches them; the edge stack adds the load balancer's rule to
# main_nodes; neither changes the egress rules here.
#
#   endpoints     interface endpoints: HTTPS in from the private subnets, nothing out
#   cluster_api   the cluster API's network interfaces (an additional cluster security group): HTTPS in from the
#                 nodes, which includes the system node that ends the Systems Manager tunnel; out to the nodes'
#                 kubelets and webhooks
#   nodes         every node, all three pools: traffic between nodes and pods, and from the cluster API. Network
#                 policies narrow it per workload (ADR-0021). No egress rules: each pool's own group has those.
#   system_nodes  the system node group: anything inside the VPC, and HTTPS to anywhere, which is how the egress proxy
#                 and the Systems Manager agent reach NAT. Nothing else in the VPC may leave it.
#   main_nodes    the main node pool: anything inside the VPC, and HTTPS to S3 through the gateway endpoint only
#   scan_nodes    the scan node pool: the same as main_nodes, in its own group so nothing that admits the API's nodes
#                 (the load balancer) admits the nodes that hold hostile files
#
# EKS also creates its own cluster security group, which allows all egress. The cluster stack must give the nodes only
# the groups above (a launch template for the system node group, which otherwise gets EKS's group), or a node would
# have a way out that this design closes.

resource "aws_security_group" "endpoints" {
  name        = "${var.name_prefix}-endpoints"
  description = "Interface VPC endpoints: HTTPS from the private subnets only (ADR-0021)"
  vpc_id      = aws_vpc.this.id

  tags = {
    Name = "${var.name_prefix}-endpoints"
  }
}

resource "aws_vpc_security_group_ingress_rule" "endpoints_https_from_private" {
  for_each = aws_subnet.private

  security_group_id = aws_security_group.endpoints.id
  description       = "HTTPS from the private subnet in ${each.key}: nodes, pods and trigger functions"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = each.value.cidr_block
}

resource "aws_security_group" "cluster_api" {
  name        = "${var.name_prefix}-cluster-api"
  description = "EKS private API endpoint: HTTPS from the nodes and the Systems Manager tunnel (ADR-0021)"
  vpc_id      = aws_vpc.this.id

  tags = {
    Name = "${var.name_prefix}-cluster-api"
  }
}

resource "aws_security_group" "nodes" {
  name        = "${var.name_prefix}-nodes"
  description = "Every EKS node: node-to-node and pod traffic, and calls from the cluster API to kubelets and webhooks"
  vpc_id      = aws_vpc.this.id

  tags = {
    Name = "${var.name_prefix}-nodes"
  }
}

resource "aws_security_group" "pool" {
  for_each = {
    system_nodes = "EKS system node group: the VPC, and HTTPS out through NAT for the egress proxy and SSM agent"
    main_nodes   = "EKS main node pool: the VPC, and HTTPS to S3 through the gateway endpoint only (ADR-0021)"
    scan_nodes   = "EKS scan node pool: the VPC, and HTTPS to S3 through the gateway endpoint only (ADR-0021)"
  }

  name        = "${var.name_prefix}-${replace(each.key, "_", "-")}"
  description = each.value
  vpc_id      = aws_vpc.this.id

  tags = {
    Name = "${var.name_prefix}-${replace(each.key, "_", "-")}"
  }
}

# ---------------------------------------------------------------------------------------------------------------------
# Cluster API and nodes
# ---------------------------------------------------------------------------------------------------------------------

resource "aws_vpc_security_group_ingress_rule" "cluster_api_https_from_nodes" {
  security_group_id            = aws_security_group.cluster_api.id
  description                  = "HTTPS from the nodes: kubelets, controllers and the system node that ends the SSM tunnel"
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
  referenced_security_group_id = aws_security_group.nodes.id
}

# EKS's documented control-plane-to-node ports: 443 for API extensions and 1025-65535 for kubelets (10250) and
# admission webhooks such as Kyverno's.
resource "aws_vpc_security_group_egress_rule" "cluster_api_to_nodes" {
  for_each = { https = [443, 443], high = [1025, 65535] }

  security_group_id            = aws_security_group.cluster_api.id
  description                  = "To the nodes on TCP ${each.value[0]}-${each.value[1]}: kubelets, webhooks and API extensions"
  ip_protocol                  = "tcp"
  from_port                    = each.value[0]
  to_port                      = each.value[1]
  referenced_security_group_id = aws_security_group.nodes.id
}

resource "aws_vpc_security_group_ingress_rule" "nodes_from_cluster_api" {
  for_each = { https = [443, 443], high = [1025, 65535] }

  security_group_id            = aws_security_group.nodes.id
  description                  = "From the cluster API on TCP ${each.value[0]}-${each.value[1]}: kubelets, webhooks and API extensions"
  ip_protocol                  = "tcp"
  from_port                    = each.value[0]
  to_port                      = each.value[1]
  referenced_security_group_id = aws_security_group.cluster_api.id
}

resource "aws_vpc_security_group_ingress_rule" "nodes_from_nodes" {
  security_group_id            = aws_security_group.nodes.id
  description                  = "Between nodes and pods; default-deny network policies narrow it per workload"
  ip_protocol                  = "-1"
  referenced_security_group_id = aws_security_group.nodes.id
}

# ---------------------------------------------------------------------------------------------------------------------
# Node pool egress: the perimeter
# ---------------------------------------------------------------------------------------------------------------------

resource "aws_vpc_security_group_egress_rule" "pool_to_vpc" {
  for_each = aws_security_group.pool

  security_group_id = each.value.id
  description       = "Anything inside the VPC: nodes, endpoints, the cluster API, Aurora and Valkey"
  ip_protocol       = "-1"
  cidr_ipv4         = aws_vpc.this.cidr_block
}

# The egress proxy is the only pod that reaches NAT, and network policies keep every other pod on system nodes off it;
# the Systems Manager agent, a host process, needs it to end the cluster tunnel (ADR-0021, T-53, R-15).
resource "aws_vpc_security_group_egress_rule" "system_nodes_https_out" {
  security_group_id = aws_security_group.pool["system_nodes"].id
  description       = "HTTPS out through NAT: allowlisted names of the egress proxy and the Systems Manager agent"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = "0.0.0.0/0"
}

# S3 in this Region uses public addresses through the gateway endpoint; its prefix list is the only outside
# destination main and scan nodes may reach (ADR-0021).
resource "aws_vpc_security_group_egress_rule" "workers_https_to_s3" {
  for_each = { for k, v in aws_security_group.pool : k => v if k != "system_nodes" }

  security_group_id = each.value.id
  description       = "HTTPS to S3 in this Region through the gateway endpoint"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  prefix_list_id    = aws_vpc_endpoint.s3_gateway.prefix_list_id
}
