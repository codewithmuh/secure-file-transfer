# What the data, cluster and edge stacks build on. Subnet and security group outputs are maps keyed by AZ ID or by
# role, so a consumer names what it means; values() gives a list.

output "vpc_id" {
  description = "ID of the VPC."
  value       = aws_vpc.this.id
}

output "vpc_cidr_block" {
  description = "The VPC's IPv4 range."
  value       = aws_vpc.this.cidr_block
}

output "availability_zone_ids" {
  description = "The VPC's AZ IDs, in the order given."
  value       = var.availability_zone_ids
}

output "public_subnet_ids" {
  description = "Public subnet IDs by AZ ID: the load balancer (edge) and the NAT gateways."
  value       = { for id, s in aws_subnet.public : id => s.id }
}

output "private_subnet_ids" {
  description = "Private subnet IDs by AZ ID: nodes and pods (cluster) and the Cognito trigger functions."
  value       = { for id, s in aws_subnet.private : id => s.id }
}

output "endpoint_subnet_ids" {
  description = "Endpoint subnet IDs by AZ ID: the cluster API's network interfaces go here (cluster), next to the interface endpoints."
  value       = { for id, s in aws_subnet.endpoints : id => s.id }
}

output "isolated_subnet_ids" {
  description = "Isolated subnet IDs by AZ ID, with no route out: Aurora and Valkey subnet groups (data)."
  value       = { for id, s in aws_subnet.isolated : id => s.id }
}

output "private_subnet_cidr_blocks" {
  description = "Private subnet ranges by AZ ID, for rules that admit the nodes, pods and trigger functions by address."
  value       = { for id, s in aws_subnet.private : id => s.cidr_block }
}

output "endpoint_subnet_cidr_blocks" {
  description = "Endpoint subnet ranges by AZ ID. Network policies let pods reach these on 443 (ADR-0021)."
  value       = { for id, s in aws_subnet.endpoints : id => s.cidr_block }
}

output "isolated_subnet_cidr_blocks" {
  description = "Isolated subnet ranges by AZ ID. Network policies let pods reach Aurora (5432) and Valkey (6379) here (ADR-0021)."
  value       = { for id, s in aws_subnet.isolated : id => s.cidr_block }
}

output "private_route_table_ids" {
  description = "Private route table IDs by AZ ID, for any later gateway endpoint."
  value       = { for id, rt in aws_route_table.private : id => rt.id }
}

output "nat_gateway_public_ips" {
  description = "The NAT gateways' public addresses by AZ ID. The sign-in web ACL accepts code exchanges only from these (abuse 3.2, edge)."
  value       = { for id, eip in aws_eip.nat : id => eip.public_ip }
}

output "security_group_ids" {
  description = <<-EOT
    Security group IDs by role (security-groups.tf). cluster_api: additional security group of the EKS cluster.
    nodes plus system_nodes: the system node group's launch template. nodes plus main_nodes, nodes plus scan_nodes: the
    Karpenter node classes. endpoints: the interface endpoints. Data stores admit main_nodes and scan_nodes; the load
    balancer reaches main_nodes.
  EOT
  value = {
    endpoints    = aws_security_group.endpoints.id
    cluster_api  = aws_security_group.cluster_api.id
    nodes        = aws_security_group.nodes.id
    system_nodes = aws_security_group.pool["system_nodes"].id
    main_nodes   = aws_security_group.pool["main_nodes"].id
    scan_nodes   = aws_security_group.pool["scan_nodes"].id
  }
}

output "s3_prefix_list_id" {
  description = "Prefix list of S3 in this Region (the gateway endpoint), for security group rules toward S3."
  value       = aws_vpc_endpoint.s3_gateway.prefix_list_id
}

output "vpc_endpoint_ids" {
  description = <<-EOT
    VPC endpoint IDs by key: sqs, kms, secretsmanager, ecr-api, ecr-dkr, sts, email, ec2, eks-auth, s3-peer (not in dev)
    and s3-gateway. For aws:SourceVpce conditions in bucket and key policies.
  EOT
  value = merge(
    { for k, e in aws_vpc_endpoint.interface : k => e.id },
    { "s3-gateway" = aws_vpc_endpoint.s3_gateway.id },
  )
}

output "dns_firewall_allowed_domains" {
  description = "Every name DNS Firewall answers in this VPC; everything else gets NXDOMAIN."
  value       = local.dns_allowed_domains
}

output "flow_log_id" {
  description = "ID of the VPC flow log, or null until flow_log_destination_arn is set."
  value       = one(aws_flow_log.this[*].id)
}

output "karpenter_discovery_tag" {
  description = "Tag on the private subnets for Karpenter's subnetSelectorTerms."
  value       = { "karpenter.sh/discovery" = var.name_prefix }
}
